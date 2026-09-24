# Pinned by digest so a rebuild of the same commit gets the same base; the tag
# stays for the reader. Dependabot (docker ecosystem) proposes the new digest
# monthly, which is how base-image security fixes arrive -- a pin nobody bumps
# would freeze them out instead.
FROM python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9

WORKDIR /app

# The docs corpus (docs.search/get/list) clones each project's docs repo
# and pulls it on a throttled loop. git for the clone; openssh-client because
# Gerrit remotes are ssh:// (git's https helper is already in git-core).
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends git openssh-client \
 && rm -rf /var/lib/apt/lists/*

# ssh refuses to run for a uid with no passwd entry ("No user exists for uid
# 65532"), and it needs a HOME for ~/.ssh (deploy key + known_hosts). Give the
# unprivileged uid a real account and home instead of running as root.
RUN groupadd -g 65532 nonroot \
 && useradd -u 65532 -g 65532 -m -d /home/nonroot -s /usr/sbin/nologin nonroot

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir .

USER 65532:65532

ENV HOME=/home/nonroot
ENV GATEWAY_HOST=0.0.0.0
ENV GATEWAY_PORT=8080

# Liveness only: /healthz answers without a bearer and calls no backend. The
# image has no curl, so it is Python's own urllib -- with proxies disabled, since
# an HTTP(S)_PROXY an operator sets for the backends must not carry a probe of
# 127.0.0.1. A wildcard bind is probed on loopback; a specific one, on itself.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import os, urllib.request as u; h = os.environ.get('GATEWAY_HOST', '127.0.0.1'); h = '127.0.0.1' if h in ('', '0.0.0.0') else h; u.build_opener(u.ProxyHandler({})).open('http://%s:%s/healthz' % (h, os.environ.get('GATEWAY_PORT', '8080')), timeout=4)"

CMD ["mcp-governance-gateway"]
