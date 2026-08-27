FROM python:3.12-slim

WORKDIR /app

# The docs corpus (docs.search/get/list) shallow-clones each project's docs repo
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

CMD ["mcp-governance-gateway"]
