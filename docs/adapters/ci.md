# CI Adapter (Jenkins, read-only)

`ci.status` / `ci.log` / `ci.artifact` over Jenkins. Read-only by design — a
rerun tool would be a separate item and would need the confirmation gate.

## Tenancy

Jenkins jobs carry no project concept, so the boundary is a server-side
allowlist: `CI_JOBS_FILE` maps `{"<project>": ["job", ...]}`. A token sees only
its project's jobs, and a job outside the allowlist is "unknown" whether or
not it exists on the instance — no existence oracle over Jenkins.

## Tools

| Tool | Arguments | Returns |
|---|---|---|
| `ci.status` | — | `jobs[] {job,build,result,building,timestamp,durationMs}` (`result`: SUCCESS/FAILURE/BUILDING/UNKNOWN…) |
| `ci.log` | `job`, `lines` (1–1000, default 200) | last-build console tail `{job,build,result,lines[],truncated}` |
| `ci.artifact` | `job`, `build` (optional, default last successful) | `{job,build,artifacts[] {fileName,relativePath,download}}` — metadata plus a per-file `download` URL, **never bytes** |

Logs are size-capped (bounded 512KB fetch, tail only): console output can
embed anything a build printed. These three tool calls share the per-user read
quota and are audited like every other tool — the artifact **download** is a
separate endpoint with its own limits and its own audit event, described below.

## Artifact download

`ci.artifact` lists a build's artifacts with a `download` URL each; the file
itself comes from a separate streaming endpoint, so a 100 MB image never enters
the MCP JSON channel or the agent's context:

```
GET <base>/ci/artifact?job=<job>&build=<n>&path=<relativePath>
Authorization: Bearer <the caller's own MCP token>
```

The endpoint authenticates the caller's **own bearer token** — no per-user CI
credential to provision, which is the point: the gateway already holds a
read-only CI account, and handing each user their own would reintroduce exactly
the credential sprawl this gateway exists to remove. It fetches from Jenkins
server-side with that account (which never leaves the process) and streams the
bytes back.

Two gates, both on the byte path and not only on the listing: the same
project→jobs allowlist as every other `ci.*` call, **and** that `path` is a real
artifact of that build. Only paths Jenkins itself lists are fetchable, so `..`,
an absolute path or an invented one is refused — identically to an unknown job
(404, no oracle for what exists). `build` is validated to a positive integer or
`lastSuccessfulBuild` / `lastBuild` before it reaches a URL path segment.

### Limits on the data plane

The bytes do not pass through an MCP result, so none of the tool-level limits
reach them. Three bounds apply instead:

| Bound | Default | Variable |
|---|---|---|
| Maximum artifact size | 256 MB | `CI_ARTIFACT_MAX_BYTES` |
| Concurrent downloads | 4 | `CI_ARTIFACT_MAX_CONCURRENT` |

A declared size over the cap is refused with 413 before any byte is streamed. An
absent or dishonest `Content-Length` cannot buy an unbounded transfer either: the
running total is checked per chunk and the connection is cut when it passes the
cap, which the caller sees as a short read. Concurrency is refused with 503 rather
than queued, because a stream holds a thread and an upstream connection for its
whole duration.

Every transfer emits its own audit event (`ci.artifact.download`) with the actor,
project, `job:path`, the outcome — `ok`, `rejected`, `truncated`, `interrupted`,
`backend_error` — and the number of bytes delivered. Without it the byte movement
would be the one operation the gateway performed and did not record.

The bytes served are the bytes the build wrote: the gateway asks Jenkins for an
identity-coded body and answers 502 (`backend_error`) if the upstream codes it
anyway, whether a `Transfer-Encoding` that is anything but the single bare
`chunked` field `http.client` itself de-chunks, or a `Content-Encoding` naming a
coding other than `identity` — a gzip stream saved under the artifact's own name
would be silent corruption. An empty field in either header names no coding and
is served as the identity bytes it is. Redirects are followed
only within the origin the request went to; one that leaves it (another host,
`ftp://`) is a backend failure, so a Jenkins credential never travels with it.
That rule is installed process-wide by `build_server`, so it covers every
backend credential the gateway sends, not only Jenkins'.

Honest cost that remains: the gateway is a data path, so a 200 MB pull is 200 MB
in and out of the host. Range/resume is not passed through, so an interrupted
transfer restarts from the beginning.

## Config

`JENKINS_BASE_URL`, `JENKINS_USER` + `JENKINS_TOKEN` (API token, basic auth),
`JENKINS_TIMEOUT_SEC`, `CI_JOBS_FILE`, plus the two limits above.
`CI_ARTIFACT_BASE_URL` (e.g.
`https://gateway.example/adapter`) is the public base spliced into the
`download` URLs; unset → `ci.artifact` returns a relative `/ci/artifact?…` the
caller resolves against its own endpoint origin. Enabled only when url + jobs
file are both set; `tools/list` hides `ci.*` for projects with no jobs.
