# CI Adapter (Jenkins)

`ci.status` / `ci.builds` / `ci.log` / `ci.artifact` read Jenkins.
`ci.rerun` starts a build and `ci.stop` cancels or stops one; nothing else here changes anything.

## Tenancy

Jenkins jobs carry no project concept, so the boundary is a server-side
allowlist: `CI_JOBS_FILE` maps `{"<project>": ["job", ...]}`. A token sees only
its project's jobs, and a job outside the allowlist is "unknown" whether or
not it exists on the instance — no existence oracle over Jenkins.

`ci.rerun` reads a **second** allowlist, `CI_TRIGGER_JOBS_FILE`, in the same
shape. Two files rather than one because the questions are different: the jobs
an agent may watch are not the jobs it may spend build capacity on, and one
list would make every visible job a startable one. Unset means no project may
start anything. A job that is watchable but not startable is refused with the
same 404 a foreign job gets.

## Tools

| Tool | Arguments | Returns |
|---|---|---|
| `ci.status` | — | `jobs[] {job,build,result,building,timestamp,startedAt,durationMs}` (`result`: SUCCESS/FAILURE/BUILDING/UNKNOWN…) |
| `ci.builds` | `job` (**optional** — omitted means every job in the project), `count` (1–50, default 10) | `{jobs[] {job,builds[] {build,result,building,timestamp,startedAt,durationMs},count},count}`, newest first |
| `ci.log` | `job`, `lines` (1–1000, default 200) | last-build console tail `{job,build,result,lines[],truncated}` |
| `ci.rerun` | `job`, `confirm` | `{job,queueItem,queueUrl,alreadyQueued}` — **confirmation-gated**, needs the `ci_runner` role and the trigger allowlist |
| `ci.stop` | `job`, exactly one of `queueItem` / `build`, `confirm` | `{job,queueItem}` or `{job,build}` — **confirmation-gated**, same `ci_runner` role and trigger allowlist as `ci.rerun` |

`ci.stop` is `ci.rerun`'s counterpart and is listed only where `ci.rerun` is
(a trigger allowlist configured and the `ci_runner` role held). It cancels a
queued item or stops a running build; pass exactly one of `queueItem` or
`build`. Queue ids are global in Jenkins, so the job allowlist alone cannot
authorise a cancellation: before posting, the gateway reads the queue item and
refuses unless its task URL is exactly that top-level, allowlisted job (`job/<name>/`;
a folder or multibranch job with the same leaf name is not it) — a foreign, missing
or unreadable item never cancels. The confirmation binds the exact target, so a
confirmation issued for one build or item cannot be spent on another. An item
that has already started is no longer in the queue and must be stopped by
build number. Every call is audited with `job:target` as the resource.

`alreadyQueued` is three-valued. `true` is the only certain answer: the queue item existed before the trigger, so this call added nothing. `false` means only that it was not seen beforehand — another client can queue the same job in the window between the read and the trigger. `null` means the queue could not be read at all. Rounding the last two to `false` is what makes an agent wait for a distinct build that never arrives.

Job names are spelled as Jenkins's own top-level job names and are URL-quoted whole, so a job inside a folder (`/job/team/job/build`) cannot be named here — that is true of the read allowlist too, and is a limitation of the whole family rather than of `ci.rerun`.
| `ci.artifact` | `job`, `build` (optional, default last successful) | `{job,build,artifacts[] {fileName,relativePath,download}}` — metadata plus a per-file `download` URL, **never bytes** |

`ci.builds` is a **last-N view**: a job that has been red for longer than
`count` builds is indistinguishable from one red since its first build. With
`job` omitted it walks the project's allowlist in one call — the shape of the
question it exists for — and the per-job count is reduced so the history stays
within one shared row budget of 200. The floor is one row per job, so a project
with more than 200 allowlisted jobs gets one build each and the answer is then
as wide as `ci.status` already is: the budget bounds the *depth* of the history,
the allowlist bounds the *width*, and neither bounds the other.

Like `ci.status`, a project-wide call makes one Jenkins request per allowlisted
job, sequentially, so its worst case is the job count times `JENKINS_TIMEOUT_SEC`.
Both tools share that shape; keep the allowlist to the jobs a project actually
watches.

`startedAt` is the ISO-8601 field to reason with; the raw Jenkins `timestamp`
(epoch ms) is kept beside it because `ci.status` has emitted it since 0.1.0.

Logs are size-capped (bounded 512KB fetch, tail only): console output can
embed anything a build printed. These four tool calls share the per-user read
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
single CI account, and handing each user their own would reintroduce exactly
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
