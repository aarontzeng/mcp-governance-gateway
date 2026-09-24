"""The CI family: Jenkins reads, and two gated writes.

Tenancy is the server-side project -> jobs allowlist. `ci.rerun` and `ci.stop`
spend build capacity, so they take a SECOND allowlist (the jobs a project may
START, which is not the set it may watch), the ci_runner role, and the
confirmation gate.
"""
from __future__ import annotations

from typing import Any

from ..auth import Principal
from ..ci_backend import CiBackendError
from ..memory_backend import RequestContext
from . import args
from .base import CI, CI_RUNNER, FEATURE_CI, FEATURE_CI_WRITE, WRITE, ToolHost, ToolSpec

_READ = frozenset({FEATURE_CI})
_WRITE = frozenset({FEATURE_CI, FEATURE_CI_WRITE})
_BUILD_MAX = 1_000_000_000

TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec(
        name="ci.status",
        family=CI,
        requires=_READ,
        description="Last-build status of this project's CI jobs (read-only).",
        input_schema={"type": "object", "properties": {}, "additionalProperties": False},
    ),
    ToolSpec(
        name="ci.log",
        family=CI,
        requires=_READ,
        description=(
            "The end of the last build's console log for one CI job (read-only). The whole "
            "console is streamed and only its last 512 KB kept, so the lines are the real tail; "
            "`truncated` is true when you asked for more lines than that window holds."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "job": {"type": "string"},
                "lines": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 200},
            },
            "required": ["job"],
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        name="ci.builds",
        family=CI,
        requires=_READ,
        description=(
            "Recent build history, newest first (read-only): build number, result, startedAt "
            "and duration per build. Omit `job` to get every job in the project — that is the "
            "call for 'which of my jobs regressed'; name a job to look at one in more depth. "
            "This is a last-N view: a job that has been red for longer than `count` builds "
            "looks the same as one red since its first build. Across many jobs the per-job "
            "count is silently reduced to share one row budget."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "job": {"type": "string", "description": "Omitted (or blank) means every job in this project."},
                "count": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
            },
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        name="ci.rerun",
        family=CI,
        access=WRITE,
        role=CI_RUNNER,
        requires=_WRITE,
        description=(
            "Start a build of one CI job (two-step: call once to get a confirmationId, "
            "then again with `confirm` set). Re-runs the job as configured; there are no "
            "build parameters. Returns the QUEUE ITEM, not a build number — the build does "
            "not exist until Jenkins's quiet period elapses, and two reruns inside it are "
            "coalesced into one build, which `alreadyQueued` reports. Poll ci.builds for the "
            "result. Only jobs on this project's trigger allowlist can be started, which is "
            "not the same list ci.status shows you."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "job": {"type": "string"},
                "confirm": {"type": "string"},
            },
            "required": ["job"],
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        name="ci.stop",
        family=CI,
        access=WRITE,
        role=CI_RUNNER,
        requires=_WRITE,
        # The queue item or build IS what was stopped; without this the audit had
        # no handle on it.
        resource_id=lambda result: f"{result['job']}:{result.get('queueItem') or result.get('build')}",
        description=(
            "Cancel a queued item or stop an explicit build. Pass exactly one of queueItem "
            "or build. Uses the same ci_runner role and trigger allowlist as ci.rerun. "
            "Call once for a confirmationId, then again with confirm. Queue ownership is "
            "checked before cancellation; an item that already started must be stopped by build number."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "job": {"type": "string"},
                "queueItem": {"type": "integer", "minimum": 1},
                "build": {"type": "integer", "minimum": 1},
                "confirm": {"type": "string"},
            },
            "required": ["job"],
            "additionalProperties": False,
        },
    ),
    ToolSpec(
        name="ci.artifact",
        family=CI,
        requires=_READ,
        description=(
            "List one build's artifacts for a CI job: fileName, relativePath and a gateway "
            "download URL per file. Metadata only — fetch a file from the download URL with "
            "your existing bearer token; the bytes never travel through this tool, so a "
            "100 MB image cannot land in your context."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "job": {"type": "string"},
                "build": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Build number; omitted means the last successful build.",
                },
            },
            "required": ["job"],
            "additionalProperties": False,
        },
    ),
)


def call(host: ToolHost, name: str, arguments: dict[str, Any], principal: Principal, context: RequestContext) -> dict[str, Any]:
    backend = host.ci_backend
    if backend is None:
        raise CiBackendError("CI is not enabled on this gateway", status=404)
    # ci.rerun pays this too, unlike issues.create which takes no quota at
    # all. Deliberate, and the asymmetry is worth stating: a build trigger
    # spends a shared resource, so a bound on how fast one can be asked for
    # is a feature rather than an oversight -- and both passes of the
    # two-step count, which is the honest price of the gate.
    host.enforce_read_quota(principal)
    if name == "ci.status":
        return backend.status(context)
    if name == "ci.log":
        job = args.required_text(arguments, "job", max_len=200)
        return backend.log(job, context, args.optional_int(arguments, "lines", minimum=1, maximum=1000))
    if name == "ci.builds":
        job = args.optional_text(arguments, "job", max_len=200)
        return backend.builds(job, context, args.optional_int(arguments, "count", minimum=1, maximum=50))
    if name == "ci.artifact":
        job = args.required_text(arguments, "job", max_len=200)
        build = args.optional_int(arguments, "build", minimum=1, maximum=_BUILD_MAX)
        return backend.artifacts(job, context, build)
    if name == "ci.stop":
        job = args.required_text(arguments, "job", max_len=200)
        queue_item = args.optional_int(arguments, "queueItem", minimum=1, maximum=_BUILD_MAX)
        build = args.optional_int(arguments, "build", minimum=1, maximum=_BUILD_MAX)
        if (queue_item is None) == (build is None):
            raise ValueError("pass exactly one of queueItem or build")
        backend.require_triggerable(job, context)
        semantic = {"job": job, "queueItem": queue_item, "build": build}
        pending = host.confirmation_gate(
            name, semantic, arguments, principal,
            f"Stop CI job {job!r}, " + (f"queue item {queue_item}" if queue_item is not None else f"build {build}"))
        if pending is not None:
            return pending
        return backend.stop(job, context, queue_item=queue_item, build=build)
    if name == "ci.rerun":
        job = args.required_text(arguments, "job", max_len=200)
        # Allowlist FIRST, then the confirmation. Minting a nonce for a job
        # this project may not start would ask someone to confirm an action
        # that is going to 404, and would make "three gates" untrue of the
        # first call -- it would check the role and nothing else.
        backend.require_triggerable(job, context)
        # Then the gate, before the side effect, as issues.create does: a
        # rerun that started a build and THEN asked for confirmation would
        # have spent the thing the confirmation exists to protect.
        pending = host.confirmation_gate(name, {"job": job}, arguments, principal, f"Start a CI build of {job!r}")
        if pending is not None:
            return pending
        return backend.rerun(job, context)
    raise ValueError(f"Unknown ci tool: {name}")
