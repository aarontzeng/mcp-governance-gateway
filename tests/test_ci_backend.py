from __future__ import annotations

import json
import unittest
from typing import Any

from mcp_governance_gateway.audit import AuditEvent, AuditSink
from mcp_governance_gateway.auth import Principal
from mcp_governance_gateway.ci_backend import CiBackendError, JenkinsHttpBackend, load_ci_jobs
from mcp_governance_gateway.mcp import GatewayApp
from mcp_governance_gateway.memory_backend import MemoryBackend, RequestContext


def _ctx(project="proj-a"):
    return RequestContext(actor="10000000", project=project, client="t", request_id="req-1")


LAST_BUILD = {"number": 128, "result": "FAILURE", "building": False, "timestamp": 1780000000000, "duration": 65000}


class FakeJenkins(JenkinsHttpBackend):
    def __init__(self, jobs=None, replies=None, trigger_jobs=None):
        super().__init__("https://jenkins.example", "svc", "TOKEN",
                         jobs or {"proj-a": ["swarm-build", "swarm-lint"]},
                         trigger_jobs_by_project=trigger_jobs)
        self.paths: list[str] = []
        self.posts: list[str] = []
        self.replies = replies or {}

    _NO_POST_REPLY = object()   # so a configured `None` is not "not configured"

    def _post(self, path: str) -> str | None:
        self.posts.append(path)
        reply = self.replies.get("POST", self._NO_POST_REPLY)
        if isinstance(reply, CiBackendError):
            raise reply
        return "https://jenkins.example/queue/item/7/" if reply is self._NO_POST_REPLY else reply

    def _fetch(self, path: str) -> bytes:
        self.paths.append(path)
        for key, reply in self.replies.items():
            if key in path:
                if isinstance(reply, CiBackendError):
                    raise reply
                return reply if isinstance(reply, bytes) else str(reply).encode()
        import json as _json
        if "/api/json" in path:
            return _json.dumps(LAST_BUILD).encode()
        if "/consoleText" in path:
            return b"\n".join(b"line %d" % i for i in range(1, 501))
        return b"{}"


ARTIFACT_LISTING = {
    "number": 291,
    "artifacts": [
        {"fileName": "image.bin", "relativePath": "out/image.bin"},
        {"fileName": "notes.log", "relativePath": "out/logs/notes.log"},
        {"fileName": "no-path.bin"},  # malformed entry: skipped, never crashes the listing
    ],
}


class ArtifactListingTests(unittest.TestCase):
    def _fake(self, **kw):
        import json as _json
        return FakeJenkins(replies={"/api/json": _json.dumps(ARTIFACT_LISTING).encode()}, **kw)

    def test_lists_metadata_with_a_download_url_per_file(self):
        backend = JenkinsHttpBackend(
            "https://jenkins.example", "svc", "TOKEN", {"proj-a": ["swarm-build"]},
            artifact_base_url="https://gw.example/adapter",
        )
        import json as _json
        backend._fetch = lambda path: _json.dumps(ARTIFACT_LISTING).encode()  # type: ignore[method-assign]
        out = backend.artifacts("swarm-build", _ctx())
        self.assertEqual((out["job"], out["build"], out["count"]), ("swarm-build", 291, 2))
        first = out["artifacts"][0]
        self.assertEqual(first["relativePath"], "out/image.bin")
        self.assertEqual(
            first["download"],
            "https://gw.example/adapter/ci/artifact?job=swarm-build&build=291&path=out%2Fimage.bin",
        )
        # never any bytes: a build artifact is routinely tens of megabytes
        self.assertNotIn("content", first)
        self.assertNotIn("bytes", first)

    def test_download_url_is_relative_when_no_base_is_configured(self):
        out = self._fake().artifacts("swarm-build", _ctx())
        self.assertTrue(out["artifacts"][0]["download"].startswith("/ci/artifact?"))

    def test_foreign_and_nonexistent_jobs_are_indistinguishable(self):
        fake = self._fake()
        errors = []
        for job in ("swarm-lint-of-another-project", "does-not-exist"):
            with self.assertRaises(CiBackendError) as cm:
                fake.artifacts(job, _ctx())
            errors.append((str(cm.exception), cm.exception.status))
        self.assertEqual(errors[0], errors[1])
        self.assertEqual(errors[0][1], 404)

    def test_a_job_from_another_tenant_is_not_reachable(self):
        # allowlisted for proj-a, requested by proj-b
        with self.assertRaises(CiBackendError) as cm:
            self._fake().artifacts("swarm-build", _ctx("proj-b"))
        self.assertEqual(cm.exception.status, 404)

    def test_omitted_build_asks_for_the_last_successful_one(self):
        fake = self._fake()
        fake.artifacts("swarm-build", _ctx())
        self.assertIn("/lastSuccessfulBuild/api/json", fake.paths[-1])

    def test_build_ref_cannot_carry_a_path(self):
        fake = self._fake()
        for bad in ("../../evil", "lastBuild/../../x", "0", "-1", "abc", 0, -5, True):
            with self.subTest(bad=bad):
                with self.assertRaises(CiBackendError) as cm:
                    fake.artifacts("swarm-build", _ctx(), bad)
                self.assertEqual(cm.exception.status, 400)
        # the known aliases and a positive number are accepted
        for good in ("lastBuild", "lastSuccessfulBuild", "291", 291):
            with self.subTest(good=good):
                fake.artifacts("swarm-build", _ctx(), good)


class ArtifactDownloadTests(unittest.TestCase):
    """locate_artifact() is the gate to the bytes (open_artifact() is it plus the
    open), so its two checks matter: the tenant allowlist, and that the path is
    one Jenkins itself listed. open_located() trusts its argument: nothing in the
    package calls it with a path locate_artifact() did not return."""

    def _backend(self):
        import json as _json
        backend = JenkinsHttpBackend(
            "https://jenkins.example", "svc", "TOKEN", {"proj-a": ["swarm-build"]},
        )
        self.opened: list[str] = []
        backend._fetch = lambda path: _json.dumps(ARTIFACT_LISTING).encode()  # type: ignore[method-assign]
        backend._open = lambda path: self.opened.append(path) or "STREAM"    # type: ignore[method-assign]
        return backend

    def test_a_listed_path_is_opened_url_encoded(self):
        backend = self._backend()
        self.assertEqual(backend.open_artifact("swarm-build", 291, "out/logs/notes.log", _ctx()), "STREAM")
        self.assertEqual(self.opened, ["/job/swarm-build/291/artifact/out/logs/notes.log"])

    def test_traversal_and_invented_paths_are_refused_identically(self):
        backend = self._backend()
        errors = set()
        for path in ("../../../etc/passwd", "/etc/passwd", "out/../out/image.bin", "out/secret.bin", ""):
            with self.subTest(path=path):
                with self.assertRaises(CiBackendError) as cm:
                    backend.open_artifact("swarm-build", 291, path, _ctx())
                self.assertEqual(cm.exception.status, 404)
                errors.add(str(cm.exception))
        self.assertEqual(len(errors), 1)   # one message: no oracle for what exists
        self.assertEqual(self.opened, [])  # nothing was ever fetched

    def test_a_traversal_shaped_path_from_the_ci_server_is_not_trusted(self):
        # Adversarial review, 2026-08-10: membership in the listing was the whole
        # traversal guard, and quoting does not neutralize `..` (dots are unreserved,
        # so quote("..") is ".."). A hostile or buggy listing could therefore point
        # the fetch outside the artifact path.
        import json as _json
        backend = self._backend()
        backend._fetch = lambda path: _json.dumps({"number": 1, "artifacts": [  # type: ignore[method-assign]
            {"fileName": "x", "relativePath": "../../../etc/passwd"},
            {"fileName": "y", "relativePath": "/etc/shadow"},
            {"fileName": "ok", "relativePath": "out/image.bin"},
        ]}).encode()
        # they are not listed to the caller ...
        self.assertEqual(
            [a["relativePath"] for a in backend.artifacts("swarm-build", _ctx())["artifacts"]],
            ["out/image.bin"],
        )
        # ... and not fetchable even when asked for by name
        for path in ("../../../etc/passwd", "/etc/shadow"):
            with self.subTest(path=path):
                with self.assertRaises(CiBackendError) as cm:
                    backend.open_artifact("swarm-build", 1, path, _ctx())
                self.assertEqual(cm.exception.status, 404)
        self.assertEqual(self.opened, [])

    def test_a_malformed_listing_stays_inside_the_backend_error_boundary(self):
        # `null` in the list used to raise AttributeError, which is not a
        # CiBackendError, so it escaped the handler's error mapping entirely.
        import json as _json
        for payload in ({"artifacts": [None]}, {"artifacts": "not-a-list"}, {}, {"artifacts": [{"x": 1}]}):
            with self.subTest(payload=payload):
                backend = self._backend()
                backend._fetch = lambda path, p=payload: _json.dumps(p).encode()  # type: ignore[method-assign]
                self.assertEqual(backend.artifacts("swarm-build", _ctx())["count"], 0)
                with self.assertRaises(CiBackendError):
                    backend.open_artifact("swarm-build", 1, "out/image.bin", _ctx())

    def test_the_allowlist_is_enforced_on_the_download_too(self):
        # The tenant boundary must hold on the byte path, not only on the listing.
        backend = self._backend()
        with self.assertRaises(CiBackendError) as cm:
            backend.open_artifact("swarm-build", 291, "out/image.bin", _ctx("proj-b"))
        self.assertEqual(cm.exception.status, 404)
        self.assertEqual(self.opened, [])

    def test_a_garbled_upstream_reply_is_reported_as_ci_unavailable(self):
        # A bad status line or an over-long header is an http.client.HTTPException,
        # not an OSError: it must still come back as a CiBackendError, or it would
        # escape the artifact route's error handling and never be audited.
        import http.client
        from unittest import mock
        backend = JenkinsHttpBackend(
            "https://jenkins.example", "svc", "TOKEN", {"proj-a": ["swarm-build"]},
        )
        backend._fetch = lambda path: json.dumps(ARTIFACT_LISTING).encode()  # type: ignore[method-assign]
        with mock.patch("mcp_governance_gateway.ci_backend.request.urlopen",
                        side_effect=http.client.BadStatusLine("garbage")):
            with self.assertRaises(CiBackendError) as cm:
                backend.open_artifact("swarm-build", 291, "out/image.bin", _ctx())
        self.assertEqual(str(cm.exception), "CI unavailable")
        self.assertIsNone(cm.exception.status)

    def test_a_garbled_upstream_reply_to_a_status_read_is_ci_unavailable_too(self):
        import http.client
        from unittest import mock
        backend = JenkinsHttpBackend(
            "https://jenkins.example", "svc", "TOKEN", {"proj-a": ["swarm-build"]},
        )
        with mock.patch("mcp_governance_gateway.ci_backend.request.urlopen",
                        side_effect=http.client.BadStatusLine("garbage")):
            with self.assertRaises(CiBackendError) as cm:
                backend.status(_ctx())
        self.assertEqual(str(cm.exception), "CI unavailable")

    def test_a_status_reply_that_ends_mid_body_is_ci_unavailable(self):
        # The two tests above fail urlopen itself; this one fails the read()
        # inside the `with` block, where a truncated body actually surfaces.
        import http.client
        from unittest import mock

        class _Truncated:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self, n=-1):
                raise http.client.IncompleteRead(b"")

        backend = JenkinsHttpBackend(
            "https://jenkins.example", "svc", "TOKEN", {"proj-a": ["swarm-build"]},
        )
        with mock.patch("mcp_governance_gateway.ci_backend.request.urlopen", return_value=_Truncated()):
            with self.assertRaises(CiBackendError) as cm:
                backend.status(_ctx())
        self.assertEqual(str(cm.exception), "CI unavailable")

    def test_every_jenkins_request_asks_for_an_identity_coded_body(self):
        # The artifact route serves the bytes as they arrive and refuses a coded
        # body; asking for identity is what makes that refusal the exception.
        from unittest import mock
        sent = []

        def capture(req, timeout):
            sent.append(req)
            raise OSError("not connected")

        backend = JenkinsHttpBackend(
            "https://jenkins.example", "svc", "TOKEN", {"proj-a": ["swarm-build"]},
        )
        with mock.patch("mcp_governance_gateway.ci_backend.request.urlopen", side_effect=capture):
            with self.assertRaises(CiBackendError):
                backend.status(_ctx())
            with self.assertRaises(CiBackendError):
                backend.open_located("/job/swarm-build/291/artifact/out/image.bin")
        self.assertEqual([r.get_header("Accept-encoding") for r in sent], ["identity", "identity"])


class StatusTests(unittest.TestCase):
    def test_status_lists_allowlisted_jobs(self):
        out = FakeJenkins().status(_ctx())
        self.assertEqual(out["count"], 2)
        self.assertEqual(out["jobs"][0]["job"], "swarm-build")
        self.assertEqual(out["jobs"][0]["result"], "FAILURE")
        self.assertEqual(out["jobs"][0]["build"], 128)

    def test_building_state_wins(self):
        import json as _json
        fake = FakeJenkins(replies={"/api/json": _json.dumps(dict(LAST_BUILD, building=True, result=None)).encode()})
        out = fake.status(_ctx())
        self.assertEqual(out["jobs"][0]["result"], "BUILDING")

    def test_the_last_build_row_carries_the_same_iso_time_as_the_history_rows(self):
        # ci.status and ci.builds share one row normalizer so they cannot drift.
        # They already had: the listing rejected a non-string `result` while this
        # row passed one through (review, 2026-09-04).
        import json as _json
        fake = FakeJenkins(replies={"/api/json": _json.dumps(
            dict(LAST_BUILD, result=42, timestamp=1780000000000)).encode()})
        row = fake.status(_ctx())["jobs"][0]
        self.assertEqual(row["startedAt"], "2026-05-28T20:26:40Z")
        self.assertEqual(row["result"], "UNKNOWN")   # a non-string result is not a result

    def test_job_with_no_builds_is_unknown_not_error(self):
        fake = FakeJenkins(replies={"/api/json": CiBackendError("CI HTTP 404", status=404)})
        out = fake.status(_ctx())
        self.assertEqual(out["jobs"][0]["result"], "UNKNOWN")

    def test_a_never_built_job_has_the_same_keys_as_a_built_one(self):
        # Two shapes from one tool is work pushed onto every caller. The
        # never-built row carries the same keys with nulls.
        built = FakeJenkins().status(_ctx())["jobs"][0]
        never = FakeJenkins(replies={"/api/json": CiBackendError("CI HTTP 404", status=404)}).status(_ctx())["jobs"][0]
        self.assertEqual(set(built), set(never))
        self.assertIsNone(never["startedAt"])

    def test_project_without_jobs_rejected(self):
        with self.assertRaises(CiBackendError):
            FakeJenkins().status(_ctx(project="proj-b"))


class LogTests(unittest.TestCase):
    def test_log_tails_last_lines(self):
        out = FakeJenkins().log("swarm-build", _ctx(), lines=5)
        self.assertEqual(out["lines"], ["line 496", "line 497", "line 498", "line 499", "line 500"])
        self.assertEqual(out["result"], "FAILURE")

    def test_default_and_max_lines(self):
        out = FakeJenkins().log("swarm-build", _ctx())
        self.assertEqual(len(out["lines"]), 200)
        out = FakeJenkins().log("swarm-build", _ctx(), lines=99999)
        self.assertEqual(len(out["lines"]), 500)  # capped at 1000, only 500 exist

    def test_job_outside_allowlist_is_unknown_even_if_it_exists(self):
        # no oracle over the Jenkins instance: not-allowlisted == unknown
        fake = FakeJenkins()
        with self.assertRaises(CiBackendError) as cm:
            fake.log("some-other-team-job", _ctx())
        self.assertEqual(cm.exception.status, 404)
        self.assertEqual(fake.paths, [])  # never touched Jenkins

    def test_job_name_is_url_quoted(self):
        fake = FakeJenkins(jobs={"proj-a": ["team/job with space"]})
        fake.log("team/job with space", _ctx(), lines=1)
        self.assertIn("/job/team%2Fjob%20with%20space/", fake.paths[0])


class LoadJobsTests(unittest.TestCase):
    def test_load_and_validate(self):
        import json as _json, tempfile, os
        d = tempfile.mkdtemp()
        p = os.path.join(d, "jobs.json")
        open(p, "w").write(_json.dumps({"proj-a": ["a", "b"]}))
        self.assertEqual(load_ci_jobs(p), {"proj-a": ["a", "b"]})
        open(p, "w").write(_json.dumps({"proj-a": "not-a-list"}))
        with self.assertRaises(ValueError):
            load_ci_jobs(p)


class _NullMemory(MemoryBackend):
    def search(self, query, limit, context):  # pragma: no cover
        return {"results": []}


class _ListAudit(AuditSink):
    def __init__(self):
        self.events: list[AuditEvent] = []

    def write(self, event: AuditEvent) -> None:
        self.events.append(event)


class BuildHistoryTests(unittest.TestCase):
    """ci.builds over a fake Jenkins.

    The reply shapes here are the ones a real Jenkins 2.531 returned when this was
    written: rows newest first, `result` a string, `timestamp`/`duration` in ms, and
    an extra `_class` key the parser must ignore rather than choke on.
    """

    def _fake(self, rows, jobs=None):
        import json as _json
        payload = _json.dumps({"builds": rows}).encode()
        return FakeJenkins(jobs=jobs, replies={"tree=builds": payload})

    def _rows(self, n, first=30):
        return [
            {"_class": "hudson.model.FreeStyleBuild", "number": first - i, "result": "SUCCESS",
             "building": False, "timestamp": 1780000000000 + i, "duration": 20 + i}
            for i in range(n)
        ]

    def _one(self, out):
        self.assertEqual(out["count"], 1)
        return out["jobs"][0]

    def test_history_comes_back_newest_first_and_normalized(self):
        job = self._one(self._fake(self._rows(3)).builds("swarm-build", _ctx()))
        self.assertEqual(job["job"], "swarm-build")
        self.assertEqual([b["build"] for b in job["builds"]], [30, 29, 28])
        self.assertEqual(job["builds"][0]["result"], "SUCCESS")
        self.assertEqual(job["builds"][0]["durationMs"], 20)
        self.assertEqual(job["count"], 3)

    def test_time_is_reported_as_iso_beside_the_raw_jenkins_milliseconds(self):
        # Every other timestamp this gateway emits is ISO-8601, and this is the one
        # tool whose whole payload is time; an agent comparing builds to "this week"
        # should not have to know Jenkins speaks epoch ms.
        job = self._one(self._fake(self._rows(1)).builds("swarm-build", _ctx()))
        self.assertEqual(job["builds"][0]["timestamp"], 1780000000000)
        self.assertEqual(job["builds"][0]["startedAt"], "2026-05-28T20:26:40Z")

    def test_the_job_endpoint_is_asked_with_a_bounded_range(self):
        fake = self._fake(self._rows(3))
        fake.builds("swarm-build", _ctx())
        self.assertIn("/job/swarm-build/api/json?tree=builds[", fake.paths[-1])
        self.assertTrue(fake.paths[-1].endswith("{0,10}"))  # the schema's declared default
        fake.builds("swarm-build", _ctx(), count=999)
        self.assertTrue(fake.paths[-1].endswith("{0,50}"))  # capped, never the caller's number
        fake.builds("swarm-build", _ctx(), count=0)
        self.assertTrue(fake.paths[-1].endswith("{0,1}"))   # 0 means zero, not "unspecified"

    def test_a_server_that_returns_more_rows_than_asked_is_still_bounded(self):
        # This is the OUTPUT contract, not a defence against an unbounded fetch:
        # a listing over the 512KB read cap is cut mid-JSON and never reaches here.
        job = self._one(self._fake(self._rows(30)).builds("swarm-build", _ctx(), count=4))
        self.assertEqual(job["count"], 4)
        self.assertEqual([b["build"] for b in job["builds"]], [30, 29, 28, 27])

    def test_malformed_entries_are_dropped_rather_than_served(self):
        rows = [
            None,                                   # a null in the list
            "not-a-dict",
            {"result": "SUCCESS"},                  # no number
            {"number": True, "result": "SUCCESS"},  # bool is an int in Python
            {"number": 0, "result": "SUCCESS"},
            {"number": "12", "result": "SUCCESS"},  # a string number is not a number
            {"number": 7, "result": "SUCCESS", "building": False},
        ]
        job = self._one(self._fake(rows).builds("swarm-build", _ctx()))
        self.assertEqual([b["build"] for b in job["builds"]], [7])

    def test_a_non_numeric_time_from_the_ci_server_becomes_null_not_a_list(self):
        rows = [{"number": 9, "result": "SUCCESS", "timestamp": [], "duration": {"x": 1}}]
        build = self._one(self._fake(rows).builds("swarm-build", _ctx()))["builds"][0]
        self.assertIsNone(build["timestamp"])
        self.assertIsNone(build["startedAt"])
        self.assertIsNone(build["durationMs"])

    def test_a_nan_or_infinite_time_does_not_escape_the_error_boundary(self):
        # `json.loads` accepts the non-standard NaN/Infinity literals, and
        # `int(nan)` raises a ValueError that is NOT a CiBackendError -- so this
        # used to surface as a 500 rather than a tool error. (Review, 2026-09-04.)
        import json as _json
        raw = b'{"builds": [{"number": 9, "result": "SUCCESS", "timestamp": NaN, "duration": Infinity}]}'
        self.assertTrue(_json.loads(raw))  # the literal really does parse
        build = self._one(FakeJenkins(replies={"tree=builds": raw}).builds("swarm-build", _ctx()))["builds"][0]
        self.assertIsNone(build["timestamp"])
        self.assertIsNone(build["durationMs"])

    def test_a_nonsense_epoch_leaves_the_iso_field_null_rather_than_failing(self):
        rows = [{"number": 9, "result": "SUCCESS", "timestamp": 10 ** 25}]
        build = self._one(self._fake(rows).builds("swarm-build", _ctx()))["builds"][0]
        self.assertEqual(build["timestamp"], 10 ** 25)
        self.assertIsNone(build["startedAt"])

    def test_a_listing_that_is_not_a_list_is_empty_not_an_error(self):
        # The fixture must be NON-ITERABLE. A dict or a string would let this test
        # pass with the `isinstance(entries, list)` guard deleted -- iterating a
        # dict yields its keys and iterating a string yields characters, both of
        # which the per-entry check then drops. (Found by review, 2026-09-04.)
        for not_a_list in (5, None, True, {"oops": 1}, "nope"):
            job = self._one(self._fake(not_a_list).builds("swarm-build", _ctx()))
            self.assertEqual(job["builds"], [])

    def test_building_and_missing_results_are_named_not_null(self):
        rows = [{"number": 9, "building": True, "result": None},
                {"number": 8, "building": False, "result": None},
                {"number": 7, "building": False, "result": 42}]
        job = self._one(self._fake(rows).builds("swarm-build", _ctx()))
        self.assertEqual([b["result"] for b in job["builds"]], ["BUILDING", "UNKNOWN", "UNKNOWN"])

    def test_foreign_and_nonexistent_jobs_are_indistinguishable(self):
        fake = self._fake(self._rows(1))
        with self.assertRaises(CiBackendError) as a:
            fake.builds("someone-elses-job", _ctx())
        with self.assertRaises(CiBackendError) as b:
            fake.builds("no-such-job-anywhere", _ctx())
        self.assertEqual(str(a.exception), str(b.exception))
        self.assertEqual(a.exception.status, 404)
        self.assertEqual(fake.paths, [])  # refused before any request reached the CI server

    def test_a_project_with_no_jobs_cannot_read_history(self):
        for job in ("swarm-build", None):
            with self.assertRaises(CiBackendError):
                self._fake(self._rows(1)).builds(job, _ctx(project="proj-b"))


class ProjectWideHistoryTests(unittest.TestCase):
    """`job` omitted: the whole project in one call.

    The motivating question -- "which of my jobs regressed" -- is project-shaped.
    Requiring a job name would make an agent answer it with one call per job, each
    spending its own read quota and producing its own audit event.
    """

    def _fake(self, jobs, rows=3):
        import json as _json
        payload = _json.dumps({"builds": [
            {"number": 30 - i, "result": "SUCCESS", "building": False,
             "timestamp": 1780000000000, "duration": 20} for i in range(rows)]}).encode()
        return FakeJenkins(jobs=jobs, replies={"tree=builds": payload})

    def test_every_allowlisted_job_is_reported_in_one_call(self):
        out = self._fake({"proj-a": ["swarm-build", "swarm-lint"]}).builds(None, _ctx())
        self.assertEqual(out["count"], 2)
        self.assertEqual([j["job"] for j in out["jobs"]], ["swarm-build", "swarm-lint"])
        self.assertEqual(out["jobs"][0]["count"], 3)

    def test_a_blank_job_name_means_the_whole_project_not_an_error(self):
        out = self._fake({"proj-a": ["swarm-build", "swarm-lint"]}).builds("   ", _ctx())
        self.assertEqual(out["count"], 2)

    def test_many_jobs_share_one_row_budget(self):
        names = [f"job-{i}" for i in range(40)]
        fake = self._fake({"proj-a": names})
        fake.builds(None, _ctx(), count=50)
        # 200 // 40 == 5 per job, not the 50 that was asked for.
        self.assertTrue(all(p.endswith("{0,5}") for p in fake.paths), fake.paths[:2])
        self.assertEqual(len(fake.paths), 40)

    def test_more_jobs_than_the_budget_degrade_to_one_row_each(self):
        # Integer division floors to 0 past the budget and `max(1, ...)` catches it,
        # so the total is then bounded by the allowlist rather than by the budget --
        # the same width ci.status already returns. Stated rather than hidden.
        names = [f"job-{i}" for i in range(250)]
        fake = self._fake({"proj-a": names})
        out = fake.builds(None, _ctx(), count=50)
        self.assertTrue(all(p.endswith("{0,1}") for p in fake.paths))
        self.assertEqual(out["count"], 250)

    def test_one_job_missing_on_the_ci_server_does_not_fail_the_project(self):
        # Allowlisted but renamed or deleted on Jenkins: `status()` already reports
        # that job as UNKNOWN rather than failing the listing, and so does this.
        fake = FakeJenkins(jobs={"proj-a": ["gone", "swarm-lint"]},
                           replies={"tree=builds": CiBackendError("CI HTTP 404", status=404)})
        out = fake.builds(None, _ctx())
        self.assertEqual(out["count"], 2)
        self.assertEqual(out["jobs"][0], {"job": "gone", "builds": [], "count": 0})

    def test_an_unavailable_ci_server_is_still_an_error(self):
        fake = FakeJenkins(jobs={"proj-a": ["swarm-build"]},
                           replies={"tree=builds": CiBackendError("CI HTTP 500", status=500)})
        with self.assertRaises(CiBackendError):
            fake.builds(None, _ctx())


class LogMetadataTests(unittest.TestCase):
    """`ci.log` takes its build/result from the same row as `ci.status`.

    That is not obvious from `log()` -- it calls `_job_status` for metadata -- so
    the shared normalizer reaches a third tool. Pinned here because a review
    found it unlisted and untested rather than because it is new behaviour.
    """

    def _log(self, last_build):
        import json as _json
        fake = FakeJenkins(replies={"/api/json": _json.dumps(last_build).encode()})
        return fake.log("swarm-build", _ctx(), lines=1)

    def test_a_non_string_result_reads_as_unknown_in_the_log_metadata_too(self):
        self.assertEqual(self._log({"number": 128, "result": 42, "building": False})["result"], "UNKNOWN")

    def test_a_last_build_with_no_usable_number_reads_as_never_built(self):
        for body in ({"building": True}, {"number": 0, "result": "FAILURE"}, {"number": True}):
            out = self._log(body)
            self.assertIsNone(out["build"], body)
            self.assertEqual(out["result"], "UNKNOWN", body)

    def test_an_ordinary_last_build_is_unchanged(self):
        out = self._log(dict(LAST_BUILD))
        self.assertEqual((out["build"], out["result"]), (128, "FAILURE"))
        self.assertEqual(out["lines"], ["line 500"])   # the console tail is untouched


class RerunTests(unittest.TestCase):
    """ci.rerun over a fake Jenkins.

    The reply shapes are the ones a real Jenkins 2.531 gave: 201 with a
    `Location` naming a QUEUE ITEM, no build number, and two triggers inside the
    quiet period handed back the SAME item.
    """

    def _fake(self, trigger=("swarm-build",), jobs=None, replies=None):
        return FakeJenkins(jobs=jobs, replies=replies,
                           trigger_jobs={"proj-a": list(trigger)} if trigger is not None else None)

    def test_a_rerun_returns_the_queue_item_not_a_build(self):
        # The build number does not exist yet: Jenkins holds the request in the
        # quiet period first. Claiming a build here would be inventing one.
        fake = self._fake()
        out = fake.rerun("swarm-build", _ctx())
        self.assertEqual(out["job"], "swarm-build")
        self.assertEqual(out["queueItem"], 7)
        self.assertNotIn("build", out)
        self.assertEqual(fake.posts, ["/job/swarm-build/build"])

    def test_an_uncoalesced_rerun_reports_false_only_when_the_queue_was_read(self):
        import json as _json
        fake = self._fake(replies={"/queue/api/json": _json.dumps({"items": []}).encode()})
        self.assertIs(fake.rerun("swarm-build", _ctx())["alreadyQueued"], False)

    def test_a_coalesced_rerun_says_so_rather_than_claiming_a_new_build(self):
        # Measured against 2.531: two triggers inside the quiet period return the
        # same queue item and produce ONE build. Reporting the second as a fresh
        # start would be a lie an agent would then wait on.
        import json as _json
        fake = self._fake(replies={"/queue/api/json": _json.dumps({"items": [{"id": 7}]}).encode()})
        self.assertTrue(fake.rerun("swarm-build", _ctx())["alreadyQueued"])

    def test_a_queue_read_that_fails_says_unknown_rather_than_not_queued(self):
        # This test used to assert False, which PINNED a lie: a coalesced trigger
        # we could not observe is not a new build. False is a claim; None is the
        # truth when the queue could not be read. (Review, 2026-09-04.)
        fake = self._fake(replies={"/queue/api/json": CiBackendError("CI HTTP 500", status=500)})
        out = fake.rerun("swarm-build", _ctx())
        self.assertEqual(out["queueItem"], 7)
        self.assertIsNone(out["alreadyQueued"])

    def test_an_unparseable_location_also_makes_the_answer_unknown(self):
        fake = self._fake(replies={"POST": "not a url"})
        self.assertIsNone(fake.rerun("swarm-build", _ctx())["alreadyQueued"])

    def test_a_job_off_the_trigger_list_is_refused_before_a_confirmation_is_minted(self):
        # Minting a nonce for a job this project cannot start would ask someone to
        # confirm an action that is going to 404, and would make the first call a
        # role check and nothing else.
        import json as _json
        app = GatewayApp(memory_backend=_NullMemory(), audit_sink=_ListAudit(),
                         ci_backend=FakeJenkins(trigger_jobs={"proj-a": ["swarm-build"]}))
        runner = Principal(actor="9", project="proj-a", roles=("ci_runner",), token_id="t9")
        resp = app.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                               "params": {"name": "ci.rerun", "arguments": {"job": "swarm-lint"}}}, runner)
        self.assertTrue(resp["result"].get("isError"))
        self.assertNotIn("confirmationId", _json.dumps(resp))

    def test_a_location_that_cannot_be_parsed_is_a_missing_hint_not_an_error(self):
        for location in (None, "", "https://jenkins.example/queue/", "not a url"):
            out = self._fake(replies={"POST": location}).rerun("swarm-build", _ctx())
            self.assertIsNone(out["queueItem"], location)

    def test_the_trigger_allowlist_is_not_the_read_allowlist(self):
        # swarm-lint is watchable and must not be startable. The refusal is the
        # same 404 a job in another project gets: no oracle over what exists.
        fake = self._fake(trigger=("swarm-build",))
        with self.assertRaises(CiBackendError) as watchable:
            fake.rerun("swarm-lint", _ctx())
        with self.assertRaises(CiBackendError) as foreign:
            fake.rerun("no-such-job", _ctx())
        self.assertEqual(str(watchable.exception), str(foreign.exception))
        self.assertEqual(watchable.exception.status, 404)
        self.assertEqual(fake.posts, [])   # refused before anything reached Jenkins

    def test_no_trigger_allowlist_means_nobody_can_start_anything(self):
        # The default for a tool that spends CI capacity is "no".
        fake = self._fake(trigger=None)
        with self.assertRaises(CiBackendError) as caught:
            fake.rerun("swarm-build", _ctx())
        self.assertEqual(caught.exception.status, 404)
        self.assertEqual(fake.posts, [])

    def test_another_project_cannot_start_this_project_s_jobs(self):
        with self.assertRaises(CiBackendError):
            self._fake().rerun("swarm-build", _ctx(project="proj-b"))

    def test_a_403_names_the_credential_problem_it_almost_always_is(self):
        # Jenkins refuses a password POST without a session-bound crumb, and
        # exempts API tokens. A bare "CI HTTP 403" would send an operator looking
        # for a permissions problem they do not have.
        #
        # Driven through the REAL _post with urlopen patched, because the message
        # lives there; the recording fake would only prove the fake.
        import urllib.error
        from unittest import mock
        real = JenkinsHttpBackend("https://jenkins.example", "svc", "TOKEN",
                                  {"proj-a": ["swarm-build"]},
                                  trigger_jobs_by_project={"proj-a": ["swarm-build"]})
        error_403 = urllib.error.HTTPError("u", 403, "Forbidden", {}, None)
        with mock.patch("mcp_governance_gateway.ci_backend.request.urlopen", side_effect=error_403):
            with self.assertRaises(CiBackendError) as caught:
                real.rerun("swarm-build", _ctx())
        self.assertIn("API token", str(caught.exception))
        self.assertEqual(caught.exception.status, 403)

    def test_the_real_post_returns_the_location_header_and_sends_no_body(self):
        from unittest import mock
        real = JenkinsHttpBackend("https://jenkins.example", "svc", "TOKEN",
                                  {"proj-a": ["swarm-build"]},
                                  trigger_jobs_by_project={"proj-a": ["swarm-build"]})
        captured = {}

        class _Response:
            headers = {"Location": "https://jenkins.example/queue/item/11/"}

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, *a):
                return b"{}"

        def fake_urlopen(req, timeout=None):
            captured["method"] = req.get_method()
            captured["data"] = req.data
            captured["url"] = req.full_url
            return _Response()

        with mock.patch("mcp_governance_gateway.ci_backend.request.urlopen", side_effect=fake_urlopen):
            out = real.rerun("swarm-build", _ctx())
        self.assertEqual(out["queueItem"], 11)
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["data"], b"")     # no parameters: this re-runs as configured
        self.assertTrue(captured["url"].endswith("/job/swarm-build/build"))

    def test_the_job_name_is_url_quoted_into_the_path(self):
        fake = self._fake(trigger=("needs quoting",), jobs={"proj-a": ["needs quoting"]})
        fake.rerun("needs quoting", _ctx())
        self.assertEqual(fake.posts, ["/job/needs%20quoting/build"])

    def test_has_trigger_project_is_separate_from_has_project(self):
        fake = self._fake(trigger=("swarm-build",))
        self.assertTrue(fake.has_project("proj-a"))
        self.assertTrue(fake.has_trigger_project("proj-a"))
        self.assertFalse(self._fake(trigger=None).has_trigger_project("proj-a"))
        self.assertTrue(self._fake(trigger=None).has_project("proj-a"))


class StopTests(unittest.TestCase):
    """A queue id is global, so a permitted job alone cannot authorize cancellation."""

    def _fake(self, reply=b'{"task":{"name":"build-job","url":"job/build-job/"}}', trigger=True):
        return FakeJenkins(jobs={"proj-a": ["build-job", "read-only"]},
                           trigger_jobs={"proj-a": ["build-job"]} if trigger else None,
                           replies={"/queue/item/": reply})

    def test_stop_posts_to_the_explicit_build_with_shared_credentials(self):
        fake = self._fake()
        out = fake.stop("build-job", _ctx(), build=12)
        self.assertEqual(out, {"job": "build-job", "cancelled": "build", "build": 12})
        self.assertEqual(fake.posts, ["/job/build-job/12/stop"])

    def test_queue_cancellation_verifies_the_job_before_posting(self):
        fake = self._fake()
        out = fake.stop("build-job", _ctx(), queue_item=7)
        self.assertEqual(out, {"job": "build-job", "cancelled": "queueItem", "queueItem": 7})
        self.assertEqual(fake.paths, ["/queue/item/7/api/json?tree=task[name,url]"])
        self.assertEqual(fake.posts, ["/queue/cancelItem?id=7"])

    def test_foreign_missing_and_unreadable_queue_owners_never_cancel(self):
        for reply in (b'{"task":{"name":"foreign-job","url":"job/foreign-job/"}}', b'{}', b'{"task":[]}',
                      # same leaf name, different job: a folder / multibranch item
                      b'{"task":{"name":"build-job","url":"job/team/job/build-job/"}}',
                      b'{"task":{"name":"build-job"}}',                       # no URL: cannot qualify it
                      CiBackendError("unavailable", status=503)):
            with self.subTest(reply=reply):
                fake = self._fake(reply)
                with self.assertRaises(CiBackendError):
                    fake.stop("build-job", _ctx(), queue_item=7)
                self.assertEqual(fake.posts, [])

    def test_stop_requires_exactly_one_positive_integer_target(self):
        for target in ({}, {"queue_item": 7, "build": 12},
                       *({field: value} for field in ("queue_item", "build")
                         for value in (True, 0, -1, "12", "lastBuild", 1.5))):
            with self.subTest(target=target):
                fake = self._fake()
                with self.assertRaises(CiBackendError):
                    fake.stop("build-job", _ctx(), **target)
                self.assertEqual(fake.posts, [])
                self.assertEqual(fake.paths, [])

    def test_stop_enforces_the_trigger_allowlist_before_any_request(self):
        for fake, job, context in ((self._fake(), "read-only", _ctx()),
                                   (self._fake(), "build-job", _ctx(project="proj-b")),
                                   (self._fake(trigger=False), "build-job", _ctx())):
            with self.assertRaises(CiBackendError):
                fake.stop(job, context, build=12)
            self.assertEqual((fake.posts, fake.paths), ([], []))

    def test_gateway_stop_is_role_gated_confirmed_bound_and_audited(self):
        fake, audit = self._fake(), _ListAudit()
        app = GatewayApp(memory_backend=_NullMemory(), audit_sink=audit, ci_backend=fake)
        runner = Principal(actor="runner", project="proj-a", roles=("ci_runner",), token_id="r")
        reader = Principal(actor="reader", project="proj-a", roles=(), token_id="v")

        def call(args, principal=runner):
            return app.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                   "params": {"name": "ci.stop", "arguments": args}}, principal)

        self.assertEqual(call({"job": "build-job", "build": 12}, reader)["error"]["code"], -32003)
        for args in ({"job": "read-only", "build": 12}, {"job": "build-job"},
                     {"job": "build-job", "build": True}):
            self.assertNotIn("confirmationId", str(call(args)))
        pending = call({"job": "build-job", "build": 12})["result"]["structuredContent"]
        self.assertTrue(pending["confirmationRequired"])
        self.assertEqual(fake.posts, [])
        changed = call({"job": "build-job", "build": 13, "confirm": pending["confirmationId"]})
        self.assertTrue(changed["result"]["structuredContent"]["confirmationRequired"])
        self.assertEqual(fake.posts, [])
        pending = call({"job": "build-job", "build": 12})["result"]["structuredContent"]
        out = call({"job": "build-job", "build": 12, "confirm": pending["confirmationId"]})
        self.assertEqual(out["result"]["structuredContent"]["build"], 12)
        self.assertEqual(fake.posts, ["/job/build-job/12/stop"])
        self.assertEqual((audit.events[-1].tool, audit.events[-1].outcome), ("ci.stop", "ok"))
        self.assertEqual(str(audit.events[-1].resource_id), "build-job:12")

    def test_gateway_queue_confirmation_binds_and_rechecks_the_queue_item(self):
        fake = self._fake()
        app = GatewayApp(memory_backend=_NullMemory(), audit_sink=_ListAudit(), ci_backend=fake)
        runner = Principal(actor="runner", project="proj-a", roles=("ci_runner",), token_id="r")

        def call(args):
            return app.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                   "params": {"name": "ci.stop", "arguments": args}}, runner)

        args = {"job": "build-job", "queueItem": 7}
        pending = call(args)["result"]["structuredContent"]
        self.assertEqual(fake.posts, [])
        changed = call({**args, "queueItem": 8, "confirm": pending["confirmationId"]})
        self.assertTrue(changed["result"]["structuredContent"]["confirmationRequired"])
        pending = call(args)["result"]["structuredContent"]
        fake.replies["/queue/item/"] = b'{"task":{"name":"foreign-job"}}'
        self.assertTrue(call({**args, "confirm": pending["confirmationId"]})["result"]["isError"])
        self.assertEqual(fake.posts, [])

    def test_stop_visibility_matches_rerun(self):
        for trigger, roles in ((True, ("ci_runner",)), (False, ("ci_runner",)), (True, ())):
            app = GatewayApp(memory_backend=_NullMemory(), audit_sink=_ListAudit(),
                             ci_backend=self._fake(trigger=trigger))
            principal = Principal(actor="actor", project="proj-a", roles=roles, token_id="t")
            listed = app.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, principal)
            names = {tool["name"] for tool in listed["result"]["tools"]}
            self.assertEqual("ci.stop" in names, trigger and bool(roles))


class GatewayCiTests(unittest.TestCase):
    def setUp(self):
        self.audit = _ListAudit()
        self.app = GatewayApp(memory_backend=_NullMemory(), audit_sink=self.audit, ci_backend=FakeJenkins())
        self.pa = Principal(actor="1", project="proj-a", roles=(), token_id="t1")
        self.pb = Principal(actor="2", project="proj-b", roles=(), token_id="t2")

    def _call(self, principal, name, arguments):
        return self.app.handle_rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": name, "arguments": arguments}}, principal)

    def test_status_through_gateway_with_audit(self):
        resp = self._call(self.pa, "ci.status", {})
        self.assertEqual(resp["result"]["structuredContent"]["count"], 2)
        self.assertEqual(self.audit.events[-1].tool, "ci.status")
        self.assertEqual(self.audit.events[-1].outcome, "ok")

    def test_tools_list_hides_ci_for_project_without_jobs(self):
        la = self.app.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, self.pa)
        lb = self.app.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, self.pb)
        self.assertIn("ci.status", {t["name"] for t in la["result"]["tools"]})
        self.assertNotIn("ci.status", {t["name"] for t in lb["result"]["tools"]})

    def test_builds_through_gateway_with_audit(self):
        import json as _json
        rows = [{"number": 5, "result": "FAILURE", "building": False}]
        app = GatewayApp(memory_backend=_NullMemory(), audit_sink=self.audit,
                         ci_backend=FakeJenkins(replies={"tree=builds": _json.dumps({"builds": rows}).encode()}))
        resp = app.handle_rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "ci.builds", "arguments": {"job": "swarm-build"}}}, self.pa)
        self.assertEqual(resp["result"]["structuredContent"]["jobs"][0]["builds"][0]["build"], 5)
        self.assertEqual(self.audit.events[-1].tool, "ci.builds")
        self.assertEqual(self.audit.events[-1].outcome, "ok")

    def test_the_project_wide_call_is_one_quota_tick_and_one_audit_event(self):
        import json as _json
        app = GatewayApp(memory_backend=_NullMemory(), audit_sink=self.audit,
                         ci_backend=FakeJenkins(replies={"tree=builds": _json.dumps(
                             {"builds": [{"number": 5, "result": "FAILURE"}]}).encode()}))
        reads: list = []
        original = app._memory_write_limiter.check_read
        app._memory_write_limiter.check_read = lambda p: (reads.append(p) or original(p))
        before = len(self.audit.events)
        resp = app.handle_rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "ci.builds", "arguments": {}}}, self.pa)
        self.assertEqual(resp["result"]["structuredContent"]["count"], 2)   # both jobs
        self.assertEqual(len(self.audit.events) - before, 1)
        self.assertEqual(len(reads), 1)   # one quota tick for the whole project

    def test_builds_is_offered_and_refused_on_the_same_terms_as_the_rest_of_the_family(self):
        la = self.app.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, self.pa)
        lb = self.app.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, self.pb)
        self.assertIn("ci.builds", {t["name"] for t in la["result"]["tools"]})
        self.assertNotIn("ci.builds", {t["name"] for t in lb["result"]["tools"]})
        self.assertTrue(self._call(self.pb, "ci.builds", {"job": "swarm-build"})["result"].get("isError"))

    def test_rerun_needs_the_role_and_is_confirmation_gated(self):
        app = GatewayApp(memory_backend=_NullMemory(), audit_sink=self.audit,
                         ci_backend=FakeJenkins(trigger_jobs={"proj-a": ["swarm-build"]}))
        runner = Principal(actor="3", project="proj-a", roles=("ci_runner",), token_id="t3")

        # Without the role the tool is denied by POLICY, which is a JSON-RPC error
        # rather than a tool result -- the same shape an issue write gets -- and
        # nothing reaches Jenkins.
        denied = app.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                 "params": {"name": "ci.rerun", "arguments": {"job": "swarm-build"}}}, self.pa)
        self.assertEqual(denied["error"]["code"], -32003)
        self.assertIn("ci run role", denied["error"]["message"])
        self.assertEqual(self.audit.events[-1].outcome, "denied")
        self.assertEqual(app._ci_backend.posts, [])

        # With the role, the FIRST call must not start anything: it asks to confirm.
        first = app.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                "params": {"name": "ci.rerun", "arguments": {"job": "swarm-build"}}}, runner)
        pending = first["result"]["structuredContent"]
        self.assertTrue(pending["confirmationRequired"])
        self.assertEqual(app._ci_backend.posts, [], "a build was started before the confirmation")
        self.assertEqual(self.audit.events[-1].outcome, "confirm_required")

        # The second call, carrying the id, is the one that spends CI capacity.
        second = app.handle_rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "ci.rerun",
                        "arguments": {"job": "swarm-build", "confirm": pending["confirmationId"]}}}, runner)
        self.assertEqual(second["result"]["structuredContent"]["queueItem"], 7)
        self.assertEqual(app._ci_backend.posts, ["/job/swarm-build/build"])
        self.assertEqual(self.audit.events[-1].outcome, "ok")

    def test_rerun_is_offered_only_to_a_runner_on_a_project_with_a_trigger_list(self):
        with_trigger = GatewayApp(memory_backend=_NullMemory(), audit_sink=self.audit,
                                  ci_backend=FakeJenkins(trigger_jobs={"proj-a": ["swarm-build"]}))
        runner = Principal(actor="3", project="proj-a", roles=("ci_runner",), token_id="t3")

        def names(app, principal):
            listed = app.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, principal)
            return {t["name"] for t in listed["result"]["tools"]}

        self.assertIn("ci.rerun", names(with_trigger, runner))
        self.assertNotIn("ci.rerun", names(with_trigger, self.pa))          # no role
        self.assertNotIn("ci.rerun", names(self.app, runner))               # no trigger list
        self.assertIn("ci.status", names(self.app, runner))                 # reads unaffected

    def test_other_project_gets_clean_error_not_data(self):
        resp = self._call(self.pb, "ci.log", {"job": "swarm-build"})
        result = resp["result"]
        self.assertTrue(result.get("isError"))
        self.assertNotIn("line 500", str(resp))


if __name__ == "__main__":
    unittest.main()
