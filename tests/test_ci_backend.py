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
    def __init__(self, jobs=None, replies=None):
        super().__init__("https://jenkins.example", "svc", "TOKEN", jobs or {"proj-a": ["swarm-build", "swarm-lint"]})
        self.paths: list[str] = []
        self.replies = replies or {}

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

    def test_job_with_no_builds_is_unknown_not_error(self):
        fake = FakeJenkins(replies={"/api/json": CiBackendError("CI HTTP 404", status=404)})
        out = fake.status(_ctx())
        self.assertEqual(out["jobs"][0]["result"], "UNKNOWN")

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

    def test_other_project_gets_clean_error_not_data(self):
        resp = self._call(self.pb, "ci.log", {"job": "swarm-build"})
        result = resp["result"]
        self.assertTrue(result.get("isError"))
        self.assertNotIn("line 500", str(resp))


if __name__ == "__main__":
    unittest.main()
