"""HttpMemoryBackend against a faked urlopen: framing and encoding failures, same-origin redirects, and the listing shapes."""
from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from unittest import mock

from fakes import FakeResponse

from mcp_governance_gateway.audit import ListAuditSink
from mcp_governance_gateway.auth import Principal
from mcp_governance_gateway.ci_backend import CiBackendError
from mcp_governance_gateway.config import Settings
from mcp_governance_gateway.issue_backend import IssueBackendError, RedmineHttpBackend
from mcp_governance_gateway.mcp import GatewayApp
from mcp_governance_gateway.memory_backend import HttpMemoryBackend, RequestContext
from mcp_governance_gateway.server import build_server


class HttpMemoryBackendTests(unittest.TestCase):
    def test_search_passes_project_and_strips_aggregate_fields(self) -> None:
        captured: dict[str, object] = {}

        def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
            captured["url"] = req.full_url
            captured["body"] = json.loads(req.data.decode("utf-8"))
            return FakeResponse(
                {
                    "format": "v1",
                    "results": [
                        {
                            "observation": {
                                "id": "obs_1",
                                "project": "example-project",
                                "title": "Tenancy is server-side",
                                "narrative": "The project claim never comes from the client.",
                                "concepts": ["actor:10000001"],
                                "timestamp": "2026-07-10T00:00:00Z",
                            },
                            "score": 0.9,
                        },
                        {"observation": {"id": "obs_2"}, "score": 0.7},
                    ],
                    "tokens_used": 1000,
                    "truncated": True,
                }
            )

        from mcp_governance_gateway import http_client

        original = http_client.request.urlopen
        http_client.request.urlopen = fake_urlopen
        try:
            backend = HttpMemoryBackend(
                base_url="http://memory.internal:3111", backend_token=None,
                search_path="/agentmemory/search", save_path="/agentmemory/remember",
            )
            result = backend.search(
                "tenant isolation", 10,
                RequestContext(actor="u", project="example-project", client="t", request_id="r"),
            )
        finally:
            http_client.request.urlopen = original

        # gateway injects the token's project; agentmemory filters server-side
        self.assertEqual(captured["body"], {"query": "tenant isolation", "limit": 10, "project": "example-project"})
        # Each hit arrives wrapped as {observation, score}: the wrapper is unwrapped
        # to the documented flat schema, so `content` carries the text instead of
        # being empty while the real fields sit one level down untouched.
        self.assertEqual(result["count"], 2)
        first = result["results"][0]
        self.assertEqual(first["id"], "obs_1")
        self.assertEqual(first["content"], "The project claim never comes from the client.")
        self.assertEqual(first["createdAt"], "2026-07-10T00:00:00Z")  # from `timestamp`
        self.assertEqual(first["score"], 0.9)                          # kept off the wrapper
        self.assertNotIn("observation", first)
        self.assertNotIn("tokens_used", result)                        # aggregate fields still stripped
        self.assertEqual(result["results"][1]["id"], "obs_2")
        for k in ("tokens_used", "truncated", "format", "text"):
            self.assertNotIn(k, result)

    def test_search_fails_closed_on_non_list_results(self) -> None:
        def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
            return FakeResponse(
                {"results": {"leak": {"project": "OTHER-Q"}}, "text": "AGGREGATE SECRET", "tokens_used": 9999}
            )

        from mcp_governance_gateway import http_client

        original = http_client.request.urlopen
        http_client.request.urlopen = fake_urlopen
        try:
            backend = HttpMemoryBackend(
                base_url="http://memory.internal:3111", backend_token=None,
                search_path="/agentmemory/search", save_path="/agentmemory/remember",
            )
            result = backend.search(
                "q", 10, RequestContext(actor="u", project="example-project", client="t", request_id="r"),
            )
        finally:
            http_client.request.urlopen = original

        self.assertEqual(result, {"results": [], "count": 0})

    def test_search_caps_results_at_requested_limit(self) -> None:
        def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
            # backend ignores `limit` and returns more than asked
            return FakeResponse({"results": [{"observation": {"id": f"o{i}"}} for i in range(20)]})

        from mcp_governance_gateway import http_client

        original = http_client.request.urlopen
        http_client.request.urlopen = fake_urlopen
        try:
            backend = HttpMemoryBackend(
                base_url="http://memory.internal:3111", backend_token=None,
                search_path="/agentmemory/search", save_path="/agentmemory/remember",
            )
            result = backend.search(
                "q", 5, RequestContext(actor="u", project="example-project", client="t", request_id="r"),
            )
        finally:
            http_client.request.urlopen = original

        self.assertEqual(result["count"], 5)
        self.assertEqual(len(result["results"]), 5)

    def test_save_maps_to_remember_and_returns_validated_nested_id(self) -> None:
        captured: dict[str, object] = {}

        def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
            captured["url"] = req.full_url
            captured["method"] = req.get_method()
            captured["body"] = json.loads(req.data.decode("utf-8"))
            captured["auth"] = req.headers.get("Authorization")
            return FakeResponse({"success": True, "memory": {"id": "mem_1", "project": "example-project"}})

        from mcp_governance_gateway import http_client

        original = http_client.request.urlopen
        http_client.request.urlopen = fake_urlopen
        try:
            backend = HttpMemoryBackend(
                base_url="http://memory.internal:3111", backend_token="backend-token",
                search_path="/agentmemory/search", save_path="/agentmemory/remember",
            )
            result = backend.save(
                "remember this", ["phase1"],
                RequestContext(actor="user@example.com", project="example-project", client="test", request_id="req_1"),
            )
        finally:
            http_client.request.urlopen = original

        self.assertEqual(result, {"saved": True, "project": "example-project", "id": "mem_1"})
        self.assertEqual(captured["url"], "http://memory.internal:3111/agentmemory/remember")
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["auth"], "Bearer backend-token")
        self.assertEqual(
            captured["body"],
            {
                "content": "remember this",
                "project": "example-project",
                "concepts": ["phase1", "actor:user@example.com"],
            },
        )

    def test_save_does_not_echo_hostile_backend_body(self) -> None:
        def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
            return FakeResponse(
                {
                    "success": True,
                    "memory": {"id": "mem_9", "project": "OTHER-PROJECT-Q"},
                    "neighbors": [{"content": "Q private", "project": "Q"}],
                    "text": "aggregate from Q",
                }
            )

        from mcp_governance_gateway import http_client

        original = http_client.request.urlopen
        http_client.request.urlopen = fake_urlopen
        try:
            backend = HttpMemoryBackend(
                base_url="http://memory.internal:3111", backend_token=None,
                search_path="/agentmemory/search", save_path="/agentmemory/remember",
            )
            result = backend.save(
                "x", [],
                RequestContext(actor="u", project="example-project", client="t", request_id="r"),
            )
        finally:
            http_client.request.urlopen = original

        # backend body not echoed; and a project mismatch (memory.project != caller
        # project) means the foreign id is not surfaced
        self.assertEqual(result, {"saved": True, "project": "example-project"})
        self.assertNotIn("id", result)
        self.assertNotIn("neighbors", result)
        self.assertNotIn("text", result)

    def test_list_filters_to_project_and_sorts_newest_first(self) -> None:
        def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
            # /memories does not filter by project server-side; the gateway must.
            return FakeResponse(
                {
                    "memories": [
                        {"id": "m1", "project": "example-project", "title": "a", "content": "A",
                         "type": "decision", "updatedAt": "2026-06-01"},
                        {"id": "m2", "project": "OTHER", "title": "leak", "content": "B", "updatedAt": "2026-06-09"},
                        {"id": "m3", "project": "example-project", "title": "c", "content": "C",
                         "concepts": ["x"], "updatedAt": "2026-06-05"},
                    ],
                    "total": 3, "limit": 500, "offset": 0,
                }
            )

        from mcp_governance_gateway import http_client

        original = http_client.request.urlopen
        http_client.request.urlopen = fake_urlopen
        try:
            backend = HttpMemoryBackend(
                base_url="http://memory.internal:3111", backend_token=None,
                search_path="/agentmemory/search", save_path="/agentmemory/remember",
            )
            result = backend.list(
                10, 0, RequestContext(actor="u", project="example-project", client="t", request_id="r"),
            )
        finally:
            http_client.request.urlopen = original

        self.assertEqual(result["total"], 2)  # OTHER-project item dropped
        self.assertEqual([m["id"] for m in result["memories"]], ["m3", "m1"])  # newest first
        self.assertNotIn("OTHER", [m["project"] for m in result["memories"]])
        self.assertEqual(result["memories"][1]["concepts"], [])  # missing concepts normalized to []

    def test_list_paginates_over_filtered_set(self) -> None:
        def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
            return FakeResponse(
                {
                    "memories": [
                        {"id": "m1", "project": "p", "updatedAt": "2026-06-01"},
                        {"id": "m3", "project": "p", "updatedAt": "2026-06-05"},
                        {"id": "m2", "project": "p", "updatedAt": "2026-06-09"},
                    ],
                    "total": 3, "limit": 500, "offset": 0,
                }
            )

        from mcp_governance_gateway import http_client

        original = http_client.request.urlopen
        http_client.request.urlopen = fake_urlopen
        try:
            backend = HttpMemoryBackend(
                base_url="http://memory.internal:3111", backend_token=None,
                search_path="/agentmemory/search", save_path="/agentmemory/remember",
            )
            page = backend.list(1, 1, RequestContext(actor="u", project="p", client="t", request_id="r"))
        finally:
            http_client.request.urlopen = original

        self.assertEqual(page["total"], 3)
        self.assertEqual(page["count"], 1)
        self.assertEqual([m["id"] for m in page["memories"]], ["m3"])  # newest-first [m2,m3,m1], offset 1
        self.assertEqual(page["offset"], 1)


class BackendFramingErrorTests(unittest.TestCase):
    """A backend reply that breaks HTTP framing -- a body that ends inside a
    chunk, a garbled status line -- raises http.client.HTTPException, which is
    not an OSError. Each HTTP backend must still report it as its own error:
    anything else escapes the tool dispatcher, which then neither answers nor
    audits the call. urlopen is faked to hand back a response whose read()
    fails, the way a truncated body does; nothing here touches the network."""

    def _ctx(self) -> RequestContext:
        return RequestContext(actor="u", project="p", client="t", request_id="r", issue_project="97")

    def _patched(self):
        import http.client

        class _Truncated:
            # The status line and headers arrived; the body ends inside a chunk.
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self, n=-1):
                raise http.client.IncompleteRead(b"")

        return mock.patch("mcp_governance_gateway.http_client.request.urlopen",
                          return_value=_Truncated())

    def _memory(self) -> HttpMemoryBackend:
        return HttpMemoryBackend(
            base_url="http://memory.internal:3111", backend_token=None,
            search_path="/agentmemory/search", save_path="/agentmemory/remember",
        )

    def test_a_truncated_memory_reply_is_memory_backend_unavailable(self) -> None:
        from mcp_governance_gateway.memory_backend import MemoryBackendError
        backend = self._memory()
        # One case per request path: search POSTs, lesson_list GETs.
        for name, call in (("post", lambda: backend.search("q", 5, self._ctx())),
                           ("get", lambda: backend.lesson_list(5, self._ctx()))):
            with self.subTest(path=name):
                with self._patched():
                    with self.assertRaises(MemoryBackendError) as cm:
                        call()
                self.assertEqual(str(cm.exception), "memory backend unavailable")

    def test_a_truncated_redmine_reply_is_issue_tracker_unavailable(self) -> None:
        backend = RedmineHttpBackend(base_url="http://tracker.example", api_key="k")
        with self._patched():
            with self.assertRaises(IssueBackendError) as cm:
                backend.get("1", self._ctx())
        self.assertEqual(str(cm.exception), "issue tracker unavailable")

    def test_a_truncated_gitlab_reply_is_issue_tracker_unavailable(self) -> None:
        from mcp_governance_gateway.gitlab_backend import GitLabHttpBackend
        backend = GitLabHttpBackend("https://gitlab.example", "TOKEN")
        with self._patched():
            with self.assertRaises(IssueBackendError) as cm:
                backend.get("1", self._ctx())
        self.assertEqual(str(cm.exception), "issue tracker unavailable")

    def test_a_truncated_reply_is_answered_and_audited_by_the_dispatcher(self) -> None:
        # The property the three tests above serve: through handle_rpc the
        # caller gets a tool error, not silence, and the audit log records it.
        audit = ListAuditSink()
        app = GatewayApp(memory_backend=self._memory(), audit_sink=audit)
        principal = Principal(actor="u@x", project="p", roles=("developer",), token_id="t")
        with self._patched():
            response = app.handle_rpc(
                {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                 "params": {"name": "memory.search", "arguments": {"query": "q"}}},
                principal,
            )
        assert response is not None
        self.assertTrue(response["result"]["isError"])
        self.assertIn("memory backend unavailable", response["result"]["content"][0]["text"])
        self.assertEqual(audit.events[-1].outcome, "backend_error")


class BackendRequestEncodingErrorTests(unittest.TestCase):
    """A request http.client cannot put on the wire -- a credential outside
    latin-1, a request target outside ASCII -- raises ValueError (its Unicode
    subclasses) inside urlopen, before any socket is opened. Round 7: with the
    backend clauses catching only OSError and HTTPException, the dispatcher
    reported such a call as the CALLER's invalid arguments. Nothing is faked:
    the base URLs point at a closed port that is never reached, because the
    encoding fails first; the mutation check is what proves that order."""

    def _ctx(self) -> RequestContext:
        return RequestContext(actor="u", project="p", client="t", request_id="r", issue_project="97")

    def test_a_credential_or_path_the_request_cannot_carry_is_the_backends_error(self) -> None:
        from mcp_governance_gateway.ci_backend import JenkinsHttpBackend
        from mcp_governance_gateway.gitlab_backend import GitLabHttpBackend
        from mcp_governance_gateway.memory_backend import MemoryBackendError
        bad = "k\u0100y"       # outside latin-1: no header value can carry it
        cases = (
            ("memory-post", MemoryBackendError, "memory backend unavailable",
             lambda: HttpMemoryBackend(base_url="http://127.0.0.1:9", backend_token=bad,
                                       search_path="/s", save_path="/r").search("q", 5, self._ctx())),
            ("memory-get", MemoryBackendError, "memory backend unavailable",
             lambda: HttpMemoryBackend(base_url="http://127.0.0.1:9", backend_token=bad,
                                       search_path="/s", save_path="/r").lesson_list(5, self._ctx())),
            ("redmine", IssueBackendError, "issue tracker unavailable",
             lambda: RedmineHttpBackend(base_url="http://127.0.0.1:9", api_key=bad).get("1", self._ctx())),
            ("gitlab", IssueBackendError, "issue tracker unavailable",
             lambda: GitLabHttpBackend("http://127.0.0.1:9", bad).get("1", self._ctx())),
            # Jenkins credentials are base64 (always ASCII); its request target
            # is the exposure -- a base path the validated Settings would refuse.
            ("ci-fetch", CiBackendError, "CI unavailable",
             lambda: JenkinsHttpBackend("http://127.0.0.1:9/caf\u00e9", None, None,
                                        {"p": ["job-a"]}).status(self._ctx())),
            ("ci-open", CiBackendError, "CI unavailable",
             lambda: JenkinsHttpBackend("http://127.0.0.1:9/caf\u00e9", None, None,
                                        {"p": ["job-a"]}).open_located("/job/job-a/1/artifact/a")),
        )
        for name, exc_type, message, call in cases:
            with self.subTest(backend=name):
                with self.assertRaises(exc_type) as cm:
                    call()
                self.assertEqual(str(cm.exception), message)
                self.assertIsInstance(cm.exception.__cause__, ValueError)


class SameOriginRedirectTests(unittest.TestCase):
    """build_server installs an opener whose redirects may not leave the
    origin a request was sent to. Round 7: urllib's default follows a
    redirect to another host -- or to ftp://, whose response is not an
    HTTPResponse and has no `chunked` -- and copies Authorization along."""

    def _handler(self):
        from mcp_governance_gateway.server import SameOriginRedirects
        return SameOriginRedirects()

    def _redirect(self, newurl):
        from urllib import request
        req = request.Request("https://ci.internal:8443/job/x/lastBuild/api/json",
                              headers={"Authorization": "Basic Zm9v"})
        return self._handler().redirect_request(req, None, 302, "Found", {}, newurl)

    def test_a_redirect_off_the_origin_is_refused_as_a_backend_failure(self) -> None:
        from urllib import error
        for newurl in ("ftp://ci.internal/x", "https://evil.example/x",
                       "http://ci.internal:8443/x", "https://ci.internal:9443/x"):
            with self.subTest(newurl=newurl):
                with self.assertRaises(error.URLError):   # an OSError: every backend clause catches it
                    self._redirect(newurl)

    def test_a_redirect_within_the_origin_is_followed(self) -> None:
        followed = self._redirect("https://CI.internal:8443/job/x/291/api/json")
        assert followed is not None
        self.assertEqual(followed.full_url, "https://CI.internal:8443/job/x/291/api/json")

    def test_an_explicit_default_port_is_the_same_origin(self) -> None:
        # Round 8: a proxy that redirects "https://ci.internal/x" to
        # "https://ci.internal:443/x" names the same origin; comparing the raw
        # netloc refused it as a backend failure on every request.
        from urllib import error, request

        from mcp_governance_gateway.server import SameOriginRedirects
        req = request.Request("https://ci.internal/job/x/lastBuild/api/json")
        followed = SameOriginRedirects().redirect_request(req, None, 302, "Found", {}, "https://ci.internal:443/job/x/291/api/json")
        assert followed is not None
        self.assertEqual(followed.full_url, "https://ci.internal:443/job/x/291/api/json")
        with self.assertRaises(error.URLError):   # the default port of the OTHER scheme is not
            SameOriginRedirects().redirect_request(req, None, 302, "Found", {}, "https://ci.internal:80/job/x")

    def test_build_server_installs_the_handler_process_wide(self) -> None:
        from urllib import error, request

        from mcp_governance_gateway.server import SameOriginRedirects
        tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump({"tokens": [{"token": "t", "actor": "a", "project": "p", "roles": ["developer"]}]}, tf)
        tf.close()
        self.addCleanup(lambda: os.unlink(tf.name))
        srv = build_server(Settings(
            host="127.0.0.1", port=0, token_file=tf.name, allowed_origins=(),
            memory_base_url="http://127.0.0.1:59999", memory_backend_token=None,
            memory_search_path="/s", memory_save_path="/r", memory_timeout_sec=2,
            memory_save_max_text_bytes=32768, memory_user_writes_per_minute=30,
            memory_project_writes_per_day=5000, memory_user_reads_per_minute=120,
        ))
        self.addCleanup(srv.server_close)
        installed = request._opener      # what urlopen will use from now on
        self.assertTrue(any(isinstance(h, SameOriginRedirects) for h in installed.handlers))

        # Round 10: the handler is not only installed but in the path urlopen
        # takes -- a real 302 to another port is refused before it is followed.
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class _Redirecting(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:9/x")
                self.end_headers()

            def log_message(self, *args):
                pass

        origin = HTTPServer(("127.0.0.1", 0), _Redirecting)
        self.addCleanup(origin.server_close)
        threading.Thread(target=origin.handle_request, daemon=True).start()
        with self.assertRaisesRegex(error.URLError, "leaves the backend's origin"):
            request.urlopen(f"http://127.0.0.1:{origin.server_address[1]}/job", timeout=5)


class MemoryListingShapeTests(unittest.TestCase):
    """What the listing endpoints keep when the limit bites."""

    def _backend(self, path, payload):
        from mcp_governance_gateway import http_client

        def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
            self.assertIn(path, req.full_url)
            return FakeResponse(payload)

        original = http_client.request.urlopen
        http_client.request.urlopen = fake_urlopen
        self.addCleanup(lambda: setattr(http_client.request, "urlopen", original))
        return HttpMemoryBackend(
            base_url="http://memory.internal:3111", backend_token=None,
            search_path="/agentmemory/search", save_path="/agentmemory/remember",
        )

    @staticmethod
    def _ctx() -> RequestContext:
        return RequestContext(actor="u", project="p", client="t", request_id="r")

    def test_lessons_keep_the_most_reinforced_when_capped(self) -> None:
        backend = self._backend("/lessons", {"lessons": [
            {"id": "l1", "project": "p", "content": "weak", "confidence": 0.2},
            {"id": "l2", "project": "p", "content": "strong", "confidence": 0.95},
            {"id": "l3", "project": "p", "content": "mid", "confidence": 0.6},
            {"id": "l4", "project": "p", "content": "unscored"},  # missing confidence sorts last, no crash
        ]})
        out = backend.lesson_list(2, self._ctx())
        self.assertEqual([lesson["id"] for lesson in out["lessons"]], ["l2", "l3"])

    def test_a_malformed_confidence_does_not_take_the_listing_down(self) -> None:
        # Adversarial review, 2026-08-10: the sort key negated the raw field, so a
        # string confidence raised TypeError outside MemoryBackendError handling.
        backend = self._backend("/lessons", {"lessons": [
            {"id": "l1", "project": "p", "content": "numeric", "confidence": 0.9},
            {"id": "l2", "project": "p", "content": "stringly", "confidence": "0.95"},
            {"id": "l3", "project": "p", "content": "nonsense", "confidence": "high"},
        ]})
        out = backend.lesson_list(10, self._ctx())
        self.assertEqual(out["count"], 3)
        # a parseable string still sorts by its value; an unparseable one sorts last
        self.assertEqual([lesson["id"] for lesson in out["lessons"]], ["l2", "l1", "l3"])

    def test_action_list_is_the_live_board_unless_asked_otherwise(self) -> None:
        payload = {"actions": [
            {"id": "a1", "project": "p", "title": "open", "status": "pending"},
            {"id": "a2", "project": "p", "title": "shipped", "status": "done"},
            {"id": "a3", "project": "p", "title": "stuck", "status": "blocked"},
        ]}
        open_only = self._backend("/actions", payload).action_list(10, self._ctx())
        self.assertEqual([a["id"] for a in open_only["actions"]], ["a1", "a3"])
        self.assertEqual(open_only["count"], 2)
        everything = self._backend("/actions", payload).action_list(10, self._ctx(), include_done=True)
        self.assertEqual([a["id"] for a in everything["actions"]], ["a1", "a2", "a3"])

    def test_done_actions_cannot_crowd_open_ones_out_of_the_limit(self) -> None:
        # The whole point of the default: with the cap at 1, a done action listed
        # first must not be the one thing the caller sees.
        backend = self._backend("/actions", {"actions": [
            {"id": "done", "project": "p", "title": "d", "status": "done"},
            {"id": "live", "project": "p", "title": "l", "status": "active"},
        ]})
        self.assertEqual([a["id"] for a in backend.action_list(1, self._ctx())["actions"]], ["live"])


class NormalizeActorTests(unittest.TestCase):
    def test_lesson_and_action_surface_actor_from_tags(self) -> None:
        from mcp_governance_gateway.memory_backend import (
            _normalize_action,
            _normalize_lesson,
        )
        lesson = _normalize_lesson({"id": "l1", "project": "p", "content": "c", "confidence": 0.9,
                                    "reinforcements": 2, "tags": ["actor:alice@x"], "createdAt": "2026"})
        self.assertEqual(lesson["actor"], "alice@x")
        action = _normalize_action({"id": "a1", "project": "p", "title": "t", "status": "pending",
                                    "tags": ["misc", "actor:bob@x"], "createdAt": "2026"})
        self.assertEqual(action["actor"], "bob@x")
        # no actor tag present -> None (never crashes)
        self.assertIsNone(_normalize_lesson({"id": "l2", "tags": []})["actor"])
        self.assertIsNone(_normalize_action({"id": "a2"})["actor"])


if __name__ == "__main__":
    unittest.main()
