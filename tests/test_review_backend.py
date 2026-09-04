from __future__ import annotations

import base64
import http.client
import io
import re
import unittest
import unittest.mock
from typing import Any

from mcp_governance_gateway.memory_backend import RequestContext
from mcp_governance_gateway.review_backend import (
    GitHubReviewBackend,
    ReviewBackendError,
    ReviewSpec,
    _derive_branch,
)


def _spec(project: str = "proj-docs", repo: str = "example-org/docs-corpus", base: str = "main") -> ReviewSpec:
    return ReviewSpec(
        project=project,
        type="github",
        repo=repo,
        api="https://api.github.com",
        base_branch=base,
    )


def _ctx(actor: str = "10112030", request_id: str = "req-test-1") -> RequestContext:
    return RequestContext(actor=actor, project="proj-docs", client="t", request_id=request_id)


class FakeGitHub(GitHubReviewBackend):
    """Fake transport recording calls and returning canned responses."""

    def __init__(self, replies: dict[tuple[str, str], Any] | None = None) -> None:
        super().__init__()
        self.recorded: list[tuple[str, str, dict[str, Any] | None]] = []
        self.replies: dict[tuple[str, str], Any] = replies or {}

    def _request(
        self,
        spec: ReviewSpec,
        method: str,
        path: str,
        credential: str,
        body: dict[str, Any] | None = None,
    ) -> Any:
        self.recorded.append((method, path, body))
        # Exact match first, then partial match by (method, path)
        reply = self.replies.get((method, path))
        if reply is None:
            for (m, p), r in self.replies.items():
                if m == method and (p == path or path.endswith(p) or p in path):
                    reply = r
                    break
        if isinstance(reply, Exception):
            raise reply
        if reply is not None:
            return reply

        # Default responses satisfying the happy-path steps
        if method == "GET" and "/git/ref/heads/" in path:
            return {"object": {"sha": "c0ffee1234567890abcdef1234567890abcdef12"}}
        if method == "POST" and path.endswith("/git/refs"):
            return {"ref": (body or {}).get("ref", ""), "object": {"sha": "c0ffee1234567890abcdef1234567890abcdef12"}}
        if method == "PUT" and "/contents/" in path:
            return {"content": {"sha": "blob7890abcdef1234567890abcdef1234567890"}}
        if method == "POST" and path.endswith("/pulls"):
            return {"number": 101, "html_url": "https://github.com/example-org/docs-corpus/pull/101"}
        if method == "POST" and "/issues/" in path and "/comments" in path:
            return {"id": 1, "body": (body or {}).get("body", "")}
        if method == "GET" and "/pulls/" in path:
            return {
                "number": 101,
                "state": "open",
                "title": "Default Proposal",
                "html_url": "https://github.com/example-org/docs-corpus/pull/101",
                "merged": False,
                "head": {"ref": "mcpgw/test-branch"},
            }
        return {}


class GitHubReviewBackendTests(unittest.TestCase):
    def setUp(self) -> None:
        self.spec = _spec()
        self.ctx = _ctx()

    def test_open_change_issues_exact_four_step_sequence(self) -> None:
        backend = FakeGitHub()
        content = "# Project Documentation\n\nInitial documentation draft."
        message = "Add project documentation\n\nDetailed rationale for proposal."
        result = backend.open_change(self.spec, "wiki/architecture.md", content, message, "tok_123", self.ctx)

        # Assert returned shape
        self.assertEqual(result["number"], 101)
        self.assertEqual(result["url"], "https://github.com/example-org/docs-corpus/pull/101")
        branch = result["branch"]
        self.assertTrue(branch.startswith("mcpgw/wiki-architecture.md-"))

        # Assert exactly four requests were made, in order
        self.assertEqual(len(backend.recorded), 4)

        # Step 1: GET /repos/{repo}/git/ref/heads/{base} -> base sha
        step1 = backend.recorded[0]
        self.assertEqual(step1[0], "GET")
        self.assertEqual(step1[1], f"/repos/{self.spec.repo}/git/ref/heads/{self.spec.base_branch}")
        self.assertIsNone(step1[2])

        # Step 2: POST /repos/{repo}/git/refs -> create branch pointing to base sha
        step2 = backend.recorded[1]
        self.assertEqual(step2[0], "POST")
        self.assertEqual(step2[1], f"/repos/{self.spec.repo}/git/refs")
        self.assertEqual(
            step2[2],
            {"ref": f"refs/heads/{branch}", "sha": "c0ffee1234567890abcdef1234567890abcdef12"},
        )

        # Step 3: PUT /repos/{repo}/contents/{path} -> upload new file content without sha
        step3 = backend.recorded[2]
        self.assertEqual(step3[0], "PUT")
        self.assertEqual(step3[1], f"/repos/{self.spec.repo}/contents/wiki/architecture.md")
        self.assertEqual(step3[2]["message"], message)
        self.assertEqual(step3[2]["branch"], branch)
        self.assertEqual(
            step3[2]["content"],
            base64.b64encode(content.encode("utf-8")).decode("ascii"),
        )
        self.assertNotIn("sha", step3[2])

        # Step 4: POST /repos/{repo}/pulls -> open review proposal targeting base
        step4 = backend.recorded[3]
        self.assertEqual(step4[0], "POST")
        self.assertEqual(step4[1], f"/repos/{self.spec.repo}/pulls")
        self.assertEqual(
            step4[2],
            {
                "title": "Add project documentation",
                "head": branch,
                "base": self.spec.base_branch,
                "body": "Detailed rationale for proposal.",
            },
        )

    def test_open_change_sends_no_sha_and_update_change_sends_base_sha(self) -> None:
        # open_change must omit sha so GitHub's 422 refusal kicks in if the file already exists
        backend_open = FakeGitHub()
        backend_open.open_change(self.spec, "doc.md", "c", "msg", "tok", self.ctx)
        open_put = backend_open.recorded[2][2]
        self.assertIsNotNone(open_put)
        self.assertNotIn("sha", open_put)

        # update_change must send base_sha so GitHub's 409 conflict kicks in if the remote blob moved
        backend_update = FakeGitHub()
        backend_update.update_change(self.spec, "doc.md", "c", "msg", "base_blob_sha_abc", "tok", self.ctx)
        update_put = backend_update.recorded[2][2]
        self.assertIsNotNone(update_put)
        self.assertEqual(update_put["sha"], "base_blob_sha_abc")

    def test_open_change_maps_422_on_contents_put_to_409_already_exists(self) -> None:
        # When creating a document without sha, GitHub replies 422 Unprocessable Entity
        # if the path already exists. We surface this as 409 saying the document already exists.
        path = "wiki/existing_guide.md"
        backend = FakeGitHub(
            replies={("PUT", f"/repos/{self.spec.repo}/contents/{path}"): ReviewBackendError("review host HTTP 422", status=422)}
        )
        with self.assertRaises(ReviewBackendError) as cm:
            backend.open_change(self.spec, path, "content", "msg", "tok", self.ctx)
        self.assertEqual(cm.exception.status, 409)
        self.assertIn("already exists", str(cm.exception).lower())
        # The proposal must stop immediately without creating a pull request
        self.assertEqual(len(backend.recorded), 3)

    def test_update_change_maps_409_on_contents_put_to_document_changed(self) -> None:
        # When updating a document with a stale sha, GitHub replies 409 Conflict.
        # We preserve 409 and clarify that the document changed since it was read.
        path = "wiki/concurrent_edit.md"
        backend = FakeGitHub(
            replies={("PUT", f"/repos/{self.spec.repo}/contents/{path}"): ReviewBackendError("review host HTTP 409", status=409)}
        )
        with self.assertRaises(ReviewBackendError) as cm:
            backend.update_change(self.spec, path, "content", "msg", "stale_blob_sha", "tok", self.ctx)
        self.assertEqual(cm.exception.status, 409)
        self.assertIn("changed", str(cm.exception).lower())
        self.assertEqual(len(backend.recorded), 3)

    def test_step1_404_explains_corpus_has_no_commits_yet(self) -> None:
        # An empty corpus repo has no branch ref yet and returns 404 from step 1.
        # A plain "HTTP 404" would mislead callers into thinking the repo itself is missing.
        backend = FakeGitHub(
            replies={("GET", f"/repos/{self.spec.repo}/git/ref/heads/{self.spec.base_branch}"): ReviewBackendError("review host HTTP 404", status=404)}
        )
        with self.assertRaises(ReviewBackendError) as cm:
            backend.open_change(self.spec, "first_doc.md", "c", "m", "tok", self.ctx)
        self.assertEqual(cm.exception.status, 404)
        self.assertIn("no commits yet", str(cm.exception).lower())
        self.assertNotIn("HTTP 404", str(cm.exception))
        self.assertEqual(len(backend.recorded), 1)

    def test_comment_posts_to_issue_comments_and_never_pull_reviews(self) -> None:
        backend = FakeGitHub()
        stamped_body = "Looks good to me.\n\n[via mcp-governance-gateway | actor=10112030 | audit=req-1]"
        backend.comment(self.spec, 42, stamped_body, "tok", self.ctx)

        self.assertEqual(len(backend.recorded), 1)
        method, path, body = backend.recorded[0]
        self.assertEqual(method, "POST")
        self.assertEqual(path, f"/repos/{self.spec.repo}/issues/42/comments")
        self.assertEqual(body, {"body": stamped_body})

        # Crucial governance constraint: agents may not review or approve PRs
        for _, p, _ in backend.recorded:
            self.assertNotIn("/reviews", p)

    def test_content_is_base64_utf8_and_roundtrips_non_ascii(self) -> None:
        content = "# 繁體中文與符號測試\n\n說明文檔 — 包含破折號、歐元符號 € 以及多語言文字。"
        backend = FakeGitHub()
        backend.open_change(self.spec, "wiki/i18n.md", content, "Add i18n notes", "tok", self.ctx)

        put_body = backend.recorded[2][2]
        self.assertIsNotNone(put_body)
        raw_b64 = put_body["content"]
        decoded_text = base64.b64decode(raw_b64.encode("ascii")).decode("utf-8")
        self.assertEqual(decoded_text, content)

    def test_branch_name_derived_random_suffix_and_safe_characters(self) -> None:
        backend = FakeGitHub()
        path = "wiki/getting started.md"
        r1 = backend.open_change(self.spec, path, "c", "m", "tok", self.ctx)
        r2 = backend.open_change(self.spec, path, "c", "m", "tok", self.ctx)

        # Two proposals for the same document must not collide
        self.assertNotEqual(r1["branch"], r2["branch"])

        # Path with spaces, slashes, uppercase, and unicode characters
        complex_path = "Nested/Folder/用戶指南 & Quick-Start #1.md"
        r3 = backend.open_change(self.spec, complex_path, "c", "m", "tok", self.ctx)
        branch = r3["branch"]

        self.assertTrue(branch.startswith("mcpgw/"))
        self.assertRegex(branch, r"\A[a-z0-9._/-]+\Z")
        self.assertLessEqual(len(branch), 100)

    def test_path_with_dot_dot_or_leading_slash_refused_before_any_request(self) -> None:
        bad_paths = [
            "/leading_slash.md",
            "//double_leading.md",
            "../parent_traversal.md",
            "wiki/../../escaped.md",
            "nested/../escape.md",
            "..",
            "",
        ]
        for bad_path in bad_paths:
            with self.subTest(path=bad_path):
                backend = FakeGitHub()
                with self.assertRaises(ReviewBackendError) as cm:
                    backend.open_change(self.spec, bad_path, "c", "m", "tok", self.ctx)
                self.assertEqual(cm.exception.status, 400)
                self.assertEqual(len(backend.recorded), 0)

                with self.assertRaises(ReviewBackendError) as cm:
                    backend.update_change(self.spec, bad_path, "c", "m", "sha123", "tok", self.ctx)
                self.assertEqual(cm.exception.status, 400)
                self.assertEqual(len(backend.recorded), 0)

    def test_change_ref_not_positive_int_refused_before_any_request(self) -> None:
        bad_refs: list[Any] = [0, -1, -99, "42", "invalid", None, True, False, 3.14]
        for bad_ref in bad_refs:
            with self.subTest(ref=bad_ref):
                backend = FakeGitHub()
                with self.assertRaises(ReviewBackendError) as cm:
                    backend.comment(self.spec, bad_ref, "body", "tok", self.ctx)
                self.assertEqual(cm.exception.status, 400)
                self.assertEqual(len(backend.recorded), 0)

                with self.assertRaises(ReviewBackendError) as cm:
                    backend.get_change(self.spec, bad_ref, "tok", self.ctx)
                self.assertEqual(cm.exception.status, 400)
                self.assertEqual(len(backend.recorded), 0)

    def test_credential_sent_in_header_and_not_stored_on_instance(self) -> None:
        backend = GitHubReviewBackend()
        token = "ghp_super_secret_caller_token_never_stored"

        # The backend instance has no service account and must not retain caller tokens
        self.assertNotIn(token, str(vars(backend)))
        for val in vars(backend).values():
            self.assertNotEqual(val, token)

        captured_req: request.Request | None = None

        class MockResponse:
            def __enter__(self) -> MockResponse:
                return self

            def __exit__(self, *args: Any) -> None:
                pass

            def read(self, *args: Any) -> bytes:
                return b'{"ok": true}'

        def mock_urlopen(req: request.Request, timeout: float | None = None) -> MockResponse:
            nonlocal captured_req
            captured_req = req
            return MockResponse()

        with unittest.mock.patch("urllib.request.urlopen", side_effect=mock_urlopen):
            backend._request(self.spec, "GET", "/test/path", credential=token)

        self.assertIsNotNone(captured_req)
        assert captured_req is not None
        self.assertEqual(captured_req.get_header("Authorization"), f"Bearer {token}")
        self.assertEqual(captured_req.get_header("Accept"), "application/vnd.github+json")
        self.assertEqual(captured_req.get_header("X-github-api-version"), "2022-11-28")

        # Confirm instance state still does not hold the token after execution
        self.assertNotIn(token, str(vars(backend)))
        for val in vars(backend).values():
            self.assertNotEqual(val, token)

    def test_oversized_or_non_json_response_raises_review_backend_error(self) -> None:
        backend = GitHubReviewBackend()

        class MockResponse:
            def __init__(self, data: bytes) -> None:
                self._data = data

            def __enter__(self) -> MockResponse:
                return self

            def __exit__(self, *args: Any) -> None:
                pass

            def read(self, amt: int) -> bytes:
                return self._data[:amt]

        # 1. Response exceeding _MAX_RESPONSE_BYTES (2 MB)
        with unittest.mock.patch("urllib.request.urlopen", return_value=MockResponse(b"x" * (2_000_000 + 1))):
            with self.assertRaises(ReviewBackendError) as cm:
                backend._request(self.spec, "GET", "/path", "tok")
            self.assertIn("too large", str(cm.exception))

        # 2. Non-JSON response (e.g. proxy/gateway HTML error page)
        with unittest.mock.patch("urllib.request.urlopen", return_value=MockResponse(b"<html>502 Bad Gateway</html>")):
            with self.assertRaises(ReviewBackendError) as cm:
                backend._request(self.spec, "GET", "/path", "tok")
            self.assertIn("invalid json", str(cm.exception).lower())

        # 3. Empty response
        with unittest.mock.patch("urllib.request.urlopen", return_value=MockResponse(b"")):
            with self.assertRaises(ReviewBackendError) as cm:
                backend._request(self.spec, "GET", "/path", "tok")
            self.assertIn("invalid json", str(cm.exception).lower())

    def test_get_change_reads_proposal_metadata(self) -> None:
        pr_payload = {
            "number": 42,
            "state": "open",
            "title": "Docs proposal for wiki",
            "html_url": "https://github.com/example-org/docs-corpus/pull/42",
            "merged": False,
            "head": {"ref": "mcpgw/wiki-guide-abc12345"},
        }
        backend = FakeGitHub(replies={("GET", f"/repos/{self.spec.repo}/pulls/42"): pr_payload})
        data = backend.get_change(self.spec, 42, "tok", self.ctx)

        self.assertEqual(
            data,
            {
                "number": 42,
                "state": "open",
                "title": "Docs proposal for wiki",
                "url": "https://github.com/example-org/docs-corpus/pull/42",
                "merged": False,
                "branch": "mcpgw/wiki-guide-abc12345",
            },
        )
        self.assertEqual(backend.recorded[0][:2], ("GET", f"/repos/{self.spec.repo}/pulls/42"))

    def test_path_percent_encoding_escapes_special_characters_per_segment(self) -> None:
        backend = FakeGitHub()
        backend.open_change(self.spec, "wiki/category#1/my file?v=1.md", "c", "m", "tok", self.ctx)
        step3_path = backend.recorded[2][1]
        self.assertEqual(
            step3_path,
            f"/repos/{self.spec.repo}/contents/wiki/category%231/my%20file%3Fv%3D1.md",
        )

    def test_network_and_http_exceptions_map_to_review_host_unavailable(self) -> None:
        backend = GitHubReviewBackend()
        errors = [
            OSError("Connection refused"),
            http.client.RemoteDisconnected("Remote end closed connection"),
            ValueError("Invalid URL or encoding"),
        ]
        for exc in errors:
            with self.subTest(exc=exc):
                with unittest.mock.patch("urllib.request.urlopen", side_effect=exc):
                    with self.assertRaises(ReviewBackendError) as cm:
                        backend._request(self.spec, "GET", "/path", "tok")
                    self.assertIn("unavailable", str(cm.exception))


class CredentialHygieneTests(unittest.TestCase):
    """A credential that cannot be an HTTP header must not reach one.

    `http.client.putheader` raises a ValueError whose message CONTAINS the header
    value, and this module chains its causes -- so a stored credential carrying a
    CR, LF or NUL appeared verbatim in any formatted traceback. Nothing formats
    one today, which made it one `logger.exception` away rather than a live leak.
    (Found by review, 2026-09-04.)
    """

    def _backend(self):
        return GitHubReviewBackend(timeout_sec=1)

    def _spec(self):
        return ReviewSpec(project="p", type="github", repo="o/r",
                          api="https://api.github.com", base_branch="main")

    def _ctx(self):
        return RequestContext(actor="1", project="p", client="t", request_id="r")

    def test_a_credential_with_a_control_character_never_reaches_a_traceback(self):
        import traceback
        for bad in ("abc\r\nX-Injected: SUPERSECRET", "tok\x00en", "with space", "", "tab\there"):
            with self.assertRaises(ReviewBackendError) as caught:
                self._backend().get_change(self._spec(), 1, bad, self._ctx())
            self.assertEqual(caught.exception.status, 409)
            try:
                raise caught.exception
            except ReviewBackendError:
                rendered = traceback.format_exc()
            self.assertNotIn("SUPERSECRET", rendered)
            if bad:   # "" is a substring of everything; the point is the value is not echoed
                self.assertNotIn(bad, str(caught.exception))
                self.assertNotIn(bad, rendered)

    def test_the_refusal_says_what_is_wrong_rather_than_blaming_the_network(self):
        # It surfaced as "review host unavailable", which sends an operator to
        # look at connectivity for what is a corrupt stored credential.
        with self.assertRaises(ReviewBackendError) as caught:
            self._backend().get_change(self._spec(), 1, "bad\ncred", self._ctx())
        self.assertIn("re-enroll", str(caught.exception))
        self.assertNotIn("unavailable", str(caught.exception))
