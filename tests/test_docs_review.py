"""The docs write path from a tool call to a review host.

The adapter has its own suite; this one is about everything that decides
whether a call is allowed to reach one — the review spec, the caller's
credential, the roles, the confirmation gate, and what a proposal may name.
"""
from __future__ import annotations

import json
import unittest

from mcp_governance_gateway.audit import AuditEvent, AuditSink
from mcp_governance_gateway.auth import Principal
from mcp_governance_gateway.docs_review import DocsReviewService
from mcp_governance_gateway.mcp import GatewayApp
from mcp_governance_gateway.memory_backend import RequestContext
from mcp_governance_gateway.redmine_keystore import KeyState
from mcp_governance_gateway.review_backend import ReviewBackendError, ReviewSpec, parse_review_spec

SPEC = ReviewSpec(project="team-a", type="github", repo="org/handbook",
                  api="https://api.github.com", base_branch="main")


def _ctx(actor="10000001", project="team-a"):
    return RequestContext(actor=actor, project=project, client="t", request_id="req-1")


class _Corpus:
    SERVED_DIRS = ("raw/", "wiki/")

    def __init__(self, spec=SPEC, present=()):
        self._spec, self._present = spec, set(present)

    def review_spec_for(self, project):
        return self._spec if project == "team-a" else None

    def has_project(self, project):
        return project == "team-a"

    def get(self, path, context):
        if path not in self._present:
            raise ReviewBackendError("document not found", status=404)
        return {"path": path, "sha": "blob-sha"}

    def lint(self, context):
        return {"findings": [{"kind": "broken_link", "path": "wiki/x.md"}], "count": 1}


class _Backend:
    """Records what it was asked to do, and what credential it was handed."""

    def __init__(self):
        self.calls = []

    def open_change(self, spec, path, content, message, credential, context):
        self.calls.append(("open", path, content, message, credential))
        return {"number": 7, "url": "https://example/pull/7", "branch": "mcpgw/x-1234"}

    def update_change(self, spec, path, content, message, base_sha, credential, context):
        self.calls.append(("update", path, content, message, base_sha, credential))
        return {"number": 8, "url": "https://example/pull/8", "branch": "mcpgw/y-5678"}

    def comment(self, spec, change_ref, body, credential, context):
        self.calls.append(("comment", change_ref, body, credential))
        return {"id": 99}

    def get_change(self, spec, change_ref, credential, context):
        self.calls.append(("get", change_ref, credential))
        return {"number": change_ref, "state": "open", "merged": False}

    def list_changes(self, spec, limit, credential, context):
        self.calls.append(("list", spec.repo, limit, credential))
        return {"changes": [{"number": 7, "isAuthor": True}], "count": 1}

    def add_reviewer(self, spec, change_ref, reviewer, credential, context):
        self.calls.append(("reviewer", spec.repo, change_ref, reviewer, credential))
        return {"number": change_ref, "reviewer": reviewer}

    def close_change(self, spec, change_ref, message, credential, context):
        self.calls.append(("close", spec.repo, change_ref, message, credential))
        return {"number": change_ref, "abandoned": True}


def _service(present=(), state=KeyState.OK, credential="ghp-caller", spec=SPEC, backends=None):
    backend = _Backend()
    service = DocsReviewService(
        corpus=_Corpus(spec=spec, present=present),
        backends={"github": backend} if backends is None else backends,
        key_resolver=lambda actor, backend_key: (state, credential),
        credential_portal_url="https://portal.example/creds",
    )
    return service, backend


class SpecTests(unittest.TestCase):
    def test_no_review_block_leaves_the_corpus_read_only(self):
        self.assertIsNone(parse_review_spec("p", {"url": "u"}, "main"))

    def test_a_malformed_review_block_is_a_load_error_not_a_surprise_later(self):
        # An operator who wrote a review block believes writes are on. Failing at
        # the first write instead would make that a runtime discovery.
        for bad in ({"review": "github"},
                    {"review": {"type": "gerrit", "repo": "a/b"}},
                    {"review": {"type": "github", "repo": "not a repo"}},
                    {"review": {"type": "github", "repo": "a/b", "api": "ftp://x"}},
                    {"review": {"type": "github", "repo": "a/b", "baseBranch": "bad branch"}}):
            with self.assertRaises(ValueError, msg=bad):
                parse_review_spec("p", bad, "main")

    def test_the_base_branch_defaults_to_the_branch_the_corpus_reads(self):
        # Otherwise the two drift and proposals target something nobody reads.
        spec = parse_review_spec("p", {"review": {"type": "github", "repo": "a/b"}}, "trunk")
        self.assertEqual(spec.base_branch, "trunk")

    def test_the_credential_backend_key_is_distinct_from_the_issue_tracker_s(self):
        # A person's issue-tracker token and their docs-host token are different
        # secrets; the store is keyed by (actor, backend) so both can exist.
        self.assertEqual(SPEC.backend_key, "docs-github")


class PathTests(unittest.TestCase):
    def test_a_proposal_can_only_name_a_document_the_read_path_would_serve(self):
        # Without this the docs tools are "propose any file into this repository":
        # a workflow file, a source file, a CODEOWNERS. A human still has to merge
        # it, which makes it a lure rather than a compromise -- behind a tool whose
        # name says "docs".
        service, backend = _service()
        for path in (".github/workflows/ci.yml", "src/server.py", "README.md",
                     "wiki/notes.txt", "wiki/.hidden.md", "wiki//x.md", "wiki/../etc/x.md"):
            with self.assertRaises(ReviewBackendError, msg=path) as caught:
                service.create(path, "body", "why", _ctx())
            self.assertEqual(caught.exception.status, 400, path)
        self.assertEqual(backend.calls, [])

    def test_a_control_character_in_a_path_is_refused(self):
        # A NUL survived both this check and the URL quoting (as %00) until a
        # review found it. Git's own tree rules make it inert, but "inert because
        # something downstream refuses it" is not a validation story.
        service, backend = _service()
        for path in ("raw/x\x00.md", "raw/\x00foo/bar/x.md", "wiki/a\tb.md",
                     "wiki/a\nb.md", "wiki/a\x7f.md"):
            with self.assertRaises(ReviewBackendError, msg=repr(path)) as caught:
                service.create(path, "b", "m", _ctx())
            self.assertEqual(caught.exception.status, 400, repr(path))
        self.assertEqual(backend.calls, [])

    def test_the_documents_it_does_allow_are_exactly_the_ones_it_serves(self):
        service, backend = _service()
        for path in ("wiki/onboarding.md", "raw/reports/2026-01-01-x.md"):
            service.create(path, "body", "why", _ctx())
        self.assertEqual([c[1] for c in backend.calls], ["wiki/onboarding.md", "raw/reports/2026-01-01-x.md"])


class CredentialTests(unittest.TestCase):
    def test_a_caller_who_has_not_enrolled_is_told_how_to(self):
        service, backend = _service(state=KeyState.MISSING, credential=None)
        with self.assertRaises(ReviewBackendError) as caught:
            service.create("wiki/x.md", "b", "m", _ctx())
        self.assertEqual(caught.exception.status, 428)
        self.assertIn("portal.example", str(caught.exception))
        self.assertEqual(backend.calls, [])

    def test_the_three_credential_failures_are_three_different_answers(self):
        # Collapsing them sends people to re-enrol when re-enrolling is not the fix.
        for state, status in ((KeyState.DEGRADED, 503), (KeyState.UNDECRYPTABLE, 409),
                              (KeyState.MISSING, 428)):
            service, _ = _service(state=state, credential=None)
            with self.assertRaises(ReviewBackendError) as caught:
                service.create("wiki/x.md", "b", "m", _ctx())
            self.assertEqual(caught.exception.status, status, state)

    def test_no_credential_store_at_all_is_not_a_silent_shared_account(self):
        service = DocsReviewService(corpus=_Corpus(), backends={"github": _Backend()})
        with self.assertRaises(ReviewBackendError) as caught:
            service.create("wiki/x.md", "b", "m", _ctx())
        self.assertEqual(caught.exception.status, 428)

    def test_the_caller_s_own_credential_is_what_reaches_the_host(self):
        service, backend = _service(credential="ghp-alice")
        service.create("wiki/x.md", "b", "m", _ctx())
        self.assertEqual(backend.calls[0][-1], "ghp-alice")


class ServiceTests(unittest.TestCase):
    def test_a_create_over_an_existing_document_is_refused_with_the_useful_message(self):
        service, backend = _service(present={"wiki/x.md"})
        with self.assertRaises(ReviewBackendError) as caught:
            service.create("wiki/x.md", "b", "m", _ctx())
        self.assertEqual(caught.exception.status, 409)
        self.assertIn("docs.update", str(caught.exception))
        self.assertEqual(backend.calls, [])

    def test_an_update_carries_the_sha_the_caller_read(self):
        service, backend = _service(present={"wiki/x.md"})
        service.update("wiki/x.md", "b", "m", "blob-sha", _ctx())
        self.assertEqual(backend.calls[0][4], "blob-sha")

    def test_a_comment_is_stamped_before_it_leaves(self):
        # An unstamped comment is indistinguishable from one the person wrote.
        service, backend = _service()
        service.comment(7, "looks fine", _ctx())
        body = backend.calls[0][2]
        self.assertIn("looks fine", body)
        self.assertIn("via mcp-governance-gateway", body)
        self.assertIn("actor=10000001", body)
        self.assertIn("audit=req-1", body)

    def test_a_project_with_no_review_host_is_read_only(self):
        service, backend = _service()
        self.assertFalse(service.has_project("other"))
        with self.assertRaises(ReviewBackendError) as caught:
            service.create("wiki/x.md", "b", "m", _ctx(project="other"))
        self.assertEqual(caught.exception.status, 404)

    def test_a_configured_host_type_with_no_adapter_fails_loud(self):
        gitlab = ReviewSpec(project="team-a", type="gitlab", repo="g/h",
                            api="https://gitlab.example/api/v4", base_branch="main")
        service, _ = _service(spec=gitlab, backends={"github": _Backend()})
        with self.assertRaises(ReviewBackendError) as caught:
            service.create("wiki/x.md", "b", "m", _ctx())
        self.assertEqual(caught.exception.status, 503)


class _Audit(AuditSink):
    def __init__(self):
        self.events: list[AuditEvent] = []

    def write(self, event):
        self.events.append(event)


class _NullMemory:
    def has_project(self, project):
        return True


class GatewayTests(unittest.TestCase):
    """Through handle_rpc: roles, the gate, and what tools/list advertises."""

    def setUp(self):
        self.audit = _Audit()
        self.service, self.backend = _service()
        self.app = GatewayApp(memory_backend=_NullMemory(), audit_sink=self.audit,
                              docs_corpus=_Corpus(), docs_review=self.service)
        self.reader = Principal(actor="1", project="team-a", roles=(), token_id="t1")
        self.writer = Principal(actor="1", project="team-a", roles=("docs_writer",), token_id="t1")
        self.reviewer = Principal(actor="1", project="team-a", roles=("docs_reviewer",), token_id="t1")

    def _call(self, principal, name, arguments):
        return self.app.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                    "params": {"name": name, "arguments": arguments}}, principal)

    def _names(self, principal):
        listed = self.app.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                                     principal)
        return {t["name"] for t in listed["result"]["tools"]}

    def test_writing_needs_the_write_role_and_commenting_needs_the_review_role(self):
        denied = self._call(self.reader, "docs.create",
                            {"path": "wiki/x.md", "content": "c", "message": "m"})
        self.assertEqual(denied["error"]["code"], -32003)
        self.assertIn("docs write role", denied["error"]["message"])
        self.assertEqual(self.backend.calls, [])

        # A writer is not automatically a reviewer: they are different acts, and a
        # deployment may well grant only one.
        refused = self._call(self.writer, "docs.review_comment", {"change": 7, "body": "hi"})
        self.assertIn("docs review role", refused["error"]["message"])

    def test_the_first_call_proposes_nothing(self):
        first = self._call(self.writer, "docs.create",
                           {"path": "wiki/x.md", "content": "c", "message": "m"})
        pending = first["result"]["structuredContent"]
        self.assertTrue(pending["confirmationRequired"])
        self.assertEqual(self.backend.calls, [], "a proposal was opened before the confirmation")

        second = self._call(self.writer, "docs.create",
                            {"path": "wiki/x.md", "content": "c", "message": "m",
                             "confirm": pending["confirmationId"]})
        self.assertEqual(second["result"]["structuredContent"]["number"], 7)
        self.assertEqual(self.backend.calls[0][0], "open")
        self.assertEqual(self.audit.events[-1].outcome, "ok")

    def test_a_credential_in_a_document_body_is_refused_before_the_gate(self):
        # A corpus is team-visible, and a document body is the likeliest place in
        # this gateway for a pasted key to end up.
        resp = self._call(self.writer, "docs.create",
                          {"path": "wiki/x.md", "message": "m",
                           "content": "Deploy with this token:\n\n    ghp_1234567890abcdefghijklmnopqrstuvwxyzAB\n"})
        # Rejected as an invalid argument, the same shape a secret in a memory
        # write gets, and BEFORE a confirmation id exists -- so there is nothing
        # to confirm and nothing reached the review host.
        self.assertEqual(resp["error"]["code"], -32602)
        self.assertNotIn("ghp_", json.dumps(resp))
        self.assertEqual(self.backend.calls, [])
        self.assertEqual(self.audit.events[-1].outcome, "invalid")

    def test_tools_list_advertises_only_what_this_principal_could_call(self):
        self.assertNotIn("docs.create", self._names(self.reader))
        self.assertIn("docs.create", self._names(self.writer))
        self.assertNotIn("docs.review_comment", self._names(self.writer))
        self.assertIn("docs.review_comment", self._names(self.reviewer))
        self.assertIn("docs.get", self._names(self.reader))       # reads unaffected

    def test_a_read_only_corpus_advertises_no_write_tools_at_all(self):
        app = GatewayApp(memory_backend=_NullMemory(), audit_sink=self.audit, docs_corpus=_Corpus())
        listed = app.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                                self.writer)
        names = {t["name"] for t in listed["result"]["tools"]}
        self.assertIn("docs.get", names)
        for tool in ("docs.create", "docs.update", "docs.review_comment", "docs.review_get"):
            self.assertNotIn(tool, names)

    def test_a_change_reference_that_is_not_a_positive_int_is_refused(self):
        for bad in (0, -1, "7", 1.5, True, None):
            resp = self._call(self.reviewer, "docs.review_comment", {"change": bad, "body": "x"})
            self.assertIn("error", resp, bad)
        self.assertEqual(self.backend.calls, [])

    def test_review_list_uses_the_project_spec_without_confirmation(self):
        result = self._call(self.reader, "docs.review_list", {"limit": 4})["result"]["structuredContent"]
        self.assertEqual(result["changes"][0]["number"], 7)
        self.assertEqual(self.backend.calls, [("list", "org/handbook", 4, "ghp-caller")])

    def test_adding_a_reviewer_is_role_guarded_confirmed_and_audited(self):
        args = {"change": 7, "reviewer": "alex"}
        self.assertIn("error", self._call(self.reader, "docs.review_add_reviewer", args))
        first = self._call(self.reviewer, "docs.review_add_reviewer", args)["result"]["structuredContent"]
        self.assertTrue(first["confirmationRequired"])
        self.assertEqual(self.backend.calls, [])
        for changed in ({"change": 8}, {"reviewer": "sam"}):
            result = self._call(self.reviewer, "docs.review_add_reviewer",
                                {**args, **changed, "confirm": first["confirmationId"]})
            self.assertTrue(result["result"]["structuredContent"]["confirmationRequired"])
            self.assertEqual(self.backend.calls, [])
        result = self._call(self.reviewer, "docs.review_add_reviewer",
                            {**args, "confirm": first["confirmationId"]})["result"]["structuredContent"]
        self.assertEqual(result["reviewer"], "alex")
        self.assertEqual(self.backend.calls, [("reviewer", "org/handbook", 7, "alex", "ghp-caller")])
        self.assertEqual(self.audit.events[-1].tool, "docs.review_add_reviewer")
        self.assertEqual(self.audit.events[-1].outcome, "ok")

    def test_abandon_is_writer_only_and_binds_its_message_before_closing(self):
        args = {"change": 7, "message": "Superseded"}
        self.assertIn("error", self._call(self.reviewer, "docs.review_abandon", args))
        first = self._call(self.writer, "docs.review_abandon", args)["result"]["structuredContent"]
        self.assertTrue(first["confirmationRequired"])
        self.assertEqual(self.backend.calls, [])
        changed = self._call(self.writer, "docs.review_abandon",
                             {**args, "message": "Different", "confirm": first["confirmationId"]})
        self.assertTrue(changed["result"]["structuredContent"]["confirmationRequired"])
        self.assertEqual(self.backend.calls, [])
        pending = self._call(self.writer, "docs.review_abandon", args)["result"]["structuredContent"]
        result = self._call(self.writer, "docs.review_abandon",
                            {**args, "confirm": pending["confirmationId"]})["result"]["structuredContent"]
        self.assertTrue(result["abandoned"])
        self.assertEqual(self.backend.calls[0][:3], ("close", "org/handbook", 7))

    def test_lint_is_available_on_a_read_only_corpus(self):
        import tempfile
        from pathlib import Path
        from test_docs_backend import _make_remote
        from mcp_governance_gateway.docs_backend import DocsCorpus
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        remote = _make_remote(tmp.name, "lint", {"wiki/x.md": "# X\n[Missing](missing.md)\n"})
        self.app._docs_corpus = DocsCorpus({"team-a": {"url": remote, "branch": "master"}},
                                           str(Path(tmp.name) / "clones"))
        self.app._docs_review = None
        self.assertIn("docs.lint", self._names(self.reader))
        result = self._call(self.reader, "docs.lint", {})["result"]["structuredContent"]
        self.assertEqual(result["findings"][0]["kind"], "broken_link")
        self.assertEqual(set(result), {"findings", "count", "commit"})
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["findings"], [{"kind": "broken_link", "path": "wiki/x.md", "target": "missing.md"}])

    def test_inline_confirmation_cannot_be_reused_for_a_different_body(self):
        for tool in ("docs.create", "docs.update"):
            args = {"path": "wiki/x.md", "content": "original", "message": "m"}
            if tool == "docs.update":
                args["sha"] = "blob-sha"
            pending = self._call(self.writer, tool, args)["result"]["structuredContent"]
            result = self._call(self.writer, tool, {**args, "content": "substitute",
                                "confirm": pending["confirmationId"]})["result"]["structuredContent"]
            self.assertTrue(result["confirmationRequired"])
        self.assertEqual(self.backend.calls, [])

    def _stage_body(self, body):
        minted = self.app._asset_stage.mint_upload_url("1", "team-a", "t1", "content")
        self.app._asset_stage.accept_upload(minted["url"].rsplit("/", 1)[1], body.encode(), "1", "team-a", "t1")
        return minted["stagedId"]

    def _enable_stage(self):
        from mcp_governance_gateway.docs_assets import AssetStage
        self.now = 0
        self.app._asset_stage = AssetStage("https://gateway.example", clock=lambda: self.now)

    def test_staged_confirmation_lands_exact_body_and_consumes_it(self):
        self._enable_stage()
        for tool in ("docs.create", "docs.update"):
            body = "# Long\n" + "text " * 7000 + "\n"
            sid = self._stage_body(body)
            args = {"path": "wiki/x.md", "message": "Long page", "contentStaged": sid}
            if tool == "docs.update":
                args["sha"] = "blob-sha"
            first = self._call(self.writer, tool, args)["result"]["structuredContent"]
            self.assertEqual(set(first["arguments"]), set(args))
            self.assertEqual(first["arguments"]["contentStaged"], sid)
            self.assertNotIn("content", first["arguments"])
            result = self._call(self.writer, tool, {**args, "confirm": first["confirmationId"]})
            self.assertEqual(result["result"]["structuredContent"]["status"], "proposed")
            self.assertEqual(self.backend.calls[-1][2], body)
            replay = self._call(self.writer, tool, args)
            self.assertTrue(replay["result"]["isError"])

    # Position: follows test_staged_confirmation_lands_exact_body_and_consumes_it.
    def test_tool_minted_stage_cannot_be_prepared_by_another_token(self):
        from dataclasses import replace
        self._enable_stage()
        minted = self._call(self.writer, "docs.asset_stage_url", {})["result"]["structuredContent"]
        self.app._asset_stage.accept_upload(minted["url"].rsplit("/", 1)[1], b"# Mine",
                                           "1", "team-a", "t1")
        args = {"path": "wiki/x.md", "message": "m", "contentStaged": minted["stagedId"]}
        result = self._call(replace(self.writer, token_id="t2"), "docs.create", args)
        self.assertTrue(result["result"]["isError"])
        self.assertNotIn("confirmationId", json.dumps(result))
        self.assertEqual(self.backend.calls, [])
        pending = self._call(self.writer, "docs.create", args)["result"]["structuredContent"]
        result = self._call(self.writer, "docs.create", {**args, "confirm": pending["confirmationId"]})
        self.assertEqual(result["result"]["structuredContent"]["status"], "proposed")

    def test_staged_confirmation_refuses_inline_substitution_and_both_body_keys(self):
        self._enable_stage()
        sid = self._stage_body("# Original\n")
        args = {"path": "wiki/x.md", "message": "m", "contentStaged": sid}
        pending = self._call(self.writer, "docs.create", args)["result"]["structuredContent"]
        for body in ("# Different", "", None):
            result = self._call(self.writer, "docs.create",
                                {**args, "content": body, "confirm": pending["confirmationId"]})
            self.assertIn("not both", result["error"]["message"])
        result = self._call(self.writer, "docs.create", {"path": "wiki/x.md", "message": "m",
                            "content": "# Different", "confirm": pending["confirmationId"]})
        self.assertTrue(result["result"]["structuredContent"]["confirmationRequired"])
        self.assertEqual(self.backend.calls, [])

    def test_stage_expired_after_prepare_is_a_tool_error_at_confirm(self):
        self._enable_stage()
        args = {"path": "wiki/x.md", "message": "m", "contentStaged": self._stage_body("# Expires")}
        pending = self._call(self.writer, "docs.create", args)["result"]["structuredContent"]
        self.now = 3601
        result = self._call(self.writer, "docs.create", {**args, "confirm": pending["confirmationId"]})
        self.assertTrue(result["result"]["isError"])
        self.assertIn("unknown stagedId", json.dumps(result))
        self.assertEqual(self.audit.events[-1].backend_status, "404")
        self.assertEqual(self.backend.calls, [])

    # Position: follows test_stage_expired_after_prepare_is_a_tool_error_at_confirm.
    def test_expired_stage_is_a_tool_error_before_confirmation(self):
        self._enable_stage()
        args = {"path": "wiki/x.md", "message": "m", "contentStaged": self._stage_body("# Expires")}
        self.now = 3601
        result = self._call(self.writer, "docs.create", args)
        self.assertTrue(result["result"]["isError"])
        self.assertNotIn("confirmationId", json.dumps(result))
        self.assertEqual(self.audit.events[-1].backend_status, "404")
        self.assertEqual(self.backend.calls, [])

    def test_failed_proposal_leaves_staged_body_reusable(self):
        from unittest.mock import patch
        self._enable_stage()
        sid = self._stage_body("# Retry me\n")
        args = {"path": "wiki/x.md", "message": "m", "contentStaged": sid}
        pending = self._call(self.writer, "docs.create", args)["result"]["structuredContent"]
        with patch.object(self.backend, "open_change", side_effect=ReviewBackendError("host unavailable", status=502)):
            result = self._call(self.writer, "docs.create", {**args, "confirm": pending["confirmationId"]})
        self.assertTrue(result["result"]["isError"])
        self.assertEqual(self.app._asset_stage.peek(sid, "1", "team-a", "t1"), "# Retry me\n")
        pending = self._call(self.writer, "docs.create", args)["result"]["structuredContent"]
        result = self._call(self.writer, "docs.create", {**args, "confirm": pending["confirmationId"]})
        self.assertEqual(result["result"]["structuredContent"]["status"], "proposed")

    def test_staging_discovery_requires_configuration_project_and_writer(self):
        self.assertNotIn("docs.asset_stage_url", self._names(self.writer))
        self._enable_stage()
        self.assertIn("docs.asset_stage_url", self._names(self.writer))
        self.assertNotIn("docs.asset_stage_url", self._names(self.reader))
        result = self._call(self.writer, "docs.asset_stage_url", {"kind": "content"})
        self.assertTrue(result["result"]["structuredContent"]["stagedId"].startswith("doc_"))
        other = Principal(actor="1", project="team-b", roles=("docs_writer",), token_id="t2")
        self.assertNotIn("docs.asset_stage_url", self._names(other))
        self.assertTrue(self._call(other, "docs.asset_stage_url", {})["result"]["isError"])

    def test_staged_body_prefix_and_secret_are_checked_before_confirmation(self):
        self._enable_stage()
        args = {"path": "wiki/x.md", "message": "m", "contentStaged": "ast_not-content"}
        result = self._call(self.writer, "docs.create", args)
        self.assertIn("doc_", result["error"]["message"])
        args["contentStaged"] = self._stage_body("ghp_1234567890abcdefghijklmnopqrstuvwxyzAB")
        result = self._call(self.writer, "docs.create", args)
        self.assertIn("possible secret", result["error"]["message"])
        self.assertEqual(self.backend.calls, [])


if __name__ == "__main__":
    unittest.main()


class ShippedExampleTests(unittest.TestCase):
    """The examples an adopter copies must load verbatim, `_comment` and all."""

    def _examples(self):
        from pathlib import Path
        return Path(__file__).resolve().parent.parent / "config" / "examples"

    def test_the_docs_repos_example_loads_with_its_prose_intact(self):
        # JSON has no comments, so these files carry a `_comment` key. A loader
        # that treated it as a project made the shipped example a boot error.
        from mcp_governance_gateway.docs_backend import load_docs_repos
        repos = load_docs_repos(str(self._examples() / "docs-repos.example.json"))
        self.assertNotIn("_comment", repos)
        self.assertEqual(repos["team-a"]["review"].repo, "org/handbook")
        self.assertIsNone(repos["team-b"].get("review"))

    def test_only_the_comment_key_is_prose_a_leading_underscore_is_a_project(self):
        # `_scratch` is a legal project name and an existing test says so, so the
        # skip is exactly one key rather than a prefix rule.
        import json as _json, tempfile, os
        from mcp_governance_gateway.docs_backend import load_docs_repos
        path = os.path.join(tempfile.mkdtemp(), "r.json")
        with open(path, "w", encoding="utf-8") as handle:
            _json.dump({"_comment": ["prose"], "_scratch": {"url": "u", "branch": "main"}}, handle)
        repos = load_docs_repos(path)
        self.assertEqual(list(repos), ["_scratch"])

    def test_the_ci_examples_load_with_their_prose_intact(self):
        from mcp_governance_gateway.ci_backend import load_ci_jobs, load_ci_trigger_jobs
        jobs = load_ci_trigger_jobs(str(self._examples() / "ci-trigger-jobs.example.json"))
        self.assertNotIn("_comment", jobs)
        self.assertEqual(jobs["demo-project"], ["demo-tests"])
        self.assertNotIn("_comment", load_ci_jobs(str(self._examples() / "ci-trigger-jobs.example.json")))
