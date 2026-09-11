import io
import os
from email.message import Message
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from dataclasses import replace

from mcp_governance_gateway.auth import AuthError
from mcp_governance_gateway.config import Settings
from mcp_governance_gateway.docs_assets import (
    AssetStage, AssetStageError, MAX_ASSET_BYTES, STAGE_TTL_SEC, URL_TTL_SEC,
)
from mcp_governance_gateway.server import build_server, make_handler


class StagedContentTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.stage = AssetStage("https://gateway.example", clock=lambda: self.now)

    def mint(self):
        result = self.stage.mint_upload_url("alice", "project-a", "token-a")
        return result, result["url"].rsplit("/", 1)[1]

    def upload(self, body=b"# Title\n"):
        result, token = self.mint()
        self.stage.accept_upload(token, body, "alice", "project-a", "token-a")
        return result["stagedId"]

    # Position: first test in StagedContentTests.
    def test_markdown_round_trip_and_preallocated_id(self):
        result, token = self.mint()
        body = "# Title\n" + "x" * 33000
        uploaded = self.stage.accept_upload(token, body.encode(), "alice", "project-a", "token-a")
        self.assertEqual(uploaded["stagedId"], result["stagedId"])
        self.assertTrue(result["stagedId"].startswith("doc_"))
        self.assertEqual(self.stage.peek(result["stagedId"], "alice", "project-a", "token-a"), body)

    # Position: follows test_markdown_round_trip_and_preallocated_id.
    def test_upload_token_is_one_shot_and_kind_is_fixed(self):
        result, token = self.mint()
        self.stage.accept_upload(token, b"# original", "alice", "project-a", "token-a")
        with self.assertRaises(AssetStageError):
            self.stage.accept_upload(token, b"# replacement", "alice", "project-a", "token-a")
        self.assertEqual(self.stage.peek(result["stagedId"], "alice", "project-a", "token-a"), "# original")
        with self.assertRaises(AssetStageError):
            self.stage.mint_upload_url("alice", "project-a", "token-a", "image")

    # Position: follows test_upload_token_is_one_shot_and_kind_is_fixed.
    def test_upload_and_read_require_owner_and_project(self):
        result, token = self.mint()
        for actor, project in (("bob", "project-a"), ("alice", "project-b")):
            with self.assertRaises(AssetStageError):
                self.stage.accept_upload(token, b"# stolen", actor, project, "token-a")
        self.stage.accept_upload(token, b"# mine", "alice", "project-a", "token-a")
        for actor, project in (("bob", "project-a"), ("alice", "project-b")):
            with self.assertRaises(AssetStageError):
                self.stage.peek(result["stagedId"], actor, project, "token-a")
            with self.assertRaises(AssetStageError):
                with self.stage.claim(result["stagedId"], actor, project, "token-a"):
                    self.fail("foreign stage was claimed")

    # Position: follows test_upload_and_read_require_owner_and_project.
    def test_stage_requires_the_minting_token_for_upload_peek_and_claim(self):
        result, token = self.mint()
        with self.assertRaises(AssetStageError):
            self.stage.accept_upload(token, b"stolen", "alice", "project-a", "token-b")
        self.stage.accept_upload(token, b"mine", "alice", "project-a", "token-a")
        with self.assertRaises(AssetStageError):
            self.stage.peek(result["stagedId"], "alice", "project-a", "token-b")
        with self.assertRaises(AssetStageError):
            with self.stage.claim(result["stagedId"], "alice", "project-a", "token-b"):
                self.fail("another token claimed the stage")
        with self.stage.claim(result["stagedId"], "alice", "project-a", "token-a") as body:
            self.assertEqual(body, "mine")

    # Position: follows test_stage_requires_the_minting_token_for_upload_peek_and_claim.
    def test_invalid_utf8_empty_and_oversized_bodies_consume_url(self):
        for body, status in ((b"\xff", 415), (b"", 400), (b"x" * (MAX_ASSET_BYTES + 1), 413)):
            _, token = self.mint()
            with self.assertRaises(AssetStageError) as error:
                self.stage.accept_upload(token, body, "alice", "project-a", "token-a")
            self.assertEqual(error.exception.status, status)
            with self.assertRaises(AssetStageError):
                self.stage.accept_upload(token, b"valid", "alice", "project-a", "token-a")

    # Position: follows test_invalid_utf8_empty_and_oversized_bodies_consume_url.
    def test_upload_and_stage_expire_at_their_boundaries(self):
        _, token = self.mint()
        self.now += URL_TTL_SEC
        with self.assertRaises(AssetStageError):
            self.stage.accept_upload(token, b"late", "alice", "project-a", "token-a")
        sid = self.upload()
        self.now += STAGE_TTL_SEC
        with self.assertRaises(AssetStageError):
            self.stage.peek(sid, "alice", "project-a", "token-a")

    # Position: follows test_upload_and_stage_expire_at_their_boundaries.
    def test_claim_consumes_only_on_success_and_excludes_concurrent_claims(self):
        sid = self.upload()
        with self.assertRaisesRegex(RuntimeError, "host failed"):
            with self.stage.claim(sid, "alice", "project-a", "token-a"):
                with self.assertRaises(AssetStageError):
                    with self.stage.claim(sid, "alice", "project-a", "token-a"):
                        self.fail("double claim")
                raise RuntimeError("host failed")
        self.assertEqual(self.stage.peek(sid, "alice", "project-a", "token-a"), "# Title\n")
        with self.stage.claim(sid, "alice", "project-a", "token-a") as content:
            self.assertEqual(content, "# Title\n")
            self.now += STAGE_TTL_SEC
            self.mint()  # garbage collection cannot delete an in-flight claim
        with self.assertRaises(AssetStageError):
            self.stage.peek(sid, "alice", "project-a", "token-a")

    # Position: follows test_claim_consumes_only_on_success_and_excludes_concurrent_claims.
    def test_pending_urls_and_staged_bytes_are_quota_bounded(self):
        for _ in range(16):
            self.mint()
        with self.assertRaises(AssetStageError) as error:
            self.mint()
        self.assertEqual(error.exception.status, 429)
        self.now += URL_TTL_SEC
        self.upload(b"1234")
        with patch("mcp_governance_gateway.docs_assets.MAX_STAGED_BYTES_PER_USER", 4):
            with self.assertRaises(AssetStageError) as error:
                self.upload(b"5")
        self.assertEqual(error.exception.status, 429)

    # Position: follows test_pending_urls_and_staged_bytes_are_quota_bounded.
    def test_staged_byte_quota_accepts_exact_fit_and_refuses_one_more(self):
        with patch("mcp_governance_gateway.docs_assets.MAX_STAGED_BYTES_PER_USER", 5):
            self.upload(b"1234")
            sid = self.upload(b"5")
            self.assertEqual(self.stage.peek(sid, "alice", "project-a", "token-a"), "5")
            with self.assertRaises(AssetStageError) as error:
                self.upload(b"6")
            self.assertEqual(error.exception.status, 429)


class UploadRouteTests(unittest.TestCase):
    def setUp(self):
        self.stage = AssetStage("https://gateway.example")
        self.minted = self.stage.mint_upload_url("alice", "project-a", "token-a")

    def request(self, body=b"# title", bearer="valid", actor="alice", project="project-a", headers=None, serves_mcp=True, token_id="token-a", forwarded=None):
        class Authenticator:
            def authenticate_header(self, value):
                if value != "Bearer valid":
                    raise AuthError("unauthorized")
                return SimpleNamespace(actor=actor, project=project, token_id=token_id)
        handler = object.__new__(make_handler())
        handler.server = SimpleNamespace(asset_stage=self.stage, authenticator=Authenticator(),
                                         serves_mcp=serves_mcp, allowed_origins=(),
                                         identity_verifier=SimpleNamespace(resolve=lambda get, p: SimpleNamespace(
                                             actor=forwarded or p.actor, project=p.project, token_id=p.token_id)))
        handler.path = self.minted["url"].removeprefix("https://gateway.example")
        handler.headers = Message()
        handler.headers["Authorization"] = "Bearer " + bearer
        for key, value in (headers if headers is not None else [("Content-Length", str(len(body)))]):
            handler.headers[key] = value
        handler.rfile = io.BytesIO(body)
        result = []
        handler._send_json = lambda status, payload: result.append((status, payload))
        handler.do_PUT()
        self.assertTrue(handler.close_connection)
        return result[0]

    # Position: first test in UploadRouteTests, after StagedContentTests.
    def test_put_uses_bearer_identity_and_returns_preallocated_id(self):
        status, result = self.request()
        self.assertEqual(status, 201)
        self.assertEqual(result["stagedId"], self.minted["stagedId"])
        self.assertEqual(self.stage.peek(result["stagedId"], "alice", "project-a", "token-a"), "# title")

    # Position: follows test_put_uses_bearer_identity_and_returns_preallocated_id.
    def test_put_resolves_forwarded_identity_and_requires_the_minting_token(self):
        self.assertEqual(self.request(actor="front-gateway", forwarded="bob")[0], 404)
        self.assertEqual(self.request(actor="front-gateway", forwarded="alice", token_id="token-b")[0], 404)
        self.assertEqual(self.request(actor="front-gateway", forwarded="alice")[0], 201)

    # Position: follows test_put_resolves_forwarded_identity_and_requires_the_minting_token.
    def test_authentication_tenancy_origin_and_listener_refusals(self):
        self.assertEqual(self.request(bearer="invalid")[0], 401)
        self.assertEqual(self.request(actor="bob")[0], 404)
        self.assertEqual(self.request(project="project-b")[0], 404)
        self.assertEqual(self.request(serves_mcp=False)[0], 404)
        self.assertEqual(self.request(headers=[("Content-Length", "7"), ("Origin", "https://other.example")])[0], 403)

    # Position: follows test_authentication_tenancy_origin_and_listener_refusals.
    def test_framing_size_and_truncated_uploads_are_refused(self):
        for headers in ([], [("Content-Length", "7"), ("Content-Length", "7")],
                        [("Content-Length", "-1")], [("Content-Length", "7"), ("Transfer-Encoding", "chunked")],
                        [("Content-Length", "8")]):
            self.assertEqual(self.request(headers=headers)[0], 400)
        self.assertEqual(self.request(headers=[("Content-Length", str(MAX_ASSET_BYTES + 1))])[0], 413)


class StageConfigurationTests(unittest.TestCase):
    # Position: first test in StageConfigurationTests, after UploadRouteTests.
    def test_stage_base_url_is_validated_and_shared_with_app(self):
        with patch.dict(os.environ, {"GATEWAY_TOKEN_FILE": "unused", "DOCS_ASSET_BASE_URL": "https://gateway.example"}, clear=True):
            settings = Settings.from_env()
            self.assertEqual(settings.docs_asset_base_url, "https://gateway.example")
            os.environ["DOCS_ASSET_BASE_URL"] = "bad-url"
            with self.assertRaises(ValueError):
                Settings.from_env()
        settings = replace(settings, token_file=None, docs_repos_file="unused", docs_clone_dir="unused", redmine_keystore_file="unused")
        with (patch("mcp_governance_gateway.server.GatewayHTTPServer", return_value=SimpleNamespace()),
              patch("mcp_governance_gateway.server.GatewayApp") as app,
              patch("mcp_governance_gateway.server.DocsCorpus"),
              patch("mcp_governance_gateway.server.load_docs_repos", return_value={}),
              patch("mcp_governance_gateway.server.RedmineKeyStore", return_value=SimpleNamespace(degraded=False, get=lambda *a, **k: None)),
              patch("mcp_governance_gateway.server.request.install_opener")):
            server = build_server(settings)
            self.assertIsInstance(server.asset_stage, AssetStage)
            self.assertIs(server.asset_stage, app.call_args.kwargs["asset_stage"])
            self.assertIsNone(build_server(replace(settings, docs_asset_base_url=None)).asset_stage)
