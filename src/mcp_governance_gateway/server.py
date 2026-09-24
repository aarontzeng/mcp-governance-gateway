"""The HTTP layer: one listener (optionally two), a route table, and the wiring
that turns Settings into a running gateway.

Routes are a table rather than an if-chain per HTTP verb, so "which paths
exist" and "which methods each takes" are one list a reader can check
against docs/architecture.md, and an unrouted path is 404 whatever the
method while a served path asked for with the wrong method is 405.

Diagnostics go through `logging` to stderr. stdout belongs to the audit
stream (JsonLinesAuditSink) and nothing here writes to it.
"""
from __future__ import annotations

import json
import logging
import re
import signal
import sys
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib import error, request
from urllib.parse import urlsplit

from .artifact_route import stream_artifact
from .audit import AuditSink, JsonLinesAuditSink
from .auth import AuthError, BearerTokenAuthenticator, IdentityVerifier, Principal
from .ci_backend import JenkinsHttpBackend, load_ci_jobs, load_ci_trigger_jobs
from .config import Settings
from .docs_assets import MAX_ASSET_BYTES, AssetStage, AssetStageError
from .docs_backend import DocsCorpus, load_docs_repos
from .docs_review import DocsReviewService
from .gitlab_backend import GitLabHttpBackend
from .internal_api import InternalApi
from .issue_backend import IssueBackend, RedmineHttpBackend
from .limits import InMemoryMemoryWriteLimiter, MemoryLimitConfig
from .mcp import GatewayApp
from .memory_backend import ActorLabels, HttpMemoryBackend
from .oidc import (
    CompositeAuthenticator,
    GrantsFile,
    JwksCache,
    OidcAuthenticator,
    discover_jwks_url,
)
from .redmine_keystore import CredentialStore, load_master_keys
from .review_backend import GitHubReviewBackend

log = logging.getLogger(__name__)


class SameOriginRedirects(request.HTTPRedirectHandler):
    """urllib's default follows a redirect anywhere -- another host, or ftp://,
    whose response is not an HTTPResponse -- and copies the Authorization header
    along. Every request this process makes carries a backend credential, so a
    redirect may only stay on the origin the request was sent to."""

    @staticmethod
    def _origin(url: str) -> tuple[str, str, int | None]:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        # An explicit default port names the same origin as no port at all.
        port = parts.port if parts.port is not None else {"http": 80, "https": 443}.get(scheme)
        return scheme, (parts.hostname or "").lower(), port

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if self._origin(newurl) != self._origin(req.full_url):
            target = urlsplit(newurl)
            raise error.URLError(f"redirect leaves the backend's origin: {code} to {target.scheme}://{target.netloc}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class GatewayHTTPServer(ThreadingHTTPServer):
    app: GatewayApp
    authenticator: BearerTokenAuthenticator
    identity_verifier: IdentityVerifier
    allowed_origins: tuple[str, ...]
    internal_api: InternalApi | None = None
    keystore: CredentialStore | None = None
    ci_backend: JenkinsHttpBackend | None = None  # for the /ci/artifact download route
    asset_stage: AssetStage | None = None
    audit_sink: AuditSink | None = None            # artifact transfers are audited here
    artifact_max_bytes: int = 256 * 1024 * 1024
    artifact_streams: threading.Semaphore = threading.Semaphore(4)
    # Which surfaces this listener answers. One process may run two: the MCP
    # listener agents reach, and an admin listener for credential enrollment.
    # A route this listener does not serve is 404, not 403 -- an admin surface
    # that is not routed here should look absent rather than forbidden.
    serves_mcp: bool = True
    serves_internal: bool = True
    oidc_grants: GrantsFile | None = None   # for the /healthz staleness flag


# `/internal/redmine-key` was named when Redmine was the only backend; the store
# now holds GitLab credentials too. The old spelling stays an alias forever --
# it is what every deployed enrollment page calls.
_CREDENTIALS = re.compile(r"/internal/(?:credentials|redmine-key)")

# (method, path pattern, Handler method). Matched on the path with any query
# string and trailing slash removed. See docs/architecture.md for why the three
# non-MCP routes exist and are not tools.
_ROUTES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("GET", re.compile(r"/healthz"), "_healthz"),
    ("POST", re.compile(r"/mcp"), "_mcp"),
    ("PUT", re.compile(r"/docs/asset-stage/(?P<token>[A-Za-z0-9_-]+)"), "_asset_upload"),
    ("GET", re.compile(r"/ci/artifact"), "_ci_artifact"),
    ("GET", _CREDENTIALS, "_credentials_status"),
    ("POST", _CREDENTIALS, "_credentials_set"),
    ("DELETE", _CREDENTIALS, "_credentials_clear"),
    ("GET", re.compile(r"/internal/my-issues"), "_my_issues"),
)


def is_origin_allowed(origin: str | None, allowed_origins: tuple[str, ...]) -> bool:
    return origin is None or origin in allowed_origins


def _is_loopback_host(host: str) -> bool:
    import ipaddress

    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def make_handler() -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server: GatewayHTTPServer
        # MCP clients reuse one persistent connection (HTTP/1.1 keep-alive). Speaking
        # HTTP/1.0 makes the server close after each response, which the client sees
        # as ECONNRESET on its next request (e.g. notifications/initialized after
        # initialize). Every response is framed (Content-Length, or chunked for an
        # artifact stream of unknown length), so keep-alive is safe; timeout
        # closes idle connections so persistent clients don't leak threads.
        protocol_version = "HTTP/1.1"
        timeout = 65

        # ------------------------------------------------------------ routing

        def do_GET(self) -> None:
            self._dispatch("GET")

        def do_POST(self) -> None:
            self._dispatch("POST")

        def do_PUT(self) -> None:
            self._dispatch("PUT")

        def do_DELETE(self) -> None:
            self._dispatch("DELETE")

        def _dispatch(self, method: str) -> None:
            path = urlsplit(self.path).path.rstrip("/") or "/"
            path_served = False
            for route_method, pattern, handler_name in _ROUTES:
                match = pattern.fullmatch(path)
                if match is None:
                    continue
                if route_method != method:
                    path_served = True
                    continue
                getattr(self, handler_name)(match)
                return
            # A body this listener never read must not become the next request
            # on a persistent connection, so a refusal closes it.
            self.close_connection = True
            if path_served:
                self._send_json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "method not allowed"})
            else:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        # ------------------------------------------------------------- routes

        def _healthz(self, match: re.Match[str]) -> None:
            payload: dict[str, Any] = {"ok": True}
            if self.server.keystore is not None:
                payload["keystoreDegraded"] = self.server.keystore.degraded
            if self.server.oidc_grants is not None:
                # An allow-list whose last edit did not parse is fail-OPEN.
                payload["oidcGrantsStale"] = self.server.oidc_grants.stale
            self._send_json(HTTPStatus.OK, payload)

        def _mcp(self, match: re.Match[str]) -> None:
            if not self.server.serves_mcp:
                self.close_connection = True
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            origin = self.headers.get("Origin")
            if not is_origin_allowed(origin, self.server.allowed_origins):
                self.close_connection = True
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden origin"})
                return
            try:
                principal = self.server.authenticator.authenticate_header(self.headers.get("Authorization"))
                principal = self.server.identity_verifier.resolve(self.headers.get, principal)
            except AuthError:
                self.close_connection = True
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return
            try:
                body = self._read_json()
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            if not isinstance(body, dict):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "request body must be a JSON object"})
                return
            response = self.server.app.handle_rpc(body, principal)
            if response is None:
                self.send_response(HTTPStatus.ACCEPTED)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self._send_json(HTTPStatus.OK, response)

        def _asset_upload(self, match: re.Match[str]) -> None:
            # Close even on refusal: an unread upload must never become the next
            # request on a persistent connection. Tokens are never logged.
            self.close_connection = True
            stage = self.server.asset_stage
            if not self.server.serves_mcp or stage is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            try:
                principal = self.server.authenticator.authenticate_header(self.headers.get("Authorization"))
                principal = self.server.identity_verifier.resolve(self.headers.get, principal)
            except AuthError:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return
            if not is_origin_allowed(self.headers.get("Origin"), self.server.allowed_origins):
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "origin denied"})
                return
            lengths = self.headers.get_all("Content-Length", [])
            if (self.headers.get_all("Transfer-Encoding", []) or len(lengths) != 1
                    or not lengths[0].isascii() or not lengths[0].isdigit()):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "one Content-Length is required"})
                return
            length = int(lengths[0])
            if length > MAX_ASSET_BYTES:
                self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "upload exceeds size limit"})
                return
            try:
                data = self.rfile.read(length)
                if len(data) != length:
                    raise AssetStageError("incomplete upload body")
                result = stage.accept_upload(match["token"], data, principal.actor, principal.project, principal.token_id)
            except (TimeoutError, OSError):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "incomplete upload body"})
                return
            except AssetStageError as exc:
                self._send_json(exc.status, {"error": str(exc)})
                return
            self._send_json(HTTPStatus.CREATED, result)

        def _ci_artifact(self, match: re.Match[str]) -> None:
            stream_artifact(self)

        def _credentials_status(self, match: re.Match[str]) -> None:
            principal = self._internal_principal("GET")
            if principal is not None:
                assert self.server.internal_api is not None
                self._send_json(*self.server.internal_api.status(principal))

        def _credentials_set(self, match: re.Match[str]) -> None:
            principal = self._internal_principal("POST")
            if principal is None:
                return
            assert self.server.internal_api is not None
            try:
                body = self._read_json()
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            if not isinstance(body, dict):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "request body must be a JSON object"})
                return
            self._send_json(*self.server.internal_api.set_key(principal, body.get("key")))

        def _credentials_clear(self, match: re.Match[str]) -> None:
            principal = self._internal_principal("DELETE")
            if principal is not None:
                assert self.server.internal_api is not None
                self._send_json(*self.server.internal_api.clear_key(principal))

        def _my_issues(self, match: re.Match[str]) -> None:
            principal = self._internal_principal("GET")
            if principal is not None:
                assert self.server.internal_api is not None
                self._send_json(*self.server.internal_api.my_issues(principal))

        def _internal_principal(self, method: str) -> Principal | None:
            """The caller of a credential-enrollment route, or None once a refusal
            has been sent. Bearer-authenticated and strictly scoped to the token's
            own actor: the identity-propagation override is deliberately NOT
            applied here, so a forged X-Forwarded-User cannot retarget the actor."""
            if self.server.internal_api is None or not self.server.serves_internal:
                # Not routed on this listener reads as absent, not as forbidden.
                self.close_connection = True
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return None
            if method != "GET" and not is_origin_allowed(self.headers.get("Origin"), self.server.allowed_origins):
                # State-changing and reachable by a browser that holds the bearer;
                # /mcp has had this check since 0.1.0 and these had not.
                self.close_connection = True
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden origin"})
                return None
            try:
                return self.server.authenticator.authenticate_header(self.headers.get("Authorization"))
            except AuthError:
                self.close_connection = True
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return None

        # ------------------------------------------------------------ helpers

        def _read_json(self) -> Any:
            length_raw = self.headers.get("Content-Length", "0")
            try:
                length = int(length_raw)
            except ValueError as exc:
                raise ValueError("invalid content length") from exc
            if length <= 0 or length > 2_000_000:
                raise ValueError("invalid request size")
            raw = self.rfile.read(length)
            try:
                return json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError as exc:
                raise ValueError("invalid JSON body") from exc

        def _send_json(self, status: HTTPStatus | int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            return   # the audit stream is the access log

    return Handler


# ------------------------------------------------------------------ wiring


def _build_authenticator(settings: Settings) -> tuple[Any, GrantsFile | None]:
    """The token file (plus the runtime store), wrapped so OIDC answers what
    the file does not.

    Fail-loud at boot: an unreachable IdP here means discovery failed, and a
    gateway that started anyway would answer 401 to every OIDC caller with
    nothing in the log saying why. The JWKS fetch itself is deliberately NOT
    forced at boot -- once running, an IdP outage keeps the last-good keys
    rather than locking everyone out (oidc.JwksCache).
    """
    token_sources: list[tuple[str | Path, bool]] = []
    if settings.token_file:
        token_sources.append((settings.token_file, True))
    if settings.user_token_file:
        # optional, runtime-managed per-user token store (may be absent/empty); hot-reloaded
        token_sources.append((settings.user_token_file, False))
    # A deployment whose identities all come from an IdP legitimately has no
    # opaque tokens; an empty authenticator refuses every bearer, which is what
    # the OIDC path is then there to answer. The empty-store guard exists to
    # catch a misconfigured token file, so it stays on for everyone else -- but
    # with OIDC it would refuse to boot over a runtime store that is simply
    # still empty, which is the normal state before the first token is minted.
    tokens = (BearerTokenAuthenticator.from_files(token_sources, allow_empty=settings.oidc_enabled)
              if token_sources else BearerTokenAuthenticator({}))
    issuer, audience, grants_file = settings.oidc_issuer, settings.oidc_audience, settings.oidc_grants_file
    if not (issuer and audience and grants_file):
        return tokens, None   # Settings.from_env refuses a half-configured OIDC, so this is "off"
    jwks_url = settings.oidc_jwks_url or discover_jwks_url(issuer)
    grants = GrantsFile(grants_file)
    oidc = OidcAuthenticator(
        issuer=issuer,
        audience=audience,
        jwks=JwksCache(jwks_url, ttl_sec=settings.oidc_jwks_ttl_sec),
        grants=grants,
        clock_skew_sec=settings.oidc_clock_skew_sec,
        groups_claim=settings.oidc_groups_claim,
        required_scope=settings.oidc_required_scope,
    )
    log.info("OIDC enabled: issuer=%s audience=%s jwks=%s", issuer, audience, jwks_url)
    return CompositeAuthenticator(tokens, oidc), grants


def _build_credential_store(settings: Settings) -> CredentialStore | None:
    if not settings.redmine_keystore_file:
        if settings.redmine_enforce_personal_key:
            # Fail fast at boot rather than silently attributing every write to the shared
            # service account while an operator believes enforcement is on.
            raise ValueError(
                "REDMINE_ENFORCE_PERSONAL_KEY is set but REDMINE_KEYSTORE_FILE is not — "
                "enforced per-user mode needs a key store"
            )
        return None
    active, master_keys = (
        load_master_keys(settings.redmine_keystore_master_file)
        if settings.redmine_keystore_master_file
        else (None, {})
    )
    keystore = CredentialStore(settings.redmine_keystore_file, active_key_id=active, master_keys=master_keys)
    if keystore.degraded:
        log.warning(
            "credential store is DEGRADED (master key unavailable) — per-user attribution is disabled; "
            "issue writes use the shared key (optional mode) or fail (enforced mode). "
            "Fix REDMINE_KEYSTORE_MASTER_FILE."
        )
    return keystore


def _build_issue_backend(settings: Settings, keystore: CredentialStore | None) -> IssueBackend | None:
    if settings.issue_backend == "gitlab":
        # GitLab deployment (ADR-0013): shared token + attribution footer, with
        # the same per-user credential store as Redmine (keyed by backend) and
        # its own enforced-mode switch.
        if settings.redmine_enforce_personal_key:
            raise ValueError("REDMINE_ENFORCE_PERSONAL_KEY has no effect with ISSUE_BACKEND=gitlab; unset it")
        if settings.gitlab_enforce_personal_key and keystore is None:
            raise ValueError("enforced personal-token mode requires a key store (REDMINE_KEYSTORE_FILE)")
        if not settings.gitlab_base_url:
            return None
        return GitLabHttpBackend(
            base_url=settings.gitlab_base_url,
            token=settings.gitlab_token,
            timeout_sec=settings.gitlab_timeout_sec,
            key_resolver=((lambda actor: keystore.get(actor, backend="gitlab")) if keystore is not None else None),
            enforce_personal=settings.gitlab_enforce_personal_key,
            credential_portal_url=settings.credential_portal_url,
        )
    if settings.issue_backend == "redmine":
        if not settings.redmine_base_url:
            return None
        return RedmineHttpBackend(
            base_url=settings.redmine_base_url,
            api_key=settings.redmine_api_key,
            timeout_sec=settings.redmine_timeout_sec,
            key_resolver=(keystore.get if keystore is not None else None),
            enforce_personal=settings.redmine_enforce_personal_key,
            credential_portal_url=settings.credential_portal_url,
        )
    raise ValueError(f"unknown ISSUE_BACKEND {settings.issue_backend!r}; allowed: redmine, gitlab")


def _build_memory_backend(settings: Settings, actor_labels: ActorLabels) -> HttpMemoryBackend:
    return HttpMemoryBackend(
        base_url=settings.memory_base_url,
        backend_token=settings.memory_backend_token,
        search_path=settings.memory_search_path,
        save_path=settings.memory_save_path,
        timeout_sec=settings.memory_timeout_sec,
        list_path=settings.memory_list_path,
        lesson_path=settings.memory_lesson_path,
        action_path=settings.memory_action_path,
        actor_labels=actor_labels,
    )


def _build_memory_limits(settings: Settings) -> MemoryLimitConfig:
    return MemoryLimitConfig(
        max_save_text_bytes=settings.memory_save_max_text_bytes,
        user_writes_per_minute=settings.memory_user_writes_per_minute,
        project_writes_per_day=settings.memory_project_writes_per_day,
        user_reads_per_minute=settings.memory_user_reads_per_minute,
    )


def _build_docs(
    settings: Settings, actor_labels: ActorLabels, keystore: CredentialStore | None,
) -> tuple[DocsCorpus | None, DocsReviewService | None, AssetStage | None]:
    """The corpus (reads), the review service (proposals) and the asset stage
    (long bodies), each inert without the one before it."""
    if not (settings.docs_repos_file and settings.docs_clone_dir):
        return None, None, None
    corpus = DocsCorpus(
        load_docs_repos(settings.docs_repos_file),
        settings.docs_clone_dir,
        pull_interval_sec=settings.docs_pull_interval_sec,
        repos_file=settings.docs_repos_file,
        actor_labels=actor_labels,
    )
    # The docs write path exists only when a project's corpus names a review host
    # AND a credential store is configured: proposals are made under the caller's
    # own credential, so without a store there is nobody for the gateway to be.
    if keystore is None:
        return corpus, None, None
    review = DocsReviewService(
        corpus=corpus,
        backends={"github": GitHubReviewBackend(timeout_sec=settings.docs_review_timeout_sec)},
        key_resolver=lambda actor, backend: keystore.get(actor, backend=backend),
        credential_portal_url=settings.credential_portal_url,
    )
    stage = AssetStage(settings.docs_asset_base_url) if settings.docs_asset_base_url else None
    return corpus, review, stage


def _build_ci_backend(settings: Settings) -> JenkinsHttpBackend | None:
    if not (settings.jenkins_base_url and settings.ci_jobs_file):
        return None
    return JenkinsHttpBackend(
        base_url=settings.jenkins_base_url,
        user=settings.jenkins_user,
        token=settings.jenkins_token,
        jobs_by_project=load_ci_jobs(settings.ci_jobs_file),
        timeout_sec=settings.jenkins_timeout_sec,
        artifact_base_url=settings.ci_artifact_base_url,
        trigger_jobs_by_project=(load_ci_trigger_jobs(settings.ci_trigger_jobs_file)
                                 if settings.ci_trigger_jobs_file else None),
    )


def build_server(settings: Settings) -> GatewayHTTPServer:
    request.install_opener(request.build_opener(SameOriginRedirects))
    authenticator, oidc_grants = _build_authenticator(settings)
    actor_labels = ActorLabels(settings.user_token_file)
    keystore = _build_credential_store(settings)
    issue_backend = _build_issue_backend(settings, keystore)
    docs_corpus, docs_review, asset_stage = _build_docs(settings, actor_labels, keystore)
    ci_backend = _build_ci_backend(settings)
    audit_sink = JsonLinesAuditSink()
    app = GatewayApp(
        memory_backend=_build_memory_backend(settings, actor_labels),
        audit_sink=audit_sink,
        memory_write_limiter=InMemoryMemoryWriteLimiter(_build_memory_limits(settings)),
        issue_backend=issue_backend,
        docs_corpus=docs_corpus,
        ci_backend=ci_backend,
        docs_review=docs_review,
        asset_stage=asset_stage,
    )
    server = GatewayHTTPServer((settings.host, settings.port), make_handler())
    server.app = app
    server.asset_stage = asset_stage
    server.authenticator = authenticator
    server.identity_verifier = IdentityVerifier(
        secret=settings.identity_claims_secret or "",
        prefix=settings.identity_header_prefix,
    )
    server.allowed_origins = settings.allowed_origins
    server.oidc_grants = oidc_grants
    server.keystore = keystore
    # The internal API (portal key page / my-issues) works for either backend:
    # both implement verify_key and list_assigned_to_me, and the keystore binds
    # each enrolled credential to the deployment's backend.
    server.internal_api = (
        InternalApi(keystore, issue_backend, audit_sink, backend_name=settings.issue_backend)
        if keystore is not None else None
    )
    server.ci_backend = ci_backend  # the /ci/artifact streaming download route
    server.audit_sink = audit_sink
    server.artifact_max_bytes = settings.ci_artifact_max_bytes
    server.artifact_streams = threading.Semaphore(settings.ci_artifact_max_concurrent)
    return server


def build_admin_server(settings: Settings, main_server: GatewayHTTPServer) -> GatewayHTTPServer:
    """A second listener that serves ONLY the credential-enrollment routes.

    It shares the main server's authenticator, keystore and audit sink rather than
    building its own: two authenticators would be two hot-reload clocks, and a
    revocation that took effect on one socket and not the other is the kind of
    difference nobody notices until it matters.
    """
    assert settings.admin_port is not None, "build_admin_server is called only when ADMIN_PORT is set"
    admin = GatewayHTTPServer((settings.admin_host, settings.admin_port), make_handler())
    admin.app = main_server.app
    admin.authenticator = main_server.authenticator
    admin.identity_verifier = main_server.identity_verifier
    admin.allowed_origins = settings.allowed_origins
    admin.keystore = main_server.keystore
    admin.internal_api = main_server.internal_api
    admin.audit_sink = main_server.audit_sink
    admin.serves_mcp = False
    admin.serves_internal = True
    main_server.serves_internal = False   # exactly one listener answers them
    return admin


# --------------------------------------------------------------- process


class ShutdownRequested(Exception):
    """Raised in the main thread by the SIGTERM handler, so `serve_forever`
    unwinds through the same cleanup as Ctrl-C."""


def _request_shutdown(signum: int, frame: Any) -> None:
    raise ShutdownRequested(signum)


def install_shutdown_signal() -> None:
    """SIGTERM is what a container runtime sends on stop. Left to the default
    disposition it kills the process mid-request: no `server_close`, and a
    keep-alive client sees a reset rather than a refused connection. Raising
    into the main thread lets `main` run the same `finally` as an interrupt."""
    signal.signal(signal.SIGTERM, _request_shutdown)


def configure_logging(level: int = logging.INFO) -> None:
    """Diagnostics to stderr, one line each, with a level and the module that
    spoke. stdout is the audit stream's alone: the "listening on" line used to
    go there and sat between two JSON audit records."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    package = logging.getLogger("mcp_governance_gateway")
    package.addHandler(handler)
    package.setLevel(level)


def main() -> None:
    configure_logging()
    settings = Settings.from_env()
    if not _is_loopback_host(settings.host):
        log.warning(
            "serving plaintext HTTP on %s:%s. Bind to loopback or a private network behind a "
            "TLS-terminating ingress; bearer tokens are sent in cleartext over this hop.",
            settings.host, settings.port,
        )
    server = build_server(settings)
    admin = None
    if settings.admin_port:
        admin = build_admin_server(settings, server)
        if not _is_loopback_host(settings.admin_host):
            log.warning("the admin listener is bound to %s, which is not loopback. "
                        "Credential enrollment must not be routed publicly.", settings.admin_host)
        threading.Thread(target=admin.serve_forever, name="admin-listener", daemon=True).start()
        log.info("admin (credential enrollment) listening on %s:%s", settings.admin_host, settings.admin_port)
    log.info("mcp-governance-gateway listening on %s:%s", settings.host, settings.port)
    install_shutdown_signal()
    try:
        server.serve_forever()
    except (KeyboardInterrupt, ShutdownRequested):
        pass
    finally:
        server.server_close()
        if admin is not None:
            admin.shutdown()
            admin.server_close()


if __name__ == "__main__":
    main()
