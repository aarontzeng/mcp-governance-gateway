from __future__ import annotations

from http import HTTPStatus
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import re
import sys
import threading
import time
import uuid
from typing import Any
from urllib import error, request
from urllib.parse import parse_qs, urlparse, urlsplit

from .audit import AuditEvent, AuditSink, JsonLinesAuditSink
from .auth import AuthError, BearerTokenAuthenticator, IdentityVerifier
from .config import Settings
from .docs_review import DocsReviewService
from .docs_assets import AssetStage, AssetStageError, MAX_ASSET_BYTES
from .review_backend import GitHubReviewBackend
from .oidc import CompositeAuthenticator, GrantsFile, JwksCache, OidcAuthenticator, discover_jwks_url
from .ci_backend import (
    CiBackendError,
    JenkinsHttpBackend,
    STREAM_CHUNK,
    load_ci_jobs,
    load_ci_trigger_jobs,
)
from .docs_backend import DocsCorpus, load_docs_repos
from .internal_api import InternalApi
from .gitlab_backend import GitLabHttpBackend
from .issue_backend import RedmineHttpBackend
from .limits import InMemoryMemoryWriteLimiter, MemoryLimitConfig
from .mcp import GatewayApp
from .memory_backend import ActorLabels, HttpMemoryBackend, RequestContext
from .redmine_keystore import RedmineKeyStore, load_master_keys


_FILENAME_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_filename(name: str) -> str:
    """A basename safe to place inside a quoted header value. Anything outside the
    whitelist collapses to `_`; an empty result becomes a placeholder, so the header
    is always well-formed."""
    return _FILENAME_SAFE.sub("_", name).strip("._") or "artifact"


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
    keystore: RedmineKeyStore | None = None
    ci_backend: JenkinsHttpBackend | None = None  # for the /ci/artifact download route
    asset_stage: AssetStage | None = None
    audit_sink: AuditSink | None = None            # artifact transfers are audited here
    artifact_max_bytes: int = 256 * 1024 * 1024
    artifact_streams: "threading.Semaphore" = threading.Semaphore(4)
    # Which surfaces this listener answers. One process may run two: the MCP
    # listener agents reach, and an admin listener for credential enrollment.
    # A route this listener does not serve is 404, not 403 -- an admin surface
    # that is not routed here should look absent rather than forbidden.
    serves_mcp: bool = True
    serves_internal: bool = True
    oidc_grants: "GrantsFile | None" = None   # for the /healthz staleness flag


# `/internal/redmine-key` was named when Redmine was the only backend; the store
# now holds GitLab credentials too. The old spelling stays an alias forever --
# it is what every deployed enrollment page calls.
_CREDENTIAL_PATHS = ("/internal/credentials", "/internal/redmine-key")
_MY_ISSUES_PATH = "/internal/my-issues"


def is_origin_allowed(origin: str | None, allowed_origins: tuple[str, ...]) -> bool:
    return origin is None or origin in allowed_origins


def _is_loopback_host(host: str) -> bool:
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

        def do_GET(self) -> None:
            if self.path == "/healthz":
                payload: dict[str, Any] = {"ok": True}
                if self.server.keystore is not None:
                    payload["keystoreDegraded"] = self.server.keystore.degraded
                if self.server.oidc_grants is not None:
                    # An allow-list whose last edit did not parse is fail-OPEN.
                    payload["oidcGrantsStale"] = self.server.oidc_grants.stale
                self._send_json(HTTPStatus.OK, payload)
                return
            path = self.path.split("?")[0].rstrip("/")
            if path in _CREDENTIAL_PATHS or path == _MY_ISSUES_PATH:
                self._internal(path, "GET")
                return
            if path == "/ci/artifact":
                self._ci_artifact_download()
                return
            self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)

        def do_PUT(self) -> None:
            # Close even on refusal: an unread upload must never become the next
            # request on a persistent connection. Tokens are never logged.
            self.close_connection = True
            stage = self.server.asset_stage
            match = re.fullmatch(r"/docs/asset-stage/([A-Za-z0-9_-]+)", self.path)
            if not self.server.serves_mcp or stage is None or match is None:
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
                result = stage.accept_upload(match[1], data, principal.actor, principal.project, principal.token_id)
            except (TimeoutError, OSError):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "incomplete upload body"})
                return
            except AssetStageError as exc:
                self._send_json(exc.status, {"error": str(exc)})
                return
            self._send_json(HTTPStatus.CREATED, result)

        def _ci_artifact_download(self) -> None:
            # The artifact fetch ci.artifact points at. Authenticated by the caller's
            # own bearer token -- the identity-propagation override is deliberately NOT
            # applied here, as on the internal endpoints -- tenant-scoped by the same
            # CI job allowlist as every other ci.* call, and streamed from the CI server
            # with the gateway's read-only credential, which never leaves the process.
            # The bytes travel over this dedicated endpoint rather than the MCP JSON
            # channel, so they land on disk instead of in the agent's context.
            ci = self.server.ci_backend
            if ci is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            try:
                principal = self.server.authenticator.authenticate_header(self.headers.get("Authorization"))
            except AuthError:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return
            query = parse_qs(urlparse(self.path).query)
            job = (query.get("job") or [""])[0]
            build = (query.get("build") or [""])[0] or None
            rel_path = (query.get("path") or [""])[0]
            if not job or not rel_path:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "job and path are required"})
                return
            request_id = str(uuid.uuid4())
            started = time.monotonic()
            context = RequestContext(
                actor=principal.actor, project=principal.project,
                client="ci-artifact", request_id=request_id,
            )

            # Recorded only once locate_artifact has checked them against the
            # allowlist and the build's own listing: until then job and path are
            # whatever the caller typed, and the audit log is append-only.
            resource_id: str | None = None

            def audit(outcome: str, reason: str = "", sent: int | None = None) -> None:
                # Every MCP tool call is audited; without this the byte transfer was
                # the one operation the gateway performed and did not record.
                sink = self.server.audit_sink
                if sink is None:
                    return
                sink.write(AuditEvent(
                    request_id=request_id, actor=principal.actor, project=principal.project,
                    tool="ci.artifact.download", decision="allow", outcome=outcome,
                    reason=reason, resource_id=resource_id,
                    duration_ms=int((time.monotonic() - started) * 1000), bytes_sent=sent,
                ))

            # A stream holds a thread and an upstream connection for its whole
            # duration, so concurrency is capped rather than left to the thread pool.
            if not self.server.artifact_streams.acquire(blocking=False):
                audit("rejected", "artifact stream limit reached")
                self._send_json(HTTPStatus.SERVICE_UNAVAILABLE,
                                {"error": "too many artifact downloads in flight, retry shortly"})
                return
            try:
                try:
                    # locate_artifact enforces the allowlist AND that this path is a real
                    # artifact of the build, which is what makes traversal impossible.
                    location = ci.locate_artifact(job, build, rel_path, context)
                    resource_id = f"{job}:{rel_path}"   # validated: safe to record from here on
                    upstream = ci.open_located(location)
                except CiBackendError as exc:
                    audit("backend_error", str(exc))
                    self._send_json(int(exc.status or 502), {"error": str(exc)})
                    return
                cap = self.server.artifact_max_bytes
                codings = [field.strip().lower() for field in upstream.headers.get_all("Content-Encoding", [])]
                if any(c not in ("", "identity") for c in codings):
                    # The request asked for identity; a body coded anyway is not
                    # the artifact, and the client would save it under its name.
                    # Every field is read: http.client's get() returns only the
                    # first of a repeated header.
                    audit("backend_error", "upstream content coding is not one this gateway decodes")
                    upstream.close()
                    self._send_json(HTTPStatus.BAD_GATEWAY,
                                    {"error": "CI sent the artifact under a content coding this gateway cannot decode"})
                    return
                transfer = [field.strip().lower() for field in upstream.headers.get_all("Transfer-Encoding", [])]
                if upstream.chunked and transfer == ["chunked"]:
                    # The upstream's own framing wins (RFC 9112 section 6.3):
                    # http.client de-chunked the body and ignores the
                    # Content-Length, but the header is still there to read, and
                    # forwarding it would promise a length the body need not have.
                    declared = 0
                elif any(transfer):
                    # http.client decodes a bare "chunked" and nothing else, and
                    # its verdict reads only the first field of a repeated header,
                    # so under any other value -- in any field -- the route does
                    # not vouch for the bytes it hands over (a second "chunked"
                    # field is at best a coding applied twice; "identity" is a
                    # token IANA lists as withdrawn) and refuses rather than
                    # serve them.
                    audit("backend_error", "upstream transfer coding is not one this gateway decodes")
                    upstream.close()
                    self._send_json(HTTPStatus.BAD_GATEWAY,
                                    {"error": "CI sent the artifact under a transfer coding this gateway cannot decode"})
                    return
                else:
                    try:
                        declared = int(upstream.headers.get("Content-Length") or 0)
                    except ValueError:
                        declared = 0
                if declared < 0:
                    # A negative length is no length (http.client reads it the same
                    # way). Forwarded, it would make the body close-delimited again.
                    declared = 0
                if declared > cap:
                    audit("rejected", f"declared {declared} bytes exceeds cap {cap}")
                    upstream.close()
                    self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                                    {"error": f"artifact is {declared} bytes; this gateway caps downloads at {cap}"})
                    return
                sent = 0
                try:
                    self.send_response(HTTPStatus.OK)
                    # Always a download, never a document: the upstream type is
                    # whatever the build wrote, and a text/html artifact rendered
                    # in a browser on this origin would run with this origin.
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("X-Content-Type-Options", "nosniff")
                    chunked = not declared
                    if declared:
                        self.send_header("Content-Length", str(declared))
                    else:
                        # No upstream length: chunked framing is self-delimiting, so
                        # a body this gateway or the upstream cuts short is missing
                        # its terminator and every HTTP/1.1 client reports it as
                        # incomplete. Close-delimited framing would not: there the
                        # client reads to EOF and keeps a truncated file as whole.
                        self.send_header("Transfer-Encoding", "chunked")
                    # send_header does no CRLF validation of its own -- it formats
                    # "<k>: <v>\r\n" and appends -- so a filename carrying a line break
                    # would emit attacker-chosen response headers. Whitelist instead of
                    # blacklisting: only characters that are safe in a quoted filename.
                    filename = _safe_filename(rel_path.rsplit("/", 1)[-1])
                    self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                    self.end_headers()
                    while True:
                        chunk = upstream.read(STREAM_CHUNK)
                        if not chunk:
                            break
                        if sent + len(chunk) > cap:
                            # An absent or dishonest Content-Length cannot buy an
                            # unbounded transfer. The headers are already out, so the
                            # only honest move is to stop without the terminator (or
                            # short of the declared length): the client sees an
                            # incomplete body, and the audit says why.
                            audit("truncated", f"exceeded cap {cap} mid-stream", sent)
                            self.close_connection = True
                            return
                        if chunked:
                            self.wfile.write(f"{len(chunk):X}\r\n".encode("ascii") + chunk + b"\r\n")
                        else:
                            self.wfile.write(chunk)
                        sent += len(chunk)   # counted once delivered, not once read
                    if chunked:
                        self.wfile.write(b"0\r\n\r\n")
                    if declared and sent != declared:
                        # The upstream promised one length and delivered another. The
                        # client's framing is now wrong either way, so close rather
                        # than leave a keep-alive connection desynchronized.
                        audit("interrupted", f"upstream sent {sent} of {declared} declared bytes", sent)
                        self.close_connection = True
                        return
                    audit("ok", "", sent)
                except (OSError, http.client.HTTPException):
                    # Client hung up, upstream dropped, or the upstream's own framing
                    # broke mid-stream (IncompleteRead is an HTTPException, not an
                    # OSError): the headers are already out, so there is nothing to
                    # report to the caller, and the connection is desynchronized
                    # either way.
                    audit("interrupted", "client or upstream dropped mid-stream", sent)
                    self.close_connection = True
                finally:
                    upstream.close()
            finally:
                self.server.artifact_streams.release()

        def do_DELETE(self) -> None:
            path = self.path.split("?")[0].rstrip("/")
            if path in _CREDENTIAL_PATHS:
                self._internal(path, "DELETE")
                return
            self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)

        def _internal(self, path: str, method: str) -> None:
            # Credential-enrollment API. Bearer-authenticated and strictly scoped to
            # the token's own actor — the identity-propagation override is deliberately
            # NOT applied here, so a forged X-Forwarded-User cannot retarget the actor.
            api = self.server.internal_api
            if api is None or not self.server.serves_internal:
                # Not routed on this listener reads as absent, not as forbidden.
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            if method != "GET" and not is_origin_allowed(self.headers.get("Origin"), self.server.allowed_origins):
                # These two are state-changing and reachable by a browser that holds
                # the bearer; /mcp has had this check since 0.1.0 and they had not.
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden origin"})
                return
            try:
                principal = self.server.authenticator.authenticate_header(self.headers.get("Authorization"))
            except AuthError:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return
            if method == "GET" and path in _CREDENTIAL_PATHS:
                status, payload = api.status(principal)
            elif method == "GET":
                status, payload = api.my_issues(principal)
            elif method == "DELETE":
                status, payload = api.clear_key(principal)
            else:  # POST
                try:
                    body = self._read_json()
                except ValueError as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                if not isinstance(body, dict):
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "request body must be a JSON object"})
                    return
                status, payload = api.set_key(principal, body.get("key"))
            self._send_json(status, payload)

        def do_POST(self) -> None:
            if self.path.split("?")[0].rstrip("/") in _CREDENTIAL_PATHS:
                self._internal(self.path.split("?")[0].rstrip("/"), "POST")
                return
            if self.path != "/mcp" or not self.server.serves_mcp:
                self.send_error(HTTPStatus.NOT_FOUND)
                return

            origin = self.headers.get("Origin")
            if not is_origin_allowed(origin, self.server.allowed_origins):
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden origin"})
                return

            try:
                principal = self.server.authenticator.authenticate_header(self.headers.get("Authorization"))
                principal = self.server.identity_verifier.resolve(self.headers.get, principal)
            except AuthError:
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
            return

    return Handler


def _with_oidc(tokens: BearerTokenAuthenticator, settings: Settings) -> tuple[Any, "GrantsFile | None"]:
    """Wrap the token authenticator so OIDC answers what the token file does not.

    Fail-loud at boot: an unreachable IdP here means discovery failed, and a
    gateway that started anyway would answer 401 to every OIDC caller with
    nothing in the log saying why. The JWKS fetch itself is deliberately NOT
    forced at boot -- once running, an IdP outage keeps the last-good keys
    rather than locking everyone out (oidc.JwksCache).
    """
    if not settings.oidc_enabled:
        return tokens, None
    jwks_url = settings.oidc_jwks_url or discover_jwks_url(settings.oidc_issuer)
    grants = GrantsFile(settings.oidc_grants_file)
    oidc = OidcAuthenticator(
        issuer=settings.oidc_issuer,
        audience=settings.oidc_audience,
        jwks=JwksCache(jwks_url, ttl_sec=settings.oidc_jwks_ttl_sec),
        grants=grants,
        clock_skew_sec=settings.oidc_clock_skew_sec,
        groups_claim=settings.oidc_groups_claim,
        required_scope=settings.oidc_required_scope,
    )
    print(f"OIDC enabled: issuer={settings.oidc_issuer} audience={settings.oidc_audience} "
          f"jwks={jwks_url}", file=sys.stderr, flush=True)
    return CompositeAuthenticator(tokens, oidc), grants


def build_server(settings: Settings) -> GatewayHTTPServer:
    request.install_opener(request.build_opener(SameOriginRedirects))
    token_sources: list[tuple[str, bool]] = []
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
    authenticator = BearerTokenAuthenticator.from_files(token_sources, allow_empty=settings.oidc_enabled) \
        if token_sources else BearerTokenAuthenticator({})
    authenticator, oidc_grants = _with_oidc(authenticator, settings)
    actor_labels = ActorLabels(settings.user_token_file)
    memory_backend = HttpMemoryBackend(
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
    memory_limits = MemoryLimitConfig(
        max_save_text_bytes=settings.memory_save_max_text_bytes,
        user_writes_per_minute=settings.memory_user_writes_per_minute,
        project_writes_per_day=settings.memory_project_writes_per_day,
        user_reads_per_minute=settings.memory_user_reads_per_minute,
    )
    keystore = None
    if settings.redmine_keystore_file:
        active, master_keys = (
            load_master_keys(settings.redmine_keystore_master_file)
            if settings.redmine_keystore_master_file
            else (None, {})
        )
        keystore = RedmineKeyStore(settings.redmine_keystore_file, active_key_id=active, master_keys=master_keys)
        if keystore.degraded:
            print(
                "WARNING: redmine keystore is DEGRADED (master key unavailable) — per-user "
                "attribution is disabled; issue writes use the shared key (optional mode) or "
                "fail (enforced mode). Fix REDMINE_KEYSTORE_MASTER_FILE.",
                file=sys.stderr,
                flush=True,
            )
    if settings.redmine_enforce_personal_key and keystore is None:
        # Fail fast at boot rather than silently attributing every write to the shared
        # service account while an operator believes enforcement is on.
        raise ValueError(
            "REDMINE_ENFORCE_PERSONAL_KEY is set but REDMINE_KEYSTORE_FILE is not — "
            "enforced per-user mode needs a key store"
        )
    issue_backend = None
    if settings.issue_backend == "gitlab":
        # GitLab deployment (ADR-0013): shared token + attribution footer, with
        # the same per-user credential store as Redmine (keyed by backend) and
        # its own enforced-mode switch.
        if settings.redmine_enforce_personal_key:
            raise ValueError("REDMINE_ENFORCE_PERSONAL_KEY has no effect with ISSUE_BACKEND=gitlab; unset it")
        if settings.gitlab_enforce_personal_key and keystore is None:
            raise ValueError("enforced personal-token mode requires a key store (REDMINE_KEYSTORE_FILE)")
        if settings.gitlab_base_url:
            issue_backend = GitLabHttpBackend(
                base_url=settings.gitlab_base_url,
                token=settings.gitlab_token,
                timeout_sec=settings.gitlab_timeout_sec,
                key_resolver=((lambda actor: keystore.get(actor, backend="gitlab")) if keystore is not None else None),
                enforce_personal=settings.gitlab_enforce_personal_key,
                credential_portal_url=settings.credential_portal_url,
            )
    elif settings.issue_backend == "redmine":
        if settings.redmine_base_url:
            issue_backend = RedmineHttpBackend(
                base_url=settings.redmine_base_url,
                api_key=settings.redmine_api_key,
                timeout_sec=settings.redmine_timeout_sec,
                key_resolver=(keystore.get if keystore is not None else None),
                enforce_personal=settings.redmine_enforce_personal_key,
                credential_portal_url=settings.credential_portal_url,
            )
    else:
        raise ValueError(f"unknown ISSUE_BACKEND {settings.issue_backend!r}; allowed: redmine, gitlab")
    docs_corpus = None
    if settings.docs_repos_file and settings.docs_clone_dir:
        docs_corpus = DocsCorpus(
            load_docs_repos(settings.docs_repos_file),
            settings.docs_clone_dir,
            pull_interval_sec=settings.docs_pull_interval_sec,
            repos_file=settings.docs_repos_file,
            actor_labels=actor_labels,
        )
    ci_backend = None
    if settings.jenkins_base_url and settings.ci_jobs_file:
        ci_backend = JenkinsHttpBackend(
            base_url=settings.jenkins_base_url,
            user=settings.jenkins_user,
            token=settings.jenkins_token,
            jobs_by_project=load_ci_jobs(settings.ci_jobs_file),
            timeout_sec=settings.jenkins_timeout_sec,
            artifact_base_url=settings.ci_artifact_base_url,
            trigger_jobs_by_project=(load_ci_trigger_jobs(settings.ci_trigger_jobs_file)
                                     if settings.ci_trigger_jobs_file else None),
        )
    # The docs write path exists only when a project's corpus names a review host
    # AND a credential store is configured: proposals are made under the caller's
    # own credential, so without a store there is nobody for the gateway to be.
    docs_review = None
    if docs_corpus is not None and keystore is not None:
        docs_review = DocsReviewService(
            corpus=docs_corpus,
            backends={"github": GitHubReviewBackend(timeout_sec=settings.docs_review_timeout_sec)},
            key_resolver=lambda actor, backend: keystore.get(actor, backend=backend),
            credential_portal_url=settings.credential_portal_url,
        )

    asset_stage = (AssetStage(settings.docs_asset_base_url)
                   if docs_review is not None and settings.docs_asset_base_url else None)
    audit_sink = JsonLinesAuditSink()
    app = GatewayApp(
        memory_backend=memory_backend,
        audit_sink=audit_sink,
        memory_write_limiter=InMemoryMemoryWriteLimiter(memory_limits),
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
    # The internal API (portal key page / my-issues) now works for either backend:
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


def main() -> None:
    settings = Settings.from_env()
    if not _is_loopback_host(settings.host):
        print(
            f"WARNING: serving plaintext HTTP on {settings.host}:{settings.port}. "
            "Bind to loopback or a private network behind a TLS-terminating ingress; "
            "bearer tokens are sent in cleartext over this hop.",
            file=sys.stderr,
            flush=True,
        )
    server = build_server(settings)
    admin = None
    if settings.admin_port:
        admin = build_admin_server(settings, server)
        if not _is_loopback_host(settings.admin_host):
            print(
                f"WARNING: the admin listener is bound to {settings.admin_host}, which is not "
                "loopback. Credential enrollment must not be routed publicly.",
                file=sys.stderr, flush=True,
            )
        threading.Thread(target=admin.serve_forever, name="admin-listener", daemon=True).start()
        print(f"admin (credential enrollment) listening on {settings.admin_host}:{settings.admin_port}",
              flush=True)
    print(f"mcp-governance-gateway listening on {settings.host}:{settings.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if admin is not None:
            admin.shutdown()
            admin.server_close()


if __name__ == "__main__":
    main()
