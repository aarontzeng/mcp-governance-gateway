from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import re
import sys
import threading
import uuid
from typing import Any
from urllib.parse import parse_qs, urlparse

from .audit import AuditEvent, AuditSink, JsonLinesAuditSink
from .auth import AuthError, BearerTokenAuthenticator, IdentityVerifier
from .config import Settings
from .ci_backend import CiBackendError, JenkinsHttpBackend, STREAM_CHUNK, load_ci_jobs
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


class GatewayHTTPServer(ThreadingHTTPServer):
    app: GatewayApp
    authenticator: BearerTokenAuthenticator
    identity_verifier: IdentityVerifier
    allowed_origins: tuple[str, ...]
    internal_api: InternalApi | None = None
    keystore: RedmineKeyStore | None = None
    ci_backend: JenkinsHttpBackend | None = None  # for the /ci/artifact download route
    audit_sink: AuditSink | None = None            # artifact transfers are audited here
    artifact_max_bytes: int = 256 * 1024 * 1024
    artifact_streams: "threading.Semaphore" = threading.Semaphore(4)


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
        # initialize). Every response sets Content-Length, so keep-alive is safe;
        # timeout closes idle connections so persistent clients don't leak threads.
        protocol_version = "HTTP/1.1"
        timeout = 65

        def do_GET(self) -> None:
            if self.path == "/healthz":
                payload: dict[str, Any] = {"ok": True}
                if self.server.keystore is not None:
                    payload["keystoreDegraded"] = self.server.keystore.degraded
                self._send_json(HTTPStatus.OK, payload)
                return
            path = self.path.split("?")[0].rstrip("/")
            if path in ("/internal/redmine-key", "/internal/my-issues"):
                self._internal(path, "GET")
                return
            if path == "/ci/artifact":
                self._ci_artifact_download()
                return
            self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)

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
            context = RequestContext(
                actor=principal.actor, project=principal.project,
                client="ci-artifact", request_id=request_id,
            )

            def audit(outcome: str, reason: str = "", sent: int | None = None) -> None:
                # Every MCP tool call is audited; without this the byte transfer was
                # the one operation the gateway performed and did not record.
                sink = self.server.audit_sink
                if sink is None:
                    return
                sink.write(AuditEvent(
                    request_id=request_id, actor=principal.actor, project=principal.project,
                    tool="ci.artifact.download", decision="allow", outcome=outcome,
                    reason=reason, resource_id=f"{job}:{rel_path}",
                    duration_ms=None if sent is None else sent,
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
                    # open_artifact enforces the allowlist AND that this path is a real
                    # artifact of the build, which is what makes traversal impossible.
                    upstream = ci.open_artifact(job, build, rel_path, context)
                except CiBackendError as exc:
                    audit("backend_error", str(exc))
                    self._send_json(int(exc.status or 502), {"error": str(exc)})
                    return
                cap = self.server.artifact_max_bytes
                try:
                    declared = int(upstream.headers.get("Content-Length") or 0)
                except ValueError:
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
                    self.send_header(
                        "Content-Type", upstream.headers.get("Content-Type") or "application/octet-stream"
                    )
                    if declared:
                        self.send_header("Content-Length", str(declared))
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
                        sent += len(chunk)
                        if sent > cap:
                            # An absent or dishonest Content-Length cannot buy an
                            # unbounded transfer. The headers are already out, so the
                            # only honest move is to stop: the client sees a short
                            # read, and the audit says why.
                            audit("truncated", f"exceeded cap {cap} mid-stream", sent)
                            self.close_connection = True
                            return
                        self.wfile.write(chunk)
                    audit("ok", "", sent)
                except OSError:
                    # Client hung up or upstream dropped mid-stream: the headers are
                    # already out, so there is nothing to report to the caller.
                    audit("interrupted", "client or upstream dropped mid-stream", sent)
                finally:
                    upstream.close()
            finally:
                self.server.artifact_streams.release()

        def do_DELETE(self) -> None:
            if self.path.split("?")[0].rstrip("/") == "/internal/redmine-key":
                self._internal("/internal/redmine-key", "DELETE")
                return
            self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)

        def _internal(self, path: str, method: str) -> None:
            # Portal-facing internal API. Bearer-authenticated and strictly scoped to
            # the token's own actor — the identity-propagation override is deliberately
            # NOT applied here, so a forged X-Forwarded-User cannot retarget the actor.
            api = self.server.internal_api
            if api is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            try:
                principal = self.server.authenticator.authenticate_header(self.headers.get("Authorization"))
            except AuthError:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return
            if method == "GET" and path == "/internal/redmine-key":
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
            if self.path.split("?")[0].rstrip("/") == "/internal/redmine-key":
                self._internal("/internal/redmine-key", "POST")
                return
            if self.path != "/mcp":
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


def build_server(settings: Settings) -> GatewayHTTPServer:
    token_sources: list[tuple[str, bool]] = [(settings.token_file, True)]
    if settings.user_token_file:
        # optional, runtime-managed per-user token store (may be absent/empty); hot-reloaded
        token_sources.append((settings.user_token_file, False))
    authenticator = BearerTokenAuthenticator.from_files(token_sources)
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
        # GitLab deployment (ADR-0013): shared token + attribution footer; the
        # per-user keystore/enforced mode is Redmine-specific until the
        # credential store is generalized (roadmap Phase 9).
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
        )
    audit_sink = JsonLinesAuditSink()
    app = GatewayApp(
        memory_backend=memory_backend,
        audit_sink=audit_sink,
        memory_write_limiter=InMemoryMemoryWriteLimiter(memory_limits),
        issue_backend=issue_backend,
        docs_corpus=docs_corpus,
        ci_backend=ci_backend,
    )
    server = GatewayHTTPServer((settings.host, settings.port), make_handler())
    server.app = app
    server.authenticator = authenticator
    server.identity_verifier = IdentityVerifier(
        secret=settings.identity_claims_secret or "",
        prefix=settings.identity_header_prefix,
    )
    server.allowed_origins = settings.allowed_origins
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
    print(f"mcp-governance-gateway listening on {settings.host}:{settings.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
