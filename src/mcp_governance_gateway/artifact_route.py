"""`GET /ci/artifact`: the one route that streams bytes rather than answering JSON.

The artifact fetch `ci.artifact` points at. Authenticated by the caller's own
bearer token -- the identity-propagation override is deliberately NOT applied
here, as on the internal endpoints -- tenant-scoped by the same CI job
allowlist as every other `ci.*` call, and streamed from the CI server with the
gateway's read-only credential, which never leaves the process. The bytes
travel over this dedicated endpoint rather than the MCP JSON channel, so they
land on disk instead of in the agent's context.

Its own module because it is the one place where HTTP framing is done by
hand: the response is chunked or length-delimited to match what the upstream
promised, and cut short deliberately when the upstream lies.
"""
from __future__ import annotations

import http.client
import re
import time
import uuid
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import parse_qs, urlparse

from .audit import AuditEvent
from .auth import AuthError
from .ci_backend import STREAM_CHUNK, CiBackendError
from .memory_backend import RequestContext

if TYPE_CHECKING:
    from .server import GatewayHTTPServer

_FILENAME_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_filename(name: str) -> str:
    """A basename safe to place inside a quoted header value. Anything outside the
    whitelist collapses to `_`; an empty result becomes a placeholder, so the header
    is always well-formed."""
    return _FILENAME_SAFE.sub("_", name).strip("._") or "artifact"


class ArtifactHandler(Protocol):
    """What this route needs of the request handler it runs inside."""

    server: GatewayHTTPServer
    headers: Any
    path: str
    wfile: Any
    close_connection: bool

    def send_response(self, code: int, message: str | None = None) -> None: ...
    def send_header(self, keyword: str, value: str) -> None: ...
    def end_headers(self) -> None: ...
    def _send_json(self, status: HTTPStatus | int, payload: dict[str, Any]) -> None: ...


def stream_artifact(handler: ArtifactHandler) -> None:
    server = handler.server
    ci = server.ci_backend
    if ci is None:
        handler._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
        return
    try:
        principal = server.authenticator.authenticate_header(handler.headers.get("Authorization"))
    except AuthError:
        handler._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
        return
    query = parse_qs(urlparse(handler.path).query)
    job = (query.get("job") or [""])[0]
    build = (query.get("build") or [""])[0] or None
    rel_path = (query.get("path") or [""])[0]
    if not job or not rel_path:
        handler._send_json(HTTPStatus.BAD_REQUEST, {"error": "job and path are required"})
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
        sink = server.audit_sink
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
    if not server.artifact_streams.acquire(blocking=False):
        audit("rejected", "artifact stream limit reached")
        handler._send_json(HTTPStatus.SERVICE_UNAVAILABLE,
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
            handler._send_json(int(exc.status or 502), {"error": str(exc)})
            return
        cap = server.artifact_max_bytes
        codings = [field.strip().lower() for field in upstream.headers.get_all("Content-Encoding", [])]
        if any(c not in ("", "identity") for c in codings):
            # The request asked for identity; a body coded anyway is not
            # the artifact, and the client would save it under its name.
            # Every field is read: http.client's get() returns only the
            # first of a repeated header.
            audit("backend_error", "upstream content coding is not one this gateway decodes")
            upstream.close()
            handler._send_json(HTTPStatus.BAD_GATEWAY,
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
            handler._send_json(HTTPStatus.BAD_GATEWAY,
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
            handler._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                               {"error": f"artifact is {declared} bytes; this gateway caps downloads at {cap}"})
            return
        sent = 0
        try:
            handler.send_response(HTTPStatus.OK)
            # Always a download, never a document: the upstream type is
            # whatever the build wrote, and a text/html artifact rendered
            # in a browser on this origin would run with this origin.
            handler.send_header("Content-Type", "application/octet-stream")
            handler.send_header("X-Content-Type-Options", "nosniff")
            chunked = not declared
            if declared:
                handler.send_header("Content-Length", str(declared))
            else:
                # No upstream length: chunked framing is self-delimiting, so
                # a body this gateway or the upstream cuts short is missing
                # its terminator and every HTTP/1.1 client reports it as
                # incomplete. Close-delimited framing would not: there the
                # client reads to EOF and keeps a truncated file as whole.
                handler.send_header("Transfer-Encoding", "chunked")
            # send_header does no CRLF validation of its own -- it formats
            # "<k>: <v>\r\n" and appends -- so a filename carrying a line break
            # would emit attacker-chosen response headers. Whitelist instead of
            # blacklisting: only characters that are safe in a quoted filename.
            filename = safe_filename(rel_path.rsplit("/", 1)[-1])
            handler.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            handler.end_headers()
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
                    handler.close_connection = True
                    return
                if chunked:
                    handler.wfile.write(f"{len(chunk):X}\r\n".encode("ascii") + chunk + b"\r\n")
                else:
                    handler.wfile.write(chunk)
                sent += len(chunk)   # counted once delivered, not once read
            if chunked:
                handler.wfile.write(b"0\r\n\r\n")
            if declared and sent != declared:
                # The upstream promised one length and delivered another. The
                # client's framing is now wrong either way, so close rather
                # than leave a keep-alive connection desynchronized.
                audit("interrupted", f"upstream sent {sent} of {declared} declared bytes", sent)
                handler.close_connection = True
                return
            audit("ok", "", sent)
        except (OSError, http.client.HTTPException):
            # Client hung up, upstream dropped, or the upstream's own framing
            # broke mid-stream (IncompleteRead is an HTTPException, not an
            # OSError): the headers are already out, so there is nothing to
            # report to the caller, and the connection is desynchronized
            # either way.
            audit("interrupted", "client or upstream dropped mid-stream", sent)
            handler.close_connection = True
        finally:
            upstream.close()
    finally:
        server.artifact_streams.release()
