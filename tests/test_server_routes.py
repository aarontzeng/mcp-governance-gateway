"""The HTTP layer on a real socket: the artifact download route and keep-alive."""
from __future__ import annotations

import http.client
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path

from mcp_governance_gateway.audit import ListAuditSink
from mcp_governance_gateway.ci_backend import CiBackendError
from mcp_governance_gateway.config import Settings
from mcp_governance_gateway.server import build_server


class CiArtifactRouteTests(unittest.TestCase):
    """/ci/artifact is the only path in this gateway that returns raw bytes, so its
    gates are tested against a live server rather than through the backend alone."""

    # Genuinely larger than one stream chunk. Adversarial review, 2026-08-10: the
    # previous 50,000 bytes was SMALLER than STREAM_CHUNK (65,536), so the test
    # claimed multi-chunk coverage while exercising a single read.
    PAYLOAD = b"IMAGEBYTES" * 20_000

    def _server(self, project="proj-a", artifact_path="out/image.bin",
                max_bytes=None, max_concurrent=None, declare_length=True, block=None,
                declared_length=None, drop_after=None, drop_error=None, open_error=None,
                transfer_encoding=None, content_encoding=None):
        import threading
        import time

        tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump({"tokens": [
            {"token": "tok-a", "actor": "a", "project": "proj-a", "roles": ["developer"]},
            {"token": "tok-b", "actor": "b", "project": "proj-b", "roles": ["developer"]},
        ]}, tf)
        tf.close()
        self.addCleanup(lambda: os.unlink(tf.name))
        jobs = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump({"proj-a": ["swarm-build"]}, jobs)
        jobs.close()
        self.addCleanup(lambda: os.unlink(jobs.name))
        settings = Settings(
            host="127.0.0.1", port=0, token_file=tf.name, allowed_origins=(),
            memory_base_url="http://127.0.0.1:59999", memory_backend_token=None,
            memory_search_path="/s", memory_save_path="/r", memory_timeout_sec=2,
            memory_save_max_text_bytes=32768, memory_user_writes_per_minute=30,
            memory_project_writes_per_day=5000, memory_user_reads_per_minute=120,
            jenkins_base_url="https://jenkins.example", ci_jobs_file=jobs.name,
            **({"ci_artifact_max_bytes": max_bytes} if max_bytes else {}),
            **({"ci_artifact_max_concurrent": max_concurrent} if max_concurrent else {}),
        )
        srv = build_server(settings)
        self.srv = srv
        self.audit = ListAuditSink()
        srv.audit_sink = self.audit

        listing = json.dumps({"number": 291, "artifacts": [
            {"fileName": artifact_path.rsplit("/", 1)[-1], "relativePath": artifact_path},
        ]}).encode()
        payload = self.PAYLOAD

        self.reads: list[int] = []
        self.closed: list[bool] = []
        reads, closed = self.reads, self.closed

        class _Upstream:
            # The header object is what http.client hands back (an HTTPMessage),
            # so a repeated field is readable the way the route reads it.
            headers = http.client.HTTPMessage()
            headers["Content-Type"] = "application/octet-stream"
            # `declared_length` lets a test make the upstream promise a length it
            # does not deliver.
            if declare_length:
                headers["Content-Length"] = str(declared_length if declared_length is not None else len(payload))
            # An upstream that chunks its body: http.client de-chunks it and
            # ignores any Content-Length, but leaves both headers readable. A
            # tuple sends the field more than once.
            for coding in ((transfer_encoding,) if isinstance(transfer_encoding, str) else transfer_encoding or ()):
                headers["Transfer-Encoding"] = coding
            # A body coded despite Accept-Encoding: identity; http.client decodes
            # no content coding, so the bytes arrive as sent. A tuple sends the
            # field more than once.
            for coding in ((content_encoding,) if isinstance(content_encoding, str) else content_encoding or ()):
                headers["Content-Encoding"] = coding
            # http.client's own verdict: it decodes a bare "chunked" and nothing
            # else, read from the FIRST field of a repeated header.
            first_transfer = headers.get("Transfer-Encoding")
            chunked = first_transfer is not None and first_transfer.lower() == "chunked"

            def __init__(self):
                self._left = payload

            def read(self, n):
                # `block` lets a test hold a stream open deterministically, so a
                # concurrency cap can be observed instead of raced against.
                if block is not None and reads:
                    block.wait(timeout=5)
                # `drop_after` makes the upstream die mid-stream after that many
                # reads; `drop_error` picks how (a socket error by default).
                if drop_after is not None and len(reads) >= drop_after:
                    raise drop_error or OSError("upstream connection reset")
                chunk, self._left = self._left[:n], self._left[n:]
                reads.append(len(chunk))
                return chunk

            def close(self):
                closed.append(True)

        srv.ci_backend._fetch = lambda path: listing          # type: ignore[method-assign]
        def _open(path):
            # `open_error` makes the fetch itself fail, after validation passed.
            if open_error is not None:
                raise open_error
            return _Upstream()

        srv.ci_backend._open = _open                          # type: ignore[method-assign]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        time.sleep(0.2)
        return srv.server_address[1]

    def _get(self, port, query, token="tok-a"):
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        conn.request("GET", "/ci/artifact?" + query, headers=headers)
        response = conn.getresponse()
        body = response.read()
        conn.close()
        return response, body

    def test_streams_the_file_with_a_download_disposition(self) -> None:
        from mcp_governance_gateway.ci_backend import STREAM_CHUNK

        port = self._server()
        response, body = self._get(port, "job=swarm-build&build=291&path=out/image.bin")
        self.assertEqual(response.status, 200)
        self.assertEqual(body, self.PAYLOAD)  # complete across chunk boundaries
        self.assertIn('filename="image.bin"', response.getheader("Content-Disposition") or "")
        # the body really was reassembled from several reads, and upstream was closed
        self.assertGreater(len(self.PAYLOAD), STREAM_CHUNK)
        self.assertGreater(len([n for n in self.reads if n > 0]), 1)
        self.assertTrue(self.closed)


    def test_the_upstream_content_type_is_never_forwarded(self) -> None:
        # An artifact declared text/html by the build must not render on this
        # origin: the type is fixed and sniffing is disabled.
        port = self._server()
        orig_open = self.srv.ci_backend._open
        length = str(len(self.PAYLOAD))

        class _Html:
            headers = http.client.HTTPMessage()
            headers["Content-Type"] = "text/html; charset=utf-8"
            headers["Content-Length"] = length
            chunked = False

            def __init__(self):
                self._inner = orig_open(None)

            def read(self, n):
                return self._inner.read(n)

            def close(self):
                self._inner.close()

        self.srv.ci_backend._open = lambda path: _Html()  # type: ignore[method-assign]
        response, _body = self._get(port, "job=swarm-build&build=291&path=out/image.bin")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader("Content-Type"), "application/octet-stream")
        self.assertEqual(response.getheader("X-Content-Type-Options"), "nosniff")
    def test_a_filename_cannot_inject_response_headers(self) -> None:
        # Adversarial review, 2026-08-10: send_header does no CRLF validation, so a
        # listed basename containing a line break emitted attacker-chosen headers.
        port = self._server(artifact_path="out/ev\r\nX-Injected: yes.bin")
        response, body = self._get(port, "job=swarm-build&build=291&path=out/ev%0d%0aX-Injected:%20yes.bin")
        self.assertEqual(response.status, 200)
        self.assertIsNone(response.getheader("X-Injected"))
        self.assertNotIn("\r", response.getheader("Content-Disposition") or "")
        self.assertNotIn("\n", response.getheader("Content-Disposition") or "")
        self.assertEqual(body, self.PAYLOAD)

    def test_no_token_is_rejected_before_anything_is_fetched(self) -> None:
        port = self._server()
        response, _ = self._get(port, "job=swarm-build&path=out/image.bin", token=None)
        self.assertEqual(response.status, 401)

    def test_another_tenants_token_cannot_reach_the_job(self) -> None:
        port = self._server()
        response, _ = self._get(port, "job=swarm-build&path=out/image.bin", token="tok-b")
        self.assertEqual(response.status, 404)

    def test_a_path_the_build_does_not_list_is_refused(self) -> None:
        port = self._server()
        for path in ("../../../etc/passwd", "out/secret.bin"):
            with self.subTest(path=path):
                response, _ = self._get(port, "job=swarm-build&path=" + path)
                self.assertEqual(response.status, 404)

    def test_a_refused_job_or_path_is_not_written_into_the_audit_log(self) -> None:
        # Until locate_artifact has validated them, job and path are whatever the
        # caller typed; the audit log records the refusal, not the typed string.
        port = self._server()
        response, _ = self._get(port, "job=swarm-build&path=out/" + "glpat-" + "x1" * 12)
        self.assertEqual(response.status, 404)
        event = self.audit.events[-1]
        self.assertEqual(event.outcome, "backend_error")
        self.assertIsNone(event.resource_id)
        self.assertNotIn("glpat-", json.dumps(event.to_json()))

    def test_the_transfer_itself_is_audited(self) -> None:
        # Design review, 2026-08-10: every MCP tool call was audited, and the one
        # operation that moved bytes was not -- the record showed only the preceding
        # metadata lookup.
        port = self._server()
        self._get(port, "job=swarm-build&build=291&path=out/image.bin")
        event = self.audit.events[-1]
        self.assertEqual(event.tool, "ci.artifact.download")
        self.assertEqual(event.outcome, "ok")
        self.assertEqual(event.resource_id, "swarm-build:out/image.bin")
        self.assertEqual(event.bytes_sent, len(self.PAYLOAD))  # bytes delivered
        self.assertIsInstance(event.duration_ms, int)           # and how long it took
        self.assertGreaterEqual(event.duration_ms, 0)
        self.assertEqual(event.to_json()["bytesSent"], len(self.PAYLOAD))

    def test_a_declared_size_over_the_cap_is_refused_before_streaming(self) -> None:
        port = self._server(max_bytes=1024)
        response, body = self._get(port, "job=swarm-build&build=291&path=out/image.bin")
        self.assertEqual(response.status, 413)
        self.assertEqual(self.audit.events[-1].outcome, "rejected")
        self.assertNotIn(b"IMAGEBYTES", body)

    def test_a_dishonest_upstream_cannot_buy_an_unbounded_transfer(self) -> None:
        # No Content-Length to check up front: the cap has to hold on the stream.
        # Review, 2026-09-03: the stop must be VISIBLE to the client. With a
        # close-delimited body the client read to EOF and kept the prefix as a
        # complete file; chunked framing leaves the terminator out, so the client
        # reports an incomplete body instead.
        import http.client

        port = self._server(max_bytes=100_000, declare_length=False)
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/ci/artifact?job=swarm-build&build=291&path=out/image.bin",
                     headers={"Authorization": "Bearer tok-a"})
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        with self.assertRaises(http.client.IncompleteRead):
            response.read()
        conn.close()
        event = self.audit.events[-1]
        self.assertEqual(event.outcome, "truncated")
        # bytes_sent counts what was written, so it can never exceed the cap the
        # stream was stopped at.
        self.assertLessEqual(event.bytes_sent, 100_000)

    def test_a_negative_content_length_is_treated_as_no_length(self) -> None:
        # Review, 2026-09-03: "-1" parses as an int, so it slipped past the cap
        # check and was forwarded as Content-Length: -1, which every client reads
        # as "unknown, read to EOF": the capped stop was invisible again.
        import http.client

        port = self._server(max_bytes=100_000, declared_length=-1)
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/ci/artifact?job=swarm-build&build=291&path=out/image.bin",
                     headers={"Authorization": "Bearer tok-a"})
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        self.assertIsNone(response.getheader("Content-Length"))
        self.assertEqual(response.getheader("Transfer-Encoding"), "chunked")
        with self.assertRaises(http.client.IncompleteRead):
            response.read()
        conn.close()
        self.assertEqual(self.audit.events[-1].outcome, "truncated")

    def test_an_upstream_transfer_encoding_overrides_its_content_length(self) -> None:
        # Review, 2026-09-03: an upstream sending both Transfer-Encoding: chunked
        # and a Content-Length is de-chunked by http.client, which ignores the
        # length -- but the header is still readable, and forwarding it promised
        # the client a length the body did not have (here: half of it, so the
        # client would have kept a prefix as the whole file).
        import http.client

        port = self._server(declared_length=len(self.PAYLOAD) // 2, transfer_encoding="chunked")
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/ci/artifact?job=swarm-build&build=291&path=out/image.bin",
                     headers={"Authorization": "Bearer tok-a"})
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        self.assertIsNone(response.getheader("Content-Length"))
        self.assertEqual(response.getheader("Transfer-Encoding"), "chunked")
        self.assertEqual(response.read(), self.PAYLOAD)
        conn.close()
        event = self.audit.events[-1]
        self.assertEqual(event.outcome, "ok")
        self.assertEqual(event.bytes_sent, len(self.PAYLOAD))

    def test_a_transfer_coding_http_client_did_not_decode_is_refused(self) -> None:
        # Review, 2026-09-03 (round 6): http.client decodes a bare "chunked" and
        # nothing else. Under "gzip, chunked" it honours the Content-Length and
        # hands back the still-coded wire bytes, which the previous predicate
        # (any Transfer-Encoding header) would have re-chunked and served as
        # the artifact with a 200 and an "ok" audit line.
        port = self._server(transfer_encoding="gzip, chunked")
        response, body = self._get(port, "job=swarm-build&build=291&path=out/image.bin")
        self.assertEqual(response.status, 502)
        self.assertIn("transfer coding", json.loads(body)["error"])
        self.assertEqual(self.reads, [])          # not one body byte was read
        self.assertEqual(self.closed, [True])
        event = self.audit.events[-1]
        self.assertEqual(event.outcome, "backend_error")

    def test_a_transfer_coding_hidden_behind_a_repeated_field_is_refused(self) -> None:
        # Round 10: http.client's chunked verdict reads only the first field of
        # a repeated Transfer-Encoding header, so "chunked" then "gzip" was
        # de-chunked and the gzip bytes served, and "" then "gzip" passed the
        # old truthiness check on the first field alone.
        for fields in (("chunked", "gzip"), ("", "gzip")):
            with self.subTest(fields=fields):
                port = self._server(transfer_encoding=fields)
                response, body = self._get(port, "job=swarm-build&build=291&path=out/image.bin")
                self.assertEqual(response.status, 502)
                self.assertIn("transfer coding", json.loads(body)["error"])
                self.assertEqual(self.reads, [])
                self.assertEqual(self.audit.events[-1].outcome, "backend_error")

    def test_an_empty_transfer_encoding_field_names_no_coding(self) -> None:
        # Round 11: two reviewers read `any(transfer)` as a hole for a field of
        # only whitespace. This pins the route's reading instead: an empty field
        # names no coding, so the Content-Length bytes are served -- the same
        # reading the Content-Encoding check gives an empty field. The fake's
        # unstripped " " and the "" http.client's parser would store (checked
        # by hand on 3.10.12) reach the same [""] after the route's strip().
        port = self._server(transfer_encoding=" ")
        response, body = self._get(port, "job=swarm-build&build=291&path=out/image.bin")
        self.assertEqual(response.status, 200)
        self.assertEqual(body, self.PAYLOAD)
        self.assertEqual(self.audit.events[-1].outcome, "ok")

    def test_a_content_coding_http_client_did_not_decode_is_refused(self) -> None:
        # Round 7: `Content-Encoding: gzip` with a plain Content-Length passed
        # both framing checks and the gzip stream was served, 200 and audit
        # "ok", under the artifact's own filename.
        port = self._server(content_encoding="gzip")
        response, body = self._get(port, "job=swarm-build&build=291&path=out/image.bin")
        self.assertEqual(response.status, 502)
        self.assertIn("content coding", json.loads(body)["error"])
        self.assertEqual(self.reads, [])
        self.assertEqual(self.closed, [True])
        self.assertEqual(self.audit.events[-1].outcome, "backend_error")

    def test_a_content_coding_hidden_behind_a_repeated_identity_field_is_refused(self) -> None:
        # Round 8: HTTPMessage.get() returns the first of a repeated header, so
        # `Content-Encoding: identity` followed by `Content-Encoding: gzip` read
        # as identity and the gzip body was served again.
        port = self._server(content_encoding=("identity", "gzip"))
        response, body = self._get(port, "job=swarm-build&build=291&path=out/image.bin")
        self.assertEqual(response.status, 502)
        self.assertEqual(self.reads, [])
        self.assertEqual(self.audit.events[-1].outcome, "backend_error")

    def test_an_identity_content_coding_is_the_artifact_itself(self) -> None:
        port = self._server(content_encoding="identity")
        response, body = self._get(port, "job=swarm-build&build=291&path=out/image.bin")
        self.assertEqual(response.status, 200)
        self.assertEqual(body, self.PAYLOAD)

    def test_an_upstream_that_drops_mid_stream_leaves_the_body_incomplete(self) -> None:
        # No length and the upstream dies after the first chunk: no terminator is
        # written and the connection is closed, so the client learns at once that
        # the body is incomplete instead of waiting on keep-alive for the rest.
        import http.client

        port = self._server(declare_length=False, drop_after=1)
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/ci/artifact?job=swarm-build&build=291&path=out/image.bin",
                     headers={"Authorization": "Bearer tok-a"})
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        with self.assertRaises(http.client.IncompleteRead):  # not a timeout: the close is prompt
            response.read()
        conn.close()
        event = self.audit.events[-1]
        self.assertEqual(event.outcome, "interrupted")
        self.assertGreater(event.bytes_sent, 0)
        self.assertLess(event.bytes_sent, len(self.PAYLOAD))

    def test_an_upstream_whose_own_framing_breaks_is_audited_the_same_way(self) -> None:
        # Review, 2026-09-03: an upstream chunked body that ends inside a chunk
        # raises IncompleteRead, an HTTPException rather than an OSError; the
        # handler only caught the latter, so the transfer escaped the audit log.
        import http.client

        port = self._server(declare_length=False, drop_after=1,
                            drop_error=http.client.IncompleteRead(b""))
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/ci/artifact?job=swarm-build&build=291&path=out/image.bin",
                     headers={"Authorization": "Bearer tok-a"})
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        with self.assertRaises(http.client.IncompleteRead):
            response.read()
        conn.close()
        event = self.audit.events[-1]
        self.assertEqual(event.outcome, "interrupted")
        self.assertEqual(event.resource_id, "swarm-build:out/image.bin")

    def test_an_open_that_fails_after_validation_still_names_the_artifact(self) -> None:
        # The refusal test above keeps typed strings out of the audit log; once the
        # job and path have passed the allowlist and the listing they are the
        # gateway's own words, and a failed fetch has to be traceable to them.
        port = self._server(open_error=CiBackendError("CI unavailable"))
        response, _ = self._get(port, "job=swarm-build&build=291&path=out/image.bin")
        self.assertEqual(response.status, 502)
        event = self.audit.events[-1]
        self.assertEqual(event.outcome, "backend_error")
        self.assertEqual(event.resource_id, "swarm-build:out/image.bin")

    def test_an_upstream_without_a_length_is_chunk_delimited(self) -> None:
        # No upstream length: the body is chunked, so it is self-delimiting (a
        # complete file is distinguishable from a cut-short one) and the
        # connection stays usable for the next request.
        import http.client

        port = self._server(declare_length=False)
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        for _ in range(2):  # twice on one connection: keep-alive survived the stream
            conn.request("GET", "/ci/artifact?job=swarm-build&build=291&path=out/image.bin",
                         headers={"Authorization": "Bearer tok-a"})
            response = conn.getresponse()
            body = response.read()
            self.assertEqual(response.status, 200)
            self.assertIsNone(response.getheader("Content-Length"))
            self.assertEqual(response.getheader("Transfer-Encoding"), "chunked")
            self.assertNotEqual((response.getheader("Connection") or "").lower(), "close")
            self.assertEqual(body, self.PAYLOAD)
            self.assertEqual(self.audit.events[-1].outcome, "ok")
        conn.close()

    def test_an_upstream_that_delivers_less_than_it_declared_is_not_audited_ok(self) -> None:
        import http.client

        port = self._server(declared_length=len(self.PAYLOAD) + 1000)
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/ci/artifact?job=swarm-build&build=291&path=out/image.bin",
                     headers={"Authorization": "Bearer tok-a"})
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        # The gateway closes rather than leave the client waiting for bytes that
        # will never come: an incomplete read, not a timeout.
        with self.assertRaises(http.client.IncompleteRead):
            response.read()
        conn.close()
        event = self.audit.events[-1]
        self.assertEqual(event.outcome, "interrupted")
        self.assertIn("declared", event.reason)
        self.assertEqual(event.bytes_sent, len(self.PAYLOAD))

    def test_concurrent_streams_are_capped(self) -> None:
        # A stream holds a thread and an upstream connection for its whole duration,
        # so the second one must be refused, not queued behind the first.
        import http.client
        import threading

        gate = threading.Event()
        port = self._server(max_concurrent=1, block=gate)
        first = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        first.request("GET", "/ci/artifact?job=swarm-build&build=291&path=out/image.bin",
                      headers={"Authorization": "Bearer tok-a"})
        first_response = first.getresponse()
        first_response.read(10)          # the slot is now held, deterministically
        try:
            second, _ = self._get(port, "job=swarm-build&build=291&path=out/image.bin")
            self.assertEqual(second.status, 503)
            self.assertEqual(self.audit.events[-1].outcome, "rejected")
        finally:
            gate.set()                   # let the first stream finish
            try:
                first_response.read()
            except Exception:
                pass
            first.close()

    def test_missing_arguments_are_a_bad_request(self) -> None:
        port = self._server()
        for query in ("job=swarm-build", "path=out/image.bin", ""):
            with self.subTest(query=query):
                self.assertEqual(self._get(port, query)[0].status, 400)


class HttpServerKeepAliveTests(unittest.TestCase):
    def test_connection_is_kept_alive_for_followup_request(self) -> None:
        # MCP clients reuse one persistent connection: initialize, then send
        # notifications/initialized on the SAME socket. An HTTP/1.0 server closes
        # after the first response, which the client sees as ECONNRESET. Verify the
        # server speaks HTTP/1.1 keep-alive so the followup request reuses the socket.
        import http.client
        import threading
        import time

        tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump({"tokens": [{"token": "ka", "actor": "a", "project": "p", "roles": ["developer"]}]}, tf)
        tf.close()
        settings = Settings(
            host="127.0.0.1", port=0, token_file=tf.name, allowed_origins=(),
            memory_base_url="http://127.0.0.1:59999", memory_backend_token=None,
            memory_search_path="/s", memory_save_path="/r", memory_timeout_sec=2,
            memory_save_max_text_bytes=32768, memory_user_writes_per_minute=30,
            memory_project_writes_per_day=5000, memory_user_reads_per_minute=120,
        )
        srv = build_server(settings)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            time.sleep(0.2)
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            hdr = {"Authorization": "Bearer ka", "Content-Type": "application/json"}
            conn.request("POST", "/mcp", json.dumps({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t"}},
            }), hdr)
            r1 = conn.getresponse()
            r1.read()
            self.assertEqual(r1.version, 11)       # HTTP/1.1
            self.assertFalse(r1.will_close)        # keep-alive: server does not close
            sock = conn.sock
            conn.request("POST", "/mcp",
                         json.dumps({"jsonrpc": "2.0", "id": None, "method": "notifications/initialized"}), hdr)
            r2 = conn.getresponse()
            r2.read()
            self.assertEqual(r2.status, 202)
            self.assertIs(conn.sock, sock)         # same socket reused, not reconnected
        finally:
            srv.shutdown()
            Path(tf.name).unlink()


class RefusedBodyTests(unittest.TestCase):
    def test_an_oversize_post_closes_the_connection_instead_of_desynchronising_it(self):
        # The body is refused before it is read; left open, its bytes would be
        # parsed as the next request on this keep-alive connection.
        from mcp_governance_gateway.auth import BearerTokenAuthenticator, IdentityVerifier, Principal
        from mcp_governance_gateway.server import GatewayHTTPServer, make_handler
        srv = GatewayHTTPServer(("127.0.0.1", 0), make_handler())
        srv.app = None
        srv.authenticator = BearerTokenAuthenticator({"t": Principal(actor="a", project="p", roles=(), token_id="i")})
        srv.identity_verifier = IdentityVerifier(secret="")
        srv.allowed_origins = ()
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
            conn.putrequest("POST", "/mcp")
            conn.putheader("Authorization", "Bearer t")
            conn.putheader("Content-Length", str(3_000_000))
            conn.endheaders()
            response = conn.getresponse()
            self.assertEqual(response.status, 400)
            self.assertTrue(response.will_close)
        finally:
            srv.shutdown()
            srv.server_close()


class LoggingSetupTests(unittest.TestCase):
    def test_configure_logging_twice_installs_one_handler(self):
        import logging

        from mcp_governance_gateway.server import configure_logging
        package = logging.getLogger("mcp_governance_gateway")
        saved = list(package.handlers), package.propagate, package.level
        package.handlers.clear()
        try:
            configure_logging()
            configure_logging()
            self.assertEqual(len(package.handlers), 1)
            self.assertFalse(package.propagate)
        finally:
            package.handlers[:] = saved[0]
            package.propagate = saved[1]
            package.setLevel(saved[2])
