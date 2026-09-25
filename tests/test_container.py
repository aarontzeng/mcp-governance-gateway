"""The container image's own checks, run against a real listener.

The HEALTHCHECK is a shell command nothing else executes until an image is
running under an orchestrator, so a typo in it would ship silently. This runs
the exact line from the Dockerfile."""
from __future__ import annotations

import os
import re
import subprocess
import sys
import threading
import unittest
from pathlib import Path

from mcp_governance_gateway.auth import BearerTokenAuthenticator, IdentityVerifier
from mcp_governance_gateway.server import GatewayHTTPServer, make_handler

DOCKERFILE = Path(__file__).resolve().parents[1] / "Dockerfile"


def _healthcheck_command() -> str:
    text = DOCKERFILE.read_text(encoding="utf-8").replace("\\\n", " ")
    match = re.search(r"^HEALTHCHECK\b.*?\bCMD (.+)$", text, flags=re.MULTILINE)
    assert match, "the Dockerfile has no HEALTHCHECK ... CMD line"
    # The image's `python` is the interpreter running this suite.
    return match.group(1).replace("python -c", f'"{sys.executable}" -c', 1)


class HealthcheckTests(unittest.TestCase):
    def _run(self, env: dict[str, str]) -> int:
        return self._probe(env).returncode

    def _probe(self, env: dict[str, str]) -> subprocess.CompletedProcess[bytes]:
        full = {k: v for k, v in os.environ.items() if k not in ("GATEWAY_HOST", "GATEWAY_PORT")}
        # The probe must ignore a proxy the operator set for the backends.
        full.update({"HTTP_PROXY": "http://127.0.0.1:9", "http_proxy": "http://127.0.0.1:9", **env})
        return subprocess.run(["/bin/sh", "-c", _healthcheck_command()], env=full,
                              capture_output=True, timeout=20)

    def test_an_ipv6_host_makes_a_well_formed_url_even_where_ipv6_is_unavailable(self):
        # '::' used to become http://:::8080/healthz, which urllib rejects before
        # any connection is tried, so the container was unhealthy however well
        # it served. The probe may still fail here (no IPv6 loopback in this
        # environment), but it must fail at the socket, not at the URL.
        for host in ("::", "fd00::1"):
            with self.subTest(host=host):
                done = self._probe({"GATEWAY_HOST": host, "GATEWAY_PORT": "9"})
                self.assertNotEqual(done.returncode, 0)
                self.assertNotIn(b"InvalidURL", done.stderr)
                self.assertNotIn(b"nonnumeric port", done.stderr)
                self.assertIn(b"URLError", done.stderr)

    def test_the_image_base_is_pinned_by_digest(self):
        self.assertRegex(DOCKERFILE.read_text(encoding="utf-8"), r"(?m)^FROM python:[\w.-]+@sha256:[0-9a-f]{64}$")

    def test_it_passes_against_a_live_gateway_and_fails_without_one(self):
        server = GatewayHTTPServer(("127.0.0.1", 0), make_handler())
        server.app = None
        server.authenticator = BearerTokenAuthenticator({})
        server.identity_verifier = IdentityVerifier(secret="")
        server.allowed_origins = ()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = str(server.server_address[1])
        try:
            self.assertEqual(self._run({"GATEWAY_HOST": "0.0.0.0", "GATEWAY_PORT": port}), 0)
            self.assertEqual(self._run({"GATEWAY_HOST": "127.0.0.1", "GATEWAY_PORT": port}), 0)
        finally:
            server.shutdown()
            server.server_close()
        self.assertNotEqual(self._run({"GATEWAY_HOST": "0.0.0.0", "GATEWAY_PORT": port}), 0)

    def test_an_ipv6_bind_is_probed_on_its_loopback_with_brackets(self):
        import socket
        if not socket.has_ipv6:
            self.skipTest("no IPv6")
        try:
            server = GatewayHTTPServer.__new__(GatewayHTTPServer)
            GatewayHTTPServer.address_family = socket.AF_INET6
            server.__init__(("::1", 0), make_handler())
        except OSError:
            self.skipTest("IPv6 loopback unavailable")
        finally:
            GatewayHTTPServer.address_family = socket.AF_INET
        server.app = None
        server.authenticator = BearerTokenAuthenticator({})
        server.identity_verifier = IdentityVerifier(secret="")
        server.allowed_origins = ()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = str(server.server_address[1])
        try:
            self.assertEqual(self._run({"GATEWAY_HOST": "::", "GATEWAY_PORT": port}), 0)
            self.assertEqual(self._run({"GATEWAY_HOST": "::1", "GATEWAY_PORT": port}), 0)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
