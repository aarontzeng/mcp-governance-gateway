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
        full = {k: v for k, v in os.environ.items() if k not in ("GATEWAY_HOST", "GATEWAY_PORT")}
        # The probe must ignore a proxy the operator set for the backends.
        full.update({"HTTP_PROXY": "http://127.0.0.1:9", "http_proxy": "http://127.0.0.1:9", **env})
        return subprocess.run(["/bin/sh", "-c", _healthcheck_command()], env=full,
                              capture_output=True, timeout=20).returncode

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


if __name__ == "__main__":
    unittest.main()
