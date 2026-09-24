"""Settings.from_env: what is refused at boot, and why."""
from __future__ import annotations

import unittest
from unittest import mock

from mcp_governance_gateway.config import Settings


class SettingsTests(unittest.TestCase):
    def test_loads_memory_limit_settings_from_environment(self) -> None:
        with mock.patch.dict(
            "os.environ",
            {
                "GATEWAY_TOKEN_FILE": "/tmp/tokens.json",
                "MEMORY_SAVE_MAX_TEXT_BYTES": "4096",
                "MEMORY_USER_WRITES_PER_MINUTE": "7",
                "MEMORY_PROJECT_WRITES_PER_DAY": "99",
            },
            clear=True,
        ):
            settings = Settings.from_env()

        self.assertEqual(settings.memory_save_max_text_bytes, 4096)
        self.assertEqual(settings.memory_user_writes_per_minute, 7)
        self.assertEqual(settings.memory_project_writes_per_day, 99)

    def test_negative_memory_limit_is_rejected(self) -> None:
        with mock.patch.dict(
            "os.environ",
            {"GATEWAY_TOKEN_FILE": "/tmp/tokens.json", "MEMORY_USER_WRITES_PER_MINUTE": "-1"},
            clear=True,
        ):
            with self.assertRaises(ValueError):
                Settings.from_env()

    def test_a_backend_url_without_a_scheme_is_refused_at_startup(self) -> None:
        # Review, 2026-09-03 (round 6): urlopen raises ValueError on such a URL at
        # request time, which the dispatcher reports as the caller's invalid
        # arguments -- so the operator's typo must be caught here instead.
        for name in ("MEMORY_BASE_URL", "REDMINE_BASE_URL", "GITLAB_BASE_URL", "JENKINS_BASE_URL"):
            with self.subTest(name=name):
                with mock.patch.dict(
                    "os.environ", {"GATEWAY_TOKEN_FILE": "/tmp/tokens.json", name: "ci.internal:8080"},
                    clear=True,
                ):
                    with self.assertRaises(ValueError) as cm:
                        Settings.from_env()
                self.assertIn(name, str(cm.exception))

    def test_a_backend_url_http_client_cannot_encode_is_refused_at_startup(self) -> None:
        # Round 7: a non-ASCII path passes the scheme check but fails inside
        # urlopen on every request; same startup gate, same named variable.
        with mock.patch.dict(
            "os.environ", {"GATEWAY_TOKEN_FILE": "/tmp/tokens.json", "JENKINS_BASE_URL": "https://ci.internal/caf\u00e9/"},
            clear=True,
        ):
            with self.assertRaisesRegex(ValueError, "JENKINS_BASE_URL"):
                Settings.from_env()

    def test_an_explicitly_empty_memory_url_is_refused_not_defaulted(self) -> None:
        # Round 7: `MEMORY_BASE_URL=` used to be kept as "" (and fail on every
        # request); silently substituting the localhost default would instead
        # send memory payloads and the backend token wherever listens there.
        with mock.patch.dict(
            "os.environ", {"GATEWAY_TOKEN_FILE": "/tmp/tokens.json", "MEMORY_BASE_URL": ""}, clear=True,
        ):
            with self.assertRaisesRegex(ValueError, "MEMORY_BASE_URL"):
                Settings.from_env()
        # An empty OPTIONAL backend URL still means "not configured".
        with mock.patch.dict(
            "os.environ", {"GATEWAY_TOKEN_FILE": "/tmp/tokens.json", "REDMINE_BASE_URL": ""}, clear=True,
        ):
            self.assertIsNone(Settings.from_env().redmine_base_url)

    def test_a_timeout_the_socket_layer_would_reject_is_refused_at_startup(self) -> None:
        # 1e300 is finite and positive but overflows the socket clock. The
        # message must name the variable: with the predicate inverted the
        # DEFAULT memory timeout would raise first and a bare assertRaises
        # would still pass (round 7).
        for value in ("0", "-1", "inf", "nan", "1e300"):
            with self.subTest(value=value):
                with mock.patch.dict(
                    "os.environ", {"GATEWAY_TOKEN_FILE": "/tmp/tokens.json", "JENKINS_TIMEOUT_SEC": value},
                    clear=True,
                ):
                    with self.assertRaisesRegex(ValueError, "JENKINS_TIMEOUT_SEC"):
                        Settings.from_env()
        with mock.patch.dict(
            "os.environ", {"GATEWAY_TOKEN_FILE": "/tmp/tokens.json", "JENKINS_TIMEOUT_SEC": "3600"}, clear=True,
        ):
            self.assertEqual(Settings.from_env().jenkins_timeout_sec, 3600.0)
