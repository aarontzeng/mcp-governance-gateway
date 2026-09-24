"""The one JSON HTTP path every adapter now shares."""
from __future__ import annotations

import http.client
import io
import unittest
from unittest import mock
from urllib import error

from mcp_governance_gateway.errors import BackendError
from mcp_governance_gateway.http_client import JsonHttpClient


class _Err(BackendError):
    pass


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _client(**kw) -> JsonHttpClient:
    return JsonHttpClient("https://backend.example/base/", error_cls=_Err, label="thing", timeout_sec=3, **kw)


class JsonHttpClientTests(unittest.TestCase):
    def _capture(self, body: bytes = b"{}"):
        seen = {}

        def urlopen(req, timeout=None):
            seen["url"] = req.full_url
            seen["method"] = req.get_method()
            seen["headers"] = {k.lower(): v for k, v in req.header_items()}
            seen["data"] = req.data
            seen["timeout"] = timeout
            return _Response(body)

        return seen, mock.patch("mcp_governance_gateway.http_client.request.urlopen", side_effect=urlopen)

    def test_url_joins_base_and_path_once_and_encodes_params(self):
        seen, patched = self._capture()
        with patched:
            _client().request("GET", "/items", params={"q": "a b", "n": 2})
        self.assertEqual(seen["url"], "https://backend.example/base/items?q=a+b&n=2")
        self.assertEqual(seen["timeout"], 3)

    def test_headers_layer_defaults_instance_then_call(self):
        seen, patched = self._capture()
        with patched:
            _client(headers={"Authorization": "Bearer x", "Accept": "text/plain"}).request(
                "GET", "p", headers={"Accept": "application/vnd.github+json"})
        self.assertEqual(seen["headers"]["authorization"], "Bearer x")
        self.assertEqual(seen["headers"]["accept"], "application/vnd.github+json")

    def test_a_body_is_json_with_a_content_type_and_no_body_has_none(self):
        seen, patched = self._capture()
        with patched:
            _client().request("POST", "p", body={"k": "v"})
        self.assertEqual(seen["data"], b'{"k": "v"}')
        self.assertEqual(seen["headers"]["content-type"], "application/json")
        with patched:
            _client().request("DELETE", "p")
        self.assertNotIn("content-type", seen["headers"])
        self.assertIsNone(seen["data"])

    def test_an_empty_body_is_an_empty_object(self):
        _, patched = self._capture(b"  \n")
        with patched:
            self.assertEqual(_client().request("GET", "p"), {})

    def test_the_four_failures_carry_the_label(self):
        cases = [
            (error.HTTPError("u", 503, "down", {}, None), "thing HTTP 503", 503),
            (OSError("refused"), "thing unavailable", None),
            (http.client.RemoteDisconnected("gone"), "thing unavailable", None),
            (ValueError("bad header"), "thing unavailable", None),
        ]
        for exc, message, status in cases:
            with self.subTest(exc=exc):
                with mock.patch("mcp_governance_gateway.http_client.request.urlopen", side_effect=exc):
                    with self.assertRaises(_Err) as caught:
                        _client().request("GET", "p")
                self.assertEqual((str(caught.exception), caught.exception.status), (message, status))
        with mock.patch("mcp_governance_gateway.http_client.request.urlopen", return_value=_Response(b"<html>")):
            with self.assertRaises(_Err) as caught:
                _client().request("GET", "p")
        self.assertEqual(str(caught.exception), "thing returned invalid JSON")
        with mock.patch("mcp_governance_gateway.http_client.request.urlopen", return_value=_Response(b"x" * 11)):
            with self.assertRaises(_Err) as caught:
                _client(max_bytes=10).request("GET", "p")
        self.assertEqual(str(caught.exception), "thing response too large")


if __name__ == "__main__":
    unittest.main()
