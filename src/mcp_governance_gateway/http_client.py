"""The one way this process talks JSON to a backend.

Five adapters each carried the same forty lines: build a `Request`, `urlopen`
with a timeout, map `HTTPError` to a backend error carrying the status, map
everything else the socket or `http.client` can raise to "unavailable", cap
the body, decode it. They drifted -- two read an empty body as invalid JSON,
one silently truncated instead of refusing -- and the comment explaining
which exceptions mean what was pasted into each. The comment is here now.

What stays in the adapter: the credential header (each backend spells it
differently, and which credential to send is a per-call decision), and what a
non-object JSON body means to it.
"""
from __future__ import annotations

import http.client
import json
from collections.abc import Mapping
from typing import Any
from urllib import error, parse, request

from .errors import BackendError

MAX_RESPONSE_BYTES = 2_000_000


class JsonHttpClient:
    """`request()` returns the decoded JSON body (an empty body is `{}`) or
    raises `error_cls` with a message that starts with `label`:

    - `"<label> HTTP <code>"`, `status=<code>`, for a response the backend sent;
    - `"<label> unavailable"` for anything that stopped a response arriving. A
      garbled or truncated reply is an `http.client.HTTPException`, not an
      `OSError`, and a credential or redirect the request cannot be encoded
      with is a `ValueError`; either way the backend is unusable, not the caller;
    - `"<label> response too large"` past `max_bytes`, refused rather than cut;
    - `"<label> returned invalid JSON"`.
    """

    def __init__(
        self,
        base_url: str,
        *,
        error_cls: type[BackendError],
        label: str,
        timeout_sec: float,
        max_bytes: int = MAX_RESPONSE_BYTES,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._error_cls = error_cls
        self._label = label
        self._timeout_sec = timeout_sec
        self._max_bytes = max_bytes
        self._headers = dict(headers or {})

    def url(self, path: str, params: Mapping[str, Any] | None = None) -> str:
        url = f"{self._base_url}/{path.lstrip('/')}"
        if params:
            url = f"{url}?{parse.urlencode(params)}"
        return url

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        body: Any | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        return self.decode(self.fetch(method, path, params=params, body=body, headers=headers))

    def decode(self, raw: bytes) -> Any:
        """The JSON rules on their own, for a body fetched some other way."""
        if not raw.strip():
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise self._error_cls(f"{self._label} returned invalid JSON") from exc

    def fetch(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        body: Any | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> bytes:
        """The raw body, bounded. `request()` is this plus a JSON decode."""
        merged = {"Accept": "application/json", **self._headers, **(headers or {})}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            merged["Content-Type"] = "application/json"
        req = request.Request(self.url(path, params), data=data, headers=merged, method=method)
        try:
            with request.urlopen(req, timeout=self._timeout_sec) as response:
                raw = response.read(self._max_bytes + 1)
        except error.HTTPError as exc:
            raise self._error_cls(f"{self._label} HTTP {exc.code}", status=exc.code) from exc
        except (OSError, http.client.HTTPException, ValueError) as exc:
            raise self._error_cls(f"{self._label} unavailable") from exc
        if len(raw) > self._max_bytes:
            raise self._error_cls(f"{self._label} response too large")
        return raw
