"""Ephemeral markdown uploads keep long bodies out of confirmation arguments.

State and bytes share the process lifetime, like confirmations. No files remain
after restart; opaque upload tokens keep ownership server-side. Only content is
accepted. The owner's first upload reaching stage validation consumes its URL,
even if body validation fails; a foreign bearer's attempt is refused without
consuming it.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import secrets
import threading
import time
from typing import Callable, Iterator

MAX_ASSET_BYTES = 2 * 1024 * 1024
URL_TTL_SEC = 60
STAGE_TTL_SEC = 3600
MAX_STAGED_PER_USER = 16
MAX_STAGED_BYTES_PER_USER = 32 * 1024 * 1024


class AssetStageError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


@dataclass
class _Stage:
    actor: str
    project: str
    token_id: str
    expiry: float
    data: bytes | None = None
    busy: bool = False


class AssetStage:
    def __init__(self, base_url: str | None, clock: Callable[[], float] | None = None) -> None:
        self._base_url = (base_url or "").rstrip("/")
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._uploads: dict[str, str] = {}
        self._staged: dict[str, _Stage] = {}

    def mint_upload_url(self, actor: str, project: str, token_id: str, kind: str = "content") -> dict:
        if kind != "content":
            raise AssetStageError("kind must be content")
        if not self._base_url:
            raise AssetStageError("staged content needs DOCS_ASSET_BASE_URL", 404)
        with self._lock:
            self._gc_locked()
            # Pending URLs count too, otherwise minting alone grows state forever.
            mine = [m for m in self._staged.values() if m.actor == actor]
            if len(mine) >= MAX_STAGED_PER_USER:
                raise AssetStageError("staging quota exceeded", 429)
            staged_id = "doc_" + secrets.token_hex(16)
            token = secrets.token_urlsafe(32)
            self._staged[staged_id] = _Stage(actor, project, token_id, self._clock() + URL_TTL_SEC)
            self._uploads[token] = staged_id
        return {"url": f"{self._base_url}/docs/asset-stage/{token}",
                "stagedId": staged_id, "expiresInSec": URL_TTL_SEC,
                "singleUse": True, "maxBytes": MAX_ASSET_BYTES, "kind": kind,
                "allowedTypes": ["text/markdown; charset=utf-8"]}

    def accept_upload(self, token: str, data: bytes, actor: str, project: str, token_id: str) -> dict:
        with self._lock:
            self._gc_locked()
            staged_id = self._uploads.get(token, "")
            meta = self._owned_locked(staged_id, actor, project, token_id)
            del self._uploads[token]
            # The owner consumes the URL even when body validation fails.
            del self._staged[staged_id]
            if not data:
                raise AssetStageError("empty upload body")
            if len(data) > MAX_ASSET_BYTES:
                raise AssetStageError("staged content exceeds size limit", 413)
            try:
                data.decode("utf-8")
            except UnicodeDecodeError:
                raise AssetStageError("staged content must be UTF-8 text", 415) from None
            used = sum(len(m.data or b"") for m in self._staged.values() if m.actor == actor)
            if used + len(data) > MAX_STAGED_BYTES_PER_USER:
                raise AssetStageError("staging quota exceeded", 429)
            meta.data = data
            meta.expiry = self._clock() + STAGE_TTL_SEC
            self._staged[staged_id] = meta
        return {"stagedId": staged_id, "bytes": len(data), "type": "text/markdown; charset=utf-8"}

    def peek(self, staged_id: str, actor: str, project: str, token_id: str) -> str:
        with self._lock:
            self._gc_locked()
            meta = self._owned_locked(staged_id, actor, project, token_id)
            if meta.data is None:
                raise AssetStageError("staged content has not been uploaded", 409)
            return meta.data.decode("utf-8")

    @contextmanager
    def claim(self, staged_id: str, actor: str, project: str, token_id: str) -> Iterator[str]:
        """Reserve through the host write; failure releases, success consumes."""
        with self._lock:
            self._gc_locked()
            meta = self._owned_locked(staged_id, actor, project, token_id)
            if meta.data is None or meta.busy:
                raise AssetStageError("staged content unavailable or already in use", 409)
            meta.busy = True
            content = meta.data.decode("utf-8")
        try:
            yield content
        except BaseException:
            with self._lock:
                meta.busy = False
            raise
        else:
            with self._lock:
                del self._staged[staged_id]

    def _owned_locked(self, staged_id: str, actor: str, project: str, token_id: str) -> _Stage:
        meta = self._staged.get(staged_id)
        if meta is None or meta.actor != actor or meta.project != project or meta.token_id != token_id:
            raise AssetStageError("unknown stagedId (expired, consumed, or not yours)", 404)
        return meta

    def _gc_locked(self) -> None:
        now = self._clock()
        for staged_id, meta in list(self._staged.items()):
            if meta.expiry <= now and not meta.busy:
                del self._staged[staged_id]
        for token, staged_id in list(self._uploads.items()):
            if staged_id not in self._staged:
                del self._uploads[token]
