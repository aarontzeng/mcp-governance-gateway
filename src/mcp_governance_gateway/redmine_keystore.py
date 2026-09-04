from __future__ import annotations

import base64
from datetime import datetime, timezone
from enum import Enum
import json
import os
from pathlib import Path
import sys
import tempfile
import threading

try:  # cryptography is a runtime dependency; guard the import so the enum stays importable
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:  # pragma: no cover - only hit when cryptography is absent
    AESGCM = None  # type: ignore[assignment]


class KeyState(Enum):
    MISSING = "missing"  # no personal key stored for this actor -> fallback-eligible
    OK = "ok"  # decrypted successfully
    UNDECRYPTABLE = "undecryptable"  # record present but won't decrypt (corrupt / stale key_id) -> per-user fail-loud
    DEGRADED = "degraded"  # record present, store globally unusable (no master key)


class KeyStoreError(Exception):
    pass


_NONCE_BYTES = 12
_UNSET = object()


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_master_keys(path: str | Path) -> tuple[str | None, dict[str, bytes]]:
    """Load the master-key file.

    Format: ``{"active_key_id": "mk1", "keys": {"mk1": "<base64-of-32-bytes>"}}``.
    Returns ``(active_key_id, {key_id: raw_key})`` — or ``(None, {})`` when the file
    is absent/unreadable/empty, which puts the store in the *degraded* state
    (fallback-for-all, surfaced via ``/healthz`` + audit + a operator banner) rather
    than crashing. Keeping several ids supports master-key rotation: old records
    carry the ``key_id`` they were sealed with and still decrypt after the active
    key rolls forward.
    """
    p = Path(path)
    try:
        mode = p.stat().st_mode
        if mode & 0o077:  # group/other can read this — the master key is the crown jewel
            print(
                f"WARNING: redmine keystore master key {path} is group/other-accessible "
                f"(mode {oct(mode & 0o777)}); it should be 0400.",
                file=sys.stderr,
                flush=True,
            )
    except OSError:
        pass
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None, {}
    if not isinstance(data, dict):
        return None, {}
    keys: dict[str, bytes] = {}
    for kid, b64 in (data.get("keys") or {}).items():
        try:
            raw = _b64d(b64)
        except Exception:
            continue
        if len(raw) == 32:  # AES-256
            keys[str(kid)] = raw
    active = data.get("active_key_id")
    if active not in keys:
        active = next(iter(keys), None)
    return active, keys


class RedmineKeyStore:
    """Per-user Redmine API keys, encrypted at rest (AES-256-GCM), indexed by actor (employee id).

    Owned by the adapter (single UID reads and writes it, so no cross-UID setgid
    dance). Each record is
    ``{"ct": base64(nonce||ciphertext||tag), "key_id": "<mk>", "redmine_login": "...", "updated_at": "..."}``.
    The actor is bound in as AES-GCM associated data, so a record cannot be moved
    to another actor even by someone who can edit the file.
    """

    def __init__(
        self,
        store_path: str | Path,
        active_key_id: str | None = None,
        master_keys: dict[str, bytes] | None = None,
    ) -> None:
        self._path = Path(store_path)
        self._active_key_id = active_key_id
        self._master_keys = dict(master_keys or {})
        self._lock = threading.Lock()
        self._records: dict[str, dict] = {}
        self._sig: object = _UNSET
        self._reload()

    @property
    def degraded(self) -> bool:
        # No usable master key -> cannot decrypt/encrypt anything. Surfaced so ops
        # sees it (healthz/audit/banner) instead of attribution silently reverting.
        return AESGCM is None or self._active_key_id not in self._master_keys

    # --- read path -------------------------------------------------------

    def _current_sig(self) -> tuple | None:
        try:
            st = self._path.stat()
        except OSError:
            return None
        return (st.st_mtime_ns, st.st_size, st.st_ino)

    def _reload(self) -> None:
        sig = self._current_sig()
        if sig == self._sig:
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            recs = data.get("keys") if isinstance(data, dict) else None
            self._records = recs if isinstance(recs, dict) else {}
        except OSError:
            self._records = {}  # absent file -> empty store (everyone MISSING)
        except Exception as exc:
            # keep last-good on a corrupt/partial file; retry on next change -- and say
            # so, because a revoke written into that file has not taken effect.
            print(f"credential store reload failed; keeping the last-good records: {exc}", file=sys.stderr, flush=True)
        self._sig = sig

    @staticmethod
    def _is_legacy_flat(raw: dict) -> bool:
        """A pre-nesting record: one credential stored directly under the actor.

        The `ct` value must be a STRING, not merely present. A nested map is
        `{backend: record}`, so a backend NAMED "ct" would otherwise look exactly
        like a legacy record -- and the consequence is not a wrong read, it is
        silent credential loss: `set()` would rebuild the actor's map from what
        it took to be one legacy record and drop every other backend, which is
        the bug this nesting exists to fix, reintroduced for one backend name.
        A record's `ct` is always a base64 string; a nested map's value is always
        a dict, so the type is what tells them apart.
        """
        return isinstance(raw.get("ct"), str)

    def _get_record(self, actor: str, backend: str) -> dict | None:
        raw = self._records.get(actor)
        if not isinstance(raw, dict):
            return None
        if self._is_legacy_flat(raw):
            if (raw.get("backend") or "redmine") == backend:
                return raw
            return None
        rec = raw.get(backend)
        if isinstance(rec, dict):
            return rec
        return None

    def get(self, actor: str, backend: str = "redmine") -> tuple[KeyState, str | None]:
        self._reload()
        rec = self._get_record(actor, backend)
        if rec is None:
            return KeyState.MISSING, None
        if self.degraded:
            # Master key entirely absent. NOT per-user UNDECRYPTABLE -- one missing
            # shared secret must not storm every user with a fail-loud that names
            # their own key as the problem.
            #
            # DEGRADED rather than MISSING because the two are not the same fact and
            # a caller cannot tell them apart: MISSING means "never enrolled", which
            # is a standing, intended state whose fallback to the shared credential
            # is the whole reason enrolment is optional. This means "HAS a key, and
            # the store cannot use it right now". Collapsing them let an enrolled
            # caller's READS silently revert to the shared credential's visibility
            # during an outage -- a different answer, not a degraded one. Consumers
            # that only branch on OK / UNDECRYPTABLE keep their previous behaviour,
            # which is deliberate: for a WRITE, falling back is degraded-but-honest
            # (the attribution footer still names the real actor), and only the read
            # path has to fail closed. Note the ordering above: a caller with no
            # record has already returned MISSING, so this is reached only when a
            # record exists.
            return KeyState.DEGRADED, None
        master = self._master_keys.get(rec.get("key_id"))
        if master is None:
            return KeyState.UNDECRYPTABLE, None
        try:
            blob = _b64d(rec["ct"])
            nonce, ct = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
            # AAD versioning: legacy entries were bound to the actor alone; entries
            # written with a "backend" field are bound to actor|backend, so a
            # ciphertext cannot be replayed as a different backend's credential.
            aad = (f"{actor}|{backend}" if "backend" in rec else actor).encode("utf-8")
            plaintext = AESGCM(master).decrypt(nonce, ct, aad)
            return KeyState.OK, plaintext.decode("utf-8")
        except Exception:
            return KeyState.UNDECRYPTABLE, None

    def status(self, actor: str, backend: str = "redmine") -> dict:
        state, _ = self.get(actor, backend)
        rec = self._get_record(actor, backend) or {}
        return {
            "hasKey": state is KeyState.OK,
            "state": state.value,
            "redmineLogin": rec.get("login") or rec.get("redmine_login"),
            "degraded": self.degraded,
        }

    # --- write path ------------------------------------------------------

    def set(self, actor: str, plaintext: str, redmine_login: str | None, backend: str = "redmine") -> None:
        if self.degraded:
            raise KeyStoreError("keystore master key unavailable")
        master = self._master_keys[self._active_key_id]  # type: ignore[index]
        nonce = os.urandom(_NONCE_BYTES)
        # New entries always carry the backend and use the versioned AAD (see get);
        # re-enrolling upgrades a legacy entry in place.
        aad = f"{actor}|{backend}".encode("utf-8")
        ct = AESGCM(master).encrypt(nonce, plaintext.encode("utf-8"), aad)
        record = {
            "ct": _b64e(nonce + ct),
            "key_id": self._active_key_id,
            "backend": backend,
            "login": redmine_login,
            "redmine_login": redmine_login,  # rollback compat: old adapters read this name
            "updated_at": _utc_now(),
        }
        with self._lock:
            self._reload()
            records = dict(self._records)
            raw = records.get(actor)
            if isinstance(raw, dict) and self._is_legacy_flat(raw):
                legacy_backend = raw.get("backend") or "redmine"
                actor_map = {legacy_backend: raw}
            elif isinstance(raw, dict):
                actor_map = dict(raw)
            else:
                actor_map = {}
            actor_map[backend] = record
            records[actor] = actor_map
            self._atomic_write(records)

    def clear(self, actor: str, backend: str = "redmine") -> bool:
        with self._lock:
            self._reload()
            if actor not in self._records:
                return False
            raw = self._records[actor]
            if not isinstance(raw, dict):
                records = dict(self._records)
                records.pop(actor, None)
                self._atomic_write(records)
                return True
            records = dict(self._records)
            if self._is_legacy_flat(raw):
                legacy_backend = raw.get("backend") or "redmine"
                if legacy_backend != backend:
                    return False
                records.pop(actor, None)
                self._atomic_write(records)
                return True
            if backend not in raw:
                return False
            actor_map = dict(raw)
            actor_map.pop(backend, None)
            if not actor_map:
                records.pop(actor, None)
            else:
                records[actor] = actor_map
            self._atomic_write(records)
            return True

    def _atomic_write(self, records: dict[str, dict]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self._path.parent), prefix=".rk-", suffix=".tmp")
        try:
            os.fchmod(fd, 0o640)  # tighten before writing so it is never briefly world-readable
            with os.fdopen(fd, "w") as f:
                json.dump({"keys": records}, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self._path)  # atomic; new inode -> reload detects it
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        self._records = records
        self._sig = self._current_sig()
