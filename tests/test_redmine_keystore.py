from __future__ import annotations

import base64
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from mcp_governance_gateway.audit import ListAuditSink
from mcp_governance_gateway.auth import Principal
from mcp_governance_gateway.internal_api import InternalApi
from mcp_governance_gateway.issue_backend import IssueBackendError, RedmineHttpBackend
from mcp_governance_gateway.memory_backend import RequestContext
from mcp_governance_gateway.redmine_keystore import (
    KeyState,
    KeyStoreError,
    RedmineKeyStore,
    load_master_keys,
)

_ACTOR = "10000001"


def _mk(n=1):
    return {f"mk{i}": os.urandom(32) for i in range(1, n + 1)}


def _ctx(actor=_ACTOR, issue_project="proj-x"):
    return RequestContext(actor=actor, project="p", client="t", request_id="req-1", issue_project=issue_project)


class RedmineKeyStoreTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = Path(self.dir) / "redmine-keys.json"
        self.keys = _mk(2)  # mk1 + mk2, reused across reopened instances

    def store(self, master_keys=None, active="mk1"):
        return RedmineKeyStore(
            self.path,
            active_key_id=active,
            master_keys=self.keys if master_keys is None else master_keys,
        )

    def test_roundtrip_ok(self):
        ks = self.store()
        ks.set(_ACTOR, "secretkey", "jdoe")
        state, key = ks.get(_ACTOR)
        self.assertIs(state, KeyState.OK)
        self.assertEqual(key, "secretkey")
        self.assertEqual(ks.status(_ACTOR)["redmineLogin"], "jdoe")

    def test_missing_for_unknown_actor(self):
        ks = self.store()
        self.assertEqual(ks.get("nobody"), (KeyState.MISSING, None))

    def test_ciphertext_is_not_plaintext_on_disk(self):
        ks = self.store()
        ks.set(_ACTOR, "topsecret", "jdoe")
        raw = self.path.read_text()
        self.assertNotIn("topsecret", raw)

    def test_undecryptable_on_tamper(self):
        ks = self.store()
        ks.set(_ACTOR, "secretkey", "jdoe")
        data = json.loads(self.path.read_text())
        blob = base64.b64decode(data["keys"][_ACTOR]["redmine"]["ct"])
        data["keys"][_ACTOR]["redmine"]["ct"] = base64.b64encode(blob[:-1] + bytes([blob[-1] ^ 0xFF])).decode()
        self.path.write_text(json.dumps(data))
        state, key = self.store().get(_ACTOR)  # same master, fresh instance re-reads the file
        self.assertIs(state, KeyState.UNDECRYPTABLE)
        self.assertIsNone(key)

    def test_record_cannot_be_moved_to_another_actor(self):
        # AAD binds ciphertext to the actor: relabelling the record fails to decrypt.
        ks = self.store()
        ks.set(_ACTOR, "secretkey", "jdoe")
        data = json.loads(self.path.read_text())
        data["keys"]["99999999"] = data["keys"].pop(_ACTOR)
        self.path.write_text(json.dumps(data))
        self.assertIs(self.store().get("99999999")[0], KeyState.UNDECRYPTABLE)

    def test_master_key_rotation_keeps_old_records_readable(self):
        self.store(active="mk1").set(_ACTOR, "secretkey", "jdoe")  # sealed with mk1
        state, key = self.store(active="mk2").get(_ACTOR)  # active rolled to mk2; mk1 still present
        self.assertIs(state, KeyState.OK)
        self.assertEqual(key, "secretkey")

    def test_degraded_when_master_absent(self):
        self.store().set(_ACTOR, "secretkey", "jdoe")  # write with a master
        ks = self.store(master_keys={}, active=None)  # reopen with NO master keys
        self.assertTrue(ks.degraded)
        # A present record is DEGRADED, not per-user UNDECRYPTABLE (one missing shared
        # secret must not blame every user's own key) and not MISSING either -- this
        # caller HAS a key. It read MISSING once, and that collapse is what let an
        # enrolled caller's reads silently revert to the shared credential.
        self.assertEqual(ks.get(_ACTOR), (KeyState.DEGRADED, None))
        self.assertTrue(ks.status(_ACTOR)["degraded"])
        self.assertEqual(ks.status(_ACTOR)["state"], "degraded")
        # THE discriminator: a caller who never enrolled is still MISSING while
        # degraded, so the optional-enrolment fallback is untouched. If this ever
        # reads DEGRADED, every unenrolled caller loses reads during an outage.
        self.assertEqual(ks.get("99999999"), (KeyState.MISSING, None))
        with self.assertRaises(KeyStoreError):
            ks.set(_ACTOR, "x", "jdoe")

    def test_clear(self):
        ks = self.store(_mk(1))
        ks.set(_ACTOR, "secretkey", "jdoe")
        self.assertTrue(ks.clear(_ACTOR))
        self.assertEqual(ks.get(_ACTOR), (KeyState.MISSING, None))
        self.assertFalse(ks.clear(_ACTOR))  # idempotent

    def test_a_corrupt_write_keeps_the_last_good_records_and_says_so(self):
        # A bad save must not lock everyone out -- and must not be silent either,
        # because a revoke written into that file has not taken effect.
        ks = self.store()
        ks.set(_ACTOR, "secretkey", "jdoe")
        self.path.write_text("{ not valid json", encoding="utf-8")
        future = os.stat(self.path).st_mtime + 5
        os.utime(self.path, (future, future))
        with contextlib.redirect_stderr(io.StringIO()) as err:
            state, key = ks.get(_ACTOR)
        self.assertEqual((state, key), (KeyState.OK, "secretkey"))
        self.assertIn("credential store reload failed", err.getvalue())
        self.assertNotIn("secretkey", err.getvalue())

    def test_nonce_unique_for_same_plaintext(self):
        ks = self.store()
        ks.set(_ACTOR, "same", "jdoe")
        ct1 = json.loads(self.path.read_text())["keys"][_ACTOR]["redmine"]["ct"]
        ks.set(_ACTOR, "same", "jdoe")
        ct2 = json.loads(self.path.read_text())["keys"][_ACTOR]["redmine"]["ct"]
        self.assertNotEqual(ct1, ct2)  # fresh random nonce each write

    def test_load_master_keys_roundtrip_and_absent(self):
        f = Path(self.dir) / "master.json"
        f.write_text(json.dumps({"active_key_id": "mk1", "keys": {"mk1": base64.b64encode(os.urandom(32)).decode()}}))
        active, keys = load_master_keys(f)
        self.assertEqual(active, "mk1")
        self.assertIn("mk1", keys)
        self.assertEqual((None, {}), load_master_keys(Path(self.dir) / "nope.json"))


class _FakeRequestBackend(RedmineHttpBackend):
    """RedmineHttpBackend with _request stubbed so we can assert per-call key routing."""

    def __init__(self, **kw):
        super().__init__(base_url="http://redmine.internal", api_key="SVCKEY", **kw)
        self.calls: list[tuple[str, str, str | None]] = []
        self.mutate_status: int | None = None  # set to 401/403 to simulate a failing write

    def _request(self, method, path, *, params=None, body=None, api_key=None):
        key = api_key if api_key is not None else self._api_key
        self.calls.append((method, path, key))
        self.last_body = body
        if "/projects/" in path:
            return {"project": {"id": 1}}
        if path.startswith("/issues/") and method == "GET":
            return {"issue": {"id": 5, "project": {"id": 1}}}
        if path == "/users/current.json":
            return {"user": {"id": 7, "login": "jdoe", "mail": "jdoe@example.com"}}
        if method in ("PUT", "POST"):
            if self.mutate_status is not None:
                raise IssueBackendError(f"HTTP {self.mutate_status}", status=self.mutate_status)
            return {"issue": {"id": 5, "project": {"id": 1}}}
        return {}


class PerCallKeyRoutingTests(unittest.TestCase):
    def _resolver(self, state, key="PERSONAL"):
        return lambda actor: (state, key if state is KeyState.OK else None)

    def test_personal_key_used_for_the_mutation_and_trims_footer(self):
        b = _FakeRequestBackend(key_resolver=self._resolver(KeyState.OK))
        b.add_note("5", "hello", _ctx())
        put = [c for c in b.calls if c[0] == "PUT"][0]
        self.assertEqual(put[2], "PERSONAL")  # mutation uses the personal key
        # Project resolution is the only call left on the shared key. This once
        # asserted every GET was shared, which is what let a write keep failing on
        # the service account's memberships after reads were fixed -- the
        # verification GET now runs on the writer's own key.
        resolves = [c for c in b.calls if "/projects/" in c[1]]
        self.assertTrue(all(c[2] == "SVCKEY" for c in resolves), b.calls)
        verifies = [c for c in b.calls if c[0] == "GET" and "/issues/" in c[1]]
        self.assertTrue(verifies and all(c[2] == "PERSONAL" for c in verifies), b.calls)
        note = b.last_body["issue"]["notes"]
        self.assertIn("audit=", note)
        self.assertNotIn("actor=", note)  # trimmed footer for personal writes

    def test_missing_optional_falls_back_to_shared_with_full_footer(self):
        b = _FakeRequestBackend(key_resolver=self._resolver(KeyState.MISSING), enforce_personal=False)
        b.add_note("5", "hello", _ctx())
        put = [c for c in b.calls if c[0] == "PUT"][0]
        self.assertEqual(put[2], "SVCKEY")
        self.assertIn("actor=10000001", b.last_body["issue"]["notes"])  # full footer on fallback

    def test_missing_enforced_fails_loud(self):
        b = _FakeRequestBackend(key_resolver=self._resolver(KeyState.MISSING), enforce_personal=True)
        with self.assertRaises(IssueBackendError) as cm:
            b.add_note("5", "hello", _ctx())
        self.assertEqual(cm.exception.status, 428)
        self.assertFalse([c for c in b.calls if c[0] == "PUT"])  # never reached the write

    def test_undecryptable_always_fails_loud(self):
        for enforce in (False, True):
            b = _FakeRequestBackend(key_resolver=self._resolver(KeyState.UNDECRYPTABLE), enforce_personal=enforce)
            with self.assertRaises(IssueBackendError) as cm:
                b.update_status("5", "RESOLVED", None, _ctx())
            self.assertEqual(cm.exception.status, 409)

    def test_personal_write_401_and_403_get_distinct_messages(self):
        for code in (401, 403):
            b = _FakeRequestBackend(key_resolver=self._resolver(KeyState.OK))
            b.mutate_status = code
            with self.assertRaises(IssueBackendError) as cm:
                b.add_note("5", "hi", _ctx())
            self.assertEqual(cm.exception.status, code)

    def test_no_resolver_uses_shared_key(self):
        b = _FakeRequestBackend()  # key_resolver=None
        b.add_note("5", "hi", _ctx())
        self.assertTrue(all(c[2] == "SVCKEY" for c in b.calls))

    def test_enforced_without_resolver_fails_loud(self):
        # H1: enforced mode + no key store must NOT silently fall back to the shared key.
        b = _FakeRequestBackend(enforce_personal=True)  # key_resolver=None
        with self.assertRaises(IssueBackendError) as cm:
            b.add_note("5", "hi", _ctx())
        self.assertEqual(cm.exception.status, 428)
        self.assertEqual(b.calls, [])  # never touched Redmine


class VerifyKeyHeaderTests(unittest.TestCase):
    def test_key_goes_in_header_never_url(self):
        captured = {}

        class _Resp:
            def read(self, *a):
                return b'{"user":{"id":1,"login":"jdoe","mail":"a@example.com"}}'

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def router(req, timeout=None):
            captured["url"] = req.full_url
            captured["headers"] = {k.lower(): v for k, v in req.header_items()}
            return _Resp()

        import mcp_governance_gateway.issue_backend as ib

        original = ib.request.urlopen
        ib.request.urlopen = router
        try:
            RedmineHttpBackend(base_url="http://redmine.internal/redmine", api_key="SVC").verify_key("SECRETKEY")
        finally:
            ib.request.urlopen = original
        self.assertNotIn("SECRETKEY", captured["url"])  # never in the URL/query (would leak to access logs)
        self.assertEqual(captured["headers"].get("x-redmine-api-key"), "SECRETKEY")


class InternalApiTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.ks = RedmineKeyStore(Path(self.dir) / "k.json", active_key_id="mk1", master_keys=_mk(1))
        self.backend = _FakeRequestBackend(key_resolver=self.ks.get)
        self.audit = ListAuditSink()
        self.api = InternalApi(self.ks, self.backend, self.audit)

    def _p(self, email="jdoe@example.com"):
        return Principal(actor=_ACTOR, project="p", roles=("issue_writer",), token_id="t", issue_project="proj-x", email=email)

    def test_set_key_email_match_ok(self):
        status, payload = self.api.set_key(self._p(), "PERSONAL")
        self.assertEqual(status, 200)
        self.assertEqual(payload["redmineLogin"], "jdoe")
        self.assertIs(self.ks.get(_ACTOR)[0], KeyState.OK)

    def test_set_key_email_mismatch_rejected(self):
        status, payload = self.api.set_key(self._p(email="someone-else@example.com"), "PERSONAL")
        self.assertEqual(status, 403)
        self.assertIs(self.ks.get(_ACTOR)[0], KeyState.MISSING)  # not stored

    def test_set_key_invalid_key_rejected(self):
        self.backend._request = lambda *a, **k: (_ for _ in ()).throw(IssueBackendError("HTTP 401", status=401))
        status, _ = self.api.set_key(self._p(), "BAD")
        self.assertEqual(status, 400)

    def test_my_issues_gated_on_key(self):
        s, payload = self.api.my_issues(self._p())
        self.assertFalse(payload["hasKey"])  # no key set yet
        self.assertEqual(self.backend.calls, [])  # never queried Redmine without a personal key
        self.api.set_key(self._p(), "PERSONAL")
        self.backend.calls.clear()
        s, payload = self.api.my_issues(self._p())
        self.assertTrue(payload["hasKey"])
        issue_calls = [c for c in self.backend.calls if c[1] == "/issues.json"]
        # the me-scoped query must run on the PERSONAL key, never the shared service key
        self.assertTrue(issue_calls and all(c[2] == "PERSONAL" for c in issue_calls))

    def test_clear_and_status(self):
        self.api.set_key(self._p(), "PERSONAL")
        self.assertTrue(self.api.status(self._p())[1]["hasKey"])
        self.api.clear_key(self._p())
        self.assertFalse(self.api.status(self._p())[1]["hasKey"])


if __name__ == "__main__":
    unittest.main()


class BackendDimensionTests(unittest.TestCase):
    """The store gained a backend dimension (roadmap Phase 9). Legacy entries
    (no 'backend' field, AAD = actor alone) must keep decrypting, and a
    credential enrolled for one backend must never read as another's."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = Path(self.dir) / "keys.json"
        self.keys = _mk(1)

    def store(self):
        return RedmineKeyStore(self.path, active_key_id="mk1", master_keys=self.keys)

    def _write_legacy_entry(self, actor, plaintext):
        """Craft a pre-rename record: AAD = actor, no 'backend' field."""
        import json as _json
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _A
        nonce = os.urandom(12)
        ct = _A(self.keys["mk1"]).encrypt(nonce, plaintext.encode(), actor.encode())
        rec = {"ct": base64.b64encode(nonce + ct).decode(), "key_id": "mk1",
               "redmine_login": "old.login", "updated_at": "2026-07-01T00:00:00Z"}
        self.path.write_text(_json.dumps({"keys": {actor: rec}}))

    def test_legacy_entry_still_decrypts_as_redmine(self):
        self._write_legacy_entry("10000000", "OLD-REDMINE-KEY")
        st = self.store()
        state, key = st.get("10000000")  # default backend=redmine
        self.assertIs(state, KeyState.OK)
        self.assertEqual(key, "OLD-REDMINE-KEY")
        self.assertEqual(st.status("10000000")["redmineLogin"], "old.login")

    def test_legacy_entry_is_not_a_gitlab_credential(self):
        self._write_legacy_entry("10000000", "OLD-REDMINE-KEY")
        state, key = self.store().get("10000000", backend="gitlab")
        self.assertIs(state, KeyState.MISSING)
        self.assertIsNone(key)

    def test_gitlab_entry_roundtrip_and_isolation(self):
        st = self.store()
        st.set("10000000", "GITLAB-PAT", "alice", backend="gitlab")
        state, key = st.get("10000000", backend="gitlab")
        self.assertIs(state, KeyState.OK)
        self.assertEqual(key, "GITLAB-PAT")
        # the same record is NOT a redmine credential
        state, key = st.get("10000000")  # backend=redmine
        self.assertIs(state, KeyState.MISSING)

    def test_tampered_backend_field_fails_undecryptable(self):
        # flipping the stored backend label must not re-purpose the ciphertext:
        # the AAD binds actor|backend, so decryption fails closed
        import json as _json
        st = self.store()
        st.set("10000000", "GITLAB-PAT", "alice", backend="gitlab")
        data = _json.loads(self.path.read_text())
        data["keys"]["10000000"]["redmine"] = data["keys"]["10000000"].pop("gitlab")
        self.path.write_text(_json.dumps(data))
        state, key = self.store().get("10000000")  # now claims to be redmine
        self.assertIs(state, KeyState.UNDECRYPTABLE)
        self.assertIsNone(key)

    def test_reenroll_upgrades_legacy_to_versioned_aad(self):
        self._write_legacy_entry("10000000", "OLD")
        st = self.store()
        st.set("10000000", "NEW-REDMINE-KEY", "alice")  # re-enroll (backend=redmine)
        import json as _json
        rec = _json.loads(self.path.read_text())["keys"]["10000000"]
        self.assertEqual(rec["redmine"]["backend"], "redmine")
        state, key = self.store().get("10000000")
        self.assertEqual((state, key), (KeyState.OK, "NEW-REDMINE-KEY"))


class PerBackendRecordTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = Path(self.dir) / "keys.json"
        self.keys = _mk(1)

    def store(self):
        return RedmineKeyStore(self.path, active_key_id="mk1", master_keys=self.keys)

    def _write_legacy_entry(self, actor, plaintext, backend=None):
        """Craft a pre-nested legacy flat record."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _A
        nonce = os.urandom(12)
        aad = (f"{actor}|{backend}" if backend else actor).encode()
        ct = _A(self.keys["mk1"]).encrypt(nonce, plaintext.encode(), aad)
        rec = {
            "ct": base64.b64encode(nonce + ct).decode(),
            "key_id": "mk1",
            "redmine_login": f"login-{actor}",
            "updated_at": "2026-07-01T00:00:00Z",
        }
        if backend:
            rec["backend"] = backend
        return rec

    def test_one_actor_holds_redmine_and_gitlab_keys_simultaneously_and_both_decrypt(self):
        # An actor can hold credentials for multiple distinct backends without collision.
        st = self.store()
        st.set(_ACTOR, "REDMINE-KEY", "alice", backend="redmine")
        st.set(_ACTOR, "GITLAB-TOKEN", "alice", backend="gitlab")
        state_r, key_r = st.get(_ACTOR, backend="redmine")
        self.assertIs(state_r, KeyState.OK)
        self.assertEqual(key_r, "REDMINE-KEY")
        state_g, key_g = st.get(_ACTOR, backend="gitlab")
        self.assertIs(state_g, KeyState.OK)
        self.assertEqual(key_g, "GITLAB-TOKEN")

    def test_enrolling_second_backend_does_not_destroy_first_backend_key(self):
        # Regression check: in the flat format, set() overwrote the actor's only slot.
        st = self.store()
        st.set(_ACTOR, "REDMINE-KEY", "alice", backend="redmine")
        st.set(_ACTOR, "GITLAB-TOKEN", "alice", backend="gitlab")
        reopened = self.store()
        state, key = reopened.get(_ACTOR, backend="redmine")
        self.assertIs(state, KeyState.OK)
        self.assertEqual(key, "REDMINE-KEY")

    def test_clearing_one_backend_leaves_other_backend_intact(self):
        # clear() must clear only the target backend rather than the entire actor.
        st = self.store()
        st.set(_ACTOR, "REDMINE-KEY", "alice", backend="redmine")
        st.set(_ACTOR, "GITLAB-TOKEN", "alice", backend="gitlab")
        self.assertTrue(st.clear(_ACTOR, backend="redmine"))
        state_r, key_r = st.get(_ACTOR, backend="redmine")
        self.assertIs(state_r, KeyState.MISSING)
        self.assertIsNone(key_r)
        state_g, key_g = st.get(_ACTOR, backend="gitlab")
        self.assertIs(state_g, KeyState.OK)
        self.assertEqual(key_g, "GITLAB-TOKEN")

    def test_clearing_last_backend_removes_actor_from_disk_entirely(self):
        # Avoid leaving empty actor maps {"<actor>": {}} in the persistent store file.
        st = self.store()
        st.set(_ACTOR, "REDMINE-KEY", "alice", backend="redmine")
        st.set(_ACTOR, "GITLAB-TOKEN", "alice", backend="gitlab")
        self.assertTrue(st.clear(_ACTOR, backend="redmine"))
        raw = json.loads(self.path.read_text())
        self.assertIn(_ACTOR, raw["keys"])
        self.assertIn("gitlab", raw["keys"][_ACTOR])
        self.assertNotIn("redmine", raw["keys"][_ACTOR])
        self.assertTrue(st.clear(_ACTOR, backend="gitlab"))
        raw = json.loads(self.path.read_text())
        self.assertNotIn(_ACTOR, raw["keys"])
        self.assertFalse(st.clear(_ACTOR, backend="gitlab"))

    def test_legacy_flat_shape_file_is_read_for_own_backend_and_missing_for_others(self):
        # On-disk files written prior to per-backend indexing must remain readable forever.
        rec = self._write_legacy_entry(_ACTOR, "LEGACY-REDMINE-KEY")
        self.path.write_text(json.dumps({"keys": {_ACTOR: rec}}))
        st = self.store()
        state_r, key_r = st.get(_ACTOR, backend="redmine")
        self.assertIs(state_r, KeyState.OK)
        self.assertEqual(key_r, "LEGACY-REDMINE-KEY")
        self.assertEqual(st.status(_ACTOR, backend="redmine")["redmineLogin"], f"login-{_ACTOR}")
        state_g, key_g = st.get(_ACTOR, backend="gitlab")
        self.assertIs(state_g, KeyState.MISSING)
        self.assertIsNone(key_g)

    def test_legacy_file_upgraded_to_nested_on_write_and_other_actors_untouched(self):
        # Writing for an actor converts that actor's slot to nested format without modifying others.
        rec1 = self._write_legacy_entry("10000001", "ACTOR1-OLD-KEY")
        rec2 = self._write_legacy_entry("10000002", "ACTOR2-OLD-KEY")
        self.path.write_text(json.dumps({"keys": {"10000001": rec1, "10000002": rec2}}))
        st = self.store()
        st.set("10000001", "ACTOR1-GITLAB-TOKEN", "alice", backend="gitlab")
        raw = json.loads(self.path.read_text())
        # Actor 1 is upgraded to nested shape holding both the preserved legacy redmine key and new gitlab key
        self.assertIn("ct", raw["keys"]["10000001"]["redmine"])
        self.assertIn("ct", raw["keys"]["10000001"]["gitlab"])
        # Actor 2 remains in legacy flat shape untouched
        self.assertIn("ct", raw["keys"]["10000002"])
        self.assertNotIn("redmine", raw["keys"]["10000002"])
        # All credentials decrypt correctly
        self.assertEqual(st.get("10000001", backend="redmine"), (KeyState.OK, "ACTOR1-OLD-KEY"))
        self.assertEqual(st.get("10000001", backend="gitlab"), (KeyState.OK, "ACTOR1-GITLAB-TOKEN"))
        self.assertEqual(st.get("10000002", backend="redmine"), (KeyState.OK, "ACTOR2-OLD-KEY"))

    def test_a_backend_named_ct_is_not_mistaken_for_a_legacy_record(self):
        # A nested map is {backend: record}, and a LEGACY record is a record --
        # so a backend literally named "ct" made the two indistinguishable if
        # legacy detection only asked whether the key was present. The
        # consequence was not a wrong read: `set()` rebuilt the actor's map from
        # what it took to be one legacy record and DROPPED every other backend,
        # which is the exact bug this nesting exists to prevent, reintroduced for
        # one backend name. A record's `ct` is a base64 string; a nested map's
        # value is a dict, so the TYPE is what tells them apart.
        st = self.store()
        st.set(_ACTOR, "SECRET-FOR-CT", "alice", backend="ct")
        self.assertEqual(self.store().get(_ACTOR, backend="ct"), (KeyState.OK, "SECRET-FOR-CT"))

        self.store().set(_ACTOR, "SECRET-FOR-REDMINE", "alice", backend="redmine")
        self.assertEqual(self.store().get(_ACTOR, backend="ct"), (KeyState.OK, "SECRET-FOR-CT"))
        self.assertEqual(self.store().get(_ACTOR, backend="redmine"), (KeyState.OK, "SECRET-FOR-REDMINE"))

        self.assertTrue(self.store().clear(_ACTOR, backend="ct"))
        self.assertEqual(self.store().get(_ACTOR, backend="redmine"), (KeyState.OK, "SECRET-FOR-REDMINE"))
