"""Run operator scripts with isolated files and a scripted HTTP transport."""
import gzip
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class TokenScriptTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.store = self.root / "tokens.json"
        self.archive = self.root / "archive"
        self.snapshot = self.root / "before.json"
        self.rows = [{"token": "test-bearer-a", "actor": "actor-a", "project": "demo"}]
        self.write_store()
        self.env = {**os.environ, "GATEWAY_USER_TOKEN_FILE": str(self.store),
                    "GATEWAY_TOKEN_FILE": "", "TOKEN_BACKUP_DIR": str(self.archive),
                    "GATEWAY_URL": "https://gateway.example.test", "KEEP": "30",
                    "SHRINK_PCT": "25", "PYTHONDONTWRITEBYTECODE": "1"}
        # sitecustomize replaces only the HTTP transport; the real shell and
        # embedded Python still parse files, compare fingerprints and send MCP.
        (self.root / "sitecustomize.py").write_text("""
import io, json, os, urllib.request

def fake_urlopen(request, timeout):
    assert request.full_url == 'https://gateway.example.test/mcp'
    assert request.get_header('Authorization') == 'Bearer test-bearer-a'
    assert json.loads(request.data)['method'] == 'tools/list'
    assert timeout == 20
    with open(os.environ['HTTP_TRACE'], 'w') as handle:
        handle.write('called')
    if os.environ.get('HTTP_REPLY') == 'error':
        return io.BytesIO(b'{"jsonrpc":"2.0","id":1,"error":{"message":"test-bearer-a"}}')
    return io.BytesIO(b'{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}')

urllib.request.urlopen = fake_urlopen
""")
        self.env["PYTHONPATH"] = str(self.root)
        self.env["HTTP_TRACE"] = str(self.root / "http-called")

    def write_store(self):
        self.store.write_text(json.dumps({"tokens": self.rows}))

    def run_script(self, name, *args, **env):
        return subprocess.run(["bash", str(ROOT / "scripts" / name), *args],
                              env={**self.env, **env}, capture_output=True, text=True)

    def backup(self, **env):
        return self.run_script("mcpgw-token-backup.sh", **env)

    def check(self, mode, **env):
        return self.run_script("check-tokens-intact.sh", mode, str(self.snapshot), **env)

    def archives(self):
        return sorted(self.archive.glob("user-tokens-*.json.gz"))

    def test_archive_round_trip_private_and_distinct(self):
        self.assertEqual(self.backup().returncode, 0)
        self.assertEqual(self.backup().returncode, 0)
        self.assertEqual(len(self.archives()), 2)
        for path in self.archives():
            self.assertEqual(json.loads(gzip.decompress(path.read_bytes())), {"tokens": self.rows})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_shrink_refusal_preserves_archives_and_explicit_override(self):
        self.rows *= 4
        self.write_store()
        self.assertEqual(self.backup().returncode, 0)
        before = self.archives()
        self.rows = self.rows[:1]
        self.write_store()
        result = self.backup(KEEP="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("shrank", result.stderr)
        self.assertEqual(self.archives(), before)
        self.assertEqual(self.backup(SHRINK_PCT="100", KEEP="1").returncode, 0)
        self.assertEqual(len(self.archives()), 1)

    def test_invalid_store_and_config_never_publish(self):
        for data in ({"tokens": []}, {"tokens": 5}, {"tokens": [{"token": "test-bearer-a"}]}):
            self.store.write_text(json.dumps(data))
            result = self.backup()
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("test-bearer-a", result.stdout + result.stderr)
        self.write_store()
        for env in ({"KEEP": "0"}, {"KEEP": "-1"}, {"SHRINK_PCT": "101"}):
            self.assertNotEqual(self.backup(**env).returncode, 0)
        self.assertEqual(self.archives(), [])

    def test_corrupt_baseline_falls_back_and_retention_owns_only_its_names(self):
        self.assertEqual(self.backup().returncode, 0)
        good = self.archives()[0]
        good.rename(self.archive / "user-tokens-20000101T000000Z-01.json.gz")
        corrupt = self.archive / "user-tokens-20000102T000000Z-01.json.gz"
        corrupt.write_bytes(b"corrupt")
        recovery = self.archive / "user-tokens-operator-recovery.json.gz"
        recovery.write_bytes(b"keep me")
        result = self.backup(KEEP="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("unusable", result.stderr)
        self.assertEqual(recovery.read_bytes(), b"keep me")
        # new archive + the corrupt one (left in place, never a KEEP slot) + the
        # operator's file; the old good one was the KEEP=1 casualty, by policy
        self.assertEqual(len(self.archives()), 3)
        self.assertTrue(corrupt.exists())

    def test_retention_never_deletes_the_last_readable_archive(self):
        # A corrupt, NEWER file must not take a KEEP slot and push the only good
        # archive out; it is left in place and named, the good one survives.
        self.assertEqual(self.backup().returncode, 0)
        good = self.archives()[0]
        corrupt = self.archive / "user-tokens-99991231T235959Z-01.json.gz"
        corrupt.write_bytes(b"not gzip")
        out = self.backup(KEEP="1", SHRINK_PCT="100")
        self.assertNotEqual(out.returncode, 0)   # the newest name is in the future: refused, nothing pruned
        self.assertTrue(good.exists())
        corrupt.rename(self.archive / "user-tokens-20000101T000000Z-01.json.gz")
        corrupt = self.archive / "user-tokens-20000101T000000Z-01.json.gz"
        out = self.backup(KEEP="1", SHRINK_PCT="100")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("unreadable archive left in place", out.stderr)
        self.assertTrue(corrupt.exists())
        readable = [p for p in self.archives() if p != corrupt]
        self.assertEqual(len(readable), 1)          # KEEP=1 readable: the newest
        self.assertNotEqual(readable[0], good)      # the older good one was the pruned one, by policy

    def test_lock_contention_is_a_refusal_not_a_success(self):
        import fcntl
        self.archive.mkdir(mode=0o700)
        with (self.archive / ".lock").open("a") as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            out = self.backup()
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("holds the lock", out.stderr)
        self.assertEqual(self.archives(), [])

    def test_no_readable_baseline_refuses_blind_archive(self):
        self.archive.mkdir()
        (self.archive / "user-tokens-20000101T000000Z-01.json.gz").write_bytes(b"corrupt")
        self.assertNotEqual(self.backup().returncode, 0)
        self.assertEqual(len(self.archives()), 1)

    def test_snapshot_is_private_secret_free_and_live_verified(self):
        result = self.check("snapshot")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("test-bearer-a", self.snapshot.read_text() + result.stdout + result.stderr)
        self.assertEqual(stat.S_IMODE(self.snapshot.stat().st_mode), 0o600)
        result = self.check("verify")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(Path(self.env["HTTP_TRACE"]).exists())

    def test_verify_probes_one_token_of_each_kind(self):
        # A deploy can break user-token authentication while a static token still
        # works; probing only the first row would have said "ok". Both kinds get a call.
        static = self.root / "static.json"
        static.write_text(json.dumps({"tokens": [{"token": "test-bearer-static", "project": "demo", "actor": "svc"}]}))
        (self.root / "sitecustomize.py").write_text("""
import io, json, os, urllib.request

def fake_urlopen(request, timeout):
    with open(os.environ['HTTP_TRACE'], 'a') as handle:
        handle.write(request.get_header('Authorization') + '\\n')
    if request.get_header('Authorization') == 'Bearer ' + os.environ.get('HTTP_FAIL', '-'):
        return io.BytesIO(b'{"jsonrpc":"2.0","id":1,"error":{"message":"denied"}}')
    return io.BytesIO(b'{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}')

urllib.request.urlopen = fake_urlopen
""")
        self.assertEqual(self.check("snapshot", GATEWAY_TOKEN_FILE=str(static)).returncode, 0)
        out = self.check("verify", GATEWAY_TOKEN_FILE=str(static))
        self.assertEqual(out.returncode, 0, out.stderr)
        probed = Path(self.env["HTTP_TRACE"]).read_text().split()
        self.assertEqual(sorted(probed), ["Bearer", "Bearer", "test-bearer-a", "test-bearer-static"])
        self.assertIn("each kind", out.stdout)
        Path(self.env["HTTP_TRACE"]).unlink()
        # the static token still works, the user token does not: that is a failure
        out = self.check("verify", GATEWAY_TOKEN_FILE=str(static), HTTP_FAIL="test-bearer-a")
        self.assertNotEqual(out.returncode, 0)
        self.assertNotIn("test-bearer-a", out.stdout + out.stderr)

    def test_verify_without_a_gateway_url_skips_the_live_half_and_says_so(self):
        self.assertEqual(self.check("snapshot").returncode, 0)
        out = self.check("verify", GATEWAY_URL="")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("live check skipped", out.stdout)
        self.assertIn("NOT checked", out.stderr)
        self.assertFalse(Path(self.env["HTTP_TRACE"]).exists())

    def test_verify_refuses_replacement_removal_addition_and_claim_change(self):
        self.assertEqual(self.check("snapshot").returncode, 0)
        original = self.rows[0].copy()
        for rows in ([], [{**original, "token": "replacement"}],
                     [original, {**original, "actor": "other"}],
                     [{**original, "roles": ["issue_writer"]}],
                     [{**original, "project": "other"}]):
            self.rows = rows
            self.write_store()
            result = self.check("verify")
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("test-bearer-a", result.stdout + result.stderr)
            self.assertFalse(Path(self.env["HTTP_TRACE"]).exists())

    def test_live_refusal_fails_without_echoing_response(self):
        self.assertEqual(self.check("snapshot").returncode, 0)
        result = self.check("verify", HTTP_REPLY="error")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("test-bearer-a", result.stdout + result.stderr)
        self.assertTrue(Path(self.env["HTTP_TRACE"]).exists())

    def test_snapshot_refuses_missing_empty_or_malformed_stores(self):
        for data in ({"tokens": []}, {"tokens": "bad"}, {"tokens": [{}]}):
            self.store.write_text(json.dumps(data))
            self.assertNotEqual(self.check("snapshot").returncode, 0)
            self.assertFalse(self.snapshot.exists())
        self.store.unlink()
        self.assertNotEqual(self.check("snapshot").returncode, 0)
        self.assertFalse(self.snapshot.exists())

    def test_snapshot_checks_static_store_and_never_overwrites_baseline(self):
        static = self.root / "static.json"
        static.write_text(json.dumps({"tokens": self.rows}))
        self.assertEqual(self.check("snapshot", GATEWAY_TOKEN_FILE=str(static)).returncode, 0)
        original = self.snapshot.read_bytes()
        self.assertNotEqual(self.check("snapshot").returncode, 0)
        self.assertEqual(self.snapshot.read_bytes(), original)
        static.unlink()
        self.assertNotEqual(self.check("verify", GATEWAY_TOKEN_FILE=str(static)).returncode, 0)
