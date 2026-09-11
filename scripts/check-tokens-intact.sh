#!/usr/bin/env bash
# Store continuity alone cannot catch a deploy that changes authentication.
set -euo pipefail
umask 077

python3 - "$@" <<'PYTHON'
import hashlib
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.parse
import urllib.request


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in {"snapshot", "verify"}:
        raise ValueError("usage: check-tokens-intact.sh {snapshot|verify} <snapshot-file>")
    mode, snapshot_path = sys.argv[1:]
    rows = []
    fingerprints = []
    for kind, variable in (("static", "GATEWAY_TOKEN_FILE"), ("user", "GATEWAY_USER_TOKEN_FILE")):
        path = os.environ.get(variable)
        if not path:
            continue
        data = json.loads(Path(path).read_bytes())
        entries = data.get("tokens") if isinstance(data, dict) else None
        if not isinstance(entries, list):
            raise ValueError("invalid token store")
        for row in entries:
            if not isinstance(row, dict) or any(
                not isinstance(row.get(key), str) or not row[key].strip()
                for key in ("token", "actor", "project")
            ):
                raise ValueError("invalid token record")
            rows.append({**row, "_kind": kind})  # kind is for the live check only; the fingerprint above is of the row
            # Include claims: preserving a token but changing its tenant or roles
            # would authenticate the person as a different principal after deploy.
            digest = hashlib.sha256(json.dumps(row, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            fingerprints.append([kind, digest])
    if not rows:
        raise ValueError("no issued tokens in configured stores")
    manifest = {"version": 1, "tokens": sorted(fingerprints)}
    if mode == "snapshot":
        # Refuse overwrite so rerunning a deploy cannot erase its own baseline.
        fd = os.open(snapshot_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(manifest, handle)
            handle.flush()
            os.fsync(handle.fileno())
        print(f"snapshot: {len(rows)} tokens recorded")
        return
    before = json.loads(Path(snapshot_path).read_bytes())
    if before != manifest:
        raise ValueError("issued token or claims changed across deploy")
    base = os.environ.get("GATEWAY_URL", "").rstrip("/")
    if not base:
        # Store continuity is proven; the live half needs a gateway to ask.
        print(f"ok: {len(rows)} tokens unchanged; GATEWAY_URL not set, live authentication NOT checked", file=sys.stderr)
        print(f"ok: {len(rows)} tokens unchanged (live check skipped)")
        return
    parsed = urllib.parse.urlsplit(base)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.query or parsed.fragment:
        raise ValueError("set GATEWAY_URL to the gateway base URL")
    # A redirect must not forward an issued bearer to another endpoint.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    urllib.request.install_opener(urllib.request.build_opener(NoRedirect()))
    # One token of EACH kind: a deploy can break user-token authentication while
    # a static token still works, and the first row alone would have said "ok".
    checked = []
    for kind in ("static", "user"):
        row = next((r for r in rows if r["_kind"] == kind), None)
        if row is None:
            continue
        request = urllib.request.Request(
            base + "/mcp",
            data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}).encode(),
            method="POST",
            headers={"Authorization": "Bearer " + row["token"],
                     "Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
        )
        with urllib.request.urlopen(request, timeout=20) as response:
            reply = json.loads(response.read())
        if not isinstance(reply, dict) or reply.get("id") != 1 or "error" in reply or not isinstance(reply.get("result"), dict) or not isinstance(reply["result"].get("tools"), list):
            raise ValueError(f"pre-existing {kind} token did not receive a successful tools/list response")
        checked.append(kind)
    print(f"ok: {len(rows)} tokens unchanged; a pre-existing token of each kind still authenticates ({', '.join(checked)})")


try:
    main()
except (OSError, ValueError, urllib.error.URLError):
    # Never echo a server body, URL or token-store content on failure.
    sys.exit("token invariant failed: check store/snapshot files, token continuity and live gateway authentication")
PYTHON
