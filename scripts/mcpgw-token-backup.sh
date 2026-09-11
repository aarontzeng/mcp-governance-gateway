#!/usr/bin/env bash
# A separate daily archive survives repeated minter writes during an incident.
set -euo pipefail
umask 077

python3 - "${1:-${GATEWAY_USER_TOKEN_FILE:-}}" "${2:-${TOKEN_BACKUP_DIR:-}}" "${KEEP:-30}" "${SHRINK_PCT:-25}" <<'PYTHON'
import fcntl
import gzip
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time


def rows_of(data):
    rows = data.get("tokens") if isinstance(data, dict) else None
    if not isinstance(rows, list) or not rows:
        raise ValueError("expected a non-empty tokens list")
    for row in rows:
        if not isinstance(row, dict) or any(
            not isinstance(row.get(key), str) or not row[key].strip()
            for key in ("token", "actor", "project")
        ):
            raise ValueError("a record is missing token, actor or project")
    return rows


def main():
    source, destination, keep, pct = sys.argv[1:]
    if not source or not destination:
        raise ValueError("usage: mcpgw-token-backup.sh <store> <archive-directory> (or set GATEWAY_USER_TOKEN_FILE and TOKEN_BACKUP_DIR)")
    keep, pct = int(keep), int(pct)
    if keep < 1 or not 0 <= pct <= 100:
        raise ValueError("KEEP must be positive and SHRINK_PCT must be between 0 and 100")
    dest = Path(destination)
    dest.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (dest / ".lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            # A refusal, not a success: cron mail must say the archive did not run.
            sys.exit("another archive run holds the lock; skipping (exit 75)")
        # Validate and archive the same bytes even if the minter replaces its file.
        snapshot = Path(source).read_bytes()
        rows = rows_of(json.loads(snapshot))
        pattern = re.compile(r"user-tokens-\d{8}T\d{6}Z-\d{2}\.json\.gz")

        def archives():
            return sorted((p for p in dest.iterdir() if pattern.fullmatch(p.name)), reverse=True)

        previous = None
        existing = archives()
        for path in existing:
            try:
                previous = rows_of(json.loads(gzip.decompress(path.read_bytes())))
                break
            except (OSError, ValueError, EOFError):
                print("WARNING: an archive is unusable; trying the previous one", file=sys.stderr)
        if existing and previous is None:
            raise ValueError("no readable baseline; refusing to archive blind")
        if previous and len(rows) < len(previous) * (100 - pct) / 100:
            raise ValueError("store shrank beyond SHRINK_PCT; investigate before overriding with SHRINK_PCT=100")

        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        if existing and existing[0].name > f"user-tokens-{stamp}-99.json.gz":
            raise ValueError("archive timestamp is in the future; check the clock before archiving")
        fd, temporary = tempfile.mkstemp(prefix=".writing-", dir=dest)
        try:
            with os.fdopen(fd, "wb") as handle:
                with gzip.GzipFile(fileobj=handle, mode="wb") as compressed:
                    compressed.write(snapshot)
                handle.flush()
                os.fsync(handle.fileno())
            rows_of(json.loads(gzip.decompress(Path(temporary).read_bytes())))
            # Publish only complete data, without clobbering another run's name.
            for sequence in range(1, 100):
                output = dest / f"user-tokens-{stamp}-{sequence:02d}.json.gz"
                try:
                    os.link(temporary, output)
                    break
                except FileExistsError:
                    continue
            else:
                raise ValueError("all archive names for this second are occupied")
        finally:
            os.unlink(temporary)
        directory_fd = os.open(dest, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        # Operator recovery files and unpublished partials are never retention candidates,
        # and neither is anything unreadable: a corrupt archive must not consume a KEEP
        # slot and push the last good one out. Only readable archives count and only
        # readable ones are pruned; the rest are left in place and named on stderr.
        readable = []
        for path in archives():
            try:
                rows_of(json.loads(gzip.decompress(path.read_bytes())))
                readable.append(path)
            except (OSError, ValueError, EOFError):
                print(f"WARNING: unreadable archive left in place: {path.name}", file=sys.stderr)
        for stale in readable[keep:]:
            stale.unlink()
        print(f"archived {len(rows)} token records")


try:
    main()
except (OSError, ValueError, EOFError):
    # JSON and filesystem exceptions can contain secrets from malformed input.
    sys.exit("token backup failed: invalid store/configuration, unreadable archive, or store shrank; check paths, KEEP and SHRINK_PCT")
PYTHON
