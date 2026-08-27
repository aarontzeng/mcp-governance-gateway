# scripts

Standalone helper scripts. They do not require a running gateway.

## `check_owners.py` — commit-time module-ownership enforcement

Enforces per-module ownership using the [find-owners](https://gerrit.googlesource.com/plugins/find-owners/)
format: a commit that touches a path you do not own is rejected unless it
carries a `Cross-Owner: <reason>` trailer (and the path's owner approves at
review). Ownership is read from `OWNERS` files (a root fallback plus per-module
files); an optional `.owners-exempt` lists globs that anyone may edit.

### As a commit-msg hook

```bash
git config core.hooksPath .githooks
cp scripts/check_owners.py .githooks/
cat > .githooks/commit-msg <<'EOF'
#!/bin/sh
python3 "$(git rev-parse --show-toplevel)/scripts/check_owners.py" \
    --staged --message-file "$1" --author "$(git config user.email)" || exit 1
EOF
chmod +x .githooks/commit-msg
```

Note: if the repo already sets `core.hooksPath` (for example to install
Gerrit's `commit-msg` Change-Id hook), that path shadows `.git/hooks`, so chain
to the other hook from your own rather than relying on both.

### Ad hoc

```bash
# check a set of paths against OWNERS as a given author
python3 scripts/check_owners.py --author alice@example.com path/to/file ...
```

The check reads `OWNERS` and `.owners-exempt` from the base tree (not the
proposed change), and in review mode requires an authenticated author, so a
change cannot grant itself ownership in the same commit. Exit status is
non-zero when an owned path is crossed without an approved `Cross-Owner`.
