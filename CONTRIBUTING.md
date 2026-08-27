# Contributing

Thanks for your interest. This project values small, well-reasoned changes over
large ones.

## Development

```bash
pip install -e '.[dev]'      # or: pip install -e . && pip install pytest
python -m pytest -q
```

There is no separate build step — the gateway is pure Python. "Tests pass" is
the bar for a change; every backend has unit tests that drive it through a
scripted fake (see `tests/`), so you can add or change a backend without a live
instance.

## Ground rules

- **Keep the tenancy boundary server-side.** No tool may take the project/tenant
  as an argument. New backend operations must scope to the token's project and
  re-filter results defensively, matching the existing backends.
- **Writes stay confirmation-gated and role-guarded.** A new mutating tool goes
  through the confirmation flow and requires an explicit role.
- **No secrets in code, tests, logs, or error text.** Read them from the
  environment or the keystore; normalize backend errors so they cannot leak
  another tenant's data.
- **Record decisions.** A change to a boundary, a wire contract, or a security
  property should come with (or update) an ADR in `docs/decisions/`.
- **Minimal diffs.** Touch what the change requires; match the surrounding style;
  don't refactor unrelated code in the same commit.

## Adding a backend

Implement the backend's interface (see `issue_backend.py` for the pattern:
public operations, a private project resolver, a normalized output shape),
enable it from configuration in `config.py` and wire it in `server.py`, expose
its tools in `mcp.py`, and cover it with fake-driven tests. A backend must be
inert unless its configuration is present.

## Commit messages

Explain *why*, not just *what*. Reference the ADR a change implements or amends.
