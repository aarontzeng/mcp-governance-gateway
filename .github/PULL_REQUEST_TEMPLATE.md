**What this changes and why**

**Boundary check** (see [CONTRIBUTING.md](../CONTRIBUTING.md))

- [ ] No tool takes the project/tenant as an argument; results are re-filtered server-side.
- [ ] A new mutating tool goes through the confirmation flow and requires a role.
- [ ] No secrets in code, tests, fixtures, logs or error text.
- [ ] A changed boundary, wire contract or security property comes with an ADR update.
- [ ] `python -m pytest -q` passes; new behaviour has a test that fails without the change.
