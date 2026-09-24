"""MCP Governance Gateway."""

# The single source of the version: pyproject declares it dynamic and reads
# this attribute, so a release bumps one line (and the CHANGELOG heading, which
# tests/test_repo_hygiene.py holds to the same number). 0.3.0 shipped with this
# still saying 0.2.0, which every MCP client saw in `serverInfo.version`.
__version__ = "0.3.0"
