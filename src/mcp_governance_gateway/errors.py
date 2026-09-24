"""The one exception shape every backend adapter raises.

Each adapter used to declare its own `XError(Exception)` with the same
`__init__(message, status)`, and two of them (`CiBackendError`,
`ReviewBackendError`) were bare aliases of `IssueBackendError`, so an
`isinstance` check could not tell a CI failure from a tracker one. The error
boundary in `mcp.py` catches this base; the subclasses exist so a caller that
wants to distinguish the source still can.

`status` is the HTTP status the failure should surface as -- the backend's own
where it answered, a gateway-chosen one (404 for "not enabled", 503 for
"unavailable") where it did not, and None for a failure with no better name.
"""
from __future__ import annotations


class BackendError(Exception):
    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status
