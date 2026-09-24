"""The footer stamped on everything the gateway writes into a system people read.

Its presence is what tells a reader that a note, an issue description or a
review comment came through the gateway rather than from the person directly,
so it is not decoration; the audit id in it correlates the write with the
audit log. The issue trackers and the docs review host each used to spell it
out themselves.
"""
from __future__ import annotations

from .memory_backend import RequestContext


def footer(context: RequestContext, *, personal: bool = False) -> str:
    """The stamp. With a personal credential the host already shows the real
    author, so the stamp is trimmed to the audit id -- kept, not dropped, so the
    write is still marked as gateway-mediated. With a shared service credential
    the author is the service account, so the actor is named too."""
    if personal:
        return f"[via mcp-governance-gateway | audit={context.request_id}]"
    return f"[via mcp-governance-gateway | actor={context.actor} | audit={context.request_id}]"
