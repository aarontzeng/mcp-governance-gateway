"""The tool registry: one `ToolSpec` per tool, which policy, discovery,
argument validation and dispatch all read from. See `base.py` for the record
and `registry.py` for the list; each family module holds its specs and its
handler."""
from .base import ToolHandler, ToolHost, ToolSpec
from .registry import (
    HANDLERS,
    REGISTRY,
    SPECS_BY_NAME,
    declared_arguments,
    tool_definitions,
    visible_tool_definitions,
    visible_tools,
)

__all__ = [
    "HANDLERS",
    "REGISTRY",
    "SPECS_BY_NAME",
    "ToolHandler",
    "ToolHost",
    "ToolSpec",
    "declared_arguments",
    "tool_definitions",
    "visible_tool_definitions",
    "visible_tools",
]
