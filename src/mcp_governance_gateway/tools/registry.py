"""Every tool the gateway serves, in the order `tools/list` advertises them.

Adding a backend means adding its `ToolSpec`s and `call` in a family module
and listing that module here; policy, discovery and dispatch then know it
without another edit.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from ..auth import Principal
from . import ci, docs, issues, memory
from .base import (
    CI,
    DOCS,
    FEATURE_CI,
    FEATURE_CI_WRITE,
    FEATURE_DOCS,
    FEATURE_DOCS_REVIEW,
    FEATURE_DOCS_STAGE,
    FEATURE_ISSUES,
    ISSUES,
    MEMORY,
    ToolHandler,
    ToolSpec,
)

REGISTRY: tuple[ToolSpec, ...] = memory.TOOLS + issues.TOOLS + docs.TOOLS + ci.TOOLS
SPECS_BY_NAME: Mapping[str, ToolSpec] = {spec.name: spec for spec in REGISTRY}
HANDLERS: Mapping[str, ToolHandler] = {MEMORY: memory.call, ISSUES: issues.call, DOCS: docs.call, CI: ci.call}

assert len(SPECS_BY_NAME) == len(REGISTRY), "two tools share a name"
assert all(spec.name.split(".")[0] == spec.family for spec in REGISTRY), "a tool's prefix must be its family"
assert set(HANDLERS) == {spec.family for spec in REGISTRY}


def tool_definitions() -> list[dict[str, Any]]:
    """Every tool as `tools/list` would advertise it, unfiltered."""
    return [spec.definition for spec in REGISTRY]


def declared_arguments() -> Mapping[str, frozenset[str]]:
    """Tool name -> the argument names its input schema declares."""
    return {spec.name: spec.arguments for spec in REGISTRY}


def visible_tools(principal: Principal, features: Iterable[str]) -> list[ToolSpec]:
    """The tools this principal could actually call, given which deployment
    features are on. Discovery is not a security boundary -- policy re-checks
    every call -- but a tool that cannot succeed should not be offered."""
    enabled = frozenset(features)
    visible: list[ToolSpec] = []
    for spec in REGISTRY:
        if not spec.requires <= enabled:
            continue
        if spec.family == ISSUES and not principal.issue_project:
            continue
        if spec.role is not None and spec.role not in principal.roles:
            continue
        visible.append(spec)
    return visible


def visible_tool_definitions(
    principal: Principal, issue_enabled: bool, docs_enabled: bool = False, ci_enabled: bool = False,
    ci_write_enabled: bool = False, docs_review_enabled: bool = False,
    docs_stage_enabled: bool = False,
) -> list[dict[str, Any]]:
    """`visible_tools` with the features as flags, which is how the gateway
    has always asked."""
    flags = {
        FEATURE_ISSUES: issue_enabled,
        FEATURE_DOCS: docs_enabled,
        FEATURE_DOCS_REVIEW: docs_review_enabled,
        FEATURE_DOCS_STAGE: docs_stage_enabled,
        FEATURE_CI: ci_enabled,
        FEATURE_CI_WRITE: ci_write_enabled,
    }
    features = [name for name, on in flags.items() if on]
    return [spec.definition for spec in visible_tools(principal, features)]
