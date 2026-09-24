"""Argument validation shared by the tool families.

Shape only: a handler checks that a value is the type and size the schema
promised, and the backend owns its meaning (a status this tracker defines, a
path this corpus serves). Every failure is a ValueError, which dispatch turns
into an "invalid params" error and audits as such.
"""
from __future__ import annotations

from typing import Any


def required_text(arguments: dict[str, Any], key: str, max_len: int) -> str:
    value = arguments.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"'{key}' must be a non-empty string")
    if len(value) > max_len:
        raise ValueError(f"'{key}' is too long")
    return value.strip()


def optional_text(arguments: dict[str, Any], key: str, max_len: int) -> str | None:
    value = arguments.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"'{key}' must be a string")
    if len(value) > max_len:
        raise ValueError(f"'{key}' is too long")
    stripped = value.strip()
    return stripped or None


def limit(value: Any, default: int) -> int:
    if value is None:
        return default
    if not isinstance(value, int):
        raise ValueError("'limit' must be an integer")
    if value < 1 or value > 50:
        raise ValueError("'limit' must be between 1 and 50")
    return value


def offset(value: Any) -> int:
    if value is None:
        return 0
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("'offset' must be an integer")
    if value < 0:
        raise ValueError("'offset' must be >= 0")
    return value


def optional_int(arguments: dict[str, Any], key: str, *, minimum: int, maximum: int) -> int | None:
    value = arguments.get(key)
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"'{key}' must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(f"'{key}' must be between {minimum} and {maximum}")
    return value


def confidence(value: Any, default: float = 0.8) -> float:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("'confidence' must be a number between 0 and 1")
    if not 0 <= value <= 1:
        raise ValueError("'confidence' must be between 0 and 1")
    return float(value)


def tags(value: Any) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("'tags' must be a list of strings")
    if len(value) > 20:
        raise ValueError("'tags' must contain at most 20 items")
    return [item.strip() for item in value if item.strip()]


def required_issue_ref(arguments: dict[str, Any], key: str) -> str:
    value = arguments.get(key)
    if isinstance(value, int):
        value = str(value)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"'{key}' must be a non-empty string or integer")
    return value.strip()


def required_change_ref(arguments: dict[str, Any]) -> int:
    """A proposal number: a positive int, validated here because it is spliced
    into a URL path segment on the review host."""
    value = arguments.get("change")
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("'change' must be a positive integer (the proposal number)")
    return value


def planning_fields(arguments: dict[str, Any]) -> dict[str, Any]:
    """startDate / dueDate / priority / parentIssue / category — shared by issues.create and
    issues.update_status.

    Only shape is checked here; the backend owns the meaning (a real calendar date,
    a priority this tracker defines, a parent resolvable inside this project, a
    category name resolvable against that project's live list — categories are
    per-project and member-editable, so there is no fixed enum to validate here).
    """
    planning: dict[str, Any] = {}
    start_date = optional_text(arguments, "startDate", max_len=10)
    if start_date is not None:
        planning["startDate"] = start_date
    due_date = optional_text(arguments, "dueDate", max_len=10)
    if due_date is not None:
        planning["dueDate"] = due_date
    priority = optional_text(arguments, "priority", max_len=60)
    if priority is not None:
        planning["priority"] = priority
    if arguments.get("parentIssue") is not None:
        planning["parentIssue"] = required_issue_ref(arguments, "parentIssue")
    category = optional_text(arguments, "category", max_len=80)
    if category is not None:
        planning["category"] = category
    return planning


def planning_texts(planning: dict[str, Any]) -> list[str]:
    """The planning values as strings, for the secret scan. They are short and
    structured, which is not the same as unable to carry a credential."""
    return [v if isinstance(v, str) else str(v) for v in planning.values()]
