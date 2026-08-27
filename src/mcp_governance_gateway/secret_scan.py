"""Server-side secret-pattern scan for team-visible writes (memory / issues).

Shared memory and issue text are team-visible and append-only -- an agent that
writes a credential there cannot take it back. Agent guidelines routinely forbid
storing secrets, but guidance is advice to a model; this makes the same rule hold
against a model that ignores it.

High-precision patterns only: a false reject costs one reworded write, but a
pattern that fires on ordinary engineering prose (env-var NAMES, redacted
examples, ``api_key=<from-env>``) would train agents to ignore the error. So
every pattern anchors on a value-shaped blob, never on a keyword alone.

Scoped to these two stores on purpose. Somewhere a write lands in front of a
human reviewer, or in a document that legitimately discusses credential formats,
the false-positive cost inverts and this check does not belong.
"""

from __future__ import annotations

import re

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private key (PEM)", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("GitLab personal access token", re.compile(r"\bglpat-[0-9A-Za-z_\-]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("sk-style API key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}\b")),
    # A literal "Bearer <blob>" header value. "Bearer <token>" placeholders
    # don't match: '<' is outside the value charset.
    ("bearer token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9_\-.=]{20,}")),
    # key=value / key: value where the key names a credential AND the value looks
    # like one: an UNBROKEN 16+ character run containing at least one digit.
    #
    # The run is what separates a credential from prose. Allowing separators
    # inside it rejected ordinary engineering text -- `token: rotation-window-
    # 2026-08-01` and `password: see-vault-entry-4210` are 16+ characters with a
    # digit, and both were rejected before this was tightened. A credential is a
    # blob; a sentence is words with punctuation between them. Placeholders
    # ($VAR, <from-env>, {{tpl}}) and bare variable names still do not match.
    #
    # BOUNDARY: a hyphen-separated value therefore does NOT match, so a UUID used
    # as a password is a deliberate false negative. Admitting it would mean
    # admitting every hyphenated phrase with a digit, which is the failure this
    # check cannot afford (see the module docstring).
    (
        "credential assignment",
        re.compile(
            r"(?i)\b(?:password|passwd|secret|token|api[_-]?key)\b\s*[=:]\s*"
            r"['\"]?(?![$<{])[A-Za-z0-9_\-.+/]*?"
            r"(?=[A-Za-z0-9_+/]{16,})(?=[A-Za-z0-9_\-.+/]*\d)[A-Za-z0-9_+/]{16,}"
        ),
    ),
)


def find_secret(*texts: str | None) -> str | None:
    """Name of the first secret-shaped pattern found in any text, else None."""
    for text in texts:
        if not text:
            continue
        for label, pattern in _PATTERNS:
            if pattern.search(text):
                return label
    return None
