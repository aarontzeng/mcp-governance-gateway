#!/usr/bin/env python3
"""Print one release's section of CHANGELOG.md, for the GitHub release body.

    scripts/changelog-section.py 0.4.0 [CHANGELOG.md]

The section is everything under `## [0.4.0] — <date>` up to the next `## `
heading, without the heading itself; the release already carries the version
and the date. Exits 1, saying which version it looked for, when the section
is missing -- the hygiene test holds the newest heading to `__version__`, so
that means the release commit was not made the documented way.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


def section(text: str, version: str) -> str | None:
    heading = re.compile(rf"^## \[{re.escape(version)}\][^\n]*\n", re.MULTILINE)
    match = heading.search(text)
    if match is None:
        return None
    rest = text[match.end():]
    end = re.search(r"^## ", rest, re.MULTILINE)
    body = rest[: end.start()] if end else rest
    return body.strip("\n") + "\n"


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3):
        print(__doc__, file=sys.stderr)
        return 2
    version = argv[1].removeprefix("v")
    path = Path(argv[2] if len(argv) == 3 else "CHANGELOG.md")
    body = section(path.read_text(encoding="utf-8"), version)
    if body is None:
        print(f"{path}: no section for version {version}", file=sys.stderr)
        return 1
    sys.stdout.write(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
