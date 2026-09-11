"""Guards on the test suite itself, so a hygiene rule cannot regress silently."""
import re
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent


class TestTreeHygiene(unittest.TestCase):
    def test_no_test_creates_temporary_directories_inside_the_repo(self):
        # A killed run once left 23 tmp* directories in the worktree: temp dirs
        # belong to the system temp location, never under the repository root.
        offenders = []
        for path in sorted(TESTS.glob("*.py")):
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if re.search(r"(TemporaryDirectory|mkdtemp)\(\s*dir\s*=", line):
                    offenders.append(f"{path.name}:{n}: {line.strip()}")
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
