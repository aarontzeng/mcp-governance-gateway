"""Guards on the test suite itself, so a hygiene rule cannot regress silently."""
import re
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent


class TestVersionSingleSource(unittest.TestCase):
    """0.3.0 shipped with `__version__` still saying 0.2.0, so every MCP client
    saw the wrong number in `serverInfo.version`. The package attribute is now
    the only literal; these keep the build metadata and the CHANGELOG on it."""

    def test_pyproject_takes_the_version_from_the_package(self):
        import tomllib

        pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertNotIn("version", pyproject["project"], "declare it dynamic, do not duplicate it")
        self.assertIn("version", pyproject["project"].get("dynamic", []))
        self.assertEqual(
            pyproject["tool"]["setuptools"]["dynamic"]["version"],
            {"attr": "mcp_governance_gateway.__version__"},
        )

    def test_the_newest_changelog_release_is_the_package_version(self):
        from mcp_governance_gateway import __version__

        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        released = re.findall(r"^## \[(\d+\.\d+\.\d+)\]", changelog, flags=re.MULTILINE)
        self.assertTrue(released, "CHANGELOG has no released heading")
        self.assertEqual(released[0], __version__, "bump __version__ with the CHANGELOG heading")


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
