from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import check_owners  # noqa: E402
from check_owners import (  # noqa: E402
    ANYONE,
    ConfigError,
    evaluate,
    owners_for_path,
    parse_name_status_z,
    parse_owners,
)

ALICE = "alice@example.com"
BOB = "bob@example.com"
CAROL = "carol@example.com"


class ParseOwnersTests(unittest.TestCase):
    def test_comments_blanks_and_dir_owners(self):
        of = parse_owners("# top\n\n  alice@example.com  # owns it\n")
        self.assertEqual(of.dir_owners, frozenset({ALICE}))
        self.assertFalse(of.noparent)

    def test_set_noparent(self):
        self.assertTrue(parse_owners("set noparent\nalice@example.com\n").noparent)

    def test_anyone(self):
        self.assertEqual(parse_owners("*\n").dir_owners, frozenset({ANYONE}))

    def test_owner_emails_are_casefolded(self):
        of = parse_owners("Bob@Example.COM\nper-file *.py = Alice@EXAMPLE.com\n")
        self.assertEqual(of.dir_owners, frozenset({BOB}))
        self.assertEqual(of.per_file[0][1], frozenset({ALICE}))

    def test_per_file_multiple_globs_and_owners(self):
        of = parse_owners("per-file *_test.py, *_spec.py = bob@example.com, carol@example.com\n")
        self.assertEqual(len(of.per_file), 2)
        globs = {g for g, _ in of.per_file}
        self.assertEqual(globs, {"*_test.py", "*_spec.py"})
        for _, owners in of.per_file:
            self.assertEqual(owners, frozenset({BOB, CAROL}))

    def test_per_file_set_noparent_raises_instead_of_phantom_owner(self):
        # find-owners supports this form; misparsing the RHS as an owner literally
        # named "set noparent" would silently change the owner set
        with self.assertRaises(ConfigError):
            parse_owners("per-file *_test.py = set noparent\n")

    def test_unsupported_directives_raise_rather_than_silently_drop_owners(self):
        with self.assertRaises(ConfigError):
            parse_owners("include /other/OWNERS\n")
        with self.assertRaises(ConfigError):
            parse_owners("file://OWNERS\n")

    def test_garbage_raises(self):
        with self.assertRaises(ConfigError):
            parse_owners("not-an-email\n")
        with self.assertRaises(ConfigError):
            parse_owners("per-file *.py\n")  # missing '='


class OwnersForPathTests(unittest.TestCase):
    def test_inherits_from_parent_directories(self):
        owners = {"": parse_owners(f"{ALICE}\n")}
        self.assertEqual(owners_for_path("src/deep/mod.py", owners), frozenset({ALICE}))

    def test_set_noparent_stops_ascent(self):
        owners = {
            "": parse_owners(f"{ALICE}\n"),
            "src": parse_owners(f"set noparent\n{BOB}\n"),
        }
        self.assertEqual(owners_for_path("src/mod.py", owners), frozenset({BOB}))
        self.assertEqual(owners_for_path("other.py", owners), frozenset({ALICE}))

    def test_owners_accumulate_without_noparent(self):
        owners = {"": parse_owners(f"{ALICE}\n"), "src": parse_owners(f"{BOB}\n")}
        self.assertEqual(owners_for_path("src/mod.py", owners), frozenset({ALICE, BOB}))

    def test_per_file_matches_basename_in_its_own_directory_only(self):
        owners = {"src": parse_owners(f"per-file *_test.py = {BOB}\n")}
        self.assertEqual(owners_for_path("src/a_test.py", owners), frozenset({BOB}))
        self.assertEqual(owners_for_path("src/a.py", owners), frozenset())
        # find-owners semantics: per-file binds to the OWNERS file's own directory.
        # Applying it to subdirectories would widen ownership vs Gerrit's native rule.
        self.assertEqual(owners_for_path("src/deep/a_test.py", owners), frozenset())

    def test_directory_owners_still_inherit_into_subdirectories(self):
        owners = {"src": parse_owners(f"{BOB}\nper-file *_test.py = {CAROL}\n")}
        self.assertEqual(owners_for_path("src/deep/a_test.py", owners), frozenset({BOB}))
        self.assertEqual(owners_for_path("src/a_test.py", owners), frozenset({BOB, CAROL}))

    def test_unowned_path_has_no_owners(self):
        self.assertEqual(owners_for_path("x.py", {}), frozenset())


class EvaluateTests(unittest.TestCase):
    OWNERS = {
        "": parse_owners(f"{ALICE}\n"),
        "svc": parse_owners(f"set noparent\n{BOB}\n"),
    }

    def test_author_owns_everything_touched(self):
        self.assertTrue(evaluate(["a.py"], self.OWNERS, ALICE).ok)

    def test_author_email_matches_case_insensitively(self):
        self.assertTrue(evaluate(["a.py"], self.OWNERS, "Alice@Example.COM").ok)

    def test_approval_matches_case_insensitively(self):
        res = evaluate(
            ["svc/x.py"], self.OWNERS, ALICE,
            cross_owner="refactor", mode="review", approvals=frozenset({"Bob@Example.COM"}),
        )
        self.assertTrue(res.ok)

    def test_unowned_path_is_allowed(self):
        # otherwise adding one OWNERS file would lock the whole repo
        self.assertTrue(evaluate(["x.py"], {"svc": parse_owners(f"{BOB}\n")}, ALICE).ok)

    def test_anyone_marker_allows(self):
        owners = {"": parse_owners("*\n")}
        self.assertTrue(evaluate(["a.py"], owners, CAROL).ok)

    def test_crossing_without_trailer_fails(self):
        res = evaluate(["svc/x.py"], self.OWNERS, ALICE)
        self.assertFalse(res.ok)
        self.assertEqual([v.path for v in res.violations], ["svc/x.py"])
        self.assertEqual(res.violations[0].owners, frozenset({BOB}))

    def test_trailer_alone_does_not_unblock_the_author(self):
        # H1: an agent must not be able to self-approve by writing one line in
        # its own commit message
        res = evaluate(
            ["svc/x.py"], self.OWNERS, ALICE, cross_owner="refactor", mode="review", approvals=frozenset()
        )
        self.assertFalse(res.ok)

    def test_trailer_plus_non_owner_approval_still_fails(self):
        res = evaluate(
            ["svc/x.py"], self.OWNERS, ALICE,
            cross_owner="refactor", mode="review", approvals=frozenset({CAROL}),
        )
        self.assertFalse(res.ok)

    def test_lookalike_approver_does_not_match(self):
        res = evaluate(
            ["svc/x.py"], self.OWNERS, ALICE,
            cross_owner="refactor", mode="review",
            approvals=frozenset({"notbob@example.com.evil"}),
        )
        self.assertFalse(res.ok)

    def test_trailer_plus_owner_approval_passes(self):
        res = evaluate(
            ["svc/x.py"], self.OWNERS, ALICE,
            cross_owner="refactor", mode="review", approvals=frozenset({BOB}),
        )
        self.assertTrue(res.ok)

    def test_approval_must_cover_every_crossed_path(self):
        owners = {
            "svc": parse_owners(f"set noparent\n{BOB}\n"),
            "web": parse_owners(f"set noparent\n{CAROL}\n"),
        }
        res = evaluate(
            ["svc/x.py", "web/y.ts"], owners, ALICE,
            cross_owner="cross-cutting", mode="review", approvals=frozenset({BOB}),
        )
        self.assertFalse(res.ok)  # carol never approved web/
        self.assertEqual([v.path for v in res.violations], ["web/y.ts"])

    def test_local_mode_accepts_trailer_but_warns(self):
        res = evaluate(["svc/x.py"], self.OWNERS, ALICE, cross_owner="wip", mode="local")
        self.assertTrue(res.ok)
        self.assertTrue(any("approve at review time" in m for m in res.messages))

    def test_exempt_globs_skip_generated_files(self):
        owners = {"": parse_owners(f"set noparent\n{BOB}\n")}
        res = evaluate(["package-lock.json"], owners, ALICE, exempt_globs=("*.lock", "package-lock.json"))
        self.assertTrue(res.ok)
        self.assertFalse(res.violations)

    def test_exempt_globs_never_cover_governance_files(self):
        # `*` in the exempt list must not silence an OWNERS edit or the exempt
        # list's own edit -- those stay governed by BASE owners
        owners = {"svc": parse_owners(f"set noparent\n{BOB}\n")}
        res = evaluate(
            ["svc/OWNERS", ".owners-exempt"], owners, ALICE,
            exempt_globs=("*",), exempt_source=".owners-exempt",
        )
        self.assertFalse(res.ok)
        self.assertIn("svc/OWNERS", [v.path for v in res.violations])


class NameStatusZTests(unittest.TestCase):
    def test_plain_statuses(self):
        self.assertEqual(
            parse_name_status_z("M\0src/a.py\0A\0src/b.py\0D\0src/c.py\0"),
            ["src/a.py", "src/b.py", "src/c.py"],
        )

    def test_rename_and_copy_yield_both_sides(self):
        self.assertEqual(parse_name_status_z("R100\0svc/a.py\0web/a.py\0"), ["svc/a.py", "web/a.py"])
        self.assertEqual(parse_name_status_z("C75\0svc/a.py\0web/b.py\0"), ["svc/a.py", "web/b.py"])

    def test_filenames_with_tab_and_newline_survive(self):
        # NUL delimiting is the whole point: whitespace in names cannot break fields
        self.assertEqual(parse_name_status_z("M\0svc/a\tb.py\0"), ["svc/a\tb.py"])
        self.assertEqual(parse_name_status_z("M\0svc/a\nb.py\0"), ["svc/a\nb.py"])

    def test_unknown_status_fails_closed(self):
        with self.assertRaises(ConfigError):
            parse_name_status_z("Z\0weird\0")

    def test_truncated_record_fails_closed(self):
        with self.assertRaises(ConfigError):
            parse_name_status_z("M\0")


class GitIntegrationTests(unittest.TestCase):
    """Drive main() against real repos: every finding from the security review
    lived in the git layer, so the git layer is what these test."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = self._tmp.name
        self._sh("git", "init", "-q", "-b", "main", ".")
        self._sh("git", "config", "user.email", ALICE)
        self._sh("git", "config", "user.name", "Alice")
        (Path(self.repo) / "svc").mkdir()
        self._write("OWNERS", f"{ALICE}\n")
        self._write("svc/OWNERS", f"set noparent\n{BOB}\n")
        self._write("svc/mod.py", "x = 1\n")
        self._write("a.py", "x = 1\n")
        self._sh("git", "add", "-A")
        self._sh("git", "commit", "-qm", "init")

    def tearDown(self):
        self._tmp.cleanup()

    def _sh(self, *cmd):
        subprocess.run(cmd, cwd=self.repo, check=True, capture_output=True)

    def _write(self, rel, text):
        p = Path(self.repo) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")

    def _commit(self, msg="change"):
        self._sh("git", "add", "-A")
        self._sh("git", "commit", "-qm", msg)

    def _run(self, *extra):
        return check_owners.main(["--repo", self.repo, *extra])

    def test_own_file_ok(self):
        self._write("a.py", "x = 2\n")
        self._commit()
        self.assertEqual(self._run("--mode", "review", "--author", ALICE), 0)

    def test_crossing_fails(self):
        self._write("svc/mod.py", "x = 2\n")
        self._commit()
        self.assertEqual(self._run("--mode", "review", "--author", ALICE), 1)

    def test_review_mode_without_author_is_a_usage_error(self):
        # the commit's %ae is forgeable; review mode must never fall back to it
        self._write("svc/mod.py", "x = 2\n")
        self._commit()
        self.assertEqual(self._run("--mode", "review"), 2)

    def test_same_commit_owners_self_grant_is_rejected(self):
        # CRITICAL 2: the change adds alice to svc/OWNERS and crosses in the same
        # commit. OWNERS must come from the BASE tree, where alice is not an owner.
        self._write("svc/OWNERS", f"set noparent\n{BOB}\n{ALICE}\n")
        self._write("svc/mod.py", "x = 2\n")
        self._commit("self grant")
        self.assertEqual(self._run("--mode", "review", "--author", ALICE), 1)

    def test_owners_deletion_in_the_change_does_not_lift_protection(self):
        (Path(self.repo) / "svc/OWNERS").unlink()
        self._write("svc/mod.py", "x = 2\n")
        self._commit("drop owners")
        self.assertEqual(self._run("--mode", "review", "--author", ALICE), 1)

    def test_same_commit_exempt_self_grant_is_rejected(self):
        # CRITICAL 3: `*` added to .owners-exempt in the same commit must not count
        # -- the exempt list is read from the BASE tree, where it doesn't exist.
        self._write(".owners-exempt", "*\n")
        self._write("svc/mod.py", "x = 2\n")
        self._commit("exempt everything")
        self.assertEqual(
            self._run("--mode", "review", "--author", ALICE, "--exempt-file", ".owners-exempt"), 1
        )

    def test_exempt_list_from_base_tree_works(self):
        self._write(".owners-exempt", "*.lock\n")
        self._sh("git", "add", "-A")
        self._sh("git", "commit", "-qm", "add exempt list")  # now in base
        self._write("svc/dep.lock", "generated\n")
        self._commit("regen lock")
        self.assertEqual(
            self._run("--mode", "review", "--author", ALICE, "--exempt-file", ".owners-exempt"), 0
        )

    def test_non_ascii_filename_in_protected_dir_is_still_owned(self):
        # HIGH 4: with core.quotePath default, `svc/café.py` came back octal-quoted,
        # its parent looked like `"svc`, and the path was silently unowned.
        self._write("svc/café.py", "x = 1\n")
        self._commit("non-ascii")
        self.assertEqual(self._run("--mode", "review", "--author", ALICE), 1)

    def test_merge_commit_does_not_skip_the_check(self):
        # HIGH 5: wrapping the crossing in a merge must not exit 0
        self._sh("git", "checkout", "-q", "-b", "feat")
        self._write("svc/mod.py", "x = 99\n")
        self._commit("cross on branch")
        self._sh("git", "checkout", "-q", "main")
        self._write("a.py", "x = 3\n")
        self._commit("trunk moves")
        self._sh("git", "merge", "-q", "--no-ff", "feat", "-m", "merge feat")
        self.assertEqual(self._run("--mode", "review", "--author", ALICE), 1)

    def test_staged_crossing_is_blocked_before_the_commit_exists(self):
        # commit-msg hook shape: the commit object doesn't exist yet
        self._write("svc/mod.py", "x = 2\n")
        self._sh("git", "add", "-A")
        self.assertEqual(self._run("--staged"), 1)

    def test_staged_own_path_ok(self):
        self._write("a.py", "x = 2\n")
        self._sh("git", "add", "-A")
        self.assertEqual(self._run("--staged"), 0)

    def test_staged_cross_owner_trailer_passes_local_with_warning(self):
        self._write("svc/mod.py", "x = 2\n")
        self._sh("git", "add", "-A")
        msg = Path(self.repo) / ".git" / "COMMIT_EDITMSG_TEST"
        msg.write_text("touch svc\n\nCross-Owner: agreed with bob\n", encoding="utf-8")
        self.assertEqual(self._run("--staged", "--message-file", str(msg)), 0)

    def test_staged_owners_self_grant_is_rejected(self):
        # staging an OWNERS edit must not change the rules that judge the stage:
        # OWNERS comes from HEAD, not the index
        self._write("svc/OWNERS", f"set noparent\n{BOB}\n{ALICE}\n")
        self._write("svc/mod.py", "x = 2\n")
        self._sh("git", "add", "-A")
        self.assertEqual(self._run("--staged"), 1)

    def test_staged_review_mode_is_rejected(self):
        self.assertEqual(self._run("--staged", "--mode", "review", "--author", ALICE), 2)

    def test_base_flag_uses_merge_base(self):
        # changes already on the target branch are not attributed to this change
        self._sh("git", "checkout", "-q", "-b", "feat")
        self._write("a.py", "x = 5\n")
        self._commit("own change on feat")
        self.assertEqual(self._run("--mode", "review", "--author", ALICE, "--base", "main"), 0)


if __name__ == "__main__":
    unittest.main()
