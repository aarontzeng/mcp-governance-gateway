from __future__ import annotations

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from mcp_governance_gateway.audit import AuditEvent, AuditSink
from mcp_governance_gateway.auth import Principal
from mcp_governance_gateway.docs_backend import (
    DocsBackendError,
    DocsCorpus,
    load_docs_repos,
    parse_frontmatter,
    tokenize,
)
from mcp_governance_gateway.mcp import GatewayApp, visible_tool_definitions
from mcp_governance_gateway.memory_backend import ActorLabels, MemoryBackend, RequestContext


class TokenizeTests(unittest.TestCase):
    def test_ascii_words(self):
        self.assertEqual(tokenize("Hello NATS_client 42"), ["hello", "nats_client", "42"])

    def test_cjk_unigrams_and_bigrams(self):
        toks = tokenize("租戶隔離")
        for t in ("租", "戶", "隔", "離", "租戶", "戶隔", "隔離"):
            self.assertIn(t, toks)

    def test_mixed(self):
        toks = tokenize("BM25 檢索")
        self.assertIn("bm25", toks)
        self.assertIn("檢索", toks)


class FrontmatterTests(unittest.TestCase):
    def test_parses_simple_keys(self):
        meta, body = parse_frontmatter("---\ntitle: 測試報告\ndate: 2026-07-10\n---\n# Body\n")
        self.assertEqual(meta["title"], "測試報告")
        self.assertEqual(meta["date"], "2026-07-10")
        self.assertTrue(body.startswith("# Body"))

    def test_no_frontmatter(self):
        meta, body = parse_frontmatter("# Just a doc\n")
        self.assertEqual(meta, {})
        self.assertEqual(body, "# Just a doc\n")

    def test_flow_style_list_parses_to_a_list(self):
        # Returned raw, a consumer would get the literal string "[a, b]" and have
        # to re-parse frontmatter syntax itself.
        meta, _ = parse_frontmatter("---\ntags: [mcp, gateway, 'quoted one']\n---\n")
        self.assertEqual(meta["tags"], ["mcp", "gateway", "quoted one"])

    def test_a_list_valued_title_does_not_reach_the_index(self):
        # Adversarial review, 2026-08-10: the generic flow-list parser made
        # `title: [a, b]` a list, and the BM25 index concatenates the title -- so one
        # document with that frontmatter raised TypeError for the whole corpus.
        meta, _ = parse_frontmatter("---\ntitle: [one, two]\n---\n# Real Heading\n")
        self.assertEqual(meta["title"], ["one", "two"])  # the parser stays general

    def test_empty_list_and_scalars_are_unaffected(self):
        meta, _ = parse_frontmatter("---\ntags: []\ntitle: not a list\n---\n")
        self.assertEqual(meta["tags"], [])
        self.assertEqual(meta["title"], "not a list")


def _sh(cwd, *cmd):
    subprocess.run(cmd, cwd=cwd, check=True, capture_output=True)


def _make_remote(tmp: str, name: str, files: dict[str, str]) -> str:
    """A bare 'remote' with a working clone to author commits."""
    remote = str(Path(tmp) / f"{name}.git")
    work = str(Path(tmp) / f"{name}-work")
    _sh(tmp, "git", "init", "-q", "--bare", "-b", "master", remote)
    _sh(tmp, "git", "clone", "-q", remote, work)
    _sh(work, "git", "config", "user.email", "t@example.com")
    _sh(work, "git", "config", "user.name", "T")
    _write_files(work, files)
    _sh(work, "git", "add", "-A")
    _sh(work, "git", "commit", "-qm", "seed")
    _sh(work, "git", "push", "-q", "origin", "master")
    return remote


def _write_files(work: str, files: dict[str, str]) -> None:
    for rel, text in files.items():
        p = Path(work) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _ctx(project: str) -> RequestContext:
    return RequestContext(actor="10000000", project=project, client="test", request_id="req-1")


SEED = {
    "README.md": "# repo rules — not served\n",
    "raw/reports/cache-analysis.md": (
        "---\ntitle: 快取策略分析\ndate: 2026-07-01\n---\n"
        "# 快取策略分析\n\n分層快取的命中率量測與最佳化建議。\n"
    ),
    "raw/sessions/kickoff.md": "# Kickoff notes\n\nDecided to use NATS for messaging.\n",
    "wiki/index.md": "---\ntitle: Project Wiki\n---\n# Index\n\nStart here.\n",
    "wiki/.hidden/secret.md": "# hidden dotdir — not served\n",
}


class ListingMetadataTests(unittest.TestCase):
    """Lifecycle signals ride along on list(), so a reader can skip a document
    without fetching it."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        remote = _make_remote(self.tmp, "meta-docs", {
            "wiki/current.md": "---\ntitle: Current\n---\n# c\n",
            "wiki/old.md": "---\ntitle: Old\nstatus: deprecated\n---\n# o\n",
            "wiki/expiring.md": "---\ntitle: Expiring\nstale_after: 2026-10-31\n---\n# e\n",
            "wiki/design.md": "---\ntitle: Design\ndecision_status: accepted\n---\n# d\n",
        })
        self.corpus = DocsCorpus(
            {"p": {"url": remote, "branch": "master"}},
            str(Path(self.tmp) / "clones"), pull_interval_sec=0.0,
        )

    def tearDown(self):
        self._tmp.cleanup()

    def _by_path(self):
        return {d["path"]: d for d in self.corpus.list(_ctx("p"))["documents"]}

    def test_declared_signals_are_surfaced(self):
        docs = self._by_path()
        self.assertEqual(docs["wiki/old.md"]["status"], "deprecated")
        self.assertEqual(docs["wiki/expiring.md"]["staleAfter"], "2026-10-31")
        self.assertEqual(docs["wiki/design.md"]["decisionStatus"], "accepted")

    def test_undeclared_signals_are_absent_not_null(self):
        # Absent means nothing is claimed; a null would read as a claim of "none".
        current = self._by_path()["wiki/current.md"]
        for key in ("status", "staleAfter", "decisionStatus"):
            self.assertNotIn(key, current)

    def test_staleness_stays_a_raw_date(self):
        # The gateway does not decide whether a document is stale today -- each
        # consumer compares against its own clock.
        self.assertEqual(self._by_path()["wiki/expiring.md"]["staleAfter"], "2026-10-31")


class MalformedCorpusTests(unittest.TestCase):
    """One bad document must not take the project's docs tools down."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        remote = _make_remote(self.tmp, "bad-docs", {
            "wiki/listy.md": "---\ntitle: [one, two]\n---\n# Real Heading\n\nbody\n",
            "wiki/fine.md": "---\ntitle: Fine\n---\n# Fine\n\nbody\n",
        })
        self.corpus = DocsCorpus(
            {"p": {"url": remote, "branch": "master"}},
            str(Path(self.tmp) / "clones"), pull_interval_sec=0.0,
        )

    def tearDown(self):
        self._tmp.cleanup()

    def test_a_list_valued_title_falls_back_to_the_heading(self):
        out = self.corpus.get("wiki/listy.md", _ctx("p"))
        self.assertEqual(out["title"], "Real Heading")
        self.assertEqual(out["frontmatter"]["title"], ["one", "two"])  # preserved as data

    def test_search_and_list_still_work_with_that_document_present(self):
        self.assertEqual(self.corpus.list(_ctx("p"))["count"], 2)
        self.assertTrue(self.corpus.search("body", 5, _ctx("p"))["results"])


class AuthorProvenanceTests(unittest.TestCase):
    """createdBy / updatedBy come from the Git log, which is the only record of
    who wrote a document that the document itself cannot forge."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.remote = str(Path(self.tmp) / "prov.git")
        self.work = str(Path(self.tmp) / "prov-work")
        _sh(self.tmp, "git", "init", "-q", "--bare", "-b", "master", self.remote)
        _sh(self.tmp, "git", "clone", "-q", self.remote, self.work)
        self._commit("author-one", "one@example.com", {
            "wiki/a.md": "# A first\n",
            "wiki/b.md": "# B only ever touched by one\n",
        }, "seed")
        self._commit("author-two", "two@example.com", {"wiki/a.md": "# A revised\n"}, "revise a")
        self.corpus = DocsCorpus(
            {"p": {"url": self.remote, "branch": "master"}},
            str(Path(self.tmp) / "clones"), pull_interval_sec=0.0,
        )

    def _commit(self, name, email, files, message):
        _sh(self.work, "git", "config", "user.name", name)
        _sh(self.work, "git", "config", "user.email", email)
        _write_files(self.work, files)
        _sh(self.work, "git", "add", "-A")
        _sh(self.work, "git", "commit", "-qm", message)
        _sh(self.work, "git", "push", "-q", "origin", "master")

    def tearDown(self):
        self._tmp.cleanup()

    def test_creator_and_last_updater_are_distinguished(self):
        out = self.corpus.get("wiki/a.md", _ctx("p"))
        self.assertEqual(out["createdBy"], "author-one")
        self.assertEqual(out["updatedBy"], "author-two")

    def test_single_commit_document_has_the_same_author_for_both(self):
        out = self.corpus.get("wiki/b.md", _ctx("p"))
        self.assertEqual((out["createdBy"], out["updatedBy"]), ("author-one", "author-one"))

    def test_an_opaque_author_key_maps_through_the_token_store(self):
        # Where a deployment re-keyed identities, git carries the opaque id; the
        # label comes from the same store the memory listings read.
        self._commit("E1000001", "person@example.com", {"wiki/c.md": "# C\n"}, "add c")
        tokens = Path(self.tmp) / "user-tokens.json"
        tokens.write_text(json.dumps({"tokens": [
            {"token": "t", "actor": "E1000001", "email": "a.person@example.com"},
        ]}), encoding="utf-8")
        corpus = DocsCorpus(
            {"p": {"url": self.remote, "branch": "master"}},
            str(Path(self.tmp) / "clones2"), pull_interval_sec=0.0,
            actor_labels=ActorLabels(str(tokens)),
        )
        self.assertEqual(corpus.get("wiki/c.md", _ctx("p"))["createdBy"], "a.person")
        # a real-name author from a direct push is left alone
        self.assertEqual(corpus.get("wiki/a.md", _ctx("p"))["createdBy"], "author-one")


class SpecKeyedSnapshotTests(unittest.TestCase):
    """A snapshot belongs to a specification, not just to a moment in time.

    Design review, 2026-08-10: freshness alone was the invariant, so a retargeted
    project kept serving the old repository for the pull interval, and a concurrent
    reload could drop a project between the membership check and the refresh.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.first = _make_remote(self.tmp, "first", {"wiki/x.md": "# First\n"})
        self.second = _make_remote(self.tmp, "second", {"wiki/x.md": "# Second\n"})
        self.other = _make_remote(self.tmp, "other", {"wiki/y.md": "# Other\n"})
        self.repos_file = Path(self.tmp) / "docs-repos.json"
        self._write({"p": {"url": self.first, "branch": "master"},
                     "q": {"url": self.other, "branch": "master"}})
        self.corpus = DocsCorpus(
            load_docs_repos(str(self.repos_file)), str(Path(self.tmp) / "clones"),
            pull_interval_sec=3600, repos_file=str(self.repos_file),   # production-like
        )

    def _write(self, mapping):
        tmp = self.repos_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(mapping), encoding="utf-8")
        tmp.replace(self.repos_file)

    def tearDown(self):
        self._tmp.cleanup()

    def test_a_retarget_is_visible_immediately_not_after_the_pull_interval(self):
        self.assertEqual(self.corpus.get("wiki/x.md", _ctx("p"))["text"], "# First")
        self._write({"p": {"url": self.second, "branch": "master"},
                     "q": {"url": self.other, "branch": "master"}})
        self.assertEqual(self.corpus.get("wiki/x.md", _ctx("p"))["text"], "# Second")

    def test_another_projects_edit_does_not_invalidate_this_ones_snapshot(self):
        # The snapshot key is (url, branch), NOT the registry generation -- otherwise
        # every unrelated edit would force every project to refetch.
        self.corpus.get("wiki/x.md", _ctx("p"))
        before = self.corpus._snapshots["p"]
        self._write({"p": {"url": self.first, "branch": "master"},
                     "q": {"url": self.second, "branch": "master"}})   # only q changes
        self.corpus.get("wiki/x.md", _ctx("p"))
        self.assertIs(self.corpus._snapshots["p"], before)  # same object: no refetch

    def test_a_failed_first_fetch_of_a_new_spec_is_unavailable_not_the_old_corpus(self):
        # The dangerous fallback: serving the previous repository's documents under a
        # specification that now points somewhere else.
        self.assertEqual(self.corpus.get("wiki/x.md", _ctx("p"))["text"], "# First")
        self._write({"p": {"url": str(Path(self.tmp) / "does-not-exist.git"), "branch": "master"},
                     "q": {"url": self.other, "branch": "master"}})
        with self.assertRaises(DocsBackendError) as cm:
            self.corpus.get("wiki/x.md", _ctx("p"))
        self.assertEqual(cm.exception.status, 503)

    def test_a_hiccup_against_the_same_spec_still_serves_the_last_good_snapshot(self):
        # The availability compromise is kept where it is honest: same repository,
        # stale content, rather than a hard failure.
        self.corpus.get("wiki/x.md", _ctx("p"))
        original = self.corpus._git

        def flaky(cwd, *args, **kwargs):
            if args and args[0] in ("fetch", "remote"):
                raise subprocess.CalledProcessError(1, "git", stderr=b"network down")
            return original(cwd, *args, **kwargs)

        self.corpus._git = flaky
        self.corpus._snapshots["p"].refreshed_at -= 7200  # force a refresh attempt
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(self.corpus.get("wiki/x.md", _ctx("p"))["text"], "# First")
        # The reader cannot tell it was served stale content; the operator must.
        self.assertIn("last good snapshot", err.getvalue())
        self.assertIn("'p'", err.getvalue())

    def test_a_project_removed_mid_refresh_does_not_raise_keyerror(self):
        # The refresh reads its specification from a captured value, so a reload that
        # drops the project cannot make it index a mutable map that no longer has it.
        original = self.corpus._load_docs

        def drop_then_load(dest):
            self._write({"q": {"url": self.other, "branch": "master"}})  # p disappears
            self.corpus._current_registry()
            return original(dest)

        self.corpus._load_docs = drop_then_load
        out = self.corpus.get("wiki/x.md", _ctx("p"))   # must not raise KeyError
        self.assertEqual(out["text"], "# First")
        # ... and the now-absent project is refused on the next call
        with self.assertRaises(DocsBackendError) as cm:
            self.corpus.get("wiki/x.md", _ctx("p"))
        self.assertEqual(cm.exception.status, 404)

    def test_one_projects_slow_refresh_does_not_block_another(self):
        # The old single lock was held across clone/fetch/reset, so every project
        # queued behind one project's remote Git I/O.
        import threading

        gate = threading.Event()
        original = self.corpus._load_docs

        def slow_for_p(dest):
            if dest.endswith("/p"):
                gate.wait(timeout=5)
            return original(dest)

        self.corpus._load_docs = slow_for_p
        done = []
        blocked = threading.Thread(target=lambda: done.append(self.corpus.get("wiki/x.md", _ctx("p"))))
        blocked.start()
        try:
            # q must complete while p is still inside its refresh
            self.assertEqual(self.corpus.get("wiki/y.md", _ctx("q"))["text"], "# Other")
            self.assertEqual(done, [])   # p really was still blocked
        finally:
            gate.set()
            blocked.join(timeout=5)
        self.assertEqual(len(done), 1)


class CloneHistoryTests(unittest.TestCase):
    """The clone keeps full history, and a shallow one left by an earlier release is
    upgraded in place rather than requiring the cache to be deleted."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.remote = str(Path(self.tmp) / "hist.git")
        work = str(Path(self.tmp) / "hist-work")
        _sh(self.tmp, "git", "init", "-q", "--bare", "-b", "master", self.remote)
        _sh(self.tmp, "git", "clone", "-q", self.remote, work)
        for author, files, msg in [
            ("first-author", {"wiki/a.md": "# A\n"}, "add a"),
            ("second-author", {"wiki/b.md": "# B\n"}, "add b"),
        ]:
            _sh(work, "git", "config", "user.name", author)
            _sh(work, "git", "config", "user.email", author + "@example.com")
            _write_files(work, files)
            _sh(work, "git", "add", "-A")
            _sh(work, "git", "commit", "-qm", msg)
            _sh(work, "git", "push", "-q", "origin", "master")
        self.clones = str(Path(self.tmp) / "clones")

    def tearDown(self):
        self._tmp.cleanup()

    def _corpus(self):
        return DocsCorpus({"p": {"url": self.remote, "branch": "master"}}, self.clones,
                          pull_interval_sec=0.0)

    def test_a_fresh_clone_is_not_shallow_so_provenance_is_right(self):
        corpus = self._corpus()
        # a.md predates the tip: in a shallow clone it would be credited to whoever
        # pushed last, which is the wrong answer rather than a missing one
        self.assertEqual(corpus.get("wiki/a.md", _ctx("p"))["createdBy"], "first-author")
        self.assertEqual(corpus.get("wiki/b.md", _ctx("p"))["createdBy"], "second-author")

    def _is_shallow(self, dest):
        return subprocess.run(["git", "rev-parse", "--is-shallow-repository"], cwd=dest,
                              capture_output=True, text=True).stdout.strip()

    def test_an_existing_shallow_clone_is_upgraded_in_place(self):
        dest = str(Path(self.clones) / "p")
        Path(self.clones).mkdir(parents=True, exist_ok=True)
        # file:// on purpose: git ignores --depth for a plain local path (it hardlinks
        # objects instead), so this is the only way to reproduce the state an earlier
        # shallow-clone release left behind.
        _sh(self.tmp, "git", "clone", "-q", "--depth", "1", "--branch", "master",
            "file://" + self.remote, dest)
        self.assertEqual(self._is_shallow(dest), "true")
        # In that state provenance is not missing, it is wrong: the grafted tip looks
        # like the commit that introduced every file.
        shallow_authors = DocsCorpus({"p": {"url": self.remote, "branch": "master"}}, self.clones,
                                     pull_interval_sec=0.0)._file_authors(dest)
        self.assertEqual(shallow_authors["wiki/a.md"], ("second-author", "second-author"))

        corpus = self._corpus()
        self.assertEqual(corpus.get("wiki/a.md", _ctx("p"))["createdBy"], "first-author")
        self.assertEqual(self._is_shallow(dest), "false")  # upgraded, cache not deleted


class ReposHotReloadTests(unittest.TestCase):
    """A project added to the repos file becomes usable without a restart."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.remote = _make_remote(self.tmp, "hot-docs", {"wiki/x.md": "# X\n"})
        self.repos_file = Path(self.tmp) / "docs-repos.json"
        self._write({"p": {"url": self.remote, "branch": "master"}})
        self.corpus = DocsCorpus(
            load_docs_repos(str(self.repos_file)), str(Path(self.tmp) / "clones"),
            pull_interval_sec=0.0, repos_file=str(self.repos_file),
        )

    def _write(self, mapping):
        # atomic, like the writer this hot reload exists for: a new inode each time
        tmp = self.repos_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(mapping), encoding="utf-8")
        tmp.replace(self.repos_file)

    def tearDown(self):
        self._tmp.cleanup()

    def test_a_newly_added_project_is_picked_up(self):
        self.assertFalse(self.corpus.has_project("q"))
        self._write({
            "p": {"url": self.remote, "branch": "master"},
            "q": {"url": self.remote, "branch": "master"},
        })
        self.assertTrue(self.corpus.has_project("q"))
        self.assertEqual(self.corpus.get("wiki/x.md", _ctx("q"))["title"], "X")

    def test_a_corrupt_write_keeps_the_last_good_map(self):
        # A bad save must not take every project's docs tools down.
        self.repos_file.write_text("{ this is not json", encoding="utf-8")
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertTrue(self.corpus.has_project("p"))
        self.assertIn("docs repos file reload failed", err.getvalue())  # but not silently

    def test_a_changed_url_retargets_the_existing_clone(self):
        # Hot-reloading the map is not enough on its own: the clone on disk still has
        # the old origin, so the project would keep serving the old repository.
        #
        # Design review, 2026-08-10: this used pull_interval_sec=0.0, which forced a
        # refresh on every call and so could not observe the real failure -- with a
        # production interval the fresh snapshot won and the old repo kept serving.
        # The corpus here is built with a long interval on purpose.
        other = _make_remote(self.tmp, "other-docs", {"wiki/x.md": "# From the other repo\n"})
        corpus = DocsCorpus(
            load_docs_repos(str(self.repos_file)), str(Path(self.tmp) / "clones-interval"),
            pull_interval_sec=3600, repos_file=str(self.repos_file),
        )
        self.assertEqual(corpus.get("wiki/x.md", _ctx("p"))["text"], "# X")  # snapshot now fresh
        self._write({"p": {"url": other, "branch": "master"}})
        # No time has passed, so freshness alone would still serve the old corpus.
        self.assertEqual(corpus.get("wiki/x.md", _ctx("p"))["text"], "# From the other repo")

    def test_a_repos_key_that_is_not_a_plain_name_is_refused(self):
        # The key becomes the clone directory; a traversal or absolute key would
        # point git's fetch and hard-reset outside the cache root, and ".git" is
        # the path every clone is probed for.
        for key in ("../other-repo", "/abs", "a/b", "..", ".", ".git"):
            with self.subTest(key=key):
                self.repos_file.write_text(json.dumps({key: {"url": "x", "branch": "main"}}))
                with self.assertRaises(ValueError):
                    load_docs_repos(str(self.repos_file))
        self.repos_file.write_text(json.dumps({"ok-name.v2": {"url": "x", "branch": "main"}}))
        self.assertIn("ok-name.v2", load_docs_repos(str(self.repos_file)))

    def test_no_repos_file_means_no_reload_attempt(self):
        corpus = DocsCorpus({"p": {"url": self.remote, "branch": "master"}},
                            str(Path(self.tmp) / "clones2"), pull_interval_sec=0.0)
        self.assertTrue(corpus.has_project("p"))
        self.assertFalse(corpus.has_project("q"))


class DocsCorpusTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.remote = _make_remote(self.tmp, "proj-a-docs", SEED)
        self.corpus = DocsCorpus(
            {"proj-a": {"url": self.remote, "branch": "master"}},
            str(Path(self.tmp) / "clones"),
            pull_interval_sec=0.0,  # always refresh: lets tests observe new commits
        )

    def tearDown(self):
        self._tmp.cleanup()

    def test_search_english(self):
        out = self.corpus.search("NATS messaging", 5, _ctx("proj-a"))
        self.assertEqual(out["results"][0]["path"], "raw/sessions/kickoff.md")
        self.assertTrue(out["commit"])

    def test_search_cjk(self):
        out = self.corpus.search("快取", 5, _ctx("proj-a"))
        self.assertEqual(out["results"][0]["path"], "raw/reports/cache-analysis.md")
        self.assertEqual(out["results"][0]["title"], "快取策略分析")
        self.assertIn("updated", out["results"][0])

    def test_get_returns_frontmatter_and_text(self):
        out = self.corpus.get("raw/reports/cache-analysis.md", _ctx("proj-a"))
        self.assertEqual(out["frontmatter"]["date"], "2026-07-01")
        self.assertIn("最佳化", out["text"])
        self.assertNotIn("---", out["text"].splitlines()[0] if out["text"] else "")

    def test_existence_oracle_unserved_equals_nonexistent(self):
        # README.md exists in the repo but is not served; zzz.md never existed.
        # Both must fail identically (same error type, same message).
        with self.assertRaises(DocsBackendError) as a:
            self.corpus.get("README.md", _ctx("proj-a"))
        with self.assertRaises(DocsBackendError) as b:
            self.corpus.get("zzz.md", _ctx("proj-a"))
        self.assertEqual(str(a.exception), str(b.exception))
        self.assertEqual(a.exception.status, b.exception.status)
        # dot-directories are unserved too
        with self.assertRaises(DocsBackendError) as c:
            self.corpus.get("wiki/.hidden/secret.md", _ctx("proj-a"))
        self.assertEqual(str(c.exception), str(a.exception))

    def test_unconfigured_project_is_rejected(self):
        with self.assertRaises(DocsBackendError):
            self.corpus.search("anything", 5, _ctx("proj-b"))

    def test_list_returns_all_served_docs(self):
        out = self.corpus.list(_ctx("proj-a"))
        paths = [d["path"] for d in out["documents"]]
        self.assertEqual(paths, ["raw/reports/cache-analysis.md", "raw/sessions/kickoff.md", "wiki/index.md"])
        self.assertNotIn("README.md", paths)
        by = {d["path"]: d for d in out["documents"]}
        self.assertEqual(by["raw/reports/cache-analysis.md"]["updated"], "2026-07-01")

    def test_refresh_picks_up_new_commit(self):
        out = self.corpus.search("brand-new-keyword", 5, _ctx("proj-a"))
        self.assertEqual(out["count"], 0)
        work = str(Path(self.tmp) / "proj-a-docs-work")
        _write_files(work, {"raw/reports/new.md": "# New\n\nbrand-new-keyword appears here.\n"})
        _sh(work, "git", "add", "-A")
        _sh(work, "git", "commit", "-qm", "add new report")
        _sh(work, "git", "push", "-q", "origin", "master")
        out = self.corpus.search("brand-new-keyword", 5, _ctx("proj-a"))
        self.assertEqual(out["results"][0]["path"], "raw/reports/new.md")


class _NullMemory(MemoryBackend):
    def search(self, query, limit, context):  # pragma: no cover - unused
        return {"results": []}


class _ListAudit(AuditSink):
    def __init__(self):
        self.events: list[AuditEvent] = []

    def write(self, event: AuditEvent) -> None:
        self.events.append(event)


class GatewayDocsTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        remote = _make_remote(self.tmp, "proj-a-docs", SEED)
        self.corpus = DocsCorpus(
            {"proj-a": {"url": remote, "branch": "master"}},
            str(Path(self.tmp) / "clones"),
            pull_interval_sec=3600,
        )
        self.audit = _ListAudit()
        self.app = GatewayApp(memory_backend=_NullMemory(), audit_sink=self.audit, docs_corpus=self.corpus)
        self.pa = Principal(actor="10000000", project="proj-a", roles=(), token_id="t1")
        self.pb = Principal(actor="10000001", project="proj-b", roles=(), token_id="t2")

    def tearDown(self):
        self._tmp.cleanup()

    def _call(self, principal, name, arguments):
        return self.app.handle_rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": name, "arguments": arguments}},
            principal,
        )

    def test_search_through_gateway_with_audit(self):
        resp = self._call(self.pa, "docs.search", {"query": "NATS"})
        data = resp["result"]["structuredContent"]
        self.assertEqual(data["results"][0]["path"], "raw/sessions/kickoff.md")
        self.assertEqual(self.audit.events[-1].tool, "docs.search")
        self.assertEqual(self.audit.events[-1].outcome, "ok")

    def test_other_project_token_cannot_read_the_corpus(self):
        resp = self._call(self.pb, "docs.get", {"path": "raw/sessions/kickoff.md"})
        result = resp["result"]
        self.assertTrue(result.get("isError"))
        self.assertIn("no docs corpus", result["content"][0]["text"])
        # and none of proj-a's content leaks into the error surface
        self.assertNotIn("NATS", str(resp))

    def test_docs_list_through_gateway(self):
        resp = self._call(self.pa, "docs.list", {})
        data = resp["result"]["structuredContent"]
        self.assertEqual(data["count"], 3)

    def test_tools_list_hides_docs_for_unconfigured_project(self):
        la = self.app.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, self.pa)
        lb = self.app.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, self.pb)
        names_a = {t["name"] for t in la["result"]["tools"]}
        names_b = {t["name"] for t in lb["result"]["tools"]}
        self.assertIn("docs.search", names_a)
        self.assertIn("docs.get", names_a)
        self.assertNotIn("docs.search", names_b)

    def test_docs_disabled_gateway_hides_and_denies(self):
        app = GatewayApp(memory_backend=_NullMemory(), audit_sink=self.audit)
        listing = app.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, self.pa)
        self.assertNotIn("docs.search", {t["name"] for t in listing["result"]["tools"]})

    def test_visible_tool_definitions_flag(self):
        with_docs = {t["name"] for t in visible_tool_definitions(self.pa, False, True)}
        without = {t["name"] for t in visible_tool_definitions(self.pa, False, False)}
        self.assertIn("docs.get", with_docs)
        self.assertNotIn("docs.get", without)


class TreeReadTests(unittest.TestCase):
    """The corpus is read from the git tree, never from the checked-out paths.

    A docs commit is authored by whoever can push to the docs repository, which
    is a wider set than whoever administers the gateway host, so a symlink
    committed as `wiki/x.md` must not be followed into the host filesystem."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.host_secret = Path(self.tmp) / "host-secret.txt"
        self.host_secret.write_text("HOST-ONLY-CONTENT\n", encoding="utf-8")
        self.remote = _make_remote(self.tmp, "tree-docs", {"wiki/index.md": "# Index\n"})
        self.work = str(Path(self.tmp) / "tree-docs-work")

    def tearDown(self):
        self._tmp.cleanup()

    def _corpus(self):
        return DocsCorpus(
            {"p": {"url": self.remote, "branch": "master"}},
            str(Path(self.tmp) / "clones"), pull_interval_sec=0.0,
        )

    def _push(self, message):
        _sh(self.work, "git", "add", "-A")
        _sh(self.work, "git", "commit", "-qm", message)
        _sh(self.work, "git", "push", "-q", "origin", "master")

    def test_a_committed_symlink_is_not_followed_and_is_not_a_document(self):
        (Path(self.work) / "wiki" / "leak.md").symlink_to(self.host_secret)
        self._push("add symlink")
        corpus = self._corpus()
        paths = {d["path"] for d in corpus.list(_ctx("p"))["documents"]}
        self.assertEqual(paths, {"wiki/index.md"})
        with self.assertRaises(DocsBackendError) as cm:
            corpus.get("wiki/leak.md", _ctx("p"))
        self.assertEqual(cm.exception.status, 404)
        self.assertEqual(corpus.search("HOST-ONLY-CONTENT", 10, _ctx("p"))["results"], [])

    def test_a_symlinked_directory_is_not_traversed(self):
        (Path(self.work) / "wiki" / "outside").symlink_to(Path(self.tmp))
        self._push("add dir symlink")
        paths = {d["path"] for d in self._corpus().list(_ctx("p"))["documents"]}
        self.assertEqual(paths, {"wiki/index.md"})

    def test_an_oversized_document_fails_the_refresh_loudly(self):
        corpus = self._corpus()
        corpus.MAX_DOC_BYTES = 4
        with self.assertRaises(DocsBackendError) as cm:
            corpus.list(_ctx("p"))
        self.assertEqual(cm.exception.status, 503)
        self.assertIn("exceeds limits", str(cm.exception))

    def test_a_corpus_with_too_many_documents_fails_the_refresh_loudly(self):
        _write_files(self.work, {"wiki/second.md": "# Two\n"})
        self._push("second doc")
        corpus = self._corpus()
        corpus.MAX_DOCS = 1
        with self.assertRaises(DocsBackendError) as cm:
            corpus.list(_ctx("p"))
        self.assertEqual(cm.exception.status, 503)

    def test_a_corpus_over_the_total_byte_cap_fails_the_refresh_loudly(self):
        corpus = self._corpus()
        corpus.MAX_CORPUS_BYTES = 4
        with self.assertRaises(DocsBackendError) as cm:
            corpus.list(_ctx("p"))
        self.assertEqual(cm.exception.status, 503)

    def test_a_git_timeout_is_reported_as_unavailable_not_a_crash(self):
        corpus = self._corpus()
        original = corpus._git

        def hang(cwd, *args, **kwargs):
            if args and args[0] == "clone":
                raise subprocess.TimeoutExpired("git", 30)
            return original(cwd, *args, **kwargs)

        corpus._git = hang
        with self.assertRaises(DocsBackendError) as cm:
            corpus.list(_ctx("p"))
        self.assertEqual(cm.exception.status, 503)
        self.assertIn("timed out", str(cm.exception))

    def test_git_stderr_goes_to_the_operator_log_never_to_the_client(self):
        # git's stderr can quote the remote URL, a host, or a server sideband
        # message; the tool error the client reads must not carry any of it.
        corpus = self._corpus()
        original = corpus._git
        sentinel = "SENTINEL-git-said-ssh://svc-user@internal-host/x"

        def fail(cwd, *args, **kwargs):
            if args and args[0] == "clone":
                raise subprocess.CalledProcessError(128, ["git", "clone"], stderr=sentinel.encode())
            return original(cwd, *args, **kwargs)

        corpus._git = fail
        with contextlib.redirect_stderr(io.StringIO()) as err, self.assertRaises(DocsBackendError) as cm:
            corpus.list(_ctx("p"))
        self.assertEqual(cm.exception.status, 503)
        self.assertNotIn(sentinel, str(cm.exception))
        self.assertNotIn("internal-host", str(cm.exception))
        self.assertIn("docs corpus unavailable", str(cm.exception))
        self.assertIn(sentinel, err.getvalue())   # the operator still sees why

    def test_content_with_multibyte_text_survives_the_batch_read(self):
        _write_files(self.work, {"wiki/cjk.md": "# 中文標題\n\n內容 — with dash\n"})
        self._push("cjk")
        doc = self._corpus().get("wiki/cjk.md", _ctx("p"))
        self.assertEqual(doc["title"], "中文標題")
        self.assertIn("內容 — with dash", doc["text"])


if __name__ == "__main__":
    unittest.main()
