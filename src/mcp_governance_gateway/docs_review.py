"""Turning a docs proposal into a change on somebody's review host.

This is the orchestration between three things that each know one part:
`DocsCorpus` knows which project has a corpus and what a document currently
says, the credential store knows the caller's own token for that host, and a
`ReviewBackend` knows how to talk to it. None of them should know about the
other two, so the joining happens here.

The rule that shapes everything below: **a proposal is made under the caller's
own credential, or it is not made.** There is no shared service account to fall
back to. That is not a limitation to work around -- it is what makes "an agent
may propose, only a person may publish" a claim about an accountable human
rather than about a robot with a token. A caller who has not enrolled gets a
428 that says how to, exactly as the issue backends already do.
"""
from __future__ import annotations

from typing import Any, Callable

from .issue_backend import IssueBackendError
from .memory_backend import RequestContext
from .redmine_keystore import KeyState
from .review_backend import ReviewBackendError, ReviewSpec, stamped

KeyResolver = Callable[[str, str], tuple[KeyState, str | None]]


class DocsReviewService:
    """The docs write tools, from the caller's request to the review host.

    `backends` maps a review-host type ("github", "gitlab") to an implementation.
    A project whose corpus names a type with no implementation is a configuration
    error the caller cannot fix, so it fails loud rather than reading as "this
    project has no write path".
    """

    def __init__(
        self,
        corpus: Any,
        backends: dict[str, Any],
        key_resolver: KeyResolver | None = None,
        credential_portal_url: str | None = None,
    ) -> None:
        self._corpus = corpus
        self._backends = backends
        self._key_resolver = key_resolver
        self._portal = credential_portal_url

    # --- enablement ------------------------------------------------------

    def spec_for(self, project: str | None) -> ReviewSpec | None:
        if not project or self._corpus is None:
            return None
        return self._corpus.review_spec_for(project)

    def has_project(self, project: str | None) -> bool:
        """Whether this project can propose at all — the flag `tools/list` uses.

        A corpus with no `review` block is read-only, which is the default and
        the majority case. Advertising a write tool that every call would refuse
        is worse than not advertising it.
        """
        return self.spec_for(project) is not None

    # --- the tools -------------------------------------------------------

    def create(self, path: str, content: str, message: str, context: RequestContext) -> dict[str, Any]:
        spec, backend, credential = self._resolve(context)
        self._require_servable(path)
        self._refuse_if_present(spec, path, context)
        result = backend.open_change(spec, path, content, message, credential, context)
        return {"path": path, **result, "status": "proposed"}

    def update(self, path: str, content: str, message: str, base_sha: str,
               context: RequestContext) -> dict[str, Any]:
        spec, backend, credential = self._resolve(context)
        self._require_servable(path)
        result = backend.update_change(spec, path, content, message, base_sha, credential, context)
        return {"path": path, **result, "status": "proposed"}

    def comment(self, change_ref: int, body: str, context: RequestContext) -> dict[str, Any]:
        spec, backend, credential = self._resolve(context)
        # Stamped here rather than in the adapter so every host gets the same
        # footer from one place: its presence is what tells a human reader the
        # comment came through the gateway rather than from the person directly.
        return backend.comment(spec, change_ref, stamped(body, context), credential, context)

    def get(self, change_ref: int, context: RequestContext) -> dict[str, Any]:
        spec, backend, credential = self._resolve(context)
        return backend.get_change(spec, change_ref, credential, context)

    # --- internals -------------------------------------------------------

    def _require_servable(self, path: str) -> None:
        """The write path may only propose files the READ path would serve.

        Without this the docs tools are a general "propose any file into this
        repository" primitive: nothing else stopped `docs.create` naming
        `.github/workflows/ci.yml`, or a source file, or a `CODEOWNERS`. A human
        still has to merge it, so it is not a direct compromise -- it is a much
        better phishing lure than a Markdown file, sitting behind a tool whose
        name says "docs".

        The rule is exactly the read path's own filter (`_load_docs`): under one
        of the served directories, ending in `.md`, and no dot-prefixed segment.
        Keeping them identical is the point -- a document you could propose but
        never read back would be a strange thing to be able to make.
        """
        served = getattr(self._corpus, "SERVED_DIRS", ("raw/", "wiki/"))
        parts = path.split("/")
        if (not path.startswith(tuple(served)) or not path.endswith(".md")
                or any(part.startswith(".") or not part for part in parts)):
            raise ReviewBackendError(
                f"documents live under {' or '.join(served)} and end in .md; {path!r} does not, "
                "and this tool proposes documents rather than arbitrary files",
                status=400,
            )

    def _refuse_if_present(self, spec: ReviewSpec, path: str, context: RequestContext) -> None:
        """A create against an existing document is refused here as well as by
        the host.

        GitHub answers 422 for a create with no blob sha, so this is belt and
        braces — but the corpus is the thing the caller just read, so the message
        it can give ("that document exists; use docs.update") is the useful one,
        and it costs no round trip.
        """
        try:
            self._corpus.get(path, context)
        except Exception:
            return
        raise ReviewBackendError(
            f"{path} already exists in this project's corpus; use docs.update to propose a change to it",
            status=409,
        )

    def _resolve(self, context: RequestContext) -> tuple[ReviewSpec, Any, str]:
        spec = self.spec_for(context.project)
        if spec is None:
            raise ReviewBackendError(
                "this project's docs corpus is read-only: no review host is configured for it",
                status=404,
            )
        backend = self._backends.get(spec.type)
        if backend is None:
            raise ReviewBackendError(
                f"this gateway has no adapter for review host type {spec.type!r}", status=503
            )
        return spec, backend, self._credential(spec, context)

    def _credential(self, spec: ReviewSpec, context: RequestContext) -> str:
        """The caller's own token for this review host, or a loud refusal.

        The same four-state ladder the issue backends use, for the same reason:
        "you have not enrolled" and "the store is broken" and "your record can no
        longer be decrypted" are three different problems with three different
        fixes, and collapsing them into one message sends people to re-enroll
        when re-enrolling is not the answer.
        """
        hint = f" ({self._portal})" if self._portal else ""
        if self._key_resolver is None:
            raise ReviewBackendError(
                "proposing a document change needs your own credential for the review host, and this "
                "gateway has no credential store configured" + hint,
                status=428,
            )
        state, personal = self._key_resolver(context.actor, spec.backend_key)
        if state is KeyState.DEGRADED:
            raise ReviewBackendError(
                "the credential store is temporarily unusable, so the gateway cannot act as you on the "
                "review host. Proposing under a shared account would put someone else's name on your "
                "change. Re-enrolling is not the fix -- operators can see this on /healthz",
                status=503,
            )
        if state is KeyState.UNDECRYPTABLE:
            raise ReviewBackendError(
                "your credential for the review host could not be decrypted (the keystore may have been "
                "rotated); please re-enroll it" + hint,
                status=409,
            )
        if state is not KeyState.OK or not personal:
            raise ReviewBackendError(
                "proposing a document change is done under your own identity on the review host, so it "
                "needs your own credential -- there is no shared account to fall back to. Enroll one and "
                "try again" + hint,
                status=428,
            )
        return personal


__all__ = ["DocsReviewService", "IssueBackendError", "KeyResolver"]
