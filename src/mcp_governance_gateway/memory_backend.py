from __future__ import annotations

from dataclasses import dataclass
import http.client
import json
from pathlib import Path
from typing import Any
from urllib import error, parse, request

from .auth import Principal

_MAX_RESPONSE_BYTES = 2_000_000
# Upper bound on how many memories memory.list pulls from the backend before
# filtering to the caller's project (the backend does not filter server-side).
_LIST_FETCH_MAX = 5_000


class MemoryBackendError(Exception):
    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class RequestContext:
    actor: str
    project: str
    client: str
    request_id: str
    issue_project: str | None = None

    @property
    def redmine_project(self) -> str | None:
        """Deprecated alias for `issue_project`."""
        return self.issue_project

    @classmethod
    def from_principal(cls, principal: Principal, request_id: str, client: str = "unknown") -> "RequestContext":
        return cls(
            actor=principal.actor,
            project=principal.project,
            client=client,
            request_id=request_id,
            issue_project=principal.issue_project,
        )

    def metadata(self) -> dict[str, str]:
        return {
            "projectId": self.project,
            "actor": self.actor,
            "source": "mcp-governance-gateway",
            "client": self.client,
            "requestId": self.request_id,
        }


class MemoryBackend:
    def search(self, query: str, limit: int, context: RequestContext) -> dict[str, Any]:
        raise NotImplementedError

    def save(self, text: str, tags: list[str], context: RequestContext) -> dict[str, Any]:
        raise NotImplementedError

    def list(self, limit: int, offset: int, context: RequestContext) -> dict[str, Any]:
        raise NotImplementedError

    def lesson_save(self, rule: str, reason: str | None, confidence: float, context: RequestContext) -> dict[str, Any]:
        raise NotImplementedError

    def lesson_list(self, limit: int, context: RequestContext) -> dict[str, Any]:
        raise NotImplementedError

    def action_create(self, title: str, description: str | None, priority: str | None, context: RequestContext) -> dict[str, Any]:
        raise NotImplementedError

    def action_list(self, limit: int, context: RequestContext, include_done: bool = False) -> dict[str, Any]:
        raise NotImplementedError

    def action_update_status(self, action_id: str, status: str, context: RequestContext) -> dict[str, Any]:
        raise NotImplementedError


class ActorLabels:
    """Maps the immutable actor key (employee id) to a human-readable label, sourced
    from the per-user token store, so memory/lesson/action listings show a readable
    contributor instead of a bare employee id. mtime-cached; actors with no mapping
    (gateway-* service actors, already-email actors) pass through unchanged."""

    def __init__(self, token_file: str | None) -> None:
        self._path = Path(token_file) if token_file else None
        self._map: dict[str, str] = {}
        self._sig: tuple | None = None

    def get(self) -> dict[str, str]:
        if self._path is None:
            return self._map
        try:
            st = self._path.stat()
            sig = (st.st_mtime_ns, st.st_size, st.st_ino)
        except OSError:
            return self._map
        if sig != self._sig:
            try:
                data = json.loads(self._path.read_text(encoding="utf-8"))
                out: dict[str, str] = {}
                for t in data.get("tokens", []):
                    if not isinstance(t, dict):
                        continue
                    actor, email, name = t.get("actor"), t.get("email"), t.get("name")
                    # Prefer a stored display name over the email; _display_actor
                    # strips the domain off an email, which is a worse label than a
                    # real name when the store has one.
                    label = name if isinstance(name, str) and name.strip() else email
                    if isinstance(actor, str) and isinstance(label, str) and actor and label and actor not in out:
                        out[actor] = label
                        # Key by email as well: records written before a deployment
                        # re-keyed actors to an immutable id carry the raw email as
                        # their actor, and without this the same person shows up as
                        # two contributors either side of that migration.
                        if isinstance(email, str) and email and email not in out:
                            out[email] = label
                self._map = out
            except Exception:
                pass  # keep last-good on a transient read/parse error
            self._sig = sig
        return self._map


class HttpMemoryBackend(MemoryBackend):
    def __init__(
        self,
        base_url: str,
        backend_token: str | None,
        search_path: str,
        save_path: str,
        timeout_sec: float = 10,
        list_path: str = "/agentmemory/memories",
        lesson_path: str = "/agentmemory/lessons",
        action_path: str = "/agentmemory/actions",
        actor_labels: "ActorLabels | None" = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._backend_token = backend_token
        self._search_path = _normalize_path(search_path)
        self._save_path = _normalize_path(save_path)
        self._list_path = _normalize_path(list_path)
        self._lesson_path = _normalize_path(lesson_path)
        self._action_path = _normalize_path(action_path)
        self._timeout_sec = timeout_sec
        self._actor_labels = actor_labels

    def _labels(self) -> dict[str, str]:
        return self._actor_labels.get() if self._actor_labels is not None else {}

    def _label_memory(self, mem: dict[str, Any], labels: dict[str, str]) -> dict[str, Any]:
        # rewrite the `actor:<employee id>` concept to `actor:<name>` and add a readable
        # top-level `actor` field, so any MCP client shows the name, not the employee id.
        out = dict(mem)
        concepts = mem.get("concepts")
        if isinstance(concepts, list):
            new: list[Any] = []
            for c in concepts:
                if isinstance(c, str) and c.startswith("actor:"):
                    new.append("actor:" + _display_actor(c[len("actor:"):], labels))
                else:
                    new.append(c)
            out["concepts"] = new
        raw_actor = _actor_from(mem)
        if raw_actor:
            out["actor"] = _display_actor(raw_actor, labels)
        return out

    def _label_named(self, item: dict[str, Any], labels: dict[str, str]) -> dict[str, Any]:
        actor = item.get("actor")
        if actor:
            return {**item, "actor": _display_actor(actor, labels)}
        return item

    def search(self, query: str, limit: int, context: RequestContext) -> dict[str, Any]:
        # agentmemory filters by `project` server-side, and its result items carry no
        # project field of their own. The gateway always injects the token's project
        # (the client cannot override it), so results are scoped to the caller's
        # project. Return only the result list in a gateway-built envelope; the raw
        # backend body (aggregate `tokens_used`/`truncated`/etc.) is never spread in.
        response = self._post(self._search_path, {"query": query, "limit": limit, "project": context.project})
        results = response.get("results") if isinstance(response, dict) else None
        if not isinstance(results, list):
            results = []
        results = results[:limit]  # defensive cap: never return more than asked, even if the backend ignores `limit`
        labels = self._labels()
        # The search endpoint wraps each hit as {observation, score, sessionId};
        # unwrap so normalization sees the memory's own fields instead of silently
        # passing the wrapper through unlabelled and with an empty `content`. The
        # relevance score is the one useful thing on the wrapper, so it is carried
        # onto the normalized record rather than lost with it.
        results = [self._unwrap_hit(r, labels) if isinstance(r, dict) else r for r in results]
        return {"results": results, "count": len(results)}

    def _unwrap_hit(self, hit: dict[str, Any], labels: dict[str, str]) -> dict[str, Any]:
        observation = hit.get("observation")
        if not isinstance(observation, dict):
            return self._label_memory(_normalize_memory(hit), labels)
        record = self._label_memory(_normalize_memory(observation), labels)
        if hit.get("score") is not None:
            record["score"] = hit["score"]
        return record

    def save(self, text: str, tags: list[str], context: RequestContext) -> dict[str, Any]:
        # Stamp the contributor into concepts (the /remember API has no actor field)
        # so reports and the viewer can attribute and group memories by who wrote them.
        concepts = list(tags)
        concepts.append(f"actor:{context.actor}")
        payload: dict[str, Any] = {"content": text, "project": context.project, "concepts": concepts}
        response = self._post(self._save_path, payload)
        # Do not echo the backend body. agentmemory returns {success, memory:{...}};
        # return only gateway-built fields plus the validated nested memory id.
        result: dict[str, Any] = {"saved": True, "project": context.project}
        memory = response.get("memory") if isinstance(response, dict) else None
        if isinstance(memory, dict):
            memory_id = memory.get("id")
            # Only surface the id when the backend stored it under the project we
            # sent. A project mismatch is a backend anomaly; never propagate a
            # foreign-project memory id into the result or audit.
            if isinstance(memory_id, str) and memory_id and memory.get("project") == context.project:
                result["id"] = memory_id
        return result

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._backend_token:
            headers["Authorization"] = f"Bearer {self._backend_token}"

        req = request.Request(
            parse.urljoin(self._base_url + "/", path.lstrip("/")),
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self._timeout_sec) as response:
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
        except error.HTTPError as exc:
            raise MemoryBackendError(f"memory backend HTTP {exc.code}", status=exc.code) from exc
        except (OSError, http.client.HTTPException, ValueError) as exc:
            # A garbled or truncated reply is an HTTPException, not an OSError, and
            # a credential or redirect the request cannot be encoded with is a
            # ValueError; either way the backend is unusable, not the caller.
            raise MemoryBackendError("memory backend unavailable") from exc
        return _decode(raw)

    def list(self, limit: int, offset: int, context: RequestContext) -> dict[str, Any]:
        # The backend /memories endpoint does NOT filter by project, but each item
        # carries a project field. Fetch a bounded window, keep only this project's
        # items (defense-in-depth isolation), sort newest-first, then paginate.
        fetched, truncated = self._fetch_all_memories()
        scoped = [m for m in fetched if isinstance(m, dict) and m.get("project") == context.project]
        # Drop superseded versions: a near-identical re-save creates a v2 that supersedes
        # v1, but the backend list still returns the old v1 (isLatest=False). Keep only the
        # current version so recall shows each memory once (records missing the flag are kept).
        scoped = [m for m in scoped if m.get("isLatest") is not False]
        scoped.sort(key=lambda m: (m.get("updatedAt") or m.get("createdAt") or ""), reverse=True)
        total = len(scoped)
        page = scoped[offset:offset + limit]
        labels = self._labels()
        return {
            "memories": [self._label_memory(_normalize_memory(m), labels) for m in page],
            "count": len(page),
            "total": total,
            "offset": offset,
            "truncated": truncated,
        }

    def lesson_save(self, rule: str, reason: str | None, confidence: float, context: RequestContext) -> dict[str, Any]:
        # A lesson is a project-scoped "never do this again" rule. agentmemory stores it
        # under `content`; fold the optional reason in and stamp the actor as a tag. The
        # gateway always injects the token's project (client cannot override).
        content = rule if not reason else f"{rule}\n\nReason: {reason}"
        payload: dict[str, Any] = {
            "content": content,
            "project": context.project,
            "confidence": confidence,
            "tags": [f"actor:{context.actor}"],
        }
        response = self._post(self._lesson_path, payload)
        result: dict[str, Any] = {"saved": True, "project": context.project}
        lesson = response.get("lesson") if isinstance(response, dict) else None
        if isinstance(lesson, dict):
            lesson_id = lesson.get("id")
            # Only surface the id when stored under the project we sent (defense-in-depth).
            if isinstance(lesson_id, str) and lesson_id and lesson.get("project") == context.project:
                result["id"] = lesson_id
        return result

    def lesson_list(self, limit: int, context: RequestContext) -> dict[str, Any]:
        # agentmemory /lessons filters by project server-side; re-filter defensively.
        raw = self._get(self._lesson_path, {"project": context.project})
        items = raw.get("lessons") if isinstance(raw, dict) else None
        if not isinstance(items, list):
            items = []
        scoped = [lesson for lesson in items if isinstance(lesson, dict) and lesson.get("project") == context.project]
        # Highest-confidence first (stable), so the cap keeps the team's most
        # reinforced rules instead of an arbitrary backend-order prefix. A
        # non-numeric confidence sorts last rather than raising: this is a listing,
        # and one malformed record must not take the whole list down.
        scoped.sort(key=lambda lesson: -_as_number(lesson.get("confidence")))
        scoped = scoped[:limit]
        labels = self._labels()
        return {"lessons": [self._label_named(_normalize_lesson(lesson), labels) for lesson in scoped], "count": len(scoped)}

    def action_create(self, title: str, description: str | None, priority: str | None, context: RequestContext) -> dict[str, Any]:
        # An action is a project-scoped follow-up (status pending->active->done/blocked).
        # The gateway always injects the token's project; actor is stamped as a tag.
        payload: dict[str, Any] = {"title": title, "project": context.project, "tags": [f"actor:{context.actor}"]}
        if description is not None:
            payload["description"] = description
        if priority is not None:
            payload["priority"] = priority
        response = self._post(self._action_path, payload)
        result: dict[str, Any] = {"created": True, "project": context.project}
        action = response.get("action") if isinstance(response, dict) else None
        if isinstance(action, dict):
            action_id = action.get("id")
            if isinstance(action_id, str) and action_id and action.get("project") == context.project:
                result["id"] = action_id
                result["status"] = action.get("status")
        return result

    def action_list(self, limit: int, context: RequestContext, include_done: bool = False) -> dict[str, Any]:
        # agentmemory /actions filters by project server-side; re-filter defensively.
        raw = self._get(self._action_path, {"project": context.project})
        items = raw.get("actions") if isinstance(raw, dict) else None
        if not isinstance(items, list):
            items = []
        scoped = [action for action in items if isinstance(action, dict) and action.get("project") == context.project]
        if not include_done:
            # The default is the LIVE board (pending/active/blocked): done actions
            # are history and must not crowd open ones out of the limit window.
            scoped = [action for action in scoped if action.get("status") != "done"]
        scoped = scoped[:limit]
        labels = self._labels()
        return {"actions": [self._label_named(_normalize_action(action), labels) for action in scoped], "count": len(scoped)}

    def action_update_status(self, action_id: str, status: str, context: RequestContext) -> dict[str, Any]:
        # The backend update endpoint (`/actions/update`, a POST) takes only an actionId,
        # so WITHOUT a project pre-check a caller could flip another project's action.
        # Verify the target belongs to the caller's project first — mirrors issues.* where
        # get/update verify the issue belongs to the token's project (cross-project => 404).
        # The project is checked on each row as well as sent as a filter: the
        # filter is the backend's promise, the row check is this side's own.
        raw = self._get(self._action_path, {"project": context.project})
        items = raw.get("actions") if isinstance(raw, dict) else None
        if not isinstance(items, list) or not any(
            isinstance(a, dict) and a.get("id") == action_id and a.get("project") == context.project
            for a in items
        ):
            raise MemoryBackendError("action not found in project", status=404)
        response = self._post(self._action_path.rstrip("/") + "/update", {"actionId": action_id, "status": status})
        action = response.get("action") if isinstance(response, dict) else None
        # Belt-and-suspenders: only report success if the updated action is still ours.
        if not (isinstance(action, dict) and action.get("project") == context.project):
            raise MemoryBackendError("action project mismatch", status=404)
        return {"updated": True, "id": action_id, "status": action.get("status")}

    def _get(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        url = parse.urljoin(self._base_url + "/", path.lstrip("/"))
        if params:
            url = f"{url}?{parse.urlencode(params)}"
        headers = {"Accept": "application/json"}
        if self._backend_token:
            headers["Authorization"] = f"Bearer {self._backend_token}"
        req = request.Request(url, headers=headers, method="GET")
        try:
            with request.urlopen(req, timeout=self._timeout_sec) as response:
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
        except error.HTTPError as exc:
            raise MemoryBackendError(f"memory backend HTTP {exc.code}", status=exc.code) from exc
        except (OSError, http.client.HTTPException, ValueError) as exc:
            # A garbled or truncated reply is an HTTPException, not an OSError, and
            # a credential or redirect the request cannot be encoded with is a
            # ValueError; either way the backend is unusable, not the caller.
            raise MemoryBackendError("memory backend unavailable") from exc
        return _decode(raw)

    def _fetch_all_memories(self) -> tuple[list[dict[str, Any]], bool]:
        out: list[dict[str, Any]] = []
        offset = 0
        page_size = 500
        while len(out) < _LIST_FETCH_MAX:
            raw = self._get(self._list_path, {"limit": page_size, "offset": offset})
            items = raw.get("memories") if isinstance(raw, dict) else None
            if not isinstance(items, list) or not items:
                return out, False
            out.extend(items)
            offset += len(items)
            total = raw.get("total")
            if isinstance(total, int) and offset >= total:
                return out, False
            if len(items) < page_size:
                return out, False
        return out[:_LIST_FETCH_MAX], True


def _decode(raw: bytes) -> dict[str, Any]:
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise MemoryBackendError("memory backend response too large")
    if not raw:
        return {}
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise MemoryBackendError("memory backend returned invalid JSON") from exc
    if not isinstance(decoded, dict):
        return {"items": decoded}
    return decoded


def _as_number(value: Any) -> float:
    """A sortable number from an untrusted backend field; 0 for anything else."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0
    return float(value)


def _normalize_memory(memory: dict[str, Any]) -> dict[str, Any]:
    concepts = memory.get("concepts")
    # Search hits use "narrative"/"timestamp" where the list and save endpoints use
    # "content"/"createdAt"/"updatedAt"; fall back so both record shapes normalize
    # to the documented flat schema without the caller needing a shape flag.
    return {
        "id": memory.get("id"),
        "project": memory.get("project"),
        "title": memory.get("title"),
        "content": memory.get("content") or memory.get("narrative"),
        "concepts": concepts if isinstance(concepts, list) else [],
        "type": memory.get("type"),
        "createdAt": memory.get("createdAt") or memory.get("timestamp"),
        "updatedAt": memory.get("updatedAt") or memory.get("timestamp"),
    }


def _actor_from(item: dict[str, Any]) -> str | None:
    # agentmemory stores the contributor as an `actor:<who>` tag on lessons/actions
    # (memories use `concepts`); surface it so lists show who wrote each entry.
    for key in ("tags", "concepts"):
        vals = item.get(key)
        if isinstance(vals, list):
            for v in vals:
                if isinstance(v, str) and v.startswith("actor:"):
                    return v[len("actor:"):]
    return None


def _display_actor(value: str | None, labels: dict[str, str]) -> str | None:
    # employee id -> email -> local part (strip @domain); already-email actors also strip the
    # domain; gateway-* / unknown actors pass through unchanged.
    if not value:
        return value
    email = labels.get(value) or (value if "@" in value else None)
    return email.split("@", 1)[0] if email else value


def _normalize_lesson(lesson: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": lesson.get("id"),
        "project": lesson.get("project"),
        "content": lesson.get("content"),
        "confidence": lesson.get("confidence"),
        "reinforcements": lesson.get("reinforcements"),
        "actor": _actor_from(lesson),
        "createdAt": lesson.get("createdAt"),
    }


def _normalize_action(action: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": action.get("id"),
        "project": action.get("project"),
        "title": action.get("title"),
        "description": action.get("description"),
        "priority": action.get("priority"),
        "status": action.get("status"),
        "actor": _actor_from(action),
        "createdAt": action.get("createdAt"),
    }


def _normalize_path(path: str) -> str:
    return path if path.startswith("/") else f"/{path}"
