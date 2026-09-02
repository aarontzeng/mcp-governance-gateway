from __future__ import annotations

from dataclasses import dataclass
import math
import os
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    token_file: str
    allowed_origins: tuple[str, ...]
    memory_base_url: str
    memory_backend_token: str | None
    memory_search_path: str
    memory_save_path: str
    memory_timeout_sec: float
    memory_save_max_text_bytes: int
    memory_user_writes_per_minute: int
    memory_project_writes_per_day: int
    memory_user_reads_per_minute: int
    user_token_file: str | None = None
    memory_list_path: str = "/agentmemory/memories"
    memory_lesson_path: str = "/agentmemory/lessons"
    memory_action_path: str = "/agentmemory/actions"
    # Which issue backend this deployment runs: "redmine" (default) or "gitlab".
    # Per-deployment, not per-project — all current tenants share one tracker;
    # per-project routing waits for a real mixed deployment (roadmap Phase 9).
    issue_backend: str = "redmine"
    redmine_base_url: str | None = None
    redmine_api_key: str | None = None
    redmine_timeout_sec: float = 10.0
    # Per-user Redmine key store (encrypted at rest). When the store file is set the
    # adapter resolves each caller's own Redmine key by actor and uses it for issue
    # writes, falling back to redmine_api_key only per the enforce flag. Absent -> the
    # single shared redmine_api_key is used for everything (backward compatible).
    redmine_keystore_file: str | None = None
    redmine_keystore_master_file: str | None = None
    # enforced per-user mode (Decision 5/B): a write with no valid personal key
    # fails loud instead of falling back to the shared key.
    redmine_enforce_personal_key: bool = False
    gitlab_base_url: str | None = None
    gitlab_token: str | None = None
    gitlab_timeout_sec: float = 10.0
    gitlab_enforce_personal_key: bool = False
    # Shared HMAC secret for verifying a front gateway's signed identity headers
    # (the front gateway IDENTITY_CLAIMS_SECRET). Empty disables propagation.
    identity_claims_secret: str | None = None
    identity_header_prefix: str = "X-Forwarded-User"
    # Docs corpus (read-only docs.search/docs.get over per-project docs repos).
    # Enabled only when both are set; docs_repos_file maps project -> {url, branch}.
    docs_repos_file: str | None = None
    docs_clone_dir: str | None = None
    docs_pull_interval_sec: float = 300.0
    # Where a user enrolls their own downstream credential (the deployment's
    # portal / admin page). Appended to the errors that ask a caller to enroll or
    # re-enroll a key, so the message can point somewhere instead of describing
    # an endpoint the user has to go find. Unset -> those errors carry no URL.
    credential_portal_url: str | None = None
    # Jenkins CI (read-only ci.status/ci.log). Enabled when url + jobs file are set.
    jenkins_base_url: str | None = None
    jenkins_user: str | None = None
    jenkins_token: str | None = None
    jenkins_timeout_sec: float = 10.0
    ci_jobs_file: str | None = None
    # Bounds on the artifact data plane. The bytes do not pass through an MCP
    # result, so none of the tool-level limits apply to them: without these a
    # single surprise artifact, or a handful of slow clients, is the gateway's
    # first resource-exhaustion boundary.
    ci_artifact_max_bytes: int = 256 * 1024 * 1024
    ci_artifact_max_concurrent: int = 4
    # Public base for the artifact streaming endpoint ci.artifact hands back
    # (e.g. https://host/adapter). Unset -> ci.artifact returns a relative
    # "/ci/artifact?..." reference the caller prepends its own origin to.
    ci_artifact_base_url: str | None = None

    @classmethod
    def from_env(cls) -> "Settings":
        token_file = os.environ.get("GATEWAY_TOKEN_FILE")
        if not token_file:
            raise ValueError("GATEWAY_TOKEN_FILE is required")

        return cls(
            host=os.environ.get("GATEWAY_HOST", "127.0.0.1"),
            port=_int_env("GATEWAY_PORT", 8080, minimum=1),
            token_file=token_file,
            user_token_file=os.environ.get("GATEWAY_USER_TOKEN_FILE") or None,
            allowed_origins=_csv_env("GATEWAY_ALLOWED_ORIGINS"),
            memory_base_url=_url_env("MEMORY_BASE_URL", "http://127.0.0.1:3111"),
            memory_backend_token=os.environ.get("MEMORY_BACKEND_TOKEN") or None,
            memory_search_path=os.environ.get("MEMORY_SEARCH_PATH", "/agentmemory/search"),
            memory_save_path=os.environ.get("MEMORY_SAVE_PATH", "/agentmemory/remember"),
            memory_timeout_sec=_timeout_env("MEMORY_TIMEOUT_SEC"),
            memory_save_max_text_bytes=_int_env("MEMORY_SAVE_MAX_TEXT_BYTES", 32_768, minimum=0),
            memory_user_writes_per_minute=_int_env("MEMORY_USER_WRITES_PER_MINUTE", 30, minimum=0),
            memory_project_writes_per_day=_int_env("MEMORY_PROJECT_WRITES_PER_DAY", 5_000, minimum=0),
            memory_user_reads_per_minute=_int_env("MEMORY_USER_READS_PER_MINUTE", 120, minimum=0),
            memory_list_path=os.environ.get("MEMORY_LIST_PATH", "/agentmemory/memories"),
            memory_lesson_path=os.environ.get("MEMORY_LESSON_PATH", "/agentmemory/lessons"),
            memory_action_path=os.environ.get("MEMORY_ACTION_PATH", "/agentmemory/actions"),
            issue_backend=(os.environ.get("ISSUE_BACKEND") or "redmine").strip().lower(),
            redmine_base_url=_url_env("REDMINE_BASE_URL"),
            redmine_api_key=os.environ.get("REDMINE_API_KEY") or None,
            redmine_timeout_sec=_timeout_env("REDMINE_TIMEOUT_SEC"),
            redmine_keystore_file=os.environ.get("REDMINE_KEYSTORE_FILE") or None,
            redmine_keystore_master_file=os.environ.get("REDMINE_KEYSTORE_MASTER_FILE") or None,
            redmine_enforce_personal_key=_bool_env("REDMINE_ENFORCE_PERSONAL_KEY"),
            gitlab_base_url=_url_env("GITLAB_BASE_URL"),
            gitlab_token=os.environ.get("GITLAB_TOKEN") or None,
            gitlab_timeout_sec=_timeout_env("GITLAB_TIMEOUT_SEC"),
            gitlab_enforce_personal_key=_bool_env("GITLAB_ENFORCE_PERSONAL_KEY"),
            credential_portal_url=os.environ.get("CREDENTIAL_PORTAL_URL") or None,
            identity_claims_secret=os.environ.get("IDENTITY_CLAIMS_SECRET") or None,
            identity_header_prefix=os.environ.get("IDENTITY_HEADER_PREFIX", "X-Forwarded-User"),
            docs_repos_file=os.environ.get("DOCS_REPOS_FILE") or None,
            docs_clone_dir=os.environ.get("DOCS_CLONE_DIR") or None,
            docs_pull_interval_sec=float(os.environ.get("DOCS_PULL_INTERVAL_SEC", "300")),
            jenkins_base_url=_url_env("JENKINS_BASE_URL"),
            jenkins_user=os.environ.get("JENKINS_USER") or None,
            jenkins_token=os.environ.get("JENKINS_TOKEN") or None,
            jenkins_timeout_sec=_timeout_env("JENKINS_TIMEOUT_SEC"),
            ci_jobs_file=os.environ.get("CI_JOBS_FILE") or None,
            ci_artifact_base_url=os.environ.get("CI_ARTIFACT_BASE_URL") or None,
            ci_artifact_max_bytes=_int_env("CI_ARTIFACT_MAX_BYTES", 256 * 1024 * 1024, minimum=1),
            ci_artifact_max_concurrent=_int_env("CI_ARTIFACT_MAX_CONCURRENT", 4, minimum=1),
        )


def _csv_env(name: str) -> tuple[str, ...]:
    value = os.environ.get(name, "")
    return tuple(part.strip() for part in value.split(",") if part.strip())


def _bool_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _int_env(name: str, default: int, *, minimum: int | None = None) -> int:
    value = os.environ.get(name)
    parsed = default if value is None else int(value)
    if minimum is not None and parsed < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    return parsed


def _url_env(name: str, default: str | None = None) -> str | None:
    # A base URL urlopen cannot use ("ci.internal:8080", no scheme) fails at
    # request time as a ValueError, which the tool dispatcher reports as the
    # caller's mistake. Refusing it at startup names the operator's instead.
    value = os.environ.get(name) or default
    if value is None:
        return None
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError(f"{name} must be an http:// or https:// URL, got {value!r}")
    return value


def _timeout_env(name: str, default: float = 10.0) -> float:
    # Same fate for a timeout the socket layer rejects (nan, inf, negative):
    # a ValueError or OverflowError on every request instead of one at startup.
    value = os.environ.get(name)
    parsed = default if value is None else float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise ValueError(f"{name} must be a finite number of seconds greater than 0")
    return parsed
