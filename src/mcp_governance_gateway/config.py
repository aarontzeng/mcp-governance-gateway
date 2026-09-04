from __future__ import annotations

from dataclasses import dataclass
import math
import os
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    # Optional only when OIDC is configured (see from_env): a deployment whose
    # identities all come from an IdP has no opaque tokens to store.
    token_file: str | None
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
    # OIDC (ADR-0016): a second authenticator beside the token file, not a
    # replacement for it. Unset issuer -> the mode does not exist and nothing
    # about 0.1.0 behaviour changes. Audience has no default on purpose: an
    # issuer mints tokens for many audiences and accepting all of them would let
    # a token issued for an unrelated client act here. Tenancy comes from the
    # grants file, never from a claim the IdP controls.
    # Admin listener (roadmap: "credential enrollment: a primitive, not a portal").
    # Unset -> the /internal/* credential routes stay on the MCP listener, as in
    # 0.1.0. Set -> they move to their own socket and the MCP listener answers 404
    # for them, so an ingress that exposes /mcp publicly cannot expose enrollment
    # with it. Host defaults to loopback: this surface must not be routed publicly.
    admin_port: int | None = None
    admin_host: str = "127.0.0.1"
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None          # unset -> discovered from the issuer
    oidc_grants_file: str | None = None
    oidc_clock_skew_sec: int = 60
    oidc_jwks_ttl_sec: int = 600
    oidc_groups_claim: str = "groups"
    oidc_required_scope: str | None = None
    # Docs corpus (read-only docs.search/docs.get over per-project docs repos).
    # Enabled only when both are set; docs_repos_file maps project -> {url, branch}.
    docs_repos_file: str | None = None
    docs_clone_dir: str | None = None
    docs_pull_interval_sec: float = 300.0
    # Timeout for calls to a docs review host (GitHub/GitLab), separate from the
    # corpus git timeout: one is a remote API, the other a local clone.
    docs_review_timeout_sec: float = 20.0
    # Where a user enrolls their own downstream credential (the deployment's
    # portal / admin page). Appended to the errors that ask a caller to enroll or
    # re-enroll a key, so the message can point somewhere instead of describing
    # an endpoint the user has to go find. Unset -> those errors carry no URL.
    credential_portal_url: str | None = None
    # Jenkins CI. Reads (ci.status/ci.builds/ci.log/ci.artifact) are enabled when
    # url + jobs file are set; ci.rerun additionally needs ci_trigger_jobs_file.
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
    # A SECOND jobs allowlist, for ci.rerun. Unset -> no project may start any
    # build, which is the right default for a tool that spends CI capacity: the
    # set of jobs an agent may watch is not the set it may start.
    ci_trigger_jobs_file: str | None = None

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.oidc_issuer)

    @classmethod
    def from_env(cls) -> "Settings":
        oidc_issuer = _url_env("OIDC_ISSUER")
        oidc_audience = os.environ.get("OIDC_AUDIENCE") or None
        oidc_grants_file = os.environ.get("OIDC_GRANTS_FILE") or None
        # Half-configured OIDC is refused at boot rather than silently disabled:
        # an operator who set two of the three variables believes the mode is on,
        # and a gateway that quietly ignored them would authenticate nobody by a
        # route they think exists.
        if oidc_issuer and not (oidc_audience and oidc_grants_file):
            raise ValueError("OIDC_ISSUER needs OIDC_AUDIENCE and OIDC_GRANTS_FILE")
        if not oidc_issuer and (oidc_audience or oidc_grants_file or os.environ.get("OIDC_JWKS_URL")):
            raise ValueError("OIDC_AUDIENCE / OIDC_GRANTS_FILE / OIDC_JWKS_URL need OIDC_ISSUER")

        token_file = os.environ.get("GATEWAY_TOKEN_FILE")
        if not token_file and not oidc_issuer:
            # Still required in the default deployment; optional only when OIDC is
            # configured, because then there may legitimately be no opaque tokens.
            raise ValueError("GATEWAY_TOKEN_FILE is required (or configure OIDC_ISSUER)")

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
            admin_port=_optional_port_env("ADMIN_PORT"),
            admin_host=os.environ.get("ADMIN_HOST", "127.0.0.1"),
            oidc_issuer=oidc_issuer,
            oidc_audience=oidc_audience,
            oidc_jwks_url=_url_env("OIDC_JWKS_URL"),
            oidc_grants_file=oidc_grants_file,
            oidc_clock_skew_sec=_int_env("OIDC_CLOCK_SKEW_SEC", 60, minimum=0),
            oidc_jwks_ttl_sec=_int_env("OIDC_JWKS_TTL_SEC", 600, minimum=1),
            oidc_groups_claim=os.environ.get("OIDC_GROUPS_CLAIM", "groups"),
            oidc_required_scope=os.environ.get("OIDC_REQUIRED_SCOPE") or None,
            identity_claims_secret=os.environ.get("IDENTITY_CLAIMS_SECRET") or None,
            identity_header_prefix=os.environ.get("IDENTITY_HEADER_PREFIX", "X-Forwarded-User"),
            docs_repos_file=os.environ.get("DOCS_REPOS_FILE") or None,
            docs_clone_dir=os.environ.get("DOCS_CLONE_DIR") or None,
            docs_pull_interval_sec=float(os.environ.get("DOCS_PULL_INTERVAL_SEC", "300")),
            docs_review_timeout_sec=_timeout_env("DOCS_REVIEW_TIMEOUT_SEC", default=20.0),
            jenkins_base_url=_url_env("JENKINS_BASE_URL"),
            jenkins_user=os.environ.get("JENKINS_USER") or None,
            jenkins_token=os.environ.get("JENKINS_TOKEN") or None,
            jenkins_timeout_sec=_timeout_env("JENKINS_TIMEOUT_SEC"),
            ci_jobs_file=os.environ.get("CI_JOBS_FILE") or None,
            ci_artifact_base_url=os.environ.get("CI_ARTIFACT_BASE_URL") or None,
            ci_trigger_jobs_file=os.environ.get("CI_TRIGGER_JOBS_FILE") or None,
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
    # A base URL urlopen cannot use ("ci.internal:8080" without a scheme, or a
    # path http.client cannot encode) would fail on every request; refusing it
    # at startup names the operator's mistake once.
    value = os.environ.get(name, default)
    if not value and default is None:
        return None     # an optional backend, unset or set empty
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.netloc or not value.isascii():
        raise ValueError(f"{name} must be an ASCII http:// or https:// URL, got {value!r}")
    return value


_MAX_TIMEOUT_SEC = 3600.0


def _optional_port_env(name: str) -> int | None:
    value = os.environ.get(name)
    if not value:
        return None
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError(f"{name} must be a TCP port between 1 and 65535")
    return port


def _timeout_env(name: str, default: float = 10.0) -> float:
    # Same fate for a timeout the socket layer rejects (nan, inf, negative, or so
    # large its clock overflows): an error on every request instead of one here.
    value = os.environ.get(name)
    parsed = default if value is None else float(value)
    if not math.isfinite(parsed) or not 0 < parsed <= _MAX_TIMEOUT_SEC:
        raise ValueError(f"{name} must be a number of seconds greater than 0 and at most {_MAX_TIMEOUT_SEC:g}")
    return parsed
