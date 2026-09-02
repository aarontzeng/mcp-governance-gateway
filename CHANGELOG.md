# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] — 2026-09-02

First public release.

- MCP server (`tools/list`, `tools/call`) over HTTP with bearer-token
  authentication, per-token project binding and role-based policy.
- Backends: agentmemory (memories, lessons, actions), Redmine and GitLab issues,
  a per-project read-only docs corpus backed by git, Jenkins CI status/log and
  an artifact download data plane.
- Confirmation-gated issue writes bound to their exact arguments; per-user
  downstream credentials encrypted at rest; secret scanning on memory writes;
  per-user and per-project write quotas.
- JSON-lines audit stream naming the acting identity on every call.
