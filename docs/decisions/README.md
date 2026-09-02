# Architecture Decision Records

Each ADR records one decision, the alternatives weighed, and what enforces it.
Read them in order for the reasoning behind the gateway's boundaries.

| ADR | Title | Status |
|---|---|---|
| [0001](ADR-0001-mcp-governance-gateway.md) | MCP Governance Gateway | Accepted |
| [0002](ADR-0002-token-boundaries.md) | Token Boundaries | Accepted |
| [0003](ADR-0003-confirmation-and-dangerous-actions.md) | Confirmation and Dangerous Actions | Accepted |
| [0004](ADR-0004-front-gateway-boundary.md) | Keep Domain Security in an Independent Server | Accepted, amended by 0006 |
| [0005](ADR-0005-concurrency-and-transport.md) | Concurrency and Transport | Accepted |
| [0006](ADR-0006-direct-data-plane.md) | The Tool-Call Data Plane Is Direct | Accepted |
| [0007](ADR-0007-per-user-tokens.md) | One Token per User per Project, Keyed on an Immutable Id | Accepted |
| [0009](ADR-0009-per-user-downstream-credentials.md) | Per-User Downstream Credentials, Encrypted at Rest | Accepted |
| [0011](ADR-0011-per-project-docs-corpus.md) | Per-Project Docs Corpus | Accepted |
| [0012](ADR-0012-vendor-neutral-issue-project-claim.md) | Vendor-Neutral `issue_project` Tenant Claim | Accepted |
| [0013](ADR-0013-issue-backend-per-deployment.md) | Issue Backend Selected per Deployment | Accepted |
| [0015](ADR-0015-document-author-provenance.md) | Full Git History for Document Author Provenance | Accepted, amends 0011 |

Numbering is historical and non-contiguous. ADR numbers are stable identifiers,
so a decision specific to one organization's internal deployment — a particular
SSO integration, a credential-provisioning portal, a code-review ownership
rule, multi-project onboarding tooling — leaves its number unused here rather than renumbering the rest. The
decisions present are the ones that constrain the gateway itself.

Read [0001](ADR-0001-mcp-governance-gateway.md) first for what the gateway is,
then [0002](ADR-0002-token-boundaries.md) and
[0003](ADR-0003-confirmation-and-dangerous-actions.md) for the two properties
everything else is built to preserve.
