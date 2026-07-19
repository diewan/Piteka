# Demo security and privacy threat model

Status: reviewed for H-04 on 2026-07-19. Scope is the first vertical slice:
one exact GitHub deployment is approved once, dispatched by Piteka, exported,
and independently verified by Parwana.

## Assets, boundaries, and trust

The protected assets are mandate signing material, GitHub App and webhook
secrets, reservation tokens, canonical mandate/receipt bytes, raw provider
evidence, and append-only audit history. Piteka PostgreSQL is the only live-state
authority. Parwana owns canonical encoding and verification meaning. GitHub is
an external action and observation provider; its response is evidence, not
proof that every asserted fact is true.

The demo trusts one statically configured organization and three local roles.
Signed sessions bind the configured subject, organization, and role. The GitHub
adapter binds one credential reference to one installation, repository, and
environment. Resolved secret bytes exist only at the adapter boundary and are
not persisted or included in exported bundles. Offline verification receives a
hash-addressed context and requires no Piteka database or network.

## Threat review

| Threat | Required control and review result |
|---|---|
| Caller changes commit or environment after approval | Exact intent is hash-bound; verifier mismatch tests reject. The GitHub adapter independently rejects a non-configured environment. |
| Caller selects another installation or repository with the configured credential | Adapter compares all provider identifiers to its configured context before secret resolution. Negative tests cover each mismatch. |
| Cross-organization identity or role escalation | Directory construction rejects foreign members; authentication rejects organization/role tampering; capability and production re-auth policies fail closed. |
| Concurrent or repeated mandate use | PostgreSQL compare-and-swap admits one reservation; terminal replay is rejected and audited. |
| Ambiguous provider outcome | Mandate becomes quarantined and cannot be released for this profile. Absence of a provider result is not non-occurrence. |
| Forged or replayed webhook | HMAC verification precedes processing; delivery identifiers are idempotent. Invalid and duplicate cases are tested. |
| Secret disclosure through storage, export, logs, or errors | Stores hold opaque references/digests, not raw execution credentials; bundle assembly excludes reservation tokens; a regression test asserts resolved bytes do not appear in error/debug rendering. Production log-sink inspection remains a pilot gate. |
| Missing or selectively disclosed evidence | Export fails on missing referenced evidence; verifier preserves indeterminate outcomes and uncertainty. |
| Canonical-byte or context substitution | Parwana owns serialization and verification; byte flips and context changes reject deterministically. |
| Oversized or unsupported input | Protocol bounds and unknown-version tests fail closed. |

## Privacy boundaries

Demo evidence is purpose-limited to deployment accountability. Raw payloads and
exported bundles may contain repository, actor, and provider identifiers and
must be access-controlled and retention-limited. Digests reduce unnecessary
payload copying but are not anonymization. Selective disclosure must preserve
explicit uncertainty and must never turn absence into non-occurrence.

This review does **not** claim tenant isolation. The `X-Tenant-Id` demo header,
configured organization, in-memory adapters, and local session model are not a
production tenant boundary. Before any pilot, every tenant-bound database query,
object key, cache key, job, secret reference, audit read, and export must carry
an authenticated server-derived tenant scope, with cross-tenant integration
tests and operational access review.

## Operational assumptions and residual risk

- GitHub App permissions and repository selection must be verified out of band
  against the documented least-privilege configuration before each demo.
- Demo secret resolvers are process-memory scaffolding. Pilot deployments need
  KMS/Vault-backed resolution, rotation, revocation, and log-redaction checks.
- The adapter exercises the credential and request boundary but uses a demo
  provider transport. It must not be represented as production GitHub dispatch.
- Local sessions lack enterprise federation, revocation, and production key
  management. OIDC/service identity work is required before pilot.

## Compatibility and rollback

The review changes no protocol object, canonical serializer, database schema,
or verifier. Provider-context validation is fail-closed and can reject calls
that previously supplied identifiers inconsistent with configuration; such
calls were unsafe and have no supported compatibility guarantee. Deployment
order is unchanged. No data migration is required. Removing the validation
would reopen the finding.
