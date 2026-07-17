# ADR-0001 — Demo identity model and signed local sessions

- Status: Accepted
- Ticket: D-02 (Implement configured-organization identities and roles)
- Master Plan: §15 (User roles), §21 ("one configured organization with three
  local roles"), §5.2 (technical permission is not organizational authorization)

## Context

The first vertical slice authorizes one exact GitHub deployment, once. It needs
identities and roles to decide *who* may propose, approve, and audit — but it is
explicitly **not** a production identity provider. The master plan permits the
demo to "operate as one configured organization with three local roles," with
full tenants, memberships, service-identity administration, and KMS-backed
credentials deferred to pre-pilot hardening.

## Decision

### One configured organization, three roles

`piteka-domain` models a single `ConfiguredOrganization` holding one `Identity`
per demo `Role`:

| Role | Capabilities (see `identity::Capability`) |
|---|---|
| Requester | propose action, receive status, execute an approved mandate |
| Approver | review intent, approve, reject, require conditions, revoke |
| Auditor | read scoped records, verify bundles, inspect assurance |

Roles are capability sets, checked with `Role::grants`. Investigator, Security
operator, and Tenant administrator (master plan §15) are **not** implemented;
they are post-demo roles. No capability edits a canonical signed object —
corrections are append-only superseding records, so the capability vocabulary
contains no in-place mutation of authority, receipts, or evidence.

`ConfiguredOrganization::new` fails closed: a member whose organization differs
from the configured one is rejected (`CrossOrganizationMember`), as are duplicate
user identifiers. This is the enforcement point that keeps a cross-tenant
identity out of the demo directory.

### Signed local sessions

`piteka-application` issues and authenticates `SignedSession`s:

- `SessionAuthority::issue` takes the role and organization from the configured
  directory, **never from the caller**, so a requester cannot self-issue an
  approver session.
- `SessionAuthority::authenticate` fails closed on: algorithm mismatch, invalid
  signature, expired or not-yet-valid window, unknown subject, and a role or
  organization that disagrees with the directory. Only after all checks pass is
  an `AuthenticatedSession` produced.
- Signing is a port (`SessionSigner`) with a single algorithm today,
  `SignatureAlgorithm::DemoLocalV1`. Authentication rejects any session whose
  algorithm does not match the bound signer, so adding a scheme later cannot be
  silently accepted by an old verifier.

Session bytes (`SessionClaims::signing_bytes`) are a Piteka-local, deterministic,
length-prefixed encoding under the domain tag `piteka-demo-session-v1`. They are
**not** a Parwana accountability object and never touch the protocol's canonical
serializer or verifier; there is no second protocol serializer.

## No production claim

`DemoLocalV1`, the hard-coded `ConfiguredOrganization::demo()` fixture, and local
session signing are demo scaffolding. Piteka does not present this as an
enterprise identity, SSO, or multi-tenant authorization system.

## Path to OIDC and multi-tenant hardening

Deferred to pre-pilot (master plan §15, §21, and the storage rules in §21):

1. **Federated identity.** Replace `ConfiguredOrganization::demo()` with an
   OIDC/OAuth token exchange; map verified subject and group claims to
   `Identity` and `Role`. Bind an MCP transport identity to a Piteka service
   identity and tenant (master plan §MCP notes).
2. **Real signer.** Provide a KMS/HSM-backed `SessionSigner` (or move to signed
   OIDC tokens) as an infrastructure adapter, replacing `DemoLocalV1`. Add a
   second `SignatureAlgorithm` variant and a key-rotation path; the algorithm
   check already fails closed on mismatch.
3. **Tenancy.** Introduce tenants, memberships, and the Tenant administrator and
   Security operator roles. Enforce tenant scope in the repository layer so every
   tenant-bound query carries an enforced scope (master plan §21 storage rules).
4. **Post-demo roles.** Add Investigator (cases, counterclaims, contradictions)
   and its workflows.
5. **Session hardening.** Server-side session revocation, rotation, and audit of
   issuance/authentication events (append-only, separate from editable metadata).

The concrete demo signer and the HTTP authorization boundary that consumes these
sessions are implemented by ticket D-04 (demo authorization boundary), which
depends on this ticket.
