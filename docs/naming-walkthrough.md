# Piteka naming walkthrough — one deployment, end to end

**Audience:** someone reading Piteka for the first time.
**Authority:** [`development/CANONICAL-NAMING.md`](../../development/CANONICAL-NAMING.md)
(ADR-0015), applied to Piteka by ticket NAM-02.

Piteka handles values from five different worlds at once: protocol objects owned
by Parwana, its own application state, database rows, HTTP payloads, and results
returned by GitHub. This page follows one production deployment through all of
them and names the exact type at each step, so you can tell — from a name alone —
who owns a value and what it does *not* prove.

The rule the names follow:

```text
[Domain or Provider] + Subject + [Lifecycle Role] + [Representation] + [Version]
```

## The one-sentence version

**Piteka owns workflow; Parwana owns meaning.** Any Piteka type that would read
as a protocol object carries a qualifier saying otherwise.

## Step 1 — An agent asks to deploy

An MCP client calls `piteka_request_deployment`. Its arguments arrive as
`piteka_application::mcp::RequestDeploymentInput`.

`Input` means *untrusted and not yet normalized*. Nothing in it is authoritative
— including the `intent_id` the caller supplies. The server recomputes that id
from the stable provider parameters and rejects a mismatch with
`INTENT_MISMATCH`. A caller-supplied identifier is a claim, never authority,
which is why the type is not called `ObjectRef`: `Ref` is reserved for a
validated locator, and these are raw strings.

## Step 2 — The request is normalized into a protocol intent

`piteka_github::intent::GitHubIntentNormalizer::normalize` turns a
`GitHubDeploymentInput` into a `NormalizedGitHubDeploymentIntent`.

Read that name in pieces: **GitHubDeployment** (the provider whose vocabulary
this is) + **Intent** (the subject) + **Normalized** (what happened to it). The
qualifier matters. Inside it sits `intent: ActionIntent` — *that* is the
canonical Parwana object, unqualified because Parwana owns the bare noun. The
wrapper is Piteka's; the intent inside it is not.

If you need the JSON shape, it is
`NormalizedGitHubDeploymentIntentDtoV1` — a `Dto`, not a `Wire`. `Wire` is
reserved for representations whose field layout is part of the versioned
protocol contract. Piteka owns no such contract, so Piteka declares no `Wire`
type; a test enforces this.

## Step 3 — A human approves it

The approver sees a server-rendered panel built from
`piteka_application::hardening::ApprovalCeremonyIntent`, and the page shows an
**Approval digest**.

This is the subtlest name in Piteka, so read carefully:

| | Approval digest | Parwana intent id |
|---|---|---|
| Type | `ApprovalCeremonyIntent::digest_hex()` | `ActionRequest::intent_id_hex` |
| Computed by | Piteka, locally | Parwana's sole serializer |
| Proves | the approver signed exactly what was displayed | the exact action authorized |
| Travels | nowhere; local to the ceremony | into mandates, receipts, bundles |

They are different values with different authority. The type used to be called
`CanonicalIntent` and the label used to read "Intent digest" — both invited a
reader to treat a local anti-tampering digest as protocol identity. NAM-02
changed both.

Approving returns `ApproveActionRequestResult` — the *complete outcome of a named
use case*, which is what `Result` means here. It is not the status `Approved`;
that is `ActionRequestStatus::Approved`. Before NAM-02 both were spelled
`Approved`.

## Step 4 — Exactly one dispatch

`DispatchUseCase::execute` returns a `DispatchOutcome`:

- `Dispatched(DispatchedExecution)` — reserved and sent.
- `ReservationFailed(ReservationConflict)` — another caller won the
  compare-and-swap.
- `ReplayRejected(ReplayRejection)` — a second use of a single-use mandate,
  refused *before* any provider call.
- `DispatchFailed { .. }` — the mandate is now quarantined.

The provider's answer comes back as
`piteka_ports::github::DeploymentCreationResponse`. `Response` says it is what
GitHub told us, not something we established. It is deliberately not
`DeploymentCreated`, which reads like an `Event` — an immutable statement that a
transition happened — and would overstate what a single API reply proves.

## Step 5 — GitHub calls back

A webhook delivery is recorded as
`piteka_storage::WebhookDeliveryRecord` in the `webhook_receipts` table.

It is **not** a `Receipt`. It proves only that a delivery with this id arrived
and that we kept its raw payload digest — it says nothing about what the
deployment did. The protocol receipt is a different value entirely:
`ReceiptProjection`, which binds mandate → attempt → outcome and can honestly
report `ReceiptOutcome::Unknown`.

That distinction is the whole point of the naming rules. Before NAM-02 both were
called `WebhookReceipt` and `ReceiptProjection`, one suffix apart.

## Step 6 — Looking at what happened

Three different read surfaces, three different suffixes:

| Where you are | Type | What the suffix promises |
|---|---|---|
| Postgres | `ReceiptProjection`, `MandateProjection` | a derived read model over authoritative state |
| HTTP `/api/v1` | `ReceiptResponseV1`, `MandateChainResponseV1` | a versioned external boundary shape |
| Web UI | `WorkQueueItemViewModel`, `IntentPanelViewModel` | already-formatted state for rendering |

The UI types used to end in `Row`. `Row` is reserved for one relational
persistence mapping, so a rendered table item wearing it looked like a database
row — the opposite of the truth, since none of it is stored or authoritative.

## Step 7 — Observations from Tuppira

Investigating pulls in `piteka_application::TuppiraObservation`.

The `Tuppira` qualifier names the vocabulary owner. The bare `Observation` role
is *earned*: the value carries source identity, acquisition provenance, and
explicit uncertainty (`retraction_status`, `supersedes`). A thinner acquired
value would have to be a `Reading` or an `Input`.

What it never becomes is permission:

```rust
// ObservationQueryResult
pub const fn permits_execution(&self) -> bool { false }
```

An unavailable Tuppira produces an `EvidenceGap`, not a conclusion. Absence is
not non-occurrence.

## Step 8 — Anchoring

`InMemoryCsvSealAnchor` and `InMemoryChainAnchor` corroborate single use
independently of the Postgres reservation.

`InMemory` is a durability statement: both lose everything on restart. They were
called `Local*`, which said where they ran but not whether anything survived —
and for evidence that is the question that matters. Both remain corroboration;
the authoritative reservation is always Piteka's PostgreSQL compare-and-swap.

Their stored discriminators (`csv-seal.local.v1`, `chain.local.v1`) did **not**
change with the type names. Those values live in
`seal_consumption_proofs.anchor_backend` and in exported bundles, so moving them
would be a data migration, not a rename. Tests pin them.

## The suffixes, in one table

| Suffix | Means | Example in Piteka |
|---|---|---|
| `Input` | untrusted, not yet normalized | `RequestDeploymentInput` |
| `Result` | complete outcome of a named use case | `ApproveActionRequestResult` |
| `Record` | application-owned durable aggregate | `WebhookDeliveryRecord` |
| `Row` | one relational persistence mapping | *(none in the UI, by rule)* |
| `Projection` | derived read model, not source state | `ReceiptProjection` |
| `ViewModel` | UI-ready, already formatted | `WorkQueueItemViewModel` |
| `RequestV1` / `ResponseV1` | versioned HTTP boundary body | `ActionRequestResponseV1` |
| `DtoV1` | versioned shape nested in one of those | `ApprovalDecisionDtoV1` |
| `Response` | what a provider told us | `DeploymentCreationResponse` |
| `Wire` | canonical protocol representation | *(Parwana only — never Piteka)* |

The Rust-side API names changed without changing v1 JSON keys. The checked-in
OpenAPI document retains every original component name as a deprecated alias to
its explicit `V1` replacement. Existing generated clients and external `$ref`
links therefore remain resolvable during the v1 compatibility window. Removing
those aliases requires a separately versioned API migration.

## Adding a name

Before you add a public type, answer the questions in
[`CANONICAL-NAMING.md` §6](../../development/CANONICAL-NAMING.md). The one that
decides it:

> **Materially useful distinction communicated:**
> If empty, do not rename it. Cosmetic preference does not justify compatibility
> cost.

`tests/naming_constitution.rs` mechanically enforces the parts that can be
checked — reserved suffixes, `/api/v1` versioning, no product-local `Canonical`
or `Wire`, no bare protocol nouns. It cannot check whether a name is *true*.
That is still review's job.
