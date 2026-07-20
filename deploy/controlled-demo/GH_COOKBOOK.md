# Piteka controlled-demo — `gh` / CLI cookbook

Copy-paste command reference for setting up, running, testing, and
re-driving the controlled deployment demo. Grouped by phase.

> **Two auth identities are in play.** Most commands use the **`gh` CLI**,
> which acts as *you* (your user OAuth token). A few operations —
> creating deployments, and listing/redelivering the **GitHub App**
> webhook — require the **Piteka App's** JWT + installation token, which
> `gh` cannot mint. Those run through the Piteka binaries
> (`controlled_demo_dispatch` / `controlled_demo_flow`), which read the App
> private key from a file. Each command below is tagged **[gh]**, **[app-bin]**,
> or **[curl]** so it is clear which identity it uses.

Shared shell variables used throughout:

```bash
export OWNER=zorvan
export REPO=piteka-demo                      # dedicated, no production data
export SLUG="$OWNER/$REPO"
export ENV_NAME=piteka-demo-production
export APP_KEY=~/Work/projects/diewan/piteka-demo.2026-07-19.private-key.pem
export APP_ID=4340305
```

---

## 0. Authenticate  **[gh]**

```bash
gh auth status                               # confirm you are logged in
gh auth login                                # interactive, only if needed
```

The demo scripts (`capture_environment_snapshot.sh`, `reset.sh`) instead read a
short-lived `GITHUB_TOKEN`. You can mint one from your gh session for those:

```bash
export GITHUB_TOKEN="$(gh auth token)"
```

---

## 1. Provision the repository and environment  **[gh]**

```bash
# Private, dedicated demo repo (skip if it already exists)
gh repo create "$SLUG" --private --disable-wiki

# Create the named environment with NO protection rules
# (Piteka is the single approval authority — no reviewers, timer, or branch policy)
gh api --method PUT "/repos/$SLUG/environments/$ENV_NAME"

# Install the consumer workflow at the pinned SHA, then push
cp deploy/controlled-demo/piteka-deployment-consumer.yml \
   .github/workflows/piteka-deployment-consumer.yml
```

Install the **Piteka GitHub App** on this repository only (Deployments
read/write, Contents read) via the App's install URL in the browser — App
installation is not a `gh` CLI operation.

Verify the environment is clean (this is what `capture_environment_snapshot.sh`
enforces):  **[gh]**

```bash
gh api "/repos/$SLUG/environments/$ENV_NAME" \
  --jq '{id, name, protection_rules, deployment_branch_policy}'
# protection_rules must be [] and deployment_branch_policy must be null
```

---

## 2. Discover the stable IDs the dispatch needs  **[gh]**

The Piteka binaries need numeric repository / environment IDs and a commit SHA.

```bash
export PITEKA_GITHUB_REPOSITORY_ID="$(gh api "/repos/$SLUG" --jq .id)"
export PITEKA_GITHUB_ENVIRONMENT_ID="$(gh api "/repos/$SLUG/environments/$ENV_NAME" --jq .id)"
export PITEKA_DEMO_COMMIT_SHA="$(gh api "/repos/$SLUG/commits/main" --jq .sha)"   # exact 40-char SHA
```

The **installation ID** requires App auth, so read it from the App's
installations rather than `gh` (which would 404 on your user token):  **[app-bin]**

```bash
# The App private key you already hold identifies the installation; the
# controlled_demo_dispatch binary fails closed and lists every variable it
# still needs when run with no arguments:
cargo run -p piteka-github --bin controlled_demo_dispatch
```

(Installation ID for this demo is `147652613`; export it as
`PITEKA_GITHUB_INSTALLATION_ID`.)

---

## 3. Dispatch a deployment (the real live transport)  **[app-bin]**

`controlled_demo_dispatch` performs App JWT auth, exchanges an installation
token, and calls the Deployments API. It refuses to run unless
`PITEKA_CONFIRM_LIVE_DEMO` exactly names the disposable repo. **Supply the key
by file path — never inline the key contents.**

```bash
PITEKA_CONFIRM_LIVE_DEMO="$SLUG" \
PITEKA_GITHUB_APP_PRIVATE_KEY_FILE="$APP_KEY" \
PITEKA_GITHUB_APP_ID="$APP_ID" \
PITEKA_GITHUB_INSTALLATION_ID=147652613 \
PITEKA_GITHUB_REPOSITORY_ID="$PITEKA_GITHUB_REPOSITORY_ID" \
PITEKA_DEMO_REPOSITORY="$SLUG" \
PITEKA_GITHUB_ENVIRONMENT_ID="$PITEKA_GITHUB_ENVIRONMENT_ID" \
PITEKA_DEMO_ENVIRONMENT="$ENV_NAME" \
PITEKA_DEMO_COMMIT_SHA="$PITEKA_DEMO_COMMIT_SHA" \
PITEKA_DEMO_PAYLOAD_COMMITMENT=<schema-committed-payload> \
PITEKA_DEMO_ATTEMPT_DIGEST=<64-lowercase-hex> \
  cargo run -p piteka-github --bin controlled_demo_dispatch
# prints: deployment_id=<N>
```

For the **full application state machine** (propose → approve exact intent →
issue mandate → CAS-reserve → dispatch → consume, with a durable journal), use
`controlled_demo_flow` instead. Same provider vars **plus** `DATABASE_URL`,
`PITEKA_DEMO_RUN_ID`, and `PITEKA_DEMO_JOURNAL` (absolute path):  **[app-bin]**

```bash
DATABASE_URL=postgresql://zorvan@127.0.0.1:55432/postgres \
PITEKA_DEMO_RUN_ID=2026-07-20-intent-bound-receipt \
PITEKA_DEMO_JOURNAL=~/Work/projects/diewan/piteka/evidence/controlled-flow.json \
… (all the PITEKA_* / PITEKA_CONFIRM_LIVE_DEMO vars from above) … \
  cargo run -p piteka --bin controlled_demo_flow
# prints: deployment_id=<N>  journal=<path>
```

---

## 4. Watch and test the triggered Actions run  **[gh]**

The deployment event triggers the consumer workflow. Verify it ran and
succeeded:

```bash
# Newest deployment-triggered run (summary)
gh run list --repo "$SLUG" --event deployment --limit 1 \
  --json databaseId,status,conclusion,url --jq '.[0]'

# Follow it live until it finishes
gh run watch --repo "$SLUG" "$(gh run list --repo "$SLUG" --event deployment \
  --limit 1 --json databaseId --jq '.[0].databaseId')"

# Full detail / logs if it failed
gh run view  --repo "$SLUG" <run-id>
gh run view  --repo "$SLUG" <run-id> --log-failed
```

Inspect the deployment and its statuses directly:  **[gh]**

```bash
gh api "/repos/$SLUG/deployments?environment=$ENV_NAME&per_page=5" \
  --jq '.[] | {id, sha, task, environment}'
gh api "/repos/$SLUG/deployments/<deployment_id>/statuses" \
  --jq '.[] | {state, created_at}'      # expect in_progress then ONE terminal state
```

---

## 5. Inspect the App webhook and **redeliver**  **[app-bin]**

The GitHub App webhook (deliveries and redelivery) is App-scoped — `gh` cannot
reach `/app/hook/deliveries`. Use `controlled_demo_dispatch` in inspect mode.
The binary validates `PITEKA_DEMO_PAYLOAD_COMMITMENT` and
`PITEKA_DEMO_ATTEMPT_DIGEST` (64 hex chars) before the inspect branch even
though inspect/redeliver do not use them, so pass throwaway-but-valid values.

**List deliveries + current webhook URL:**

```bash
PITEKA_INSPECT_WEBHOOK_ONLY=1 \
PITEKA_DEMO_PAYLOAD_COMMITMENT=unused \
PITEKA_DEMO_ATTEMPT_DIGEST=$(printf '0%.0s' {1..64}) \
PITEKA_CONFIRM_LIVE_DEMO="$SLUG" \
PITEKA_GITHUB_APP_PRIVATE_KEY_FILE="$APP_KEY" PITEKA_GITHUB_APP_ID="$APP_ID" \
PITEKA_GITHUB_INSTALLATION_ID=147652613 \
PITEKA_GITHUB_REPOSITORY_ID="$PITEKA_GITHUB_REPOSITORY_ID" \
PITEKA_DEMO_REPOSITORY="$SLUG" \
PITEKA_GITHUB_ENVIRONMENT_ID="$PITEKA_GITHUB_ENVIRONMENT_ID" \
PITEKA_DEMO_ENVIRONMENT="$ENV_NAME" \
PITEKA_DEMO_COMMIT_SHA="$PITEKA_DEMO_COMMIT_SHA" \
  cargo run -q -p piteka-github --bin controlled_demo_dispatch
# prints: webhook_url=…  deliveries=[{id, event, status_code, redelivery, …}]
```

Pick the `id` of the terminal `deployment_status` delivery you need (the numeric
`id` field, e.g. `3832277500266807296`), then **redeliver** it by adding one
variable — everything else is identical:

```bash
PITEKA_INSPECT_WEBHOOK_ONLY=1 \
PITEKA_REDELIVER_ID=3832277500266807296 \
… (all the same vars as the list command above) … \
  cargo run -q -p piteka-github --bin controlled_demo_dispatch
# prints: redelivered=3832277500266807296  webhook_url=…  deliveries=[…]
```

**When you need this:** the demo uses a temporary Cloudflare tunnel as the
webhook URL. If the tunnel expires mid-run, GitHub records the terminal delivery
as `530`/`502` and no receipt is created. Start a fresh tunnel, update the App
webhook URL to it, then redeliver the terminal delivery ID above — no new
deployment is required, because the event is already signed.

Verify the redelivery landed and produced the receipt (local Postgres):  **[curl/psql]**

```bash
psql 'postgresql://zorvan@127.0.0.1:55432/postgres' -P pager=off \
  -c "select delivery_id, source, received_at from webhook_receipts order by received_at desc limit 3" \
  -c "select r.receipt_id_hex, r.outcome, r.intent_id_hex, r.evidence_gaps
        from receipt_projections r
        join execution_attempts a on a.attempt_id_hex = r.attempt_id_hex
       where a.github_deployment_id = <deployment_id>"
# newest webhook_receipts.delivery_id == the redelivered delivery's GUID;
# receipt outcome=succeeded, intent_id bound, evidence_gaps=[]
```

---

## 6. Reset / rollback  **[gh + script]**

```bash
# Snapshot evidence BEFORE a run (writes JSON + .sha256 sidecar)
GITHUB_TOKEN="$(gh auth token)" PITEKA_DEMO_REPOSITORY="$SLUG" \
  deploy/controlled-demo/capture_environment_snapshot.sh evidence/environment.json

# Remove only terminal deployments from the demo environment (fails closed on active/unknown)
GITHUB_TOKEN="$(gh auth token)" PITEKA_DEMO_REPOSITORY="$SLUG" \
  deploy/controlled-demo/reset.sh --confirm-demo-only

# Offline end-to-end checks (no network)
python3 -m unittest discover -s tests/e2e -p 'test_*.py'
```

Full rollback = remove the consumer workflow and uninstall the Piteka App. No
protocol or database migration is involved; existing evidence stays immutable.

---

## Quick index

| Task | Command | Identity |
|------|---------|----------|
| Check auth | `gh auth status` | you |
| Create repo | `gh repo create "$SLUG" --private` | you |
| Create environment | `gh api --method PUT /repos/$SLUG/environments/$ENV_NAME` | you |
| Repo / env IDs | `gh api /repos/$SLUG --jq .id` | you |
| Dispatch deployment | `cargo run …controlled_demo_dispatch` | Piteka App |
| Full flow + journal | `cargo run …controlled_demo_flow` | Piteka App |
| Watch Actions run | `gh run list/watch/view --repo "$SLUG"` | you |
| List webhook deliveries | `PITEKA_INSPECT_WEBHOOK_ONLY=1 …dispatch` | Piteka App |
| **Redeliver a delivery** | `PITEKA_INSPECT_WEBHOOK_ONLY=1 PITEKA_REDELIVER_ID=<id> …dispatch` | Piteka App |
| Verify receipt | `psql … receipt_projections` | local DB |
| Reset environment | `reset.sh --confirm-demo-only` | you (`GITHUB_TOKEN`) |
