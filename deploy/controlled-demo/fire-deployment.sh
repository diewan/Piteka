#!/usr/bin/env bash
# Fire one Postgres-backed controlled-demo deployment.
#
# Runs the full application state machine (propose → approve → issue mandate →
# reserve → dispatch to GitHub → write execution_attempt) against the local
# Postgres. The real GitHub `deployment_status` webhook then produces the
# receipt, which flows Piteka → feed → Tuppira → Hemion.
#
# Prereqs already up: Postgres :55432, piteka-web :3000 (DATABASE_URL + webhook
# secret), evidence_feed :3200, tuppira-api :8081 + ingest --watch, cloudflared
# tunnel → :3000 with the GitHub App webhook pointed at it. The supported
# container path is `deployment/scripts/up.sh demo`, which starts the watcher.
#
# Each run needs a UNIQUE PITEKA_DEMO_RUN_ID (it seeds the deterministic
# intent/mandate ids); a repeated id is idempotent and produces no new mandate.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

# ── Demo target + GitHub App (disposable demo repo) ─────────────────────────
SLUG="zorvan/piteka-demo"
export PITEKA_DEMO_REPOSITORY="$SLUG"
export PITEKA_CONFIRM_LIVE_DEMO="$SLUG"          # must equal the repo, on purpose
export PITEKA_DEMO_ENVIRONMENT="piteka-demo-production"
export PITEKA_GITHUB_APP_ID="4340305"
export PITEKA_GITHUB_INSTALLATION_ID="147652613"
export PITEKA_GITHUB_REPOSITORY_ID="1305889755"
export PITEKA_GITHUB_ENVIRONMENT_ID="18401348139"
export PITEKA_GITHUB_APP_PRIVATE_KEY_FILE="$root/piteka-demo.2026-07-19.private-key.pem"

# ── Commit to deploy: latest on the demo repo's default branch (override by
#    exporting PITEKA_DEMO_COMMIT_SHA before running) ─────────────────────────
export PITEKA_DEMO_COMMIT_SHA="${PITEKA_DEMO_COMMIT_SHA:-$(gh api "/repos/$SLUG/commits/HEAD" --jq .sha)}"

# ── Local flow bookkeeping ──────────────────────────────────────────────────
export DATABASE_URL="${DATABASE_URL:-postgres://zorvan@127.0.0.1:55432/postgres}"
export PITEKA_DEMO_RUN_ID="${PITEKA_DEMO_RUN_ID:-run-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$root/piteka/evidence"
export PITEKA_DEMO_JOURNAL="$root/piteka/evidence/controlled-flow-$PITEKA_DEMO_RUN_ID.json"

echo "repo=$SLUG  env=$PITEKA_DEMO_ENVIRONMENT  sha=$PITEKA_DEMO_COMMIT_SHA  run=$PITEKA_DEMO_RUN_ID"
echo "Dispatching (creates a REAL GitHub deployment and triggers the consumer workflow)…"

cd "$root/piteka"
cargo run -q -p piteka --bin controlled_demo_flow

echo
echo "Mandate/attempt are now in Postgres; the receipt lands when GitHub delivers"
echo "the terminal deployment_status webhook. Watch it:"
echo "  gh run watch --repo $SLUG \"\$(gh run list --repo $SLUG --event deployment --limit 1 --json databaseId --jq '.[0].databaseId')\""
echo "  curl -s http://127.0.0.1:3000/api/v1/receipts | jq"
echo "  docker logs -f diewan-tuppira-ingest"
echo "Journal: $PITEKA_DEMO_JOURNAL"
