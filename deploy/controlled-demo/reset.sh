#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_TOKEN:?set a short-lived token for the dedicated demo repository}"
: "${PITEKA_DEMO_REPOSITORY:?set owner/repository for the dedicated demo repository}"
: "${PITEKA_DEMO_ENVIRONMENT:=piteka-demo-production}"

if [[ "${1:-}" != "--confirm-demo-only" ]]; then
  echo "refusing reset: pass --confirm-demo-only after checking this is not customer production" >&2
  exit 2
fi

headers=(-H "Authorization: Bearer ${GITHUB_TOKEN}" -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28")
base="https://api.github.com/repos/${PITEKA_DEMO_REPOSITORY}"

# Delete only inactive deployments, oldest first. Active/unknown state fails closed.
curl --fail-with-body --silent --show-error "${headers[@]}" "${base}/deployments?environment=${PITEKA_DEMO_ENVIRONMENT}&per_page=100" |
  jq -r 'sort_by(.id)[] | select(.statuses_url != null) | .id' |
  while IFS= read -r deployment_id; do
    state=$(curl --fail-with-body --silent --show-error "${headers[@]}" "${base}/deployments/${deployment_id}/statuses?per_page=1" | jq -r '.[0].state // "unknown"')
    case "${state}" in
      success|failure|error|inactive)
        curl --fail-with-body --silent --show-error "${headers[@]}" -X POST "${base}/deployments/${deployment_id}/statuses" -d '{"state":"inactive"}' >/dev/null
        curl --fail-with-body --silent --show-error "${headers[@]}" -X DELETE "${base}/deployments/${deployment_id}" >/dev/null
        ;;
      *) echo "refusing to delete deployment ${deployment_id} in state ${state}" >&2; exit 1 ;;
    esac
  done
