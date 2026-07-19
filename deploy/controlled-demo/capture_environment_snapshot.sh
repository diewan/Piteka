#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_TOKEN:?set a short-lived token with repository administration read access}"
: "${PITEKA_DEMO_REPOSITORY:?set owner/repository for the dedicated demo repository}"
: "${PITEKA_DEMO_ENVIRONMENT:=piteka-demo-production}"

output=${1:-environment-snapshot.json}
api="https://api.github.com/repos/${PITEKA_DEMO_REPOSITORY}/environments/${PITEKA_DEMO_ENVIRONMENT}"
curl --fail-with-body --silent --show-error \
  --header "Authorization: Bearer ${GITHUB_TOKEN}" \
  --header "Accept: application/vnd.github+json" \
  --header "X-GitHub-Api-Version: 2022-11-28" \
  "${api}" | jq --sort-keys '{id,node_id,name,protection_rules,deployment_branch_policy}' > "${output}"

jq -e '
  (.protection_rules | type == "array" and length == 0) and
  (.deployment_branch_policy == null)
' "${output}" >/dev/null || {
  echo "environment has approval, timer, or custom protection rules; refusing demo" >&2
  exit 1
}
sha256sum "${output}" > "${output}.sha256"
