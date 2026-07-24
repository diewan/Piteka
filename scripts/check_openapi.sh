#!/usr/bin/env bash
# check_openapi.sh — Verify the checked-in OpenAPI contract against the code.
#
#   ./scripts/check_openapi.sh
#
# `openapi/openapi.yaml` is hand-maintained: there are no `utoipa` annotations in
# `piteka-api`, so there is nothing to generate the spec *from*. The previous
# `regenerate_openapi.sh` assumed otherwise — it called a `piteka_api::ApiDoc`
# that does not exist, so the drift gate it advertised never ran.
#
# Rather than pretend the spec is generated, this script checks the two things
# that can drift and that actually matter:
#
#   1. The file is valid YAML and every `$ref` resolves.
#   2. Every route the router serves is documented, and every documented path is
#      really served.
#
# Type/schema-name agreement is enforced in Rust by
# `tests/naming_constitution.rs::openapi_schema_names_match_declared_rust_types`,
# and payload stability by the `api_v1_*` tests in `apps/piteka-api/src/tests.rs`.
set -euo pipefail
cd "$(dirname "$0")/.."

SPEC="openapi/openapi.yaml"
ROUTES="apps/piteka-api/src/routes.rs"

if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 is required to check the OpenAPI contract." >&2
  exit 1
fi

python3 - "$SPEC" "$ROUTES" <<'PY'
import re
import sys

spec_path, routes_path = sys.argv[1], sys.argv[2]

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required (pip install pyyaml).", file=sys.stderr)
    raise SystemExit(1)

raw = open(spec_path).read()
try:
    spec = yaml.safe_load(raw)
except yaml.YAMLError as error:
    print(f"ERROR: {spec_path} is not valid YAML:\n{error}", file=sys.stderr)
    raise SystemExit(1)

failures = []

# 1. Every $ref resolves to a declared schema.
declared = set(spec.get("components", {}).get("schemas", {}))
referenced = set(re.findall(r"#/components/schemas/(\w+)", raw))
for dangling in sorted(referenced - declared):
    failures.append(f"$ref to undeclared schema `{dangling}`")
schemas = spec.get("components", {}).get("schemas", {})
for orphan in sorted(declared - referenced):
    schema = schemas[orphan]
    # Deprecated source-name aliases intentionally remain resolvable even
    # though endpoint definitions use their canonical replacements.
    is_compatibility_alias = (
        schema.get("deprecated") is True
        and len(schema.get("allOf", [])) == 1
        and "$ref" in schema["allOf"][0]
    )
    if not is_compatibility_alias:
        failures.append(f"schema `{orphan}` is declared but never referenced")

compatibility_aliases = {
    "ActionRequestStatus": "ActionRequestStatusDtoV1",
    "ActionRequestSummary": "ActionRequestSummaryDtoV1",
    "ActionRequestResponse": "ActionRequestResponseV1",
    "ApprovalDecisionResponse": "ApprovalDecisionDtoV1",
    "CreateActionRequestRequest": "CreateActionRequestRequestV1",
    "ApproveRequest": "ApproveActionRequestRequestV1",
    "RejectRequest": "RejectActionRequestRequestV1",
    "RevokeRequest": "RevokeActionRequestRequestV1",
    "ErrorCause": "ErrorCauseDtoV1",
    "ErrorResponse": "ErrorResponseV1",
    "ErrorDetail": "ErrorDetailDtoV1",
}
for legacy, replacement in compatibility_aliases.items():
    expected = f"#/components/schemas/{replacement}"
    alias = schemas.get(legacy, {})
    refs = [item.get("$ref") for item in alias.get("allOf", [])]
    if alias.get("deprecated") is not True or refs != [expected]:
        failures.append(
            f"compatibility schema `{legacy}` must be a deprecated alias to `{replacement}`"
        )

# 2. Documented paths and served routes agree.
#    Axum spells path parameters `{id}`, matching OpenAPI, so they compare
#    directly. Routers are composed with `.nest(prefix, inner)`, so a nested
#    router's own `.route("/…")` calls must be re-prefixed before comparing.
routes_src = open(routes_path).read()

served = set(re.findall(r'\.route\(\s*"(/api/v1[^"]*)"', routes_src))

# Resolve `.nest("/api/v1/x", <builder>(…))` by prefixing the paths declared in
# the named builder function.
for prefix, builder in re.findall(r'\.nest\(\s*"([^"]+)"\s*,\s*(\w+)', routes_src):
    # `.nest(prefix, action_routes)` names a local binding; follow it to the
    # function that produced it.
    binding = re.search(rf"let\s+{re.escape(builder)}\s*=\s*(\w+)\(", routes_src)
    fn_name = binding.group(1) if binding else builder
    body = re.search(rf"pub fn {re.escape(fn_name)}\b.*?\n}}", routes_src, re.S)
    if not body:
        failures.append(f"cannot resolve nested router `{fn_name}` for prefix `{prefix}`")
        continue
    for sub in re.findall(r'\.route\(\s*"([^"]*)"', body.group(0)):
        served.add(prefix if sub == "/" else prefix + sub)

documented = {p for p in spec.get("paths", {}) if p.startswith("/api/v1")}

# The spec serves itself and the provider webhook is authenticated out-of-band by
# HMAC rather than by this contract; neither is part of the client-facing surface.
served -= {"/api/v1/openapi.json", "/api/v1/webhooks/github"}

for undocumented in sorted(served - documented):
    failures.append(f"route `{undocumented}` is served but absent from the contract")
for unserved in sorted(documented - served):
    failures.append(f"path `{unserved}` is documented but no route serves it")

if failures:
    print("OpenAPI contract drift detected:", file=sys.stderr)
    for failure in failures:
        print(f"  - {failure}", file=sys.stderr)
    raise SystemExit(1)

print(
    f"OpenAPI contract is consistent: "
    f"{len(documented)} documented paths, {len(declared)} schemas, all refs resolve."
)
PY
