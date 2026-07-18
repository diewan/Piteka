#!/usr/bin/env bash
# regenerate_openapi.sh — Regenerate the OpenAPI contract from source types.
#
# This script is called by CI to ensure the checked-in openapi/openapi.yaml
# matches the current utoipa annotations. If the files differ, CI fails.
#
# Usage: ./scripts/regenerate_openapi.sh
#
# The script uses utoipa's built-in OpenAPI generation. Since utoipa does not
# have a CLI binary, we generate the JSON via a small Rust program and convert
# to YAML with `yq` (or fall back to a direct comparison if yq is unavailable).

set -euo pipefail
cd "$(dirname "$0")/.."

GENERATED_JSON="target/openapi-generated.json"
CHECKED_IN_YAML="openapi/openapi.yaml"

# Build the API crate (which contains the utoipa OpenApi derive).
cargo build -p piteka-api --quiet 2>/dev/null

# Generate OpenAPI JSON via a small inline program.
# We use the utoipa derive which produces a JSON string at compile time.
# Since utoipa doesn't ship a CLI, we write a tiny generator.
cat > /tmp/gen_openapi.rs << 'RUST'
use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let doc = piteka_api::ApiDoc::openapi();
    let json = serde_json::to_string_pretty(&doc)?;
    std::fs::write("target/openapi-generated.json", &json)?;
    Ok(())
}
RUST

# We'll use cargo to run a small generator instead.
# Create a temporary binary crate for OpenAPI generation.
mkdir -p target/openapi-gen/src
cat > target/openapi-gen/Cargo.toml << 'TOML'
[package]
name = "openapi-gen"
version = "0.1.0"
edition = "2024"

[[bin]]
name = "openapi-gen"
path = "src/main.rs"

[dependencies]
piteka-api = { path = "../apps/piteka-api" }
serde_json = "1"
TOML

cat > target/openapi-gen/src/main.rs << 'RUST'
fn main() {
    let doc = piteka_api::ApiDoc::openapi();
    let json = serde_json::to_string_pretty(&doc).unwrap();
    std::fs::write("../target/openapi-generated.json", &json).unwrap();
}
RUST

cargo run -p openapi-gen --quiet 2>/dev/null || {
    echo "ERROR: Failed to generate OpenAPI JSON"
    exit 1
}

# Convert JSON to YAML if yq is available, otherwise compare JSON directly.
if command -v yq &>/dev/null; then
    yq -P < target/openapi-generated.json > target/openapi-generated.yaml
    GENERATED_YAML="target/openapi-generated.yaml"
else
    # Fall back: compare the JSON representation
    # We need a simple JSON-to-YAML converter or just compare JSON
    # For now, use python if available
    if command -v python3 &>/dev/null; then
        python3 -c "
import json, sys
try:
    import yaml
    with open('target/openapi-generated.json') as f:
        data = json.load(f)
    with open('target/openapi-generated.yaml', 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
except ImportError:
    # No yaml module; just copy JSON for comparison
    import shutil
    shutil.copy('target/openapi-generated.json', 'target/openapi-generated.json.bak')
    print('WARNING: pyyaml not available, comparing JSON representation', file=sys.stderr)
" 2>/dev/null
        if [ -f target/openapi-generated.yaml ]; then
            GENERATED_YAML="target/openapi-generated.yaml"
        else
            GENERATED_YAML="target/openapi-generated.json.bak"
        fi
    else
        GENERATED_YAML="target/openapi-generated.json"
    fi
fi

# Compare with the checked-in file.
if [ -f "$CHECKED_IN_YAML" ]; then
    if ! diff -q "$GENERATED_YAML" "$CHECKED_IN_YAML" &>/dev/null; then
        echo "ERROR: OpenAPI contract drift detected."
        echo "  Generated: $GENERATED_YAML"
        echo "  Checked-in: $CHECKED_IN_YAML"
        echo "Run ./scripts/regenerate_openapi.sh to update the checked-in contract."
        diff -u "$CHECKED_IN_YAML" "$GENERATED_YAML" || true
        exit 1
    fi
    echo "OpenAPI contract is up to date."
else
    echo "WARNING: $CHECKED_IN_YAML does not exist. Copying generated version."
    cp "$GENERATED_YAML" "$CHECKED_IN_YAML"
fi
