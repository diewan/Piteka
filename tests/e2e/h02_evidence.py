#!/usr/bin/env python3
"""Fail-closed H-02 evidence handoff and offline-verification runner.

This program does not create demo evidence. It validates artifacts captured by
the real Piteka/GitHub path and delegates protocol meaning to the Parwana CLI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

STEP_IDS = tuple(range(1, 14))
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
INTEGRITY_REASON = re.compile(r"integrity|digest.?mismatch|signature.?invalid", re.I)
FORBIDDEN_ENV_PREFIXES = ("DATABASE_", "GITHUB_", "PITEKA_")
FORBIDDEN_ENV_NAMES = {"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD"}


class EvidenceError(ValueError):
    """The handoff is incomplete, ambiguous, or failed verification."""


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_manifest(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot read manifest: {error}") from error
    if not isinstance(value, dict):
        raise EvidenceError("manifest must be a JSON object")
    return value


def validate_handoff(manifest_path: Path) -> tuple[dict, dict[str, Path]]:
    manifest = load_manifest(manifest_path)
    if manifest.get("schema_version") != 1:
        raise EvidenceError("unsupported manifest schema_version")

    steps = manifest.get("steps")
    if not isinstance(steps, list) or [item.get("step") for item in steps if isinstance(item, dict)] != list(STEP_IDS):
        raise EvidenceError("steps must contain each Section 3 step exactly once, in order")
    if any(item.get("status") != "captured" or not item.get("evidence") for item in steps):
        raise EvidenceError("every step must be captured and cite evidence")

    handoff = manifest.get("outside_party_handoff")
    required_handoff = {"recipient", "no_github_org_access", "no_piteka_access", "portable_bundle", "declared_context"}
    if not isinstance(handoff, dict) or set(handoff) != required_handoff:
        raise EvidenceError("outside_party_handoff has missing or unknown fields")
    if not handoff["recipient"] or not all(handoff[key] is True for key in required_handoff - {"recipient"}):
        raise EvidenceError("outside-party independence is not established")

    artifact_table = manifest.get("artifacts")
    required = {"bundle", "mandate", "receipt", "verification_context"}
    if not isinstance(artifact_table, dict) or set(artifact_table) != required:
        raise EvidenceError("artifacts must contain exactly bundle, mandate, receipt, and verification_context")
    resolved: dict[str, Path] = {}
    base = manifest_path.resolve().parent
    for name, descriptor in artifact_table.items():
        if not isinstance(descriptor, dict) or set(descriptor) != {"path", "sha256"}:
            raise EvidenceError(f"invalid {name} descriptor")
        relative = Path(descriptor["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise EvidenceError(f"{name} path must remain inside the handoff directory")
        path = (base / relative).resolve()
        if not path.is_file() or not path.is_relative_to(base):
            raise EvidenceError(f"missing or escaping {name} artifact")
        if not HEX_64.fullmatch(str(descriptor["sha256"])) or sha256(path) != descriptor["sha256"]:
            raise EvidenceError(f"{name} digest mismatch")
        resolved[name] = path
    return manifest, resolved


def offline_environment() -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in FORBIDDEN_ENV_NAMES and not key.startswith(FORBIDDEN_ENV_PREFIXES)
    }
    env.update({"NO_PROXY": "*", "no_proxy": "*", "CSV_OFFLINE": "1"})
    return env


def run_verifier(command: list[str], bundle: Path, context: Path) -> subprocess.CompletedProcess[str]:
    if not command:
        raise EvidenceError("verifier command is empty")
    return subprocess.run(
        [*command, "verify", "--explain", "--bundle", str(bundle), "--context", str(context)],
        text=True,
        capture_output=True,
        env=offline_environment(),
        timeout=120,
        check=False,
    )


def flip_one_byte(source: Path, destination: Path) -> None:
    data = bytearray(source.read_bytes())
    if not data:
        raise EvidenceError(f"cannot mutate empty artifact {source.name}")
    data[len(data) // 2] ^= 1
    destination.write_bytes(data)


def verify_handoff(manifest_path: Path, command: list[str], work_dir: Path) -> dict:
    manifest, artifacts = validate_handoff(manifest_path)
    work_dir.mkdir(parents=True, exist_ok=True)
    clean = run_verifier(command, artifacts["bundle"], artifacts["verification_context"])
    if clean.returncode != 0:
        raise EvidenceError(f"clean bundle rejected: {(clean.stderr or clean.stdout).strip()}")

    mutations = {}
    for kind in ("mandate", "receipt"):
        mutated = work_dir / f"{kind}.one-byte-mutated.bin"
        flip_one_byte(artifacts[kind], mutated)
        # The bundle is immutable: a verifier must notice that its disclosed
        # object's committed digest no longer matches the supplied bytes.
        result = subprocess.run(
            [*command, "verify", "--explain", "--bundle", str(artifacts["bundle"]),
             "--context", str(artifacts["verification_context"]), f"--{kind}", str(mutated)],
            text=True, capture_output=True, env=offline_environment(), timeout=120, check=False,
        )
        explanation = (result.stdout + "\n" + result.stderr).strip()
        if result.returncode == 0 or not INTEGRITY_REASON.search(explanation):
            raise EvidenceError(f"mutated {kind} was not rejected with an integrity reason code")
        mutations[kind] = {"sha256": sha256(mutated), "explanation": explanation}

    return {
        "schema_version": 1,
        "source_manifest_sha256": sha256(manifest_path),
        "bundle_sha256": manifest["artifacts"]["bundle"]["sha256"],
        "clean_verification": clean.stdout.strip(),
        "mutations": mutations,
        "network_and_database_inputs_removed": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--verifier", nargs="+", required=True, help="Parwana csv CLI command prefix")
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify_handoff(args.manifest, args.verifier, args.work_dir)
        args.result.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (EvidenceError, OSError, subprocess.SubprocessError) as error:
        print(f"H-02 rejected: {error}", file=__import__("sys").stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
