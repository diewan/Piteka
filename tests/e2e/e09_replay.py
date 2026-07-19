#!/usr/bin/env python3
"""Run the E-09 replay demonstration and record reproducible evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

CHECKS = (
    (
        "no_second_provider_dispatch",
        (
            "cargo", "test", "--all-features", "-p", "piteka-application",
            "dispatch_tests::no_second_dispatch_after_consumption", "--", "--exact",
        ),
        "dispatch_tests::no_second_dispatch_after_consumption",
    ),
    (
        "visible_rejection_evidence",
        (
            "cargo", "test", "--all-features", "-p", "piteka-web",
            "tests::replay_rejection_is_visible_accessible_and_evidence_backed", "--", "--exact",
        ),
        "tests::replay_rejection_is_visible_accessible_and_evidence_backed",
    ),
)


class ReplayDemonstrationError(RuntimeError):
    """The replay demonstration did not prove a required property."""


def run_check(name: str, command: tuple[str, ...], marker: str, timeout: int) -> dict:
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise ReplayDemonstrationError(f"{name} timed out") from error

    output = result.stdout + "\n" + result.stderr
    if result.returncode != 0:
        raise ReplayDemonstrationError(
            f"{name} failed ({result.returncode})\n{output[-4000:]}"
        )
    if marker not in output or "1 passed" not in output:
        raise ReplayDemonstrationError(
            f"{name} did not prove exactly one required test passed"
        )
    return {
        "name": name,
        "command": list(command),
        "exit_code": result.returncode,
        "output_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        "test_marker": marker,
    }


def execute(timeout: int = 300) -> dict:
    return {
        "schema_version": 1,
        "ticket": "E-09",
        "result": "replay_rejected_and_evidenced_without_second_dispatch",
        "checks": [run_check(name, command, marker, timeout) for name, command, marker in CHECKS],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()
    try:
        report = execute(args.timeout)
        args.result.parent.mkdir(parents=True, exist_ok=True)
        args.result.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (OSError, ReplayDemonstrationError) as error:
        print(f"E-09 rejected: {error}", file=__import__("sys").stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
