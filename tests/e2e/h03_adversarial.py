#!/usr/bin/env python3
"""Execute and record the H-03 adversarial scenario suite.

Protocol meaning remains in Parwana.  This runner only invokes the tests owned
by Piteka, Tuppira, and Parwana and records reproducible command evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
REQUIRED_SCENARIOS = (1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13, 14)


class ScenarioError(RuntimeError):
    """A scenario was missing, ambiguous, or did not demonstrate rejection."""


@dataclass(frozen=True)
class Scenario:
    number: int
    threat: str
    repository: str
    command: tuple[str, ...]
    marker: str


def cargo(repo: str, package: str, test: str, marker: str, threat: str, number: int) -> Scenario:
    return Scenario(
        number, threat, repo,
        ("cargo", "test", "-p", package, test, "--", "--exact", "--nocapture"),
        marker,
    )


SCENARIOS = {
    item.number: item
    for item in (
        cargo("parwana", "csv-accountability-verify", "wrong_commit_and_environment_do_not_match_the_mandate", "wrong_commit_and_environment_do_not_match_the_mandate", "agent changes commit SHA after approval", 1),
        cargo("parwana", "csv-accountability-verify", "wrong_commit_and_environment_do_not_match_the_mandate", "wrong_commit_and_environment_do_not_match_the_mandate", "agent changes production to another environment", 2),
        cargo("piteka", "piteka-application", "dispatch_tests::one_concurrent_winner_on_reserve", "dispatch_tests::one_concurrent_winner_on_reserve", "two agents concurrently execute one mandate", 3),
        cargo("piteka", "piteka-application", "dispatch_tests::complete_dispatch_quarantines_mandate_on_provider_failure", "dispatch_tests::complete_dispatch_quarantines_mandate_on_provider_failure", "timeout after GitHub accepts dispatch", 4),
        cargo("piteka", "piteka-github", "tests::test_verify_webhook_invalid_signature", "tests::test_verify_webhook_invalid_signature", "forged GitHub webhook", 5),
        cargo("piteka", "piteka-storage", "tests::webhook_deliveries_are_unique_and_idempotent", "tests::webhook_deliveries_are_unique_and_idempotent", "webhook replay", 6),
        cargo("piteka", "piteka-application", "bundle_export_tests::assemble_bundle_fails_closed_when_referenced_evidence_is_missing", "bundle_export_tests::assemble_bundle_fails_closed_when_referenced_evidence_is_missing", "Piteka claims success without target evidence", 7),
        cargo("tuppira", "tuppira-shared", "types::event_tests::rejects_unknown_versions", "types::event_tests::rejects_unknown_versions", "Tuppira normalizes the same event differently across versions", 8),
        cargo("parwana", "csv-accountability-verify", "ambiguous_outcome_selective_disclosure_and_missing_evidence_remain_indeterminate", "ambiguous_outcome_selective_disclosure_and_missing_evidence_remain_indeterminate", "bundle omits contradictory evidence", 9),
        cargo("parwana", "csv-accountability", "disclosure_ambiguity_and_size_limits_are_rejected", "disclosure_ambiguity_and_size_limits_are_rejected", "malicious bundle exhausts verifier memory or CPU", 12),
        cargo("parwana", "csv-accountability-verify", "wrong_subject_expiry_revocation_and_replay_fail_closed", "wrong_subject_expiry_revocation_and_replay_fail_closed", "clock skew changes expiry evaluation", 13),
        cargo("parwana", "csv-accountability", "every_context_input_is_hash_bound", "every_context_input_is_hash_bound", "old verification context is presented as current", 14),
    )
}


def digest(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def run_scenario(scenario: Scenario, timeout: int = 300) -> dict:
    cwd = ROOT / scenario.repository
    if not cwd.is_dir():
        raise ScenarioError(f"scenario {scenario.number}: missing repository {cwd}")
    started = time.time()
    try:
        result = subprocess.run(
            scenario.command, cwd=cwd, text=True, capture_output=True,
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise ScenarioError(f"scenario {scenario.number}: timed out") from error
    output = result.stdout + "\n" + result.stderr
    if result.returncode != 0:
        raise ScenarioError(
            f"scenario {scenario.number}: command failed ({result.returncode})\n{output[-4000:]}"
        )
    if scenario.marker not in output or "1 passed" not in output:
        raise ScenarioError(
            f"scenario {scenario.number}: command did not prove exactly one named test ran"
        )
    return {
        "scenario": scenario.number,
        "threat": scenario.threat,
        "repository": scenario.repository,
        "command": list(scenario.command),
        "result": "rejected_or_indeterminate_as_required",
        "exit_code": result.returncode,
        "duration_ms": round((time.time() - started) * 1000),
        "output_sha256": digest(output),
        "test_marker": scenario.marker,
    }


def execute(numbers: list[int], timeout: int = 300) -> dict:
    if not numbers or any(number not in SCENARIOS for number in numbers):
        raise ScenarioError("scenario selection contains an unsupported or missing scenario")
    if len(numbers) != len(set(numbers)):
        raise ScenarioError("scenario selection contains duplicates")
    results = [run_scenario(SCENARIOS[number], timeout) for number in numbers]
    return {
        "schema_version": 1,
        "ticket": "H-03",
        "required_scenarios": list(REQUIRED_SCENARIOS),
        "executed_scenarios": numbers,
        "complete": tuple(numbers) == REQUIRED_SCENARIOS,
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", type=int, action="append")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    numbers = args.scenario or list(REQUIRED_SCENARIOS)
    try:
        report = execute(numbers, args.timeout)
        if args.scenario is None and not report["complete"]:
            raise ScenarioError("full run omitted a required scenario")
        args.result.parent.mkdir(parents=True, exist_ok=True)
        args.result.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except (OSError, ScenarioError) as error:
        print(f"H-03 rejected: {error}", file=__import__("sys").stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
