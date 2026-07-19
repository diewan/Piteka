#!/usr/bin/env python3
"""Fail-closed validation for the version-pinned deployment consumer."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")


def validate(event: object, expected_environment: str) -> dict[str, str]:
    if not isinstance(event, dict) or set(event) < {"deployment", "repository"}:
        raise ValueError("event must contain deployment and repository")
    deployment = event["deployment"]
    repository = event["repository"]
    if not isinstance(deployment, dict) or not isinstance(repository, dict):
        raise ValueError("deployment and repository must be objects")

    required = {"id", "sha", "ref", "task", "environment", "payload"}
    if not required.issubset(deployment):
        raise ValueError("deployment is missing required fields")
    if type(deployment["id"]) is not int or deployment["id"] <= 0:
        raise ValueError("deployment id must be a positive integer")
    sha = deployment["sha"]
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise ValueError("deployment sha must be a full lowercase commit SHA")
    if deployment["ref"] != sha:
        raise ValueError("deployment ref must equal the exact commit SHA")
    if deployment["task"] != "deploy":
        raise ValueError("deployment task must be deploy")
    if deployment["environment"] != expected_environment:
        raise ValueError("deployment environment is not the controlled environment")

    payload = deployment["payload"]
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ValueError("deployment payload is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("deployment payload must be an object")
    if set(payload) != {"schema_version", "piteka_attempt_digest"}:
        raise ValueError("deployment payload has missing or unsupported fields")
    if payload["schema_version"] != 1:
        raise ValueError("unsupported deployment payload schema")
    digest = payload["piteka_attempt_digest"]
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        raise ValueError("piteka_attempt_digest must be 64 lowercase hex characters")

    repository_id = repository.get("id")
    if type(repository_id) is not int or repository_id <= 0:
        raise ValueError("repository id must be a positive integer")
    return {
        "deployment_id": str(deployment["id"]),
        "sha": sha,
        "attempt_digest": digest,
        "repository_id": str(repository_id),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("event", type=Path)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    try:
        result = validate(json.loads(args.event.read_text()), args.environment)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"deployment event rejected: {exc}", file=sys.stderr)
        return 1
    output = "".join(f"{key}={value}\n" for key, value in result.items())
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as handle:
            handle.write(output)
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
