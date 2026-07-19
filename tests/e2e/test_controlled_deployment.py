import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "deploy/controlled-demo/validate_deployment_event.py"
spec = importlib.util.spec_from_file_location("deployment_validator", VALIDATOR)
validator = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(validator)


def valid_event():
    sha = "a" * 40
    return {
        "deployment": {
            "id": 42,
            "sha": sha,
            "ref": sha,
            "task": "deploy",
            "environment": "piteka-demo-production",
            "payload": {"schema_version": 1, "piteka_attempt_digest": "b" * 64},
        },
        "repository": {"id": 99, "full_name": "diewan/piteka-demo"},
    }


class ControlledDeploymentTests(unittest.TestCase):
    def test_accepts_exact_controlled_event(self):
        result = validator.validate(valid_event(), "piteka-demo-production")
        self.assertEqual(result["deployment_id"], "42")
        self.assertEqual(result["sha"], "a" * 40)

    def test_rejects_control_weakening_and_ambiguous_inputs(self):
        mutations = [
            ("task", "release"),
            ("environment", "customer-production"),
            ("ref", "main"),
            ("sha", "abc"),
            ("payload", {}),
            ("payload", {"schema_version": 1, "piteka_attempt_digest": "b" * 64, "extra": True}),
        ]
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                event = valid_event()
                event["deployment"][field] = value
                with self.assertRaises(ValueError):
                    validator.validate(event, "piteka-demo-production")

    def test_rejects_string_or_zero_stable_ids(self):
        for key, value in (("deployment", "42"), ("deployment", 0), ("repository", "99"), ("repository", 0)):
            event = valid_event()
            event[key]["id"] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                validator.validate(event, "piteka-demo-production")

    def test_policy_snapshot_has_one_approval_authority(self):
        policy = json.loads((ROOT / "deploy/controlled-demo/environment-policy.json").read_text())
        self.assertFalse(policy["customer_production_data_allowed"])
        self.assertEqual(policy["protection"]["required_reviewers"], [])
        self.assertEqual(policy["protection"]["wait_timer_minutes"], 0)
        self.assertEqual(policy["protection"]["custom_deployment_protection_rules"], [])

    def test_workflow_is_version_pinned_and_correlates_original_id(self):
        workflow = (ROOT / "deploy/controlled-demo/piteka-deployment-consumer.yml").read_text()
        self.assertIn("deployment:", workflow)
        self.assertIn("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", workflow)
        self.assertNotIn("environment:\n      name:", workflow)
        self.assertGreaterEqual(workflow.count("github.event.deployment.id"), 3)
        self.assertIn("github.workflow_ref", workflow)
        self.assertIn("github.workflow_sha", workflow)


if __name__ == "__main__":
    unittest.main()
