import importlib.util
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE = Path(__file__).with_name("h03_adversarial.py")
spec = importlib.util.spec_from_file_location("h03_adversarial", MODULE)
h03 = importlib.util.module_from_spec(spec)
assert spec.loader is not None
__import__("sys").modules[spec.name] = h03
spec.loader.exec_module(h03)


class H03AdversarialTests(unittest.TestCase):
    def test_registry_is_exactly_the_required_non_deferred_suite(self):
        self.assertEqual(tuple(h03.SCENARIOS), h03.REQUIRED_SCENARIOS)
        self.assertEqual(len(h03.SCENARIOS), 12)

    @patch.object(h03.subprocess, "run")
    def test_named_test_and_nonzero_exit_are_fail_closed(self, run):
        scenario = h03.SCENARIOS[1]
        run.return_value = subprocess.CompletedProcess(scenario.command, 0, "0 passed", "")
        with self.assertRaisesRegex(h03.ScenarioError, "exactly one named test"):
            h03.run_scenario(scenario)
        run.return_value = subprocess.CompletedProcess(scenario.command, 1, "", "failed")
        with self.assertRaisesRegex(h03.ScenarioError, "command failed"):
            h03.run_scenario(scenario)

    @patch.object(h03.subprocess, "run")
    def test_success_records_command_and_output_digest(self, run):
        scenario = h03.SCENARIOS[3]
        output = f"test {scenario.marker} ... ok\ntest result: ok. 1 passed; 0 failed"
        run.return_value = subprocess.CompletedProcess(scenario.command, 0, output, "")
        result = h03.run_scenario(scenario)
        self.assertEqual(result["scenario"], 3)
        self.assertEqual(len(result["output_sha256"]), 64)
        self.assertEqual(result["result"], "rejected_or_indeterminate_as_required")

    def test_missing_duplicate_and_unsupported_selections_reject(self):
        for selection in ([], [1, 1], [10]):
            with self.subTest(selection=selection), self.assertRaises(h03.ScenarioError):
                h03.execute(selection)


if __name__ == "__main__":
    unittest.main()
