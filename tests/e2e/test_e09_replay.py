import importlib.util
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE = Path(__file__).with_name("e09_replay.py")
spec = importlib.util.spec_from_file_location("e09_replay", MODULE)
e09 = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(e09)


class E09ReplayTests(unittest.TestCase):
    def test_registry_covers_dispatch_suppression_and_visible_evidence(self):
        self.assertEqual(
            [name for name, _command, _marker in e09.CHECKS],
            ["no_second_provider_dispatch", "visible_rejection_evidence"],
        )

    @patch.object(e09.subprocess, "run")
    def test_failure_and_ambiguous_success_fail_closed(self, run):
        name, command, marker = e09.CHECKS[0]
        run.return_value = subprocess.CompletedProcess(command, 1, "", "failed")
        with self.assertRaisesRegex(e09.ReplayDemonstrationError, "failed"):
            e09.run_check(name, command, marker, 10)

        run.return_value = subprocess.CompletedProcess(command, 0, "0 passed", "")
        with self.assertRaisesRegex(e09.ReplayDemonstrationError, "exactly one"):
            e09.run_check(name, command, marker, 10)

    @patch.object(e09.subprocess, "run")
    def test_success_records_commands_and_artifact_digests(self, run):
        def completed(command, **_kwargs):
            marker = next(marker for _name, expected, marker in e09.CHECKS if expected == command)
            output = f"test {marker} ... ok\ntest result: ok. 1 passed; 0 failed"
            return subprocess.CompletedProcess(command, 0, output, "")

        run.side_effect = completed
        report = e09.execute(timeout=10)
        self.assertEqual(report["ticket"], "E-09")
        self.assertEqual(len(report["checks"]), 2)
        self.assertTrue(all(len(check["output_sha256"]) == 64 for check in report["checks"]))


if __name__ == "__main__":
    unittest.main()
