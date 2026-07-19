import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from h02_evidence import EvidenceError, offline_environment, validate_handoff, verify_handoff


class H02EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        artifacts = {}
        for name in ("bundle", "mandate", "receipt", "verification_context"):
            path = self.root / f"{name}.bin"
            path.write_bytes(f"real-{name}-bytes".encode())
            artifacts[name] = {"path": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        self.manifest = self.root / "handoff.json"
        self.value = {
            "schema_version": 1,
            "steps": [{"step": step, "status": "captured", "evidence": ["bundle"]} for step in range(1, 14)],
            "outside_party_handoff": {"recipient": "auditor@example.test", "no_github_org_access": True,
                "no_piteka_access": True, "portable_bundle": True, "declared_context": True},
            "artifacts": artifacts,
        }
        self.write_manifest()

    def tearDown(self):
        self.temp.cleanup()

    def write_manifest(self):
        self.manifest.write_text(json.dumps(self.value))

    def verifier(self):
        script = self.root / "csv-stub"
        script.write_text("#!/bin/sh\ncase \"$*\" in *one-byte-mutated*) echo 'INTEGRITY_DIGEST_MISMATCH' >&2; exit 2;; *) echo 'valid; context_digest=abc';; esac\n")
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        return [str(script)]

    def test_complete_handoff_verifies_and_both_mutations_reject(self):
        result = verify_handoff(self.manifest, self.verifier(), self.root / "mutations")
        self.assertIn("valid", result["clean_verification"])
        self.assertEqual(set(result["mutations"]), {"mandate", "receipt"})

    def test_missing_duplicate_or_out_of_order_steps_reject(self):
        for steps in (self.value["steps"][:-1], list(reversed(self.value["steps"])), self.value["steps"] + [self.value["steps"][0]]):
            with self.subTest(count=len(steps)):
                self.value["steps"] = steps
                self.write_manifest()
                with self.assertRaises(EvidenceError):
                    validate_handoff(self.manifest)
        self.value["steps"] = [{"step": step, "status": "captured", "evidence": ["bundle"]} for step in range(1, 14)]

    def test_changed_artifact_and_cross_directory_path_reject(self):
        (self.root / "receipt.bin").write_bytes(b"changed")
        with self.assertRaisesRegex(EvidenceError, "digest mismatch"):
            validate_handoff(self.manifest)
        self.value["artifacts"]["receipt"]["path"] = "../receipt.bin"
        self.write_manifest()
        with self.assertRaisesRegex(EvidenceError, "inside"):
            validate_handoff(self.manifest)

    def test_outside_party_claim_must_be_explicit(self):
        self.value["outside_party_handoff"]["no_github_org_access"] = False
        self.write_manifest()
        with self.assertRaisesRegex(EvidenceError, "independence"):
            validate_handoff(self.manifest)

    def test_offline_process_drops_credentials_and_database_access(self):
        old = os.environ.copy()
        try:
            os.environ.update({"GITHUB_TOKEN": "secret", "DATABASE_URL": "postgres://secret", "PGPASSWORD": "secret"})
            env = offline_environment()
            self.assertNotIn("GITHUB_TOKEN", env)
            self.assertNotIn("DATABASE_URL", env)
            self.assertNotIn("PGPASSWORD", env)
            self.assertEqual(env["CSV_OFFLINE"], "1")
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_zero_exit_or_unstructured_tamper_failure_rejects(self):
        script = self.root / "bad-verifier"
        script.write_text("#!/bin/sh\necho nope >&2\ncase \"$*\" in *one-byte-mutated*) exit 2;; *) exit 0;; esac\n")
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        with self.assertRaisesRegex(EvidenceError, "integrity reason"):
            verify_handoff(self.manifest, [str(script)], self.root / "mutations")


if __name__ == "__main__":
    unittest.main()
