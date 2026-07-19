import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "deploy/pilot/readiness.json"


def load_manifest(path=MANIFEST):
    return json.loads(path.read_text(encoding="utf-8"))


def validate_release_gate(manifest):
    errors = []
    blockers = manifest.get("blockers", [])
    decision = manifest.get("decision")
    if blockers and decision != "no-go":
        errors.append("open blockers require a no-go decision")
    if not blockers and decision != "go":
        errors.append("a blocker-free review must make an explicit go decision")
    for blocker in blockers:
        for field in ("id", "owner", "condition", "evidence_to_close"):
            if not str(blocker.get(field, "")).strip():
                errors.append(f"blocker is missing {field}")
    if set(manifest.get("dependencies", {})) != {"H-04", "H-05", "H-06"}:
        errors.append("dependency disposition must cover H-04, H-05, and H-06")
    return errors


class PilotReadinessTests(unittest.TestCase):
    def test_checked_in_review_fails_closed_with_documented_blockers(self):
        manifest = load_manifest()
        self.assertEqual([], validate_release_gate(manifest))
        self.assertEqual("no-go", manifest["decision"])
        self.assertGreaterEqual(len(manifest["blockers"]), 1)

    def test_every_required_runbook_exists_and_is_substantive(self):
        for relative in load_manifest()["required_runbooks"]:
            path = ROOT / relative
            self.assertTrue(path.is_file(), relative)
            self.assertGreater(len(path.read_text(encoding="utf-8")), 500, relative)

    def test_adversarial_go_with_open_blockers_is_rejected(self):
        manifest = load_manifest()
        manifest["decision"] = "go"
        self.assertIn(
            "open blockers require a no-go decision",
            validate_release_gate(manifest),
        )

    def test_malformed_blocker_is_rejected(self):
        manifest = load_manifest()
        manifest["blockers"][0]["owner"] = ""
        self.assertIn("blocker is missing owner", validate_release_gate(manifest))


if __name__ == "__main__":
    unittest.main()
