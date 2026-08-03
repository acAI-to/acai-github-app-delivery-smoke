import json
import tempfile
import unittest
from pathlib import Path

from scripts import validation_profile


ROOT = Path(__file__).resolve().parents[1]


class ValidationProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = validation_profile.load_policy(ROOT)

    def test_mechanical_profile_requires_explicit_mechanical_class(self) -> None:
        result = validation_profile.select_profile(
            self.policy,
            ["docs/typo.md"],
            {"change_class": "mechanical", "validation_profile": "mechanical"},
        )
        self.assertEqual("mechanical", result["profile"])
        self.assertFalse(result["escalated"])
        self.assertEqual("success", result["ci_test_mode"])
        self.assertEqual(["test"], result["status_contexts"])

    def test_isolated_known_module_is_targeted(self) -> None:
        result = validation_profile.select_profile(self.policy, ["src/feature.py"], {})
        self.assertEqual("targeted", result["profile"])
        self.assertIn("targeted", result["required_suites"])

    def test_missing_native_mapping_escalates_target_repository(self) -> None:
        result = validation_profile.select_profile(
            self.policy,
            ["src/feature.py"],
            {"repository_kind": "apps"},
        )
        self.assertEqual("full", result["profile"])
        self.assertTrue(result["escalated"])
        self.assertIn("unavailable", result["rationale"])

    def test_explicit_native_mapping_keeps_isolated_module_targeted(self) -> None:
        result = validation_profile.select_profile(
            self.policy,
            ["src/feature.py"],
            {"repository_kind": "apps", "native_commands": ["pnpm test"]},
        )
        self.assertEqual("targeted", result["profile"])
        self.assertEqual(["pnpm test"], result["native_commands"])

    def test_mixed_mechanical_and_targeted_paths_compute_without_declaration(self) -> None:
        metadata = {"change_class": "mechanical", "validation_profile": "mechanical"}
        result = validation_profile.select_profile(
            self.policy,
            ["docs/typo.md", "src/feature.py"],
            metadata,
        )
        self.assertNotEqual("mechanical", result["profile"])
        self.assertFalse(result["escalated"])
        self.assertEqual([], validation_profile.validate_declared_profile(self.policy, ["docs/typo.md", "src/feature.py"], metadata))

    def test_shared_governance_path_is_full(self) -> None:
        result = validation_profile.select_profile(self.policy, [".github/workflows/ci.yml"], {})
        self.assertEqual("full", result["profile"])

    def test_runtime_risk_is_full_plus_runtime(self) -> None:
        for tag in ("operations", "destructive", "data-loss", "fleet-wide", "multi-host", "irreversible"):
            with self.subTest(tag=tag):
                result = validation_profile.select_profile(self.policy, ["src/feature.py"], {"risk_tags": [tag]})
                self.assertEqual("full-plus-runtime", result["profile"])
                self.assertEqual("run", result["ci_test_mode"])

    def test_policy_requires_a_ci_mode_for_every_profile(self) -> None:
        invalid = dict(self.policy)
        invalid.pop("ci_test_mode")
        with tempfile.TemporaryDirectory() as td:
            policy_path = Path(td) / "governance" / "validation-policy.json"
            policy_path.parent.mkdir()
            policy_path.write_text(json.dumps(invalid))
            with self.assertRaisesRegex(ValueError, "ci_test_mode"):
                validation_profile.load_policy(Path(td))

    def test_repository_default_profile_is_applied(self) -> None:
        result = validation_profile.select_profile(
            self.policy,
            ["roles/service/tasks/main.yml"],
            {"repository_kind": "acai-ops"},
        )
        self.assertEqual("full-plus-runtime", result["profile"])

    def test_unknown_mapping_escalates_to_full(self) -> None:
        result = validation_profile.select_profile(self.policy, ["mystery/file.xyz"], {})
        self.assertEqual("full", result["profile"])
        self.assertTrue(result["escalated"])
        self.assertIn("unknown", result["rationale"].lower())

    def test_legacy_declaration_cannot_downgrade_shared_change(self) -> None:
        result = validation_profile.select_profile(
            self.policy,
            ["governance/tier-policy.json"],
            {"validation_profile": "targeted"},
        )
        self.assertEqual("full", result["profile"])
        self.assertFalse(result["escalated"])


if __name__ == "__main__":
    unittest.main()
