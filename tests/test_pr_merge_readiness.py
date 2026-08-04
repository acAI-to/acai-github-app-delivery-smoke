import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import pr_merge_readiness


class PrMergeReadinessTests(unittest.TestCase):
    def test_default_contract_waives_only_tier_zero_and_one_gate_b(self):
        contract = json.loads((ROOT / "governance" / "merge-readiness-checks.json").read_text(encoding="utf-8"))

        self.assertEqual(2, contract["version"])
        by_name = {item.get("name", "native"): item for item in contract["checks"]}
        self.assertEqual([0, 1, 2], by_name["issue-first"]["tiers"])
        self.assertEqual([0, 1, 2], by_name["native"]["tiers"])
        self.assertEqual([2], by_name["governance/gate-b"]["tiers"])

    def test_live_snapshot_captures_pr_body_for_tier_verification(self):
        with patch.object(pr_merge_readiness, "_gh", side_effect=[
            {"state": "OPEN", "isDraft": False, "headRefOid": "a" * 40, "body": "Tier: governance/tier-1"},
            {"data": {"repository": {"pullRequest": {"timelineItems": {"nodes": []}}}}},
        ]):
            snapshot = pr_merge_readiness._snapshot("acAI-to/acai-harness", 255)

        self.assertEqual("Tier: governance/tier-1", snapshot["body"])

    def test_tier_one_requires_gate_a_but_waives_gate_b(self):
        contract = {
            "version": 2,
            "checks": [
                {"kind": "check_run", "name": "issue-first", "publisher": "github-actions", "workflow": "change-governance", "tiers": [0, 1, 2]},
                {"kind": "check_run", "name": "test", "publisher": "github-actions", "workflow": "ci", "tiers": [0, 1, 2]},
                {"kind": "commit_status", "name": "governance/gate-b", "publisher": None, "workflow": "relay", "tiers": [2]},
            ],
        }
        pr = {
            "state": "OPEN",
            "is_draft": False,
            "head_sha": "a" * 40,
            "body": "Tier: governance/tier-1",
            "ready_event": {"id": "ready-1", "created_at": "2026-07-22T19:00:00Z"},
        }
        base = {
            "kind": "check_run",
            "publisher": "github-actions",
            "status": "completed",
            "conclusion": "success",
            "head_sha": "a" * 40,
            "completed_at": "2026-07-22T19:00:01Z",
        }
        checks = [
            {**base, "name": "issue-first", "workflow": "change-governance"},
            {**base, "name": "test", "workflow": "ci"},
        ]

        self.assertEqual({"status": "ready", "blockers": []}, pr_merge_readiness.evaluate(pr, checks, contract))

    def test_tier_two_still_requires_trusted_canonical_gate_b(self):
        contract = {
            "version": 2,
            "checks": [
                {
                    "kind": "commit_status",
                    "name": "governance/gate-b",
                    "publisher": None,
                    "workflow": ".github/workflows/independent-review-gate-b-relay.yml",
                    "workflow_event": "workflow_dispatch",
                    "workflow_ref": "default_branch",
                    "workflow_status": "completed",
                    "workflow_conclusion": "success",
                    "tiers": [2],
                },
            ],
        }
        pr = {
            "state": "OPEN",
            "is_draft": False,
            "head_sha": "a" * 40,
            "body": "Tier: governance/tier-2",
            "ready_event": {"id": "ready-1", "created_at": "2026-07-22T19:00:00Z"},
        }
        gate_b = {
            "kind": "commit_status",
            "name": "governance/gate-b",
            "publisher": None,
            "workflow": ".github/workflows/independent-review-gate-b-relay.yml",
            "workflow_event": "workflow_dispatch",
            "workflow_ref": "default_branch",
            "workflow_status": "completed",
            "workflow_conclusion": "success",
            "status": "completed",
            "conclusion": "success",
            "head_sha": "a" * 40,
            "completed_at": "2026-07-22T19:00:01Z",
        }

        self.assertIn("required check is missing: governance/gate-b", pr_merge_readiness.evaluate(pr, [], contract)["blockers"])
        self.assertEqual("ready", pr_merge_readiness.evaluate(pr, [gate_b], contract)["status"])

    def test_tier_two_accepts_declared_gate_b_workflow(self):
        contract = {"version": 3, "checks": [{"kind": "commit_status", "name": "governance/gate-b", "publisher": None, "workflows": [".github/workflows/independent-review-gate-b-relay.yml"], "workflow_event": "workflow_dispatch", "workflow_ref": "default_branch", "workflow_status": "completed", "workflow_conclusion": "success", "tiers": [2]}]}
        pr = {"state": "OPEN", "is_draft": False, "head_sha": "a" * 40, "body": "Tier: governance/tier-2", "ready_event": {"id": "ready-1", "created_at": "2026-07-22T19:00:00Z"}}
        for workflow in contract["checks"][0]["workflows"]:
            with self.subTest(workflow=workflow):
                check = {"kind": "commit_status", "name": "governance/gate-b", "publisher": None, "workflow": workflow, "workflow_event": "workflow_dispatch", "workflow_ref": "default_branch", "workflow_status": "completed", "workflow_conclusion": "success", "status": "completed", "conclusion": "success", "head_sha": "a" * 40, "completed_at": "2026-07-22T19:00:01Z"}
                self.assertEqual("ready", pr_merge_readiness.evaluate(pr, [check], contract)["status"])

    def test_version_two_tier_metadata_fails_closed_when_missing_duplicate_or_malformed(self):
        contract = {"version": 2, "checks": []}
        base = {
            "state": "OPEN",
            "is_draft": False,
            "head_sha": "a" * 40,
            "ready_event": {"id": "ready-1", "created_at": "2026-07-22T19:00:00Z"},
        }
        for body in ("", "Tier: governance/tier-1\nTier: governance/tier-2", "Tier: tier-1"):
            with self.subTest(body=body):
                result = pr_merge_readiness.evaluate({**base, "body": body}, [], contract)
                self.assertEqual("blocked", result["status"])
                self.assertIn("PR body must declare exactly one well-formed governance tier", result["blockers"])

    def test_blocks_tier_change_during_snapshot_verification(self):
        initial = {
            "state": "OPEN",
            "is_draft": False,
            "head_sha": "a" * 40,
            "body": "Tier: governance/tier-1",
            "ready_event": {"id": "ready-1", "created_at": "2026-07-22T19:00:00Z"},
        }
        final = {**initial, "body": "Tier: governance/tier-2"}

        result = pr_merge_readiness.evaluate_snapshots(initial, final, [], {"version": 2, "checks": []})

        self.assertEqual("blocked", result["status"])
        self.assertIn("PR tier changed during verification", result["blockers"])

    def test_blocks_any_pr_body_change_during_snapshot_verification(self):
        initial = {
            "state": "OPEN",
            "is_draft": False,
            "head_sha": "a" * 40,
            "body": "Tier: governance/tier-1\nMerge effect: none",
            "ready_event": {
                "id": "ready-1",
                "created_at": "2026-07-22T19:00:00Z",
            },
        }
        final = {
            **initial,
            "body": "Tier: governance/tier-1\nMerge effect: live-mutation",
        }

        result = pr_merge_readiness.evaluate_snapshots(
            initial, final, [], {"version": 2, "checks": []}
        )

        self.assertEqual("blocked", result["status"])
        self.assertIn("PR body changed during verification", result["blockers"])

    def test_accepts_one_trusted_native_check_from_an_explicit_name_set(self):
        contract = {"version": 1, "checks": [{
            "kind": "check_run", "names": ["test", "native-checks"],
            "publisher": "github-actions", "workflow": ".github/workflows/ci.yml",
        }]}
        pr = {"state": "OPEN", "is_draft": False, "head_sha": "a" * 40, "ready_event": {"id": "ready-1", "created_at": "2026-07-22T19:00:00Z"}}
        check = {"kind": "check_run", "name": "native-checks", "publisher": "github-actions", "workflow": ".github/workflows/ci.yml", "status": "completed", "conclusion": "success", "head_sha": "a" * 40, "completed_at": "2026-07-22T19:00:01Z"}

        self.assertEqual("ready", pr_merge_readiness.evaluate(pr, [check], contract)["status"])

    def test_requires_every_observed_native_check_name_to_be_fresh_and_green(self):
        contract = {"version": 1, "checks": [{"kind": "check_run", "names": ["test", "native-checks"], "publisher": "github-actions", "workflow": ".github/workflows/ci.yml"}]}
        pr = {"state": "OPEN", "is_draft": False, "head_sha": "a" * 40, "ready_event": {"id": "ready-1", "created_at": "2026-07-22T19:00:00Z"}}
        base = {"kind": "check_run", "publisher": "github-actions", "workflow": ".github/workflows/ci.yml", "status": "completed", "conclusion": "success", "head_sha": "a" * 40, "completed_at": "2026-07-22T19:00:01Z"}
        failed = {**base, "name": "test", "conclusion": "failure"}
        later_success = {**base, "name": "native-checks", "completed_at": "2026-07-22T19:00:02Z"}

        result = pr_merge_readiness.evaluate(pr, [failed, later_success], contract)

        self.assertEqual("blocked", result["status"])
        self.assertIn("required check is not successful: test|native-checks (test)", result["blockers"])

    def test_ready_when_required_check_succeeds_strictly_after_ready_event(self):
        contract = {
            "version": 1,
            "checks": [{
                "kind": "check_run",
                "name": "issue-first",
                "publisher": "github-actions",
                "workflow": "change-governance",
            }],
        }
        pr = {
            "state": "OPEN",
            "is_draft": False,
            "head_sha": "a" * 40,
            "ready_event": {"id": "ready-1", "created_at": "2026-07-22T19:00:00Z"},
        }
        checks = [{
            "kind": "check_run",
            "name": "issue-first",
            "publisher": "github-actions",
            "workflow": "change-governance",
            "status": "completed",
            "conclusion": "success",
            "head_sha": "a" * 40,
            "completed_at": "2026-07-22T19:00:01Z",
        }]

        result = pr_merge_readiness.evaluate(pr, checks, contract)

        self.assertEqual("ready", result["status"])
        self.assertEqual([], result["blockers"])

    def test_blocks_check_completed_at_ready_event_timestamp(self):
        contract = {"version": 1, "checks": [{"kind": "check_run", "name": "issue-first", "publisher": "github-actions", "workflow": "change-governance"}]}
        pr = {"state": "OPEN", "is_draft": False, "head_sha": "a" * 40, "ready_event": {"id": "ready-1", "created_at": "2026-07-22T19:00:00Z"}}
        checks = [{"kind": "check_run", "name": "issue-first", "publisher": "github-actions", "workflow": "change-governance", "status": "completed", "conclusion": "success", "head_sha": "a" * 40, "completed_at": "2026-07-22T19:00:00Z"}]

        result = pr_merge_readiness.evaluate(pr, checks, contract)

        self.assertEqual("blocked", result["status"])
        self.assertIn("required check did not complete after ready event: issue-first", result["blockers"])

    def test_blocks_draft_pull_request(self):
        contract = {"version": 1, "checks": [{"kind": "check_run", "name": "issue-first", "publisher": "github-actions", "workflow": "change-governance"}]}
        pr = {"state": "OPEN", "is_draft": True, "head_sha": "a" * 40, "ready_event": {"id": "ready-1", "created_at": "2026-07-22T19:00:00Z"}}
        checks = [{"kind": "check_run", "name": "issue-first", "publisher": "github-actions", "workflow": "change-governance", "status": "completed", "conclusion": "success", "head_sha": "a" * 40, "completed_at": "2026-07-22T19:00:01Z"}]

        result = pr_merge_readiness.evaluate(pr, checks, contract)

        self.assertEqual("blocked", result["status"])
        self.assertIn("PR is still a draft", result["blockers"])

    def test_blocks_pull_request_without_ready_event(self):
        contract = {"version": 1, "checks": [{"kind": "check_run", "name": "issue-first", "publisher": "github-actions", "workflow": "change-governance"}]}
        pr = {"state": "OPEN", "is_draft": False, "head_sha": "a" * 40}
        checks = [{"kind": "check_run", "name": "issue-first", "publisher": "github-actions", "workflow": "change-governance", "status": "completed", "conclusion": "success", "head_sha": "a" * 40, "completed_at": "2026-07-22T19:00:01Z"}]

        result = pr_merge_readiness.evaluate(pr, checks, contract)

        self.assertEqual("blocked", result["status"])
        self.assertIn("latest ReadyForReviewEvent is missing", result["blockers"])

    def test_blocks_when_final_snapshot_changes_ready_event(self):
        initial = {"state": "OPEN", "is_draft": False, "head_sha": "a" * 40, "ready_event": {"id": "ready-1", "created_at": "2026-07-22T19:00:00Z"}}
        final = {"state": "OPEN", "is_draft": False, "head_sha": "a" * 40, "ready_event": {"id": "ready-2", "created_at": "2026-07-22T19:01:00Z"}}
        contract = {"version": 1, "checks": []}

        result = pr_merge_readiness.evaluate_snapshots(initial, final, [], contract)

        self.assertEqual("blocked", result["status"])
        self.assertIn("PR ready-event changed during verification", result["blockers"])

    def test_blocks_ambiguous_latest_retry(self):
        contract = {"version": 1, "checks": [{"kind": "check_run", "name": "issue-first", "publisher": "github-actions", "workflow": "change-governance"}]}
        pr = {"state": "OPEN", "is_draft": False, "head_sha": "a" * 40, "ready_event": {"id": "ready-1", "created_at": "2026-07-22T19:00:00Z"}}
        checks = [
            {"kind": "check_run", "name": "issue-first", "publisher": "github-actions", "workflow": "change-governance", "status": "completed", "conclusion": "success", "head_sha": "a" * 40, "completed_at": "2026-07-22T19:00:01Z"},
            {"kind": "check_run", "name": "issue-first", "publisher": "github-actions", "workflow": "change-governance", "status": "completed", "conclusion": "success", "head_sha": "a" * 40, "completed_at": "2026-07-22T19:00:01Z"},
        ]

        result = pr_merge_readiness.evaluate(pr, checks, contract)

        self.assertEqual("blocked", result["status"])
        self.assertIn("required check has ambiguous latest retry: issue-first", result["blockers"])

    def test_allows_a_later_successful_retry_from_the_same_trusted_workflow(self):
        contract = {"version": 1, "checks": [{"kind": "check_run", "name": "issue-first", "publisher": "github-actions", "workflow": "change-governance"}]}
        pr = {"state": "OPEN", "is_draft": False, "head_sha": "a" * 40, "ready_event": {"id": "ready-1", "created_at": "2026-07-22T19:00:00Z"}}
        failed = {"kind": "check_run", "name": "issue-first", "publisher": "github-actions", "workflow": "change-governance", "status": "completed", "conclusion": "failure", "head_sha": "a" * 40, "completed_at": "2026-07-22T19:00:01Z"}
        succeeded = {**failed, "conclusion": "success", "completed_at": "2026-07-22T19:00:02Z"}

        result = pr_merge_readiness.evaluate(pr, [failed, succeeded], contract)

        self.assertEqual("ready", result["status"])

    def test_reads_workflow_identity_from_actions_run_url(self):
        with patch.object(pr_merge_readiness, "_gh", return_value={"path": ".github/workflows/ci.yml", "head_sha": "a" * 40, "event": "pull_request"}) as gh:
            workflow = pr_merge_readiness._workflow_identity_from_url(
                "acAI-to/acai-harness",
                "https://github.com/acAI-to/acai-harness/actions/runs/12345/job/67890",
                "a" * 40,
                "main",
                {},
            )

        self.assertEqual(
            {"workflow": ".github/workflows/ci.yml", "workflow_event": "pull_request", "workflow_ref": "head", "workflow_status": None, "workflow_conclusion": None},
            workflow,
        )
        gh.assert_called_once_with("api", "repos/acAI-to/acai-harness/actions/runs/12345")

    def test_preserves_workflow_dispatch_relay_identity(self):
        relay = {"path": ".github/workflows/independent-review-gate-b-relay.yml@main", "head_sha": "b" * 40, "head_branch": "main", "event": "workflow_dispatch", "status": "completed", "conclusion": "success"}
        with patch.object(pr_merge_readiness, "_gh", return_value=relay):
            identity = pr_merge_readiness._workflow_identity_from_url("acAI-to/acai-harness", "https://github.com/acAI-to/acai-harness/actions/runs/12345", "a" * 40, "main", {})

        self.assertEqual(
            {"workflow": ".github/workflows/independent-review-gate-b-relay.yml", "workflow_event": "workflow_dispatch", "workflow_ref": "default_branch", "workflow_status": "completed", "workflow_conclusion": "success"},
            identity,
        )

    def test_rejects_workflow_dispatch_relay_from_pr_ref(self):
        relay = {"path": ".github/workflows/independent-review-gate-b-relay.yml@feature", "head_sha": "a" * 40, "head_branch": "feature", "event": "workflow_dispatch", "status": "completed", "conclusion": "success"}
        with patch.object(pr_merge_readiness, "_gh", return_value=relay):
            identity = pr_merge_readiness._workflow_identity_from_url("acAI-to/acai-harness", "https://github.com/acAI-to/acai-harness/actions/runs/12345", "a" * 40, "main", {})

        self.assertIsNone(identity)

    def test_rejects_incomplete_check_run_pagination(self):
        with patch.object(pr_merge_readiness, "_gh", side_effect=[
            {"state": "OPEN", "isDraft": False, "headRefOid": "a" * 40},
            {"data": {"repository": {"pullRequest": {"timelineItems": {"nodes": []}}}}},
            {"default_branch": "main"},
            {"total_count": 101, "check_runs": [{}] * 100},
        ]):
            with self.assertRaisesRegex(ValueError, "check-run pagination is incomplete"):
                pr_merge_readiness.collect_live_evidence("acAI-to/acai-harness", 255)

    def test_rejects_incomplete_commit_status_pagination(self):
        with patch.object(pr_merge_readiness, "_gh", side_effect=[
            {"state": "OPEN", "isDraft": False, "headRefOid": "a" * 40},
            {"data": {"repository": {"pullRequest": {"timelineItems": {"nodes": []}}}}},
            {"default_branch": "main"},
            {"total_count": 0, "check_runs": []},
            {"total_count": 1, "statuses": []},
        ]):
            with self.assertRaisesRegex(ValueError, "commit-status pagination is incomplete"):
                pr_merge_readiness.collect_live_evidence("acAI-to/acai-harness", 255)

    def test_main_reports_github_query_failure_as_json_blocker(self):
        output = io.StringIO()
        with patch.object(pr_merge_readiness, "collect_live_evidence", side_effect=ValueError("GitHub query failed")), patch.object(sys, "argv", ["pr_merge_readiness.py", "--repo", "acAI-to/acai-harness", "--pr", "255"]), redirect_stdout(output):
            exit_code = pr_merge_readiness.main()

        self.assertEqual(1, exit_code)
        self.assertIn("readiness evidence is invalid: GitHub query failed", output.getvalue())

    def test_blocks_stale_unsuccessful_untrusted_and_malformed_checks(self):
        contract = {"version": 1, "checks": [{"kind": "check_run", "name": "issue-first", "publisher": "github-actions", "workflow": "change-governance"}]}
        pr = {"state": "OPEN", "is_draft": False, "head_sha": "a" * 40, "ready_event": {"id": "ready-1", "created_at": "2026-07-22T19:00:00Z"}}
        cases = {
            "stale": ({"completed_at": "2026-07-22T18:59:59Z"}, "required check did not complete after ready event: issue-first"),
            "failed": ({"conclusion": "failure"}, "required check is not successful: issue-first"),
            "cancelled": ({"conclusion": "cancelled"}, "required check is not successful: issue-first"),
            "non_terminal": ({"status": "in_progress", "conclusion": None}, "required check is not successful: issue-first"),
            "malformed": ({"completed_at": "not-a-timestamp"}, "required check has an invalid completion timestamp: issue-first"),
            "untrusted": ({"publisher": "untrusted"}, "required check has unexpected provenance: issue-first"),
        }
        base = {"kind": "check_run", "name": "issue-first", "publisher": "github-actions", "workflow": "change-governance", "status": "completed", "conclusion": "success", "head_sha": "a" * 40, "completed_at": "2026-07-22T19:00:01Z"}

        for case, (override, blocker) in cases.items():
            with self.subTest(case=case):
                result = pr_merge_readiness.evaluate(pr, [{**base, **override}], contract)
                self.assertEqual("blocked", result["status"])
                self.assertIn(blocker, result["blockers"])

    def test_blocks_head_or_draft_snapshot_race(self):
        initial = {"state": "OPEN", "is_draft": False, "head_sha": "a" * 40, "ready_event": {"id": "ready-1", "created_at": "2026-07-22T19:00:00Z"}}

        changed_head = pr_merge_readiness.evaluate_snapshots(initial, {**initial, "head_sha": "b" * 40}, [], {"version": 1, "checks": []})
        changed_draft = pr_merge_readiness.evaluate_snapshots(initial, {**initial, "is_draft": True}, [], {"version": 1, "checks": []})

        self.assertIn("PR head changed during verification", changed_head["blockers"])
        self.assertIn("PR draft state changed during verification", changed_draft["blockers"])

    def test_blocks_closed_pull_request(self):
        pr = {"state": "CLOSED", "is_draft": False, "head_sha": "a" * 40, "ready_event": {"id": "ready-1", "created_at": "2026-07-22T19:00:00Z"}}

        result = pr_merge_readiness.evaluate(pr, [], {"version": 1, "checks": []})

        self.assertEqual("blocked", result["status"])
        self.assertIn("PR is not open", result["blockers"])

    def test_blocks_conflicting_same_name_provenance(self):
        contract = {"version": 1, "checks": [{"kind": "commit_status", "name": "governance/gate-b", "publisher": None, "workflow": "relay", "workflow_event": "workflow_dispatch", "workflow_status": "completed", "workflow_conclusion": "success"}]}
        pr = {"state": "OPEN", "is_draft": False, "head_sha": "a" * 40, "ready_event": {"id": "ready-1", "created_at": "2026-07-22T19:00:00Z"}}
        good = {"kind": "commit_status", "name": "governance/gate-b", "publisher": None, "workflow": "relay", "workflow_event": "workflow_dispatch", "workflow_status": "completed", "workflow_conclusion": "success", "status": "completed", "conclusion": "success", "head_sha": "a" * 40, "completed_at": "2026-07-22T19:00:01Z"}
        collision = {**good, "workflow": "governance-gate"}

        result = pr_merge_readiness.evaluate(pr, [good, collision], contract)

        self.assertEqual("blocked", result["status"])
        self.assertIn("required check has unexpected provenance: governance/gate-b", result["blockers"])

    def test_uses_contract_terminal_conclusion(self):
        contract = {"version": 1, "checks": [{"kind": "check_run", "name": "issue-first", "publisher": "github-actions", "workflow": "change-governance", "conclusion": "neutral"}]}
        pr = {"state": "OPEN", "is_draft": False, "head_sha": "a" * 40, "ready_event": {"id": "ready-1", "created_at": "2026-07-22T19:00:00Z"}}
        check = {"kind": "check_run", "name": "issue-first", "publisher": "github-actions", "workflow": "change-governance", "status": "completed", "conclusion": "neutral", "head_sha": "a" * 40, "completed_at": "2026-07-22T19:00:01Z"}

        result = pr_merge_readiness.evaluate(pr, [check], contract)

        self.assertEqual("ready", result["status"])


if __name__ == "__main__":
    unittest.main()
