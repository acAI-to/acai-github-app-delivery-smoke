#!/usr/bin/env python3
"""Canonical issue-plan digest and operator label-attestation validation."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlparse

APPROVAL_LABEL = "acai-plan-approved"
ATTESTATION_MARKER = "<!-- ACAI-PLAN-APPROVAL -->"
PLAN_REVIEW_MARKER = "<!-- ACAI-INDEPENDENT-PLAN-REVIEW -->"
# Operator approval fixes the outcome and acceptance criteria. Execution-plan
# refinement belongs to the agents and must not churn the operator label.
MATERIAL_HEADINGS = ("Goal", "Fixed rubric", "Non-goals")
LEGACY_MATERIAL_HEADINGS = ("Goal", "Plan", "Fixed rubric", "Non-goals")
PLAN_REVIEW_MATERIAL_HEADINGS = (
    "Goal", "Plan", "Fixed rubric", "Non-goals", "Tier + justification", "Governance metadata"
)
ISSUE_FORM_FIELD_RE = re.compile(
    r"(?ims)^\s*###\s*(Tier|Changed paths|Justification|Repository kind|Change class|Risk tags|Validation profile|GitHub status|Adversarial profile|Action phase|Merge effect|Parent issue|Parent rubric digest|No live mutation)\s*$\n+(.*?)(?=^\s*###\s|\Z)"
)
BOT_LOGINS = {"github-actions[bot]", "github-actions"}
RUN_URL_RE = re.compile(r"^https://github\.com/([^/]+/[^/]+)/actions/runs/(\d+)$")


def _line(body: str, name: str) -> str:
    match = re.search(rf"(?im)^{re.escape(name)}:\s*(.+?)\s*$", body)
    return match.group(1).strip() if match else ""


def canonical_sections(body: str, headings: tuple[str, ...]) -> str:
    normalized = str(body or "").replace("\r\n", "\n").replace("\r", "\n")
    sections: list[str] = []
    for heading in headings:
        match = re.search(
            rf"(?ms)^## {re.escape(heading)}\s*\n(.*?)(?=^## |\Z)",
            normalized,
        )
        if not match or not match.group(1).strip():
            raise ValueError(f"missing material section: ## {heading}")
        content = "\n".join(line.rstrip() for line in match.group(1).strip().splitlines())
        sections.append(f"## {heading}\n{content}")
    return "\n\n".join(sections) + "\n"


def canonical_material(body: str) -> str:
    return canonical_sections(body, MATERIAL_HEADINGS)


def material_digest(body: str) -> str:
    return hashlib.sha256(canonical_material(body).encode("utf-8")).hexdigest()


def legacy_material_digest(body: str) -> str:
    """Validate version-1 attestations without forcing existing issues to relabel."""
    return hashlib.sha256(canonical_sections(body, LEGACY_MATERIAL_HEADINGS).encode("utf-8")).hexdigest()


def canonical_plan_review_material(body: str) -> str:
    """Return all plan-review material, normalizing GitHub Issue Forms."""
    fields = {
        match.group(1).strip().lower(): match.group(2).strip()
        for match in ISSUE_FORM_FIELD_RE.finditer(str(body or ""))
    }
    try:
        canonical = canonical_sections(body, PLAN_REVIEW_MATERIAL_HEADINGS)
        if fields and any("<" in line and ">" in line for line in canonical.splitlines()):
            raise ValueError("issue-form placeholders cannot satisfy plan-review material")
        return canonical
    except ValueError:
        required = {
            "tier", "changed paths", "justification", "repository kind",
            "change class", "risk tags", "validation profile", "github status",
            "adversarial profile", "action phase", "merge effect",
        }
        if not fields or any(
            not fields.get(key) or (fields[key].startswith("<") and fields[key].endswith(">"))
            for key in required
        ):
            raise
        metadata = "\n".join(
            f"{label}: {fields[key]}"
            for key, label in (
                ("repository kind", "Repository kind"),
                ("change class", "Change class"),
                ("risk tags", "Risk tags"),
                ("validation profile", "Validation profile"),
                ("github status", "GitHub status"),
                ("adversarial profile", "Adversarial profile"),
                ("action phase", "Action phase"),
                ("merge effect", "Merge effect"),
            )
        )
        return (
            canonical_material(body)
            + "## Tier + justification\n"
            + f"Tier: {fields['tier']}\nChanged paths: {fields['changed paths']}\nJustification: {fields['justification']}\n\n"
            + "## Governance metadata\n"
            + metadata
            + "\n"
        )


def plan_review_digest(body: str) -> str:
    return hashlib.sha256(canonical_plan_review_material(body).encode("utf-8")).hexdigest()


def label_names(issue: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for raw in issue.get("labels") or []:
        name = raw.get("name") if isinstance(raw, dict) else raw
        if str(name or "").strip():
            names.add(str(name).strip())
    return names


def latest_attestation(comments: list[dict[str, Any]]) -> dict[str, Any] | None:
    marked = [
        comment
        for comment in comments
        if isinstance(comment, dict) and ATTESTATION_MARKER in str(comment.get("body", ""))
    ]
    return max(
        marked,
        key=lambda item: str(item.get("updated_at") or item.get("created_at") or ""),
        default=None,
    )


def latest_plan_review(comments: list[dict[str, Any]]) -> dict[str, Any] | None:
    marked = [
        (position, comment)
        for position, comment in enumerate(comments)
        if isinstance(comment, dict) and PLAN_REVIEW_MARKER in str(comment.get("body", ""))
    ]
    def newest_key(item: tuple[int, dict[str, Any]]) -> tuple[str, int, int]:
        position, comment = item
        raw_id = comment.get("id")
        numeric_id = raw_id if isinstance(raw_id, int) and not isinstance(raw_id, bool) else -1
        return str(comment.get("updated_at") or comment.get("created_at") or ""), numeric_id, position

    selected = max(marked, key=newest_key, default=None)
    return selected[1] if selected else None


def parse_attestation(comment: dict[str, Any] | None) -> tuple[dict[str, str], list[str]]:
    if not comment:
        return {}, ["missing GitHub Actions plan-approval attestation"]
    reasons: list[str] = []
    body = str(comment.get("body", ""))
    author = str((comment.get("user") or {}).get("login", ""))
    if author not in BOT_LOGINS:
        reasons.append("plan-approval attestation must be authored by GitHub Actions")
    if ATTESTATION_MARKER not in body:
        reasons.append("plan-approval attestation marker is missing")
    fields = {
        name: _line(body, name)
        for name in (
            "Version", "Repository", "Issue", "Actor", "Label", "Digest-SHA256",
            "Event-Digest-SHA256", "Approved-At", "Source-Event", "Source-URL", "Current-Label",
        )
    }
    if any(not value for value in fields.values()):
        reasons.append("plan-approval attestation fields are incomplete")
    return fields, reasons


def validate_plan_review(
    *, repository: str, issue: dict[str, Any], comment: dict[str, Any] | None, allowlist: set[str],
    independent_allowlist: set[str] | None = None,
) -> list[str]:
    """Validate model-agnostic independent plan-review evidence."""
    if not comment:
        return ["missing independent plan-review artifact"]
    reasons: list[str] = []
    body = str(comment.get("body", ""))
    author = str((comment.get("user") or {}).get("login", ""))
    adversarial_profile = _line(str(issue.get("body", "")), "Adversarial profile")
    trusted_authors = independent_allowlist or allowlist
    if author not in trusted_authors:
        reasons.append("plan-review author is not allowlisted")
    if PLAN_REVIEW_MARKER not in body or "INDEPENDENT_PLAN_APPROVED" not in body:
        reasons.append("plan-review marker or approval verdict is missing")
    if adversarial_profile != "independent-review":
        reasons.append("plan review requires Adversarial profile: independent-review")
    fields = {name: _line(body, name) for name in ("Repository", "Issue", "Purpose", "Digest-SHA256", "Reviewer", "Session", "Verdict")}
    if any(not value for value in fields.values()):
        reasons.append("plan-review artifact fields are incomplete")
        return list(dict.fromkeys(reasons))
    if fields["Repository"] != repository or fields["Issue"] != f"#{issue.get('number')}":
        reasons.append("plan-review repository/issue does not match")
    if fields["Purpose"] != "plan-review":
        reasons.append("plan-review purpose must be plan-review")
    expected_reviewer = "independent-review"
    if fields["Reviewer"] != expected_reviewer:
        reasons.append(f"plan-review reviewer must be {expected_reviewer}")
    if _line(body, "Contract-Version") != "3":
        reasons.append("independent plan-review contract version is missing or stale")
    expected = plan_review_digest(str(issue.get("body", "")))
    if not re.fullmatch(r"[0-9a-f]{64}", fields["Digest-SHA256"]) or fields["Digest-SHA256"] != expected:
        reasons.append("plan-review digest is stale or malformed")
    if fields["Verdict"] != "PASS":
        reasons.append("plan-review verdict must be PASS")
    if not str(comment.get("html_url", "")).startswith(f"https://github.com/{repository}/issues/{issue.get('number')}#issuecomment-"):
        reasons.append("plan-review artifact is not on the governed issue")
    return list(dict.fromkeys(reasons))


def _timestamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else None
    except ValueError:
        return None


def validate_source_run(
    source_url: str,
    repository: str,
    actor: str,
    approved_at: str,
    workflow_names: set[str] | None = None,
) -> list[str]:
    match = RUN_URL_RE.fullmatch(source_url)
    if not match or match.group(1) != repository:
        return ["source URL must be a same-repository GitHub Actions run"]
    proc = subprocess.run(
        ["gh", "api", f"repos/{repository}/actions/runs/{match.group(2)}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return ["source GitHub Actions run is unavailable"]
    try:
        run = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return ["source GitHub Actions run returned malformed JSON"]
    reasons: list[str] = []
    if run.get("event") != "issues" or run.get("conclusion") != "success":
        reasons.append("source run must be a successful issues event")
    allowed_workflows = workflow_names or {".github/workflows/plan-approval.yml"}
    workflow_path = str(run.get("path", "")).split("@", 1)[0]
    if run.get("html_url") != source_url or workflow_path not in allowed_workflows:
        reasons.append("source run URL/workflow does not match plan-approval")
    if actor and str((run.get("triggering_actor") or {}).get("login", "")) != actor:
        reasons.append("source run triggering actor does not match attestation actor")
    created = _timestamp(str(run.get("created_at", "")))
    approved = _timestamp(approved_at)
    if not created or not approved or abs((approved - created).total_seconds()) > 900:
        reasons.append("source run time is not bound to the approval event")
    return reasons


def latest_label_event(timeline: list[dict[str, Any]]) -> dict[str, Any] | None:
    matching = [
        event for event in timeline
        if isinstance(event, dict)
        and event.get("event") in {"labeled", "unlabeled"}
        and str((event.get("label") or {}).get("name", "")) == APPROVAL_LABEL
    ]
    return max(matching, key=lambda event: str(event.get("created_at", "")), default=None)


def v1_migration_attestation(
    *, repository: str, issue: dict[str, Any], comments: list[dict[str, Any]],
    timeline: list[dict[str, Any]], allowlist: set[str], previous_body: str,
) -> tuple[dict[str, str] | None, list[str]]:
    """Safely promote a v1 approval after a mutable-only issue edit.

    GitHub's issue-edited event includes the previous body.  That lets the
    trusted workflow prove both that the old v1 digest was valid before the
    edit and that the current immutable v2 material is unchanged.
    """
    comment = latest_attestation(comments)
    fields, reasons = parse_attestation(comment)
    if not fields:
        return None, reasons
    if fields.get("Version") != "1":
        return None, reasons + ["latest attestation is not version 1"]
    if fields.get("Repository") != repository or fields.get("Issue") != f"#{issue.get('number')}":
        return None, reasons + ["v1 attestation repository/issue does not match"]
    event = latest_label_event(timeline)
    if fields.get("Actor") not in allowlist:
        reasons.append("v1 attestation actor is not allowlisted")
    if not event or event.get("event") != "labeled":
        reasons.append("latest approval-label event is not labeled")
    elif str((event.get("actor") or {}).get("login", "")) != fields.get("Actor"):
        reasons.append("v1 attestation actor does not match the current label event")
    else:
        event_time = _timestamp(str(event.get("created_at", "")))
        comment_time = _timestamp(str((comment or {}).get("created_at", "")))
        approved_time = _timestamp(fields.get("Approved-At", ""))
        if not event_time or not comment_time or not approved_time:
            reasons.append("v1 attestation or current label event timestamp is invalid")
        elif comment_time < event_time or approved_time < event_time:
            reasons.append("v1 attestation is not bound to the current label application event")
    try:
        if fields.get("Digest-SHA256") != legacy_material_digest(previous_body):
            reasons.append("v1 attestation does not bind the pre-edit material")
        if material_digest(previous_body) != material_digest(str(issue.get("body", ""))):
            reasons.append("issue edit changed Goal, Fixed rubric, or Non-goals")
    except ValueError as exc:
        reasons.append(str(exc))
    return (fields if not reasons else None), reasons


def validate_approval(
    *,
    repository: str,
    issue: dict[str, Any],
    comments: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
    allowlist: set[str],
    source_run_validator: Callable[[str, str, str, str], list[str]] | None = None,
) -> list[str]:
    reasons: list[str] = []
    number = issue.get("number")
    if APPROVAL_LABEL not in label_names(issue):
        reasons.append(f"issue does not currently carry {APPROVAL_LABEL}")
    try:
        digest = material_digest(str(issue.get("body", "")))
    except ValueError as exc:
        reasons.append(str(exc))
        digest = ""
    comment = latest_attestation(comments)
    label_event = latest_label_event(timeline)
    fields, parse_reasons = parse_attestation(comment)
    reasons.extend(parse_reasons)
    if fields:
        version = fields["Version"]
        if version not in {"1", "2"}:
            reasons.append("attestation version must be 1 or 2")
        if fields["Repository"] != repository or fields["Issue"] != f"#{number}":
            reasons.append("attestation repository/issue does not match")
        if fields["Actor"] not in allowlist:
            reasons.append("attested label-event actor is not an allowlisted human operator")
        event_actor = str((label_event or {}).get("actor", {}).get("login", ""))
        event_time = _timestamp(str((label_event or {}).get("created_at", "")))
        comment_time = _timestamp(str((comment or {}).get("created_at", "")))
        if not label_event or label_event.get("event") != "labeled":
            reasons.append("latest approval-label timeline event must be labeled")
        elif event_actor != fields["Actor"] or not event_time or not comment_time or comment_time < event_time:
            reasons.append("attestation is not bound to the current label application event")
        if fields["Label"] != APPROVAL_LABEL or fields["Current-Label"] != "present":
            reasons.append("attestation label/current-label fields do not match")
        expected_digest = legacy_material_digest(str(issue.get("body", ""))) if version == "1" else digest
        if not re.fullmatch(r"[0-9a-f]{64}", fields["Digest-SHA256"] or "") or fields["Digest-SHA256"] != expected_digest:
            reasons.append("attested material digest is stale or malformed")
        if fields["Event-Digest-SHA256"] != fields["Digest-SHA256"]:
            reasons.append("attested material was not bound to the label-event issue body")
        try:
            approved_at = datetime.fromisoformat(fields["Approved-At"].replace("Z", "+00:00"))
            if approved_at.tzinfo is None or approved_at > datetime.now(timezone.utc):
                reasons.append("attestation timestamp is invalid")
        except ValueError:
            reasons.append("attestation timestamp is not ISO-8601")
        source_event = fields["Source-Event"]
        if source_event not in {"issues:labeled", "issues:edited-migration"}:
            reasons.append("attestation source event must be issues:labeled or issues:edited-migration")
        validator = source_run_validator or validate_source_run
        reasons.extend(
            validator(
                fields["Source-URL"], repository,
                "" if source_event == "issues:edited-migration" else fields["Actor"],
                fields["Approved-At"],
            )
        )
        html_url = str((comment or {}).get("html_url", ""))
        if not html_url.startswith(f"https://github.com/{repository}/issues/{number}#issuecomment-"):
            reasons.append("attestation comment is not on the governed issue")
    return list(dict.fromkeys(reasons))



def valid_scope(value: str) -> bool:
    scope = str(value or "").strip().lower()
    return len(scope) >= 5 and scope not in {"all", "everything", "any", "global", "entire repo", "whole repo"} and "*" not in scope


def main() -> int:
    payload = json.load(sys.stdin)
    reasons = validate_approval(
        repository=payload["repository"],
        issue=payload["issue"],
        comments=payload["comments"],
        timeline=payload["timeline"],
        allowlist=set(payload.get("operator_logins", [])),
    )
    if reasons:
        print("; ".join(reasons))
        return 1
    print("plan approval valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
