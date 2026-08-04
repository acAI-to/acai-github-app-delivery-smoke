#!/usr/bin/env python3
"""Authenticated API collector for cross-repository governance propagation.

It never reads a source checkout or executes a target PR. All pagination uses
the portable ``gh api --paginate`` stream; an API error or malformed page is a
hard failure rather than a best-effort eligibility decision.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
import sys
from typing import Any

from governance_release import MANIFEST_PATH, MARKER, parse
from governance_propagation_contract import body_digest, validate_pr_body


GOVERNED_ISSUE = re.compile(r"(?im)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?|issue)\s*:?[ \t]+#([1-9][0-9]*)\b")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def closure_digest(closure: dict[str, dict[str, str]]) -> str:
    return hashlib.sha256(_canonical(closure).encode()).hexdigest()


def transition_digest(old: dict[str, dict[str, str]], new: dict[str, dict[str, str]]) -> str:
    return hashlib.sha256(_canonical({"old": old, "new": new}).encode()).hexdigest()


def closure_from_manifest(manifest: dict[str, Any]) -> dict[str, dict[str, str]]:
    entries = manifest.get("files") if isinstance(manifest, dict) else None
    closure: dict[str, dict[str, str]] = {}
    if not isinstance(entries, list) or not entries:
        raise RuntimeError("attested manifest closure is malformed")
    for entry in entries:
        if not isinstance(entry, dict):
            raise RuntimeError("attested manifest closure is malformed")
        path, mode, digest = entry.get("path"), entry.get("mode"), entry.get("sha256")
        if not isinstance(path, str) or not path or path in closure or not re.fullmatch(r"100(?:644|755)", str(mode)) or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise RuntimeError("attested manifest closure is malformed")
        closure[path] = {"mode": str(mode), "sha256": digest}
    return closure


def historical_variant_reference(manifest: dict[str, Any], carrier: str) -> tuple[str, list[dict[str, str]]]:
    settings = manifest.get("settings") if isinstance(manifest, dict) else None
    migration = settings.get("v3_migration") if isinstance(settings, dict) else None
    histories = migration.get("historical_manifests") if isinstance(migration, dict) else None
    if not isinstance(histories, list) or not histories:
        raise RuntimeError("target base version-3 carrier provenance is stale or ambiguous")
    matches = []
    seen: set[str] = set()
    for item in histories:
        if not isinstance(item, dict) or set(item) not in (
            {"source_commit", "manifest_sha256"},
            {"source_commit", "manifest_sha256", "variants"},
        ):
            raise RuntimeError("target base version-3 carrier provenance is stale or ambiguous")
        item_carrier, digest = item.get("source_commit"), item.get("manifest_sha256")
        variants = item.get("variants", [])
        if (
            not isinstance(item_carrier, str) or not re.fullmatch(r"[0-9a-f]{40}", item_carrier)
            or item_carrier in seen or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or not isinstance(variants, list) or ("variants" in item and not variants)
        ):
            raise RuntimeError("target base version-3 carrier provenance is stale or ambiguous")
        seen.add(item_carrier)
        if item_carrier == carrier:
            matches.append((digest, variants))
    if len(matches) != 1:
        raise RuntimeError("target base version-3 carrier provenance is stale or ambiguous")
    return matches[0]


def complete_historical_closure(
    base: dict[str, dict[str, str]], variants: object, current: dict[str, dict[str, str]]
) -> dict[str, dict[str, str]]:
    if variants in (None, []):
        candidates = [base]
    elif not isinstance(variants, list):
        raise RuntimeError("historical closure variants are malformed")
    else:
        composed, seen = dict(base), set()
        for entry in variants:
            if not isinstance(entry, dict) or set(entry) != {"path", "mode", "sha256"}:
                raise RuntimeError("historical closure variants are malformed")
            path, mode, digest = entry.get("path"), entry.get("mode"), entry.get("sha256")
            if (
                not isinstance(path, str) or path not in base or path in seen
                or not isinstance(mode, str) or not re.fullmatch(r"100(?:644|755)", mode)
                or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or base[path] == {"mode": mode, "sha256": digest}
            ):
                raise RuntimeError("historical closure variants are malformed")
            seen.add(path)
            composed[path] = {"mode": mode, "sha256": digest}
        candidates = [base, composed]
    matched = [candidate for candidate in candidates if current == candidate]
    if len(matched) != 1:
        raise RuntimeError("target base does not match the prior attested closure")
    return matched[0]


def _run(*args: str) -> Any:
    process = subprocess.run(["gh", "api", *args], text=True, capture_output=True, check=False)
    if process.returncode:
        raise RuntimeError("GitHub API unavailable: " + " ".join(args))
    try:
        return json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("GitHub API returned malformed JSON: " + " ".join(args)) from exc


def one(path: str) -> Any:
    return _run(path)


def pages(path: str) -> list[Any]:
    process = subprocess.run(["gh", "api", "--paginate", path], text=True, capture_output=True, check=False)
    if process.returncode:
        raise RuntimeError("GitHub API unavailable: --paginate " + path)
    decoder, offset, raw, result = json.JSONDecoder(), 0, process.stdout, []
    try:
        while raw[offset:].strip():
            while offset < len(raw) and raw[offset].isspace():
                offset += 1
            page, offset = decoder.raw_decode(raw, offset)
            if not isinstance(page, list):
                raise ValueError("page is not an array")
            result.extend(page)
    except (ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("GitHub API pagination is incomplete or malformed: " + path) from exc
    return result


def content_bytes(repo: str, path: str, ref: str) -> bytes:
    value = one(f"repos/{repo}/contents/{path}?ref={ref}")
    if not isinstance(value, dict) or value.get("type") != "file" or not isinstance(value.get("content"), str):
        raise RuntimeError("commit-pinned file is unavailable or not a regular file: " + path)
    try:
        return base64.b64decode(value["content"].replace("\n", ""), validate=True)
    except ValueError as exc:
        raise RuntimeError("commit-pinned file has invalid base64: " + path) from exc


def latest_release(comments: list[dict[str, Any]], source_pr_number: int) -> dict[str, Any]:
    """Return the one unedited bot attestation bound to the requested source PR."""
    candidates = []
    for item in comments:
        if not isinstance(item, dict) or MARKER not in str(item.get("body", "")):
            continue
        payload, reasons = parse(str(item.get("body", "")))
        if reasons or not isinstance(payload, dict) or payload.get("pr") != source_pr_number:
            continue
        candidates.append(item)
    if not candidates:
        raise RuntimeError("source-PR-bound release attestation is missing or paginated-incomplete")
    latest_at = max(str(item.get("created_at", "")) for item in candidates)
    selected = [item for item in candidates if str(item.get("created_at", "")) == latest_at]
    if len(selected) != 1 or not latest_at:
        raise RuntimeError("source-PR-bound release attestation is conflicting or timestamp-ambiguous")
    candidate = selected[0]
    if candidate.get("created_at") != candidate.get("updated_at", candidate.get("created_at")):
        raise RuntimeError("release attestation has been edited")
    if str((candidate.get("user") or {}).get("login", "")) not in {"github-actions", "github-actions[bot]"}:
        raise RuntimeError("release attestation issuer is not GitHub Actions")
    payload, reasons = parse(str(candidate.get("body", "")))
    if reasons or not payload:
        raise RuntimeError("release attestation schema is malformed")
    return candidate


def governed_issue_number(source_pr: dict[str, Any]) -> int:
    """Return the one source issue whose approval/release chain binds this PR."""
    matches = GOVERNED_ISSUE.findall(str(source_pr.get("body", "")))
    if len(matches) != 1:
        raise RuntimeError("source PR must identify exactly one governed issue")
    return int(matches[0])


def tree_details(repo: str, sha: str, paths: list[str], statuses: dict[str, str]) -> list[dict[str, Any]]:
    tree = one(f"repos/{repo}/git/trees/{sha}?recursive=1")
    entries = tree.get("tree") if isinstance(tree, dict) else None
    if not isinstance(entries, list) or tree.get("truncated") is True:
        raise RuntimeError("commit tree is unavailable or truncated")
    index = {str(item.get("path")): item for item in entries if isinstance(item, dict)}
    details: list[dict[str, Any]] = []
    for path in sorted(paths):
        item = index.get(path)
        if not isinstance(item, dict):
            details.append({"path": path, "status": statuses.get(path, "D"), "deleted": True})
            continue
        raw = content_bytes(repo, path, sha) if item.get("type") == "blob" else b""
        details.append({"path": path, "status": statuses.get(path, "M"), "deleted": False, "mode": item.get("mode"), "type": item.get("type"), "sha256": hashlib.sha256(raw).hexdigest()})
    return details


def validate_first_install_base_tree(
    entries: Any, new_paths: set[str], *, truncated: Any,
) -> list[dict[str, str]]:
    """Return canonical exact-base evidence only for a clean first install."""
    error = "first install requires a complete clean exact base"
    if truncated is not False or not isinstance(entries, list):
        raise RuntimeError(error)
    canonical_entries: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in entries:
        if not isinstance(item, dict):
            raise RuntimeError(error)
        path, mode, kind, sha = item.get("path"), item.get("mode"), item.get("type"), item.get("sha")
        if (
            not isinstance(path, str) or not path or path.startswith("/") or "\\" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or path in seen or not isinstance(mode, str)
            or not re.fullmatch(r"(?:040000|100644|100755|120000|160000)", mode)
            or kind not in {"blob", "tree", "commit"}
            or (kind == "tree" and mode != "040000")
            or (kind == "commit" and mode != "160000")
            or (kind == "blob" and mode not in {"100644", "100755", "120000"})
            or not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha)
        ):
            raise RuntimeError(error)
        seen.add(path)
        canonical_entries.append({"path": path, "mode": mode, "type": kind, "sha": sha})
    def governed(path: str) -> bool:
        name = path.rsplit("/", 1)[-1]
        return (
            path in new_paths
            or path.startswith((".acai/governance-", "governance/", ".github/actions/acai-hermetic-execution/", ".github/ISSUE_TEMPLATE/governed-change"))
            or (path.startswith(".github/workflows/") and any(token in name for token in ("governance", "plan-approval", "plan-review", "gate-b-relay")))
            or path == "bin/pr-merge-readiness"
            or (path.startswith("scripts/") and (name.startswith("governance_") or name in {"check_change_pr.py", "check_gate_b.py", "director_pr_lookup.sh", "plan_approval.py", "pr_merge_readiness.py", "tier_policy.py", "validation_profile.py"}))
            or (path.startswith("tests/") and (name.startswith("test_governance_") or name in {"test_pr_merge_readiness.py", "test_validation_profile.py"}))
        )
    if any(governed(path) for path in seen):
        raise RuntimeError(error)
    return canonical_entries


def _state_and_diff_digests(
    repo: str, *, head: str, base: str, manifest: dict[str, Any], manifest_carrier: str, prior_manifest: dict[str, Any] | None = None, prior_variants: object = None, first_install: bool = False
) -> tuple[str, str, str, dict[str, dict[str, str]], dict[str, dict[str, str]], bytes, bytes]:
    state_path = ".acai/governance-bootstrap.json"
    try:
        head_bytes = content_bytes(repo, state_path, head)
        head_state = json.loads(head_bytes)
        if first_install:
            base_bytes, base_state = b"", None
        else:
            base_bytes = content_bytes(repo, state_path, base)
            base_state = json.loads(base_bytes)
    except (RuntimeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("target bootstrap state is missing, malformed, or stale") from exc
    if (not first_install and not isinstance(base_state, dict)) or not isinstance(head_state, dict):
        raise RuntimeError("target bootstrap state is missing, malformed, or stale")
    if first_install and prior_manifest is not None:
        raise RuntimeError("first install has unexpected prior manifest evidence")
    if not first_install and not isinstance(prior_manifest, dict):
        raise RuntimeError("target prior attested manifest is unavailable")
    settings_digest = str(head_state.get("settings_owner", ""))
    old = {} if first_install else closure_from_manifest(prior_manifest)
    new = closure_from_manifest(manifest)
    state_paths = base_state.get("files") if isinstance(base_state, dict) else []
    if not first_install and (not isinstance(state_paths, list) or len(state_paths) != len(set(state_paths)) or set(state_paths) != set(old)):
        raise RuntimeError("target base bootstrap state does not bind the prior attested closure")
    manifest_paths = set(new)
    head_paths = head_state.get("files")
    if (
        not isinstance(head_paths, list)
        or len(head_paths) != len(set(head_paths))
        or not all(isinstance(path, str) and path for path in head_paths)
        or set(head_paths) != manifest_paths
        or head_state.get("source_commit") != manifest.get("source_commit")
        or head_state.get("manifest_source_commit") != manifest_carrier
    ):
        raise RuntimeError("target head bootstrap state does not bind the manifest closure")
    if not re.fullmatch(r"[0-9a-f]{64}", settings_digest):
        raise RuntimeError("target bootstrap settings digest is malformed")
    old_details = tree_details(repo, base, sorted(old), {path: "U" for path in old})
    actual_old = {item["path"]: {"mode": item.get("mode"), "sha256": item.get("sha256")} for item in old_details if item.get("deleted") is False and item.get("type") == "blob"}
    if not first_install:
        old = complete_historical_closure(old, prior_variants, actual_old)
    head_details = tree_details(repo, head, sorted(new), {path: "U" for path in new})
    actual_new = {item["path"]: {"mode": item.get("mode"), "sha256": item.get("sha256")} for item in head_details if item.get("deleted") is False and item.get("type") == "blob"}
    if actual_new != new:
        raise RuntimeError("target head does not match the source attested closure")
    return (
        hashlib.sha256(head_bytes).hexdigest(),
        transition_digest(old, new),
        settings_digest,
        old,
        new,
        base_bytes,
        head_bytes,
    )


def collect(source_repo: str, source_pr_number: int, target_repo: str, target_pr_number: int) -> dict[str, Any]:
    source_pr = one(f"repos/{source_repo}/pulls/{source_pr_number}")
    if not isinstance(source_pr, dict):
        raise RuntimeError("source PR is unavailable")
    issue_number = governed_issue_number(source_pr)
    issue = one(f"repos/{source_repo}/issues/{issue_number}")
    comments = pages(f"repos/{source_repo}/issues/{issue_number}/comments?per_page=100")
    timeline = pages(f"repos/{source_repo}/issues/{issue_number}/timeline?per_page=100")
    attestation = latest_release(comments, source_pr_number)
    release, _ = parse(str(attestation.get("body", "")))
    workflow = release.get("trusted_workflow") if isinstance(release, dict) else {}
    if not isinstance(workflow, dict) or not isinstance(workflow.get("run_id"), int):
        raise RuntimeError("release attestation has no trusted workflow identity")
    run = one(f"repos/{source_repo}/actions/runs/{workflow['run_id']}")
    merge = release.get("merge_commit") if isinstance(release, dict) else ""
    manifest_info = release.get("manifest") if isinstance(release, dict) else {}
    carrier = manifest_info.get("commit") if isinstance(manifest_info, dict) else ""
    default_branch = release.get("default_branch") if isinstance(release, dict) else ""
    if not isinstance(carrier, str) or not re.fullmatch(r"[0-9a-f]{40}", carrier):
        raise RuntimeError("release attestation has no manifest carrier commit")
    comparison = one(f"repos/{source_repo}/compare/{carrier}...{workflow.get('sha', '')}")
    contained = isinstance(comparison, dict) and comparison.get("status") in {"ahead", "identical"}
    associated = pages(f"repos/{source_repo}/commits/{carrier}/pulls?per_page=100")
    manifest_bytes = content_bytes(source_repo, MANIFEST_PATH, carrier)
    try:
        manifest = json.loads(manifest_bytes)
    except (ValueError, UnicodeDecodeError) as exc:
        raise RuntimeError("source manifest bytes are malformed") from exc
    asset_commit = manifest.get("source_commit") if isinstance(manifest, dict) else ""
    if not isinstance(asset_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", asset_commit):
        raise RuntimeError("source manifest asset commit is malformed")
    manifest_paths = [str(e.get("path")) for e in manifest.get("files", []) if isinstance(e, dict) and e.get("path")]
    source_tree = tree_details(source_repo, asset_commit, manifest_paths, {path: "M" for path in manifest_paths})
    target_pr = one(f"repos/{target_repo}/pulls/{target_pr_number}")
    target_head = ((target_pr.get("head") or {}).get("sha")) if isinstance(target_pr, dict) else ""
    target_base = ((target_pr.get("base") or {}).get("sha")) if isinstance(target_pr, dict) else ""
    body = str(target_pr.get("body", "")) if isinstance(target_pr, dict) else ""
    body_reasons = validate_pr_body(
        body,
        source_repository=source_repo,
        source_pr=source_pr_number,
        target_repository=target_repo,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        head_sha=str(target_head),
        base_sha=str(target_base),
    )
    if body_reasons:
        raise RuntimeError("; ".join(body_reasons))
    try:
        base_state_bytes = content_bytes(target_repo, ".acai/governance-bootstrap.json", str(target_base))
        base_state = json.loads(base_state_bytes)
        first_install = False
    except (RuntimeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        first_install = True
        base_state_bytes, base_state = b"", None
    if first_install:
        base_repository = one(f"repos/{target_repo}/git/trees/{target_base}?recursive=1")
        base_entries = base_repository.get("tree") if isinstance(base_repository, dict) else None
        base_truncated = base_repository.get("truncated") if isinstance(base_repository, dict) else None
        base_repository_tree = validate_first_install_base_tree(
            base_entries, set(manifest_paths), truncated=base_truncated,
        )
        prior_manifest_bytes, prior_manifest, prior_variants = b"", None, None
    else:
        base_repository_tree, base_truncated = [], False
        old_source_commit = base_state.get("source_commit") if isinstance(base_state, dict) else None
        old_manifest_carrier = (
            base_state.get("source_commit")
            if isinstance(base_state, dict) and base_state.get("manifest_version") == 3
            else base_state.get("manifest_source_commit") if isinstance(base_state, dict) else None
        )
        old_source_repository = base_state.get("source_repository", source_repo) if isinstance(base_state, dict) else source_repo
        if not isinstance(old_source_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", old_source_commit) or not isinstance(old_manifest_carrier, str) or not re.fullmatch(r"[0-9a-f]{40}", old_manifest_carrier) or old_source_repository != source_repo:
            raise RuntimeError("target base bootstrap provenance is stale")
        prior_manifest_bytes = content_bytes(source_repo, MANIFEST_PATH, old_manifest_carrier)
        try:
            prior_manifest = json.loads(prior_manifest_bytes)
        except (ValueError, UnicodeDecodeError) as exc:
            raise RuntimeError("prior source manifest bytes are malformed") from exc
        expected_prior_digest = base_state.get("manifest_sha256") if isinstance(base_state, dict) else None
        if base_state.get("manifest_version") == 3 and isinstance(manifest.get("settings"), dict):
            expected_prior_digest, prior_variants = historical_variant_reference(
                manifest, old_manifest_carrier
            )
        else:
            prior_variants = None
        prior_asset_matches = (
            isinstance(prior_manifest.get("source_commit"), str)
            and re.fullmatch(r"[0-9a-f]{40}", prior_manifest["source_commit"])
            and (
                base_state.get("manifest_version") == 3
                or prior_manifest.get("source_commit") == old_source_commit
            )
        )
        if not isinstance(expected_prior_digest, str) or hashlib.sha256(prior_manifest_bytes).hexdigest() != expected_prior_digest or not prior_asset_matches:
            raise RuntimeError("target base bootstrap manifest provenance is stale")
    state_digest, diff_digest, settings_digest, old_closure, new_closure, _, head_state_bytes = _state_and_diff_digests(
        target_repo, head=str(target_head), base=str(target_base), manifest=manifest, manifest_carrier=carrier, prior_manifest=prior_manifest, prior_variants=prior_variants, first_install=first_install
    )
    files = pages(f"repos/{target_repo}/pulls/{target_pr_number}/files?per_page=100")
    deployment_comments = pages(
        f"repos/{target_repo}/issues/{target_pr_number}/comments?per_page=100"
    )
    statuses = {str(item.get("filename")): str(item.get("status", ""))[0:1].upper() for item in files if isinstance(item, dict) and item.get("filename")}
    target_paths = sorted(statuses)
    # The target diff may omit an asset that already equals the attested
    # manifest on the target default branch.  Verify the complete target-head
    # closure, while retaining the diff paths separately for scope control.
    target_tree = tree_details(target_repo, str(target_head), sorted(set(old_closure) | set(new_closure) | {".acai/governance-bootstrap.json"}), statuses)
    details = {item["path"]: item for item in target_tree}
    for path, entry in old_closure.items():
        if path not in new_closure and path in statuses:
            details[path] = {"path": path, "status": statuses[path], "deleted": True, **entry}
    return {"repository": source_repo, "source_pr": source_pr, "issue": issue, "comments": comments, "timeline": timeline, "attestation": attestation, "run": run, "default_contained": contained, "associated_prs": associated, "source_manifest_carrier": carrier, "source_manifest_bytes_base64": base64.b64encode(manifest_bytes).decode("ascii"), "source_tree": source_tree, "target": {"repository": target_repo, "pr": target_pr_number, "head": target_head, "base": target_base, "body": body, "body_digest": body_digest(body), "state_digest": state_digest, "diff_digest": diff_digest, "old_closure_digest": closure_digest(old_closure), "new_closure_digest": closure_digest(new_closure), "settings_digest": settings_digest, "installation_mode": "first-install" if first_install else "upgrade", "base_repository_tree": base_repository_tree, "base_repository_tree_truncated": base_truncated, "base_state_bytes_base64": base64.b64encode(base_state_bytes).decode("ascii"), "head_state_bytes_base64": base64.b64encode(head_state_bytes).decode("ascii"), "prior_manifest_bytes_base64": base64.b64encode(prior_manifest_bytes).decode("ascii"), "base_tree": tree_details(target_repo, str(target_base), sorted(old_closure), {path: "U" for path in old_closure}), "head_tree": tree_details(target_repo, str(target_head), sorted(new_closure), {path: "U" for path in new_closure}), "diff_paths": target_paths, "file_details": details, "deployment_comments": deployment_comments}, "pagination_complete": True}


def main() -> int:
    try:
        request = json.load(sys.stdin)
        result = collect(str(request["source_repository"]), int(request["source_pr"]), str(request["target_repository"]), int(request["target_pr"]))
        print(json.dumps(result, sort_keys=True))
    except (KeyError, TypeError, ValueError, RuntimeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
