#!/usr/bin/env python3
"""Turn normalized authenticated propagation facts into one eligibility result."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys

from governance_release import validate_release_attestation
from governance_propagation_contract import body_digest, validate_pr_body


PROPAGATION_SOURCE = re.compile(
    r"(?m)^ACAI-Propagation-Source:\s*"
    r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)#([1-9][0-9]*)\s*$"
)


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _closure_digest(closure: dict[str, dict[str, str]]) -> str:
    return hashlib.sha256(_canonical(closure).encode()).hexdigest()


def _transition_digest(old: dict[str, dict[str, str]], new: dict[str, dict[str, str]]) -> str:
    return hashlib.sha256(_canonical({"old": old, "new": new}).encode()).hexdigest()


def _closure_from_manifest(manifest: dict) -> dict[str, dict[str, str]]:
    entries = manifest.get("files") if isinstance(manifest, dict) else None
    result: dict[str, dict[str, str]] = {}
    if not isinstance(entries, list) or not entries:
        raise ValueError("attested manifest closure is malformed")
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("attested manifest closure is malformed")
        path, mode, digest = entry.get("path"), entry.get("mode"), entry.get("sha256")
        if not isinstance(path, str) or not path or path in result or not re.fullmatch(r"100(?:644|755)", str(mode)) or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("attested manifest closure is malformed")
        result[path] = {"mode": str(mode), "sha256": digest}
    return result


def _historical_variant_reference(manifest: dict, carrier: object) -> tuple[object, object]:
    settings = manifest.get("settings") if isinstance(manifest, dict) else None
    migration = settings.get("v3_migration") if isinstance(settings, dict) else None
    histories = migration.get("historical_manifests") if isinstance(migration, dict) else None
    if not isinstance(histories, list) or not histories:
        raise ValueError
    matches, seen = [], set()
    for item in histories:
        if not isinstance(item, dict) or set(item) not in (
            {"source_commit", "manifest_sha256"},
            {"source_commit", "manifest_sha256", "variants"},
        ):
            raise ValueError
        candidate, digest, variants = item.get("source_commit"), item.get("manifest_sha256"), item.get("variants", [])
        if (
            not isinstance(candidate, str) or not re.fullmatch(r"[0-9a-f]{40}", candidate)
            or candidate in seen or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or not isinstance(variants, list) or ("variants" in item and not variants)
        ):
            raise ValueError
        seen.add(candidate)
        if candidate == carrier:
            matches.append((digest, variants))
    if len(matches) != 1:
        raise ValueError
    return matches[0]


def _complete_historical_closure(base: dict[str, dict[str, str]], variants: object, current: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    if variants in (None, []):
        candidates = [base]
    elif not isinstance(variants, list):
        raise ValueError
    else:
        composed, seen = dict(base), set()
        for entry in variants:
            if not isinstance(entry, dict) or set(entry) != {"path", "mode", "sha256"}:
                raise ValueError
            path, mode, digest = entry.get("path"), entry.get("mode"), entry.get("sha256")
            if (
                not isinstance(path, str) or path not in base or path in seen
                or not isinstance(mode, str) or not re.fullmatch(r"100(?:644|755)", mode)
                or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or base[path] == {"mode": mode, "sha256": digest}
            ):
                raise ValueError
            seen.add(path)
            composed[path] = {"mode": mode, "sha256": digest}
        candidates = [base, composed]
    matched = [candidate for candidate in candidates if current == candidate]
    if len(matched) != 1:
        raise ValueError
    return matched[0]


def _derive_target_closures(target: dict, source_bytes: bytes, manifest_carrier: str) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, str]], list[str]]:
    """Independently rebuild old/new closures from raw pinned evidence."""
    reasons: list[str] = []
    try:
        source_manifest = json.loads(source_bytes)
        prior_bytes = base64.b64decode(str(target.get("prior_manifest_bytes_base64", "")), validate=True)
        prior_manifest = json.loads(prior_bytes)
        base_state_bytes = base64.b64decode(str(target.get("base_state_bytes_base64", "")), validate=True)
        base_state = json.loads(base_state_bytes)
        head_state_bytes = base64.b64decode(str(target.get("head_state_bytes_base64", "")), validate=True)
        head_state = json.loads(head_state_bytes)
        old, new = _closure_from_manifest(prior_manifest), _closure_from_manifest(source_manifest)
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        return {}, {}, ["independent old/new closure evidence is malformed"]
    expected_prior_digest = base_state.get("manifest_sha256") if isinstance(base_state, dict) else None
    prior_variants: object = None
    if isinstance(base_state, dict) and base_state.get("manifest_version") == 3 and isinstance(source_manifest.get("settings"), dict):
        try:
            expected_prior_digest, prior_variants = _historical_variant_reference(
                source_manifest, base_state.get("source_commit")
            )
        except ValueError:
            reasons.append("target base version-3 carrier provenance is stale or ambiguous")
    base_is_v3 = isinstance(base_state, dict) and base_state.get("manifest_version") == 3
    base_provenance = (
        isinstance(base_state, dict)
        and isinstance(prior_manifest.get("source_commit"), str)
        and re.fullmatch(r"[0-9a-f]{40}", prior_manifest["source_commit"])
        and (
            base_is_v3
            or (
                base_state.get("source_commit") == prior_manifest.get("source_commit")
                and isinstance(base_state.get("manifest_source_commit"), str)
                and re.fullmatch(r"[0-9a-f]{40}", base_state["manifest_source_commit"])
            )
        )
    )
    if not base_provenance or expected_prior_digest != hashlib.sha256(prior_bytes).hexdigest() or set(base_state.get("files", [])) != set(old):
        reasons.append("target base bootstrap does not bind the prior attested closure")
    if (
        not isinstance(head_state, dict)
        or head_state.get("source_commit") != source_manifest.get("source_commit")
        or head_state.get("manifest_source_commit") != manifest_carrier
        or head_state.get("settings_owner") != target.get("settings_digest")
        or hashlib.sha256(head_state_bytes).hexdigest() != target.get("state_digest")
    ):
        reasons.append("target head bootstrap does not bind the carrier, asset, or settings owner")
    def tree_closure(items: object) -> dict[str, dict[str, str]]:
        if not isinstance(items, list):
            raise ValueError
        result = {}
        for item in items:
            if not isinstance(item, dict) or item.get("deleted") is not False or item.get("type") != "blob":
                raise ValueError
            result[str(item.get("path"))] = {"mode": item.get("mode"), "sha256": item.get("sha256")}
        return result
    try:
        old = _complete_historical_closure(
            old, prior_variants, tree_closure(target.get("base_tree"))
        )
        if tree_closure(target.get("base_tree")) != old:
            reasons.append("target base tree does not match independently derived old closure")
        if tree_closure(target.get("head_tree")) != new:
            reasons.append("target head tree does not match independently derived new closure")
    except ValueError:
        reasons.append("target closure tree evidence is malformed")
    if target.get("old_closure_digest") != _closure_digest(old) or target.get("new_closure_digest") != _closure_digest(new) or target.get("diff_digest") != _transition_digest(old, new):
        reasons.append("collector closure digests do not match independently derived closures")
    return old, new, reasons


def _one_line(body: str, name: str, value: str) -> bool:
    matches = re.findall(
        rf"(?im)^\s*{re.escape(name)}\s*:\s*(.*?)\s*$", body
    )
    return len(matches) == 1 and matches[0].strip() == value


def verify_local_admission(data: dict) -> list[str]:
    """Validate the narrow trusted-default Tier-1 propagation exception."""
    pr = data.get("pr") if isinstance(data.get("pr"), dict) else {}
    body = str(pr.get("body", ""))
    source = PROPAGATION_SOURCE.findall(body)
    trusted_source = str(data.get("trusted_source_repository", ""))
    reasons: list[str] = []
    if len(source) != 1 or source[0][0] != trusted_source:
        reasons.append("propagation source metadata is missing, ambiguous, or untrusted")
        source_pr = ""
    else:
        source_pr = source[0][1]
    for name, value in (
        ("Tier", "governance/tier-1"),
        ("Action phase", "reviewable-artifact"),
        ("Merge effect", "none"),
        ("Change class", "governance-propagation"),
    ):
        if not _one_line(body, name, value):
            reasons.append(f"propagation {name} metadata is missing or invalid")
    head = str(pr.get("headRefOid", ""))
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        reasons.append("propagation exact head is unavailable")
    operators = {
        str(item).strip()
        for item in data.get("operator_logins", [])
        if str(item).strip()
    }
    if not operators:
        reasons.append("propagation operator allowlist is empty")
    statuses = [
        item
        for item in data.get("statuses", [])
        if isinstance(item, dict)
        and item.get("context") == "governance/propagation-attested"
    ]
    if len(statuses) != 1:
        reasons.append("exact-head propagation attestation is missing or ambiguous")
    else:
        status = statuses[0]
        expected_url = (
            f"https://github.com/{trusted_source}/pull/{source_pr}"
            if source_pr
            else ""
        )
        if (
            status.get("state") != "success"
            or status.get("target_url") != expected_url
            or status.get("description")
            != "Exact-head checksum-attested propagation verified locally"
            or str((status.get("creator") or {}).get("login", ""))
            not in operators
        ):
            reasons.append(
                "propagation attestation is stale, untrusted, or source-mismatched"
            )
    return list(dict.fromkeys(reasons))


def verify(data: dict) -> list[str]:
    if data.get("pagination_complete") is not True:
        return ["source/target API pagination is unavailable or incomplete"]
    target = data.get("target") if isinstance(data.get("target"), dict) else {}
    try:
        source_bytes = base64.b64decode(data.get("source_manifest_bytes_base64", ""), validate=True)
    except (ValueError, TypeError):
        return ["source commit-pinned manifest bytes are unavailable"]
    carrier = str(data.get("source_manifest_carrier", ""))
    if not re.fullmatch(r"[0-9a-f]{40}", carrier):
        return ["source manifest carrier is missing or malformed"]
    old_closure, new_closure, closure_reasons = _derive_target_closures(target, source_bytes, carrier)
    reasons = list(closure_reasons)
    reasons.extend(validate_pr_body(
        str(target.get("body", "")),
        source_repository=str(data.get("repository", "")),
        source_pr=int((data.get("source_pr") or {}).get("number", 0)),
        target_repository=str(target.get("repository", "")),
        manifest_sha256=hashlib.sha256(source_bytes).hexdigest(),
        head_sha=str(target.get("head", "")),
        base_sha=str(target.get("base", "")),
    ))
    if target.get("body_digest") != body_digest(str(target.get("body", ""))):
        reasons.append("target canonical PR body digest is stale")
    reasons.extend(validate_release_attestation(
        data.get("attestation", {}), data.get("source_pr", {}), repository=data.get("repository", ""),
        default_branch=((data.get("source_pr") or {}).get("base") or {}).get("ref", ""),
        diff_paths=target.get("diff_paths"), file_details=target.get("file_details"), issue=data.get("issue"),
        comments=data.get("comments"), timeline=data.get("timeline"), run=data.get("run"),
        source_manifest_bytes=source_bytes, source_tree=data.get("source_tree"),
        default_contained=data.get("default_contained"), associated_prs=data.get("associated_prs"),
        deployment_comments=target.get("deployment_comments"),
        target_repository=str(target.get("repository", "")),
        target_pr=target.get("pr", 0),
        target_head=str(target.get("head", "")),
        target_base=str(target.get("base", "")),
        target_body=str(target.get("body", "")),
        target_state_digest=str(target.get("state_digest", "")),
        target_diff_digest=str(target.get("diff_digest", "")),
        target_settings_digest=str(target.get("settings_digest", "")),
        target_old_closure_digest=str(target.get("old_closure_digest", "")),
        target_new_closure_digest=str(target.get("new_closure_digest", "")),
        target_old_closure=old_closure,
    ))
    return list(dict.fromkeys(reasons))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-admission", action="store_true")
    args = parser.parse_args()
    try:
        data = json.load(sys.stdin)
        reasons = (
            verify_local_admission(data)
            if args.local_admission
            else verify(data)
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        reasons = [f"malformed propagation verification payload: {exc}"]
    result = {"tier1_eligible": not reasons, "reasons": reasons}
    print(json.dumps(result, sort_keys=True))
    return 0 if not reasons else 1


if __name__ == "__main__":
    raise SystemExit(main())
