"""Versioned, fail-closed ownership descriptors for external governance settings."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

OWNER_MARKER = "ACAI_GOVERNANCE_SETTINGS_OWNER"
PIN_VALUE = re.compile(r"^\$\{pin:([A-Z][A-Z0-9_]*)\}$")


class SettingsError(ValueError):
    pass


@dataclass(frozen=True)
class ResolvedDescriptor:
    """The exact external settings transition derived from one pinned asset."""

    settings: dict[str, str]
    descriptor_digest: str
    owner_marker: str


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def descriptor_digest(settings: dict[str, str]) -> str:
    """Digest the canonical descriptor, never an inferred settings map."""
    return hashlib.sha256(
        canonical({"schema": "acai-governance-settings/v1", "settings": settings})
    ).hexdigest()


def load_descriptor(raw: bytes) -> dict[str, str]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SettingsError("settings descriptor is invalid JSON") from exc
    if not isinstance(value, dict) or set(value) != {"schema", "settings"} or value["schema"] != "acai-governance-settings/v1":
        raise SettingsError("settings descriptor schema is unsupported")
    settings = value["settings"]
    if not isinstance(settings, dict) or not settings:
        raise SettingsError("settings descriptor is empty or malformed")
    if OWNER_MARKER in settings or any(not isinstance(k, str) or not k or not isinstance(v, str) for k, v in settings.items()):
        raise SettingsError("settings descriptor contains an invalid owned setting")
    return dict(settings)


def resolve_descriptor(
    raw: bytes,
    pin_allowlists: dict[str, str],
    *,
    expected_digest: str | None = None,
) -> ResolvedDescriptor:
    """Resolve whole-value `${pin:NAME}` references from immutable pin values.

    Callers fetch ``raw`` from the release-pinned source commit, supply the
    release pin's allowlist map, and persist only ``settings``.  The returned
    ``descriptor_digest`` is the canonical descriptor asset digest; the
    ``owner_marker`` is intentionally the same immutable release identity and
    must be written after every individual setting.
    """
    settings = load_descriptor(raw)
    digest = descriptor_digest(settings)
    if expected_digest is not None:
        if not isinstance(expected_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
            raise SettingsError("expected descriptor digest is malformed")
        if digest != expected_digest:
            raise SettingsError("settings descriptor does not match its pinned digest")
    if not isinstance(pin_allowlists, dict) or any(
        not isinstance(name, str) or not isinstance(value, str)
        for name, value in pin_allowlists.items()
    ):
        raise SettingsError("release pin allowlists are malformed")
    resolved: dict[str, str] = {}
    for name, value in settings.items():
        placeholder = PIN_VALUE.fullmatch(value)
        if placeholder is None:
            if "${pin:" in value:
                raise SettingsError(f"settings descriptor has a non-whole pin reference: {name}")
            resolved[name] = value
            continue
        pin_name = placeholder.group(1)
        if pin_name not in pin_allowlists:
            raise SettingsError(f"settings descriptor pin value is unavailable: {pin_name}")
        resolved[name] = pin_allowlists[pin_name]
    return ResolvedDescriptor(resolved, digest, digest)


def migrate_v3(state: dict[str, Any], historical: dict[str, str], current: dict[str, str]) -> dict[str, str]:
    """Accept legacy v3 only when each historical setting exactly matches."""
    if state.get("manifest_version") != 3 or not isinstance(state.get("source_commit"), str):
        raise SettingsError("historical settings migration lacks attested v3 state")
    if current.get(OWNER_MARKER) is not None:
        raise SettingsError("v3 target has an unexpected settings owner marker")
    for name, value in historical.items():
        if current.get(name) != value:
            raise SettingsError(f"v3 owned setting drifted: {name}")
    return historical


def reconcile(current: dict[str, str], old: dict[str, str], new: dict[str, str], digest: str, write: Any) -> None:
    for name in sorted(set(old) | set(new)):
        if current.get(name) not in {old.get(name), new.get(name)}:
            raise SettingsError(f"unowned or drifted setting: {name}")
        if current.get(name) != new.get(name):
            write(name, new.get(name))
            if new.get(name) is None:
                current.pop(name, None)
            else:
                current[name] = new[name]
    if current.get(OWNER_MARKER) != digest:
        write(OWNER_MARKER, digest)
        current[OWNER_MARKER] = digest
