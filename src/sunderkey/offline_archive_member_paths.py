"""Project supplied archive member paths without extracting files."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_archive_member_paths"
PROFILE_ID = "AOE-GE-D23-S05"
CAPABILITY_ID = "army.ge.d23.s05"
VECTOR_ID = "AV-GE-D23-S05-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D23-S05"
WAVE_ID = "IW2-019"
COMMANDER_ID = "AOE-GE-D23-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:83d99c71cef76681c17683c2661439fafe00d3071e0615078151d0e54b09a855"
SEMANTICS_PROFILE = "supplied-archive-member-paths-v1"
DOMAIN = "sunderkey.offline-archive-member-paths.v1"
MAX_ENTRIES = 256
MAX_DOCUMENT_BYTES = 524_288
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_ROOT = re.compile(r"root:sha256:[0-9a-f]{64}\Z")
_DRIVE = re.compile(r"[A-Za-z]:")
_PROFILES = frozenset(("posix-lexical-v1", "windows-lexical-v1"))
_KINDS = frozenset(("file", "directory", "symlink"))
_WINDOWS_DEVICES = frozenset(
    ("CON", "PRN", "AUX", "NUL")
    + tuple(f"COM{index}" for index in range(1, 10))
    + tuple(f"LPT{index}" for index in range(1, 10))
)
_EFFECTS = dict.fromkeys(
    (
        "archive",
        "authority",
        "credential",
        "execution",
        "extraction",
        "filesystem",
        "network",
        "publication",
        "qualification",
        "target",
    ),
    "none",
)


class ArchiveMemberPathError(ValueError):
    """A supplied archive model or replay report was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise ArchiveMemberPathError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise ArchiveMemberPathError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise ArchiveMemberPathError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise ArchiveMemberPathError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise ArchiveMemberPathError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise ArchiveMemberPathError("Native JSON text keys are required")
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            else:
                for child in item:
                    visit(child, depth + 1)
        finally:
            active.remove(id(item))

    visit(value, 1)
    encoded = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise ArchiveMemberPathError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise ArchiveMemberPathError(f"{label} fields are invalid")


def _plan(model: Any) -> dict:
    model = json.loads(_canonical(model))
    _fields(
        model,
        {"schema_version", "semantics_profile", "extraction_profile", "root_ref", "entries"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ArchiveMemberPathError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise ArchiveMemberPathError("Semantics profile is invalid")
    if type(model["extraction_profile"]) is not str or model["extraction_profile"] not in _PROFILES:
        raise ArchiveMemberPathError("Extraction profile is invalid")
    if type(model["root_ref"]) is not str or _ROOT.fullmatch(model["root_ref"]) is None:
        raise ArchiveMemberPathError("Root must be an opaque digest reference")
    entries = model["entries"]
    if type(entries) is not list or not 1 <= len(entries) <= MAX_ENTRIES:
        raise ArchiveMemberPathError("Entry count is invalid")
    seen: set[str] = set()
    for row in entries:
        _fields(row, {"entry_id", "member_name", "kind"}, "entry")
        entry_id = row["entry_id"]
        name = row["member_name"]
        if type(entry_id) is not str or _ID.fullmatch(entry_id) is None or entry_id in seen:
            raise ArchiveMemberPathError("Entry identifier is invalid or duplicated")
        seen.add(entry_id)
        if type(name) is not str or not name or len(name) > MAX_STRING_LENGTH:
            raise ArchiveMemberPathError("Member name is invalid")
        if any(ord(character) < 32 or ord(character) == 127 for character in name):
            raise ArchiveMemberPathError("Control characters in member name are refused")
        if type(row["kind"]) is not str or row["kind"] not in _KINDS:
            raise ArchiveMemberPathError("Entry kind is invalid")
    return model


def _project_name(name: str, profile: str, kind: str) -> tuple[str, list[str]]:
    windows = profile == "windows-lexical-v1"
    if windows and _DRIVE.match(name):
        return "declared_drive_prefix", []
    if name.startswith("/") or (windows and name.startswith("\\")):
        return "declared_absolute_member", []
    parts = re.split(r"[/\\]", name) if windows else name.split("/")
    normalized: list[str] = []
    ambiguous = False
    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not normalized:
                return "declared_parent_escape", []
            normalized.pop()
            continue
        if not part.isascii() or "%" in part:
            ambiguous = True
        if windows and (
            ":" in part
            or part.endswith((".", " "))
            or part.split(".", 1)[0].upper() in _WINDOWS_DEVICES
        ):
            ambiguous = True
        normalized.append(part)
    if not normalized:
        return "unknown_empty_destination", []
    if kind == "symlink":
        return "unknown_symlink_target", normalized
    if ambiguous:
        return "unknown_name_transform", normalized
    return "lexically_contained", normalized


def _destination_key(segments: list[str], profile: str) -> tuple[str, ...]:
    if profile == "windows-lexical-v1":
        return tuple(part.casefold() for part in segments)
    return tuple(segments)


def _derive(model: Any) -> dict:
    plan = _plan(model)
    profile = plan["extraction_profile"]
    findings = []
    destinations: dict[tuple[str, ...], list[str]] = {}
    for row in plan["entries"]:
        disposition, segments = _project_name(row["member_name"], profile, row["kind"])
        finding = {
            "entry_id": row["entry_id"],
            "disposition": disposition,
            "normalized_segments": segments,
            "collision_with_entry_ids": [],
        }
        findings.append(finding)
        if disposition == "lexically_contained":
            key = _destination_key(segments, profile)
            destinations.setdefault(key, []).append(row["entry_id"])
    for finding in findings:
        if finding["disposition"] != "lexically_contained":
            continue
        segments = finding["normalized_segments"]
        key = _destination_key(segments, profile)
        collisions = sorted(item for item in destinations[key] if item != finding["entry_id"])
        if collisions:
            finding["disposition"] = "declared_destination_collision_candidate"
            finding["collision_with_entry_ids"] = collisions
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": plan,
        "findings": findings,
        "flags": {
            "archive_bytes_verified": False,
            "extractor_semantics_verified": False,
            "filesystem_state_verified": False,
            "escape_or_overwrite_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Member names, entry kinds, root identity, and platform profile are caller-supplied.",
            "The two profiles are finite lexical models, not actual extractor semantics.",
            "Containment and collision labels do not resolve links, encodings, "
            "case mode, or filesystem state.",
            "No archive is opened and no file, credential, network, or target is accessed.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "AMP-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class ArchiveMemberPaths:
    """Immutable report replayed from supplied archive member declarations."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise ArchiveMemberPathError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise ArchiveMemberPathError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_archive_member_paths(model: Any) -> ArchiveMemberPaths:
    """Compare supplied member names with a finite lexical extraction model."""
    return ArchiveMemberPaths(_derive(model))


def verify_supplied_archive_member_paths(
    report: Any, *, model: Any
) -> ArchiveMemberPaths:
    if type(report) is not ArchiveMemberPaths:
        raise ArchiveMemberPathError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise ArchiveMemberPathError("Report differs from supplied model replay")
    return ArchiveMemberPaths(expected)
