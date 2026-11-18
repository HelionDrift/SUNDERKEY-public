"""Bounded offline comparison of supplied dependency resolution evidence."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

PROFILE_ID = "AOE-GC-D17-S08"
CAPABILITY_ID = "army.gc.d17.s08"
VECTOR_ID = "AV-GC-D17-S08-01"
DOMAIN = "sunderkey.offline-dependency-resolution.v1"
ANALYSIS_PROFILE = "supplied-exact-name-registry-collision.v1"
MAX_MODEL_BYTES = 131_072
MAX_REPORT_BYTES = 524_288
MAX_DEPTH = 24
MAX_NODES = 32_768
MAX_REQUIREMENTS = 128
MAX_REGISTRIES = 64
MAX_AVAILABLE_PER_RECORD = 64
MAX_AVAILABLE_TOTAL = 4_096
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_EFFECTS = {
    "authority": "none",
    "credential_resolution": "none",
    "execution": "none",
    "network": "none",
    "package_download": "none",
    "target_interaction": "none",
    "finding_publication": "none",
    "qualification": "none",
}


class DependencyResolutionError(ValueError):
    """Invalid, unsupported, or over-budget supplied dependency evidence."""


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys or any(type(key) is not str for key in value):
        raise DependencyResolutionError(f"{label} must have exact native fields")
    return value


def _match(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise DependencyResolutionError(f"{label} must be bounded native text")
    return value


def _canonical(value: Any, *, maximum: int) -> str:
    stack = [(value, 1)]
    nodes = size = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise DependencyResolutionError("Native node or depth limit exceeded")
        kind = type(item)
        if kind is dict:
            if nodes + len(stack) + 2 * len(item) > MAX_NODES:
                raise DependencyResolutionError("Native node limit exceeded")
            size += 2 + len(item)
            for key, child in item.items():
                if type(key) is not str:
                    raise DependencyResolutionError("Native mapping keys must be strings")
                stack.append((child, depth + 1))
                stack.append((key, depth + 1))
        elif kind is list:
            if nodes + len(stack) + len(item) > MAX_NODES:
                raise DependencyResolutionError("Native node limit exceeded")
            size += 2 + len(item)
            stack.extend((child, depth + 1) for child in item)
        elif kind is str:
            try:
                encoded = item.encode("utf-8")
            except UnicodeError as exc:
                raise DependencyResolutionError("Invalid Unicode scalar text") from exc
            if len(encoded) > MAX_MODEL_BYTES:
                raise DependencyResolutionError("Native string exceeds bound")
            size += 2 + 12 * len(item)
        elif kind is int:
            if item.bit_length() > 63:
                raise DependencyResolutionError("Native integer exceeds 64 bits")
            size += len(str(item))
        elif kind is bool:
            size += 5
        elif item is None:
            size += 4
        else:
            raise DependencyResolutionError("Unsupported native primitive")
        if size > 12 * maximum:
            raise DependencyResolutionError("Native serialized size limit exceeded")
    result = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    if len(result) > maximum:
        raise DependencyResolutionError("Canonical byte limit exceeded")
    return result


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise DependencyResolutionError("JSON duplicate key rejected")
        result[key] = value
    return result


def _json_integer(text: str) -> int:
    if len(text.lstrip("-")) > 19:
        raise DependencyResolutionError("JSON integer exceeds bound")
    result = int(text)
    if result.bit_length() > 63:
        raise DependencyResolutionError("JSON integer exceeds bound")
    return result


def _unsupported_number(_text: str) -> None:
    raise DependencyResolutionError("JSON float or nonfinite number is unsupported")


def _decode(text: Any, label: str, maximum: int) -> Any:
    if type(text) is not str or not text:
        raise DependencyResolutionError(f"{label} must be nonempty native JSON text")
    try:
        length = len(text.encode("utf-8"))
    except UnicodeError as exc:
        raise DependencyResolutionError(f"{label} contains invalid Unicode") from exc
    if length > maximum:
        raise DependencyResolutionError(f"{label} exceeds byte limit")
    depth = 0
    quoted = escaped = False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise DependencyResolutionError("JSON depth limit exceeded")
        elif character in "]}":
            depth -= 1
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_json_integer,
            parse_float=_unsupported_number,
            parse_constant=_unsupported_number,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, DependencyResolutionError):
            raise
        raise DependencyResolutionError(f"{label} is malformed JSON") from exc
    _canonical(value, maximum=maximum)
    return value


def _sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("ascii")).hexdigest()


def _package(value: Any, label: str) -> dict[str, str]:
    package = _exact(value, {"name", "version", "registry_ref"}, label)
    _match(package["name"], _NAME, "package name")
    _match(package["version"], _VERSION, "package version")
    _match(package["registry_ref"], _ID, "registry reference")
    return package


def _manifest(value: Any) -> tuple[str, set[str], list[dict[str, str]]]:
    manifest = _exact(value, {"source_id", "registries", "requirements"}, "manifest")
    source_id = _match(manifest["source_id"], _ID, "manifest source_id")
    raw_registries = manifest["registries"]
    if (
        type(raw_registries) is not list
        or not raw_registries
        or len(raw_registries) > MAX_REGISTRIES
    ):
        raise DependencyResolutionError("Registries must be a bounded nonempty list")
    registries = set()
    for item in raw_registries:
        registry = _match(item, _ID, "registry identifier")
        if registry in registries:
            raise DependencyResolutionError("Duplicate registry identity")
        registries.add(registry)
    requirements = manifest["requirements"]
    if type(requirements) is not list or len(requirements) > MAX_REQUIREMENTS:
        raise DependencyResolutionError("Requirements must be a bounded list")
    ids = set()
    names = set()
    for raw in requirements:
        requirement = _exact(
            raw, {"requirement_id", "name", "intended_registry_ref"}, "requirement"
        )
        requirement_id = _match(requirement["requirement_id"], _ID, "requirement_id")
        name = _match(requirement["name"], _NAME, "requirement name")
        registry = _match(requirement["intended_registry_ref"], _ID, "intended registry")
        if registry not in registries:
            raise DependencyResolutionError("Unknown intended registry")
        if requirement_id in ids or name in names:
            raise DependencyResolutionError("Duplicate requirement identity or exact name")
        ids.add(requirement_id)
        names.add(name)
    return source_id, registries, requirements


def _lockfile(
    value: Any, registries: set[str], ids: set[str]
) -> tuple[str, dict[str, dict[str, Any]]]:
    lockfile = _exact(value, {"source_id", "entries"}, "lockfile")
    source_id = _match(lockfile["source_id"], _ID, "lockfile source_id")
    entries = lockfile["entries"]
    if type(entries) is not list or len(entries) > MAX_REQUIREMENTS:
        raise DependencyResolutionError("Lock entries must be a bounded list")
    result = {}
    for raw in entries:
        entry = _exact(
            raw,
            {"requirement_id", "name", "version", "registry_ref", "artifact_sha256"},
            "lock entry",
        )
        requirement_id = _match(entry["requirement_id"], _ID, "lock requirement_id")
        _match(entry["name"], _NAME, "lock name")
        _match(entry["version"], _VERSION, "lock version")
        registry = _match(entry["registry_ref"], _ID, "lock registry")
        _match(entry["artifact_sha256"], _DIGEST, "artifact digest")
        if requirement_id not in ids or registry not in registries or requirement_id in result:
            raise DependencyResolutionError("Unknown or duplicate lock identity")
        result[requirement_id] = entry
    return source_id, result


def _resolution(
    value: Any, registries: set[str], ids: set[str]
) -> tuple[str, dict[str, dict[str, Any]]]:
    resolution = _exact(value, {"source_id", "records"}, "resolution")
    source_id = _match(resolution["source_id"], _ID, "resolution source_id")
    records = resolution["records"]
    if type(records) is not list or len(records) > MAX_REQUIREMENTS:
        raise DependencyResolutionError("Resolution records must be a bounded list")
    result = {}
    total_available = 0
    for raw in records:
        record = _exact(raw, {"requirement_id", "selected", "available"}, "resolution record")
        requirement_id = _match(record["requirement_id"], _ID, "resolution requirement_id")
        if requirement_id not in ids or requirement_id in result:
            raise DependencyResolutionError("Unknown or duplicate resolution identity")
        selected = record["selected"]
        if selected is not None:
            _package(selected, "selected package")
            if selected["registry_ref"] not in registries:
                raise DependencyResolutionError("Selected package names an unknown registry")
        available = record["available"]
        if type(available) is not list or len(available) > MAX_AVAILABLE_PER_RECORD:
            raise DependencyResolutionError("Available packages must be a bounded list")
        total_available += len(available)
        if total_available > MAX_AVAILABLE_TOTAL:
            raise DependencyResolutionError("Available package limit exceeded")
        identities = set()
        for raw_package in available:
            package = _package(raw_package, "available package")
            identity = (package["name"], package["version"], package["registry_ref"])
            if package["registry_ref"] not in registries or identity in identities:
                raise DependencyResolutionError("Unknown registry or duplicate package identity")
            identities.add(identity)
        result[requirement_id] = record
    return source_id, result


def _model(
    value: Any,
) -> tuple[
    str,
    bool,
    str,
    list[dict[str, str]],
    str,
    dict[str, dict[str, Any]],
    str,
    dict[str, dict[str, Any]],
]:
    model = _exact(
        value,
        {
            "schema_version",
            "source_id",
            "evidence_complete",
            "manifest",
            "lockfile",
            "resolution",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise DependencyResolutionError("Unsupported schema version")
    source_id = _match(model["source_id"], _ID, "model source_id")
    complete = model["evidence_complete"]
    if type(complete) is not bool:
        raise DependencyResolutionError("Evidence completeness must be a native boolean")
    manifest_id, registries, requirements = _manifest(model["manifest"])
    ids = {row["requirement_id"] for row in requirements}
    lock_id, lock_entries = _lockfile(model["lockfile"], registries, ids)
    resolution_id, records = _resolution(model["resolution"], registries, ids)
    if len({source_id, manifest_id, lock_id, resolution_id}) != 4:
        raise DependencyResolutionError("Source identifiers must be distinct")
    return (
        source_id,
        complete,
        manifest_id,
        requirements,
        lock_id,
        lock_entries,
        resolution_id,
        records,
    )


def _projection(model: Any) -> dict[str, Any]:
    model_text = _canonical(model, maximum=MAX_MODEL_BYTES)
    (
        source_id,
        complete,
        manifest_id,
        requirements,
        lock_id,
        lock_entries,
        resolution_id,
        records,
    ) = _model(model)
    rows = []
    candidates = []
    unknowns = []
    conflicts = []
    for requirement in sorted(requirements, key=lambda item: item["requirement_id"]):
        requirement_id = requirement["requirement_id"]
        name = requirement["name"]
        intended = requirement["intended_registry_ref"]
        lock = lock_entries.get(requirement_id)
        record = records.get(requirement_id)
        reason = None
        if not complete:
            disposition = "unknown_incomplete_evidence"
            reason = "evidence_completeness_not_declared"
        elif lock is None:
            disposition = "unknown_missing_lock_entry"
            reason = "lock_entry_absent"
        elif record is None or record["selected"] is None:
            disposition = "unknown_unresolved"
            reason = "selected_resolution_absent"
        else:
            selected = record["selected"]
            selected_identity = (selected["name"], selected["version"], selected["registry_ref"])
            available = {
                (item["name"], item["version"], item["registry_ref"])
                for item in record["available"]
            }
            if (
                lock["name"] != name
                or selected["name"] != name
                or lock["version"] != selected["version"]
                or lock["registry_ref"] != selected["registry_ref"]
                or selected_identity not in available
            ):
                disposition = "conflicting_source_evidence"
                reason = "manifest_lock_resolution_or_available_disagree"
            elif selected["registry_ref"] == intended:
                disposition = "no_cross_registry_selection"
            elif not any(
                item["name"] == name and item["registry_ref"] == intended
                for item in record["available"]
            ):
                disposition = "unknown_uncorroborated_registry_pair"
                reason = "intended_registry_same_name_not_supplied"
            else:
                disposition = "collision_candidate"
                candidates.append(
                    {
                        "requirement_id": requirement_id,
                        "name": name,
                        "intended_registry_ref": intended,
                        "selected_registry_ref": selected["registry_ref"],
                        "selected_version": selected["version"],
                        "lock_artifact_sha256": lock["artifact_sha256"],
                    }
                )
        rows.append({"requirement_id": requirement_id, "disposition": disposition})
        if reason is not None:
            target = conflicts if disposition == "conflicting_source_evidence" else unknowns
            target.append({"requirement_id": requirement_id, "reason": reason})
    report = {
        "schema_version": 1,
        "analysis_profile": ANALYSIS_PROFILE,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "source": {
            "source_id": source_id,
            "model_sha256": _sha(model_text),
            "manifest": {
                "source_id": manifest_id,
                "sha256": _sha(_canonical(model["manifest"], maximum=MAX_MODEL_BYTES)),
            },
            "lockfile": {
                "source_id": lock_id,
                "sha256": _sha(_canonical(model["lockfile"], maximum=MAX_MODEL_BYTES)),
            },
            "resolution": {
                "source_id": resolution_id,
                "sha256": _sha(_canonical(model["resolution"], maximum=MAX_MODEL_BYTES)),
            },
        },
        "supplied_model": model,
        "requirement_outcomes": rows,
        "collision_candidates": candidates,
        "unknowns": unknowns,
        "source_conflicts": conflicts,
        "uncertainty": [
            "Registry and completeness declarations are supplied premises, "
            "not authenticated facts.",
            "Names and versions are opaque exact strings; no package-manager rules are modeled.",
            "A candidate is a supplied cross-registry name collision, not malicious intent.",
            "No live registry availability, package execution, exploitability, "
            "or impact is inferred.",
        ],
        "offline_only": True,
        "registry_behavior_verified": False,
        "dependency_confusion_verdict": None,
        "effects": dict(_EFFECTS),
    }
    digest = hashlib.sha256(
        _canonical({"domain": DOMAIN, "report": report}, maximum=MAX_REPORT_BYTES).encode("ascii")
    ).hexdigest()
    report["report_id"] = "DCR-" + digest[:32].upper()
    report["report_sha256"] = "sha256:" + digest
    _canonical(report, maximum=MAX_REPORT_BYTES)
    return report


_REPORT_FIELDS = {
    "schema_version",
    "analysis_profile",
    "profile_id",
    "capability_id",
    "vector_id",
    "source",
    "supplied_model",
    "requirement_outcomes",
    "collision_candidates",
    "unknowns",
    "source_conflicts",
    "uncertainty",
    "offline_only",
    "registry_behavior_verified",
    "dependency_confusion_verdict",
    "effects",
    "report_id",
    "report_sha256",
}


def _replay(document: Any) -> str:
    _exact(document, _REPORT_FIELDS, "report")
    expected = _projection(document["supplied_model"])
    if document != expected:
        raise DependencyResolutionError("Report does not replay supplied model")
    return _canonical(expected, maximum=MAX_REPORT_BYTES)


def _owned(text: str) -> DependencyResolutionReport:
    report = object.__new__(DependencyResolutionReport)
    object.__setattr__(report, "document_json", text)
    return report


@dataclass(frozen=True, slots=True)
class DependencyResolutionReport:
    """Detached unsigned resolution projection retaining its supplied model."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not DependencyResolutionReport:
            raise DependencyResolutionError("Exact report family required")
        self.to_dict()

    @classmethod
    def from_dict(cls, value: Any) -> DependencyResolutionReport:
        if cls is not DependencyResolutionReport:
            raise DependencyResolutionError("Exact report family required")
        return _owned(_replay(value))

    @classmethod
    def from_json(cls, value: Any) -> DependencyResolutionReport:
        if cls is not DependencyResolutionReport or type(value) is not str:
            raise DependencyResolutionError("Exact native report JSON required")
        document = _decode(value, "report", MAX_REPORT_BYTES)
        canonical = _replay(document)
        if value != canonical:
            raise DependencyResolutionError("Canonical report JSON required")
        return _owned(canonical)

    def to_dict(self) -> dict[str, Any]:
        if type(self) is not DependencyResolutionReport or type(self.document_json) is not str:
            raise DependencyResolutionError("Exact native report wrapper required")
        return DependencyResolutionReport.from_json(self.document_json)._document()

    def _document(self) -> dict[str, Any]:
        return _decode(self.document_json, "report", MAX_REPORT_BYTES)

    def to_json(self) -> str:
        self.to_dict()
        return self.document_json


def analyze_supplied_dependency_resolution(model: Any) -> DependencyResolutionReport:
    """Compare only supplied manifest, lockfile, and resolution records."""
    return _owned(_canonical(_projection(model), maximum=MAX_REPORT_BYTES))


def analyze_supplied_dependency_resolution_bytes(*, model_bytes: Any) -> DependencyResolutionReport:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise DependencyResolutionError("Bounded native model bytes required")
    try:
        text = model_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DependencyResolutionError("Model bytes must be UTF-8") from exc
    return analyze_supplied_dependency_resolution(_decode(text, "model", MAX_MODEL_BYTES))


def verify_supplied_dependency_resolution(report: Any, *, model: Any) -> DependencyResolutionReport:
    if type(report) is not DependencyResolutionReport:
        raise DependencyResolutionError("Exact native report wrapper required")
    retained = report.to_json()
    expected = _canonical(_projection(model), maximum=MAX_REPORT_BYTES)
    if retained != expected:
        raise DependencyResolutionError("Report differs from separately supplied model")
    return _owned(expected)


def component_fixture() -> dict[str, Any]:
    """Return fresh synthetic evidence with no registry URL or package bytes."""
    digest = "sha256:" + "a" * 64
    return {
        "schema_version": 1,
        "source_id": "synthetic-resolution-model",
        "evidence_complete": True,
        "manifest": {
            "source_id": "synthetic-manifest",
            "registries": ["internal", "public"],
            "requirements": [
                {
                    "requirement_id": "dep-widget",
                    "name": "widget-core",
                    "intended_registry_ref": "internal",
                },
            ],
        },
        "lockfile": {
            "source_id": "synthetic-lockfile",
            "entries": [
                {
                    "requirement_id": "dep-widget",
                    "name": "widget-core",
                    "version": "2.0",
                    "registry_ref": "public",
                    "artifact_sha256": digest,
                },
            ],
        },
        "resolution": {
            "source_id": "synthetic-resolution",
            "records": [
                {
                    "requirement_id": "dep-widget",
                    "selected": {
                        "name": "widget-core",
                        "version": "2.0",
                        "registry_ref": "public",
                    },
                    "available": [
                        {"name": "widget-core", "version": "1.0", "registry_ref": "internal"},
                        {"name": "widget-core", "version": "2.0", "registry_ref": "public"},
                    ],
                },
            ],
        },
    }


__all__ = [
    "DependencyResolutionError",
    "DependencyResolutionReport",
    "analyze_supplied_dependency_resolution",
    "analyze_supplied_dependency_resolution_bytes",
    "verify_supplied_dependency_resolution",
    "component_fixture",
]
