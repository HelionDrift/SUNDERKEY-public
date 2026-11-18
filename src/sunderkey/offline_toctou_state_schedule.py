"""Project a supplied check-use version schedule without exercising a target."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_toctou_state_schedule"
PROFILE_ID = "AOE-GE-D23-S10"
CAPABILITY_ID = "army.ge.d23.s10"
VECTOR_ID = "AV-GE-D23-S10-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D23-S10"
WAVE_ID = "IW2-024"
COMMANDER_ID = "AOE-GE-D23-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:74d46a3e4b56edeb6a85bf714c45f4d429d465335649f26a32fc66b3f1215781"
SEMANTICS_PROFILE = "supplied-check-use-version-schedule-v1"
DOMAIN = "sunderkey.offline-toctou-state-schedule.v1"
MAX_DOCUMENT_BYTES = 65_536
MAX_RESOURCES = 32
MAX_EVENTS = 128
MAX_NATIVE_NODES = 2_048
MAX_NATIVE_DEPTH = 10
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_REF = re.compile(r"ref:[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")
_KINDS = frozenset({"check", "mutate", "use"})
_OUTCOMES = frozenset({"accepted", "rejected", "unknown"})
_EFFECTS = dict.fromkeys(
    (
        "authority", "credential", "execution", "filesystem", "network",
        "publication", "qualification", "target",
    ),
    "none",
)


class ToctouStateScheduleError(ValueError):
    """A supplied schedule or replay report was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise ToctouStateScheduleError("Native structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_DOCUMENT_BYTES:
                raise ToctouStateScheduleError("Native string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not 0 <= item <= 1_000_000:
                raise ToctouStateScheduleError("Version integer bound exceeded")
            return
        if family not in (dict, list):
            raise ToctouStateScheduleError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise ToctouStateScheduleError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise ToctouStateScheduleError("Native JSON text keys are required")
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
        raise ToctouStateScheduleError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise ToctouStateScheduleError(f"{label} fields are invalid")


def _reference(value: Any, label: str) -> str:
    if type(value) is not str or _REF.fullmatch(value) is None:
        raise ToctouStateScheduleError(f"{label} must be an opaque reference")
    return value


def _version(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= 1_000_000:
        raise ToctouStateScheduleError("Version must be a bounded native integer")
    return value


def _model(value: Any) -> dict:
    model = json.loads(_canonical(value))
    _fields(
        model,
        {
            "schema_version", "semantics_profile", "source_id", "schedule_complete",
            "policy", "initial_versions", "events",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ToctouStateScheduleError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise ToctouStateScheduleError("Semantics profile is invalid")
    if type(model["source_id"]) is not str or _ID.fullmatch(model["source_id"]) is None:
        raise ToctouStateScheduleError("Source identifier is invalid")
    if type(model["schedule_complete"]) is not bool:
        raise ToctouStateScheduleError("Schedule completeness must be boolean")
    policy = model["policy"]
    _fields(policy, {"declaration_complete", "reject_stale_check"}, "policy")
    if any(type(policy[field]) is not bool for field in policy):
        raise ToctouStateScheduleError("Policy declarations must be boolean")
    initial = model["initial_versions"]
    if type(initial) is not list or not 1 <= len(initial) <= MAX_RESOURCES:
        raise ToctouStateScheduleError("Initial-resource count is invalid")
    resources: set[str] = set()
    for item in initial:
        _fields(item, {"resource_ref", "version"}, "initial resource")
        ref = _reference(item["resource_ref"], "Resource reference")
        if ref in resources:
            raise ToctouStateScheduleError("Initial resource is repeated")
        resources.add(ref)
        _version(item["version"])
    events = model["events"]
    if type(events) is not list or not 1 <= len(events) <= MAX_EVENTS:
        raise ToctouStateScheduleError("Event count is invalid")
    identifiers: set[str] = set()
    for event in events:
        _fields(
            event,
            {
                "event_id", "kind", "actor_ref", "resource_ref", "version",
                "check_event_id", "declared_outcome", "capture_complete",
            },
            "event",
        )
        identifier = event["event_id"]
        if type(identifier) is not str or _ID.fullmatch(identifier) is None:
            raise ToctouStateScheduleError("Event identifier is invalid")
        if identifier in identifiers:
            raise ToctouStateScheduleError("Event identifier is repeated")
        identifiers.add(identifier)
        kind = event["kind"]
        if type(kind) is not str or kind not in _KINDS:
            raise ToctouStateScheduleError("Event kind is invalid")
        _reference(event["actor_ref"], "Actor reference")
        ref = _reference(event["resource_ref"], "Resource reference")
        if ref not in resources:
            raise ToctouStateScheduleError("Event resource lacks an initial version")
        if type(event["capture_complete"]) is not bool:
            raise ToctouStateScheduleError("Capture completeness must be boolean")
        if kind == "use":
            if event["version"] is not None:
                raise ToctouStateScheduleError("Use event cannot declare a new version")
            check = event["check_event_id"]
            if type(check) is not str or _ID.fullmatch(check) is None:
                raise ToctouStateScheduleError("Use event requires a check identifier")
            outcome = event["declared_outcome"]
            if type(outcome) is not str or outcome not in _OUTCOMES:
                raise ToctouStateScheduleError("Use outcome is invalid")
        else:
            _version(event["version"])
            if (
                event["check_event_id"] is not None
                or event["declared_outcome"] is not None
                or event["capture_complete"]
            ):
                raise ToctouStateScheduleError("Non-use event fields are invalid")
    return model


def _derive(value: Any) -> dict:
    model = _model(value)
    policy = model["policy"]
    versions = {row["resource_ref"]: row["version"] for row in model["initial_versions"]}
    checks: dict[str, dict] = {}
    mutations: dict[str, list[str]] = {ref: [] for ref in versions}
    projections = []
    for index, event in enumerate(model["events"]):
        ref = event["resource_ref"]
        kind = event["kind"]
        if kind == "check":
            checks[event["event_id"]] = {
                "actor_ref": event["actor_ref"],
                "resource_ref": ref,
                "version": event["version"],
                "current_at_check": versions[ref],
                "mutation_count": len(mutations[ref]),
            }
        elif kind == "mutate":
            if event["version"] <= versions[ref]:
                raise ToctouStateScheduleError("Mutation must advance the supplied version")
            versions[ref] = event["version"]
            mutations[ref].append(event["event_id"])
        else:
            check = checks.get(event["check_event_id"])
            if check is None:
                raise ToctouStateScheduleError("Use does not reference a preceding check")
            if check["actor_ref"] != event["actor_ref"] or check["resource_ref"] != ref:
                raise ToctouStateScheduleError("Use and check ownership differ")
            intervening = len(mutations[ref]) - check["mutation_count"]
            stale = check["version"] != versions[ref] and intervening > 0
            negative = policy["reject_stale_check"] and stale
            if (
                not model["schedule_complete"]
                or not policy["declaration_complete"]
                or not event["capture_complete"]
            ):
                disposition = "unresolved_declaration_or_capture"
            elif check["version"] != check["current_at_check"]:
                disposition = "unresolved_check_version_mismatch"
            elif event["declared_outcome"] == "unknown":
                disposition = "unresolved_outcome"
            elif not negative:
                disposition = "no_declared_negative_invariant"
            elif event["declared_outcome"] == "accepted":
                disposition = "candidate_declared_stale_check_conflict"
            else:
                disposition = "declared_reject_consistent"
            projections.append(
                {
                    "event_id": event["event_id"],
                    "event_index": index,
                    "check_event_id": event["check_event_id"],
                    "checked_version": check["version"],
                    "current_version": versions[ref],
                    "intervening_mutation_count": intervening,
                    "negative_predicate": "stale_check_used" if negative else None,
                    "disposition": disposition,
                }
            )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": model,
        "use_count": len(projections),
        "projections": projections,
        "flags": {
            "schedule_verified": False,
            "target_state_verified": False,
            "concurrency_observed": False,
            "toctou_exploitation_verified": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "The event order, version values, policy and outcomes are caller assertions.",
            "A sequential supplied schedule does not prove runtime concurrency.",
            "A declared stale-check conflict does not prove target behavior.",
            "No target, network, process, credential or filesystem is accessed.",
        ],
    }
    digest = "sha256:" + hashlib.sha256(
        (DOMAIN + "\n" + _canonical(body)).encode("ascii")
    ).hexdigest()
    return json.loads(_canonical({
        **body, "analysis_id": "TSS-" + digest[7:39].upper(), "analysis_sha256": digest
    }))


@dataclass(frozen=True, slots=True, init=False)
class ToctouStateSchedule:
    """Immutable report replayed from a supplied version schedule."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise ToctouStateScheduleError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise ToctouStateScheduleError("Report differs from embedded source replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_toctou_state_schedule(model: Any) -> ToctouStateSchedule:
    """Compare supplied check-use events without exercising a target."""
    return ToctouStateSchedule(_derive(model))


def verify_supplied_toctou_state_schedule(
    report: Any, *, model: Any
) -> ToctouStateSchedule:
    if type(report) is not ToctouStateSchedule:
        raise ToctouStateScheduleError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise ToctouStateScheduleError("Report differs from supplied source replay")
    return ToctouStateSchedule(expected)
