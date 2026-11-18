"""Project supplied stream offsets and commits without broker access."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from collections import Counter
from typing import Any

COMPONENT_ID = "supplied_stream_offset_projection"
PROFILE_ID = "AOE-GB-D07-S08"
CAPABILITY_ID = "army.gb.d07.s08"
VECTOR_ID = "AV-GB-D07-S08-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D07-S08"
WAVE_ID = "IW2-008"
COMMANDER_ID = "AOE-GB-D07-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:21d3a5fc1133398930507d01dfebea14c7f18355b0a03c8288f6cc674541c032"
SEMANTICS_PROFILE = "supplied-stream-offsets-v1"
DOMAIN = "sunderkey.offline-stream-offset-projection.v1"
MAX_OFFSETS = 512
MAX_COMMITS = 256
MAX_OFFSET = 1_000_000_000_000
MAX_DOCUMENT_BYTES = 524_288
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_PARTITION = re.compile(r"partition:sha256:[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "broker",
        "credential",
        "execution",
        "filesystem",
        "network",
        "provider",
        "publication",
        "qualification",
        "target",
    ),
    "none",
)


class StreamOffsetProjectionError(ValueError):
    """A supplied stream model or replay report was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise StreamOffsetProjectionError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise StreamOffsetProjectionError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise StreamOffsetProjectionError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise StreamOffsetProjectionError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise StreamOffsetProjectionError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise StreamOffsetProjectionError("Native JSON text keys are required")
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
        raise StreamOffsetProjectionError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise StreamOffsetProjectionError(f"{label} fields are invalid")


def _offset(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_OFFSET:
        raise StreamOffsetProjectionError(f"{label} offset is invalid")
    return value


def _plan(model: Any) -> dict:
    model = json.loads(_canonical(model))
    _fields(
        model,
        {
            "schema_version",
            "semantics_profile",
            "partition_ref",
            "range_start",
            "range_end",
            "history_complete",
            "observed_offsets",
            "commits",
            "maximum_lag",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise StreamOffsetProjectionError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise StreamOffsetProjectionError("Semantics profile is invalid")
    if (
        type(model["partition_ref"]) is not str
        or _PARTITION.fullmatch(model["partition_ref"]) is None
    ):
        raise StreamOffsetProjectionError("Partition must be an opaque digest reference")
    start = _offset(model["range_start"], "Start")
    end = _offset(model["range_end"], "End")
    if end < start:
        raise StreamOffsetProjectionError("Declared range is inverted")
    _offset(model["maximum_lag"], "Maximum lag")
    if type(model["history_complete"]) is not bool:
        raise StreamOffsetProjectionError("History completeness must be an exact boolean")
    observed = model["observed_offsets"]
    commits = model["commits"]
    if type(observed) is not list or len(observed) > MAX_OFFSETS:
        raise StreamOffsetProjectionError("Observed offset count is invalid")
    if type(commits) is not list or len(commits) > MAX_COMMITS:
        raise StreamOffsetProjectionError("Commit count is invalid")
    for value in observed:
        if not start <= _offset(value, "Observed") <= end:
            raise StreamOffsetProjectionError("Observed offset is outside declared range")
    ids: set[str] = set()
    for row in commits:
        _fields(row, {"commit_id", "declared_processed_offset"}, "commit")
        commit_id = row["commit_id"]
        if type(commit_id) is not str or _ID.fullmatch(commit_id) is None:
            raise StreamOffsetProjectionError("Commit identifier is invalid")
        if commit_id in ids:
            raise StreamOffsetProjectionError("Duplicate commit identifier")
        ids.add(commit_id)
        if not start <= _offset(row["declared_processed_offset"], "Commit") <= end:
            raise StreamOffsetProjectionError("Commit offset is outside declared range")
    return model


def _derive(model: Any) -> dict:
    plan = _plan(model)
    observed = plan["observed_offsets"]
    unique = sorted(set(observed))
    duplicate_offsets = sorted(value for value, count in Counter(observed).items() if count > 1)
    gaps: list[dict] = []
    next_expected = plan["range_start"]
    for value in unique:
        if value > next_expected:
            gaps.append({"start": next_expected, "end": value - 1})
        next_expected = value + 1
    if next_expected <= plan["range_end"]:
        gaps.append({"start": next_expected, "end": plan["range_end"]})
    regressions = []
    prior = None
    for row in plan["commits"]:
        current = row["declared_processed_offset"]
        if prior is not None and current < prior:
            regressions.append(row["commit_id"])
        prior = current
    latest_observed = max(unique) if unique else None
    latest_commit = plan["commits"][-1]["declared_processed_offset"] if plan["commits"] else None
    if latest_commit is None:
        lag = None
        commit_disposition = "no_supplied_commit"
    elif latest_observed is None:
        lag = None
        commit_disposition = "no_supplied_observation"
    elif latest_commit > latest_observed:
        lag = None
        commit_disposition = "commit_ahead_of_supplied_observations"
    else:
        lag = latest_observed - latest_commit
        commit_disposition = (
            "within_supplied_lag" if lag <= plan["maximum_lag"] else "exceeds_supplied_lag"
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": plan,
        "observations": {
            "unique_offset_count": len(unique),
            "duplicate_offsets": duplicate_offsets,
            "unlisted_intervals": gaps,
            "unlisted_intervals_disposition": (
                "missing_in_declared_complete_history"
                if plan["history_complete"]
                else "unknown_incomplete_history"
            ),
            "commit_regression_ids": regressions,
            "latest_observed_offset": latest_observed,
            "latest_declared_processed_offset": latest_commit,
            "lag": lag,
            "commit_disposition": commit_disposition,
        },
        "flags": {
            "broker_state_verified": False,
            "consumer_processing_verified": False,
            "message_loss_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Offsets, order, commits, range, and completeness are caller-supplied.",
            "Unlisted intervals do not prove missing broker records or message loss.",
            "Commit lag is an abstract supplied-number difference, not processing state.",
            "No broker, consumer, provider, credential, network, or target is contacted.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "SOP-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class StreamOffsetProjection:
    """Immutable report replayed from supplied offset declarations."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise StreamOffsetProjectionError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise StreamOffsetProjectionError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_stream_offsets(model: Any) -> StreamOffsetProjection:
    """Compare only supplied offsets and declared processing commits."""
    return StreamOffsetProjection(_derive(model))


def verify_supplied_stream_offsets(report: Any, *, model: Any) -> StreamOffsetProjection:
    if type(report) is not StreamOffsetProjection:
        raise StreamOffsetProjectionError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise StreamOffsetProjectionError("Report differs from supplied model replay")
    return StreamOffsetProjection(expected)
