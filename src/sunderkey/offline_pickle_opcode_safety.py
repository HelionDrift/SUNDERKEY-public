"""Inspect bounded supplied pickle opcodes without deserializing an artifact."""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core
from .offline_pickle_opcode_inventory import (
    PickleOpcodeInventoryError,
    SEMANTICS_PROFILE,
    analyze_supplied_pickle_opcodes as analyze_pickle_opcode_inventory,
)

COMPONENT_ID = "model_supplied_pickle_opcode_safety"
PROFILE_ID = "AOE-GD-D20-S07"
CAPABILITY_ID = "army.gd.d20.s07"
VECTOR_ID = "AV-GD-D20-S07-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D20-S07"
WAVE_ID = "IW2-012"
COMMANDER_ID = "AOE-GD-D20-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-35"
BLUEPRINT_SHA256 = "sha256:a07670162bdb0d996ed7a49a37284deca510cace2327c71d558bae78306f665b"
DOMAIN = "sunderkey.offline-pickle-opcode-safety.v1"
MAX_MODEL_BYTES = 262_144
MAX_REPORT_BYTES = 524_288
MAX_ARTIFACT_BYTES = 8_192
RISKY_OPCODES = frozenset({
    "GLOBAL", "STACK_GLOBAL", "REDUCE", "BUILD", "OBJ", "INST", "NEWOBJ",
    "NEWOBJ_EX", "EXT1", "EXT2", "EXT4", "PERSID", "BINPERSID",
})
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class PickleOpcodeSafetyError(ValueError):
    """A supplied pickle model or replay is invalid."""


def _decode_blob(value: Any) -> bytes:
    if type(value) is not str or not value or len(value) > 4 * MAX_ARTIFACT_BYTES // 3 + 8:
        raise PickleOpcodeSafetyError("Artifact must contain bounded canonical base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise PickleOpcodeSafetyError("Artifact base64 is invalid") from exc
    if not raw or len(raw) > MAX_ARTIFACT_BYTES or base64.b64encode(raw).decode("ascii") != value:
        raise PickleOpcodeSafetyError("Artifact base64 is noncanonical or oversized")
    return raw


def _model(value: Any) -> tuple[dict, str, dict[str, bytes]]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "artifacts"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise PickleOpcodeSafetyError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    rows = core.bounded_list(model["artifacts"], 8, "artifacts")
    if not rows:
        raise PickleOpcodeSafetyError("Artifacts must not be empty")
    blobs: dict[str, bytes] = {}
    for item in rows:
        row = core.exact(
            item, {"artifact_id", "blob_base64", "declared_loader_policy"}, "artifact"
        )
        artifact_id = core.identifier(row["artifact_id"], "artifact ID")
        if artifact_id in blobs:
            raise PickleOpcodeSafetyError("Duplicate artifact ID")
        core.choice(
            row["declared_loader_policy"], {"allowed", "denied", "unknown"},
            "declared loader policy",
        )
        blobs[artifact_id] = _decode_blob(row["blob_base64"])
    return model, core.canonical(model), blobs


def _inspect(raw: bytes, encoded: str, policy: str, artifact_id: str) -> dict:
    names: list[str] = []
    count = 0
    try:
        inventory = analyze_pickle_opcode_inventory({
            "schema_version": 1,
            "semantics_profile": SEMANTICS_PROFILE,
            "source_id": artifact_id,
            "payload_b64": encoded,
        }).to_dict()
        count = inventory["opcode_count"]
        names = sorted(
            row["opcode"] for row in inventory["opcode_inventory"]
            if row["opcode"] in RISKY_OPCODES
        )
    except PickleOpcodeInventoryError:
        disposition = "unknown_parse"
    else:
        if not names:
            disposition = "no_risky_opcode_observed_unverified"
        elif policy == "allowed":
            disposition = "candidate_risky_pickle_opcode"
        elif policy == "denied":
            disposition = "declared_denied_loader_with_risky_opcode"
        else:
            disposition = "unknown_loader_policy_with_risky_opcode"
    return {
        "artifact_id": artifact_id,
        "artifact_sha256": core.digest(raw),
        "artifact_bytes": len(raw),
        "opcode_count": count,
        "risky_opcode_names": names,
        "disposition": disposition,
    }


def _derive(value: Any) -> dict:
    model, model_text, blobs = _model(value)
    projections = [
        _inspect(
            blobs[row["artifact_id"]], row["blob_base64"],
            row["declared_loader_policy"], row["artifact_id"],
        )
        for row in model["artifacts"]
    ]
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "artifact_projections": projections,
        "candidate_count": sum(
            row["disposition"] == "candidate_risky_pickle_opcode" for row in projections
        ),
        "unknown_count": sum(row["disposition"].startswith("unknown") for row in projections),
        "source_authenticated": False,
        "loader_policy_verified": False,
        "deserialization_performed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Only supplied bounded pickle bytes are parsed; deserialization never occurs.",
            "Risky opcodes are syntactic indicators, not proof of code execution or impact.",
            "Loader policy is a caller declaration, not verified target behavior.",
            "Absence of listed opcodes does not prove a model artifact is safe.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="POS-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class PickleOpcodeSafetyReport:
    """Unsigned parse projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise PickleOpcodeSafetyError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> PickleOpcodeSafetyReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_pickle_opcodes(model: Any) -> PickleOpcodeSafetyReport:
    return PickleOpcodeSafetyReport._owned(_derive(model))


def verify_supplied_pickle_opcodes(
    report: Any, *, model: Any
) -> PickleOpcodeSafetyReport:
    if type(report) is not PickleOpcodeSafetyReport:
        raise PickleOpcodeSafetyError("Exact pickle-opcode wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise PickleOpcodeSafetyError("Report differs from separate original model")
    return PickleOpcodeSafetyReport._owned(expected)


def verify_supplied_pickle_opcodes_bytes(
    report_bytes: bytes, *, model: Any
) -> PickleOpcodeSafetyReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise PickleOpcodeSafetyError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise PickleOpcodeSafetyError("Exported report differs from original replay")
    return PickleOpcodeSafetyReport._owned(expected)


def component_fixture() -> dict:
    def encode(value: bytes) -> str:
        return base64.b64encode(value).decode("ascii")

    return {
        "schema_version": 1,
        "source_id": "synthetic-model-artifacts",
        "artifacts": [
            {
                "artifact_id": "integer-only", "blob_base64": encode(b"I1\n."),
                "declared_loader_policy": "allowed",
            },
            {
                "artifact_id": "global-allowed", "blob_base64": encode(b"cbuiltins\nlist\n."),
                "declared_loader_policy": "allowed",
            },
            {
                "artifact_id": "global-denied", "blob_base64": encode(b"cbuiltins\nlist\n."),
                "declared_loader_policy": "denied",
            },
            {
                "artifact_id": "truncated", "blob_base64": encode(b"I1\n"),
                "declared_loader_policy": "unknown",
            },
        ],
    }
