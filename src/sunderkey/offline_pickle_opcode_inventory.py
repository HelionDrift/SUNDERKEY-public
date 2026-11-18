"""Inventory supplied pickle opcodes without loading or executing a pickle."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import pickletools
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_pickle_opcode_inventory"
PROFILE_ID = "AOE-GE-D23-S03"
CAPABILITY_ID = "army.ge.d23.s03"
VECTOR_ID = "AV-GE-D23-S03-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D23-S03"
WAVE_ID = "IW2-017"
COMMANDER_ID = "AOE-GE-D23-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:d65f895a5f6dae3abca314c08d278d8eb8145c3b4be6d958451d619c19f7f9c0"
SEMANTICS_PROFILE = "python-pickletools-opcode-inventory-v1"
DOMAIN = "sunderkey.offline-pickle-opcode-inventory.v1"
MAX_SOURCE_BYTES = 8_192
MAX_DOCUMENT_BYTES = 32_768
MAX_OPCODES = 2_048
MAX_NATIVE_NODES = 2_048
MAX_NATIVE_DEPTH = 10
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_RESOLUTION = frozenset({"GLOBAL", "STACK_GLOBAL", "EXT1", "EXT2", "EXT4", "INST"})
_CONSTRUCTION = frozenset({"REDUCE", "OBJ", "NEWOBJ", "NEWOBJ_EX"})
_PERSISTENT = frozenset({"PERSID", "BINPERSID"})
_STATE = frozenset({"BUILD"})
_EFFECTS = dict.fromkeys(
    (
        "authority", "credential", "execution", "filesystem", "network",
        "publication", "qualification", "target",
    ),
    "none",
)


class PickleOpcodeInventoryError(ValueError):
    """A supplied pickle source or replay report was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise PickleOpcodeInventoryError("Native structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_DOCUMENT_BYTES:
                raise PickleOpcodeInventoryError("Native string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise PickleOpcodeInventoryError("Native integer bound exceeded")
            return
        if family not in (dict, list):
            raise PickleOpcodeInventoryError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise PickleOpcodeInventoryError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise PickleOpcodeInventoryError("Native JSON text keys are required")
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
        raise PickleOpcodeInventoryError("Document byte bound exceeded")
    return encoded


def _source(value: Any) -> tuple[dict, bytes]:
    model = json.loads(_canonical(value))
    if type(model) is not dict or model.keys() != {
        "schema_version", "semantics_profile", "source_id", "payload_b64"
    }:
        raise PickleOpcodeInventoryError("Source model fields are invalid")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise PickleOpcodeInventoryError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise PickleOpcodeInventoryError("Semantics profile is invalid")
    if type(model["source_id"]) is not str or _ID.fullmatch(model["source_id"]) is None:
        raise PickleOpcodeInventoryError("Source identifier is invalid")
    encoded = model["payload_b64"]
    if type(encoded) is not str or not 1 <= len(encoded) <= 11_000:
        raise PickleOpcodeInventoryError("Payload encoding bound exceeded")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PickleOpcodeInventoryError("Payload is not canonical base64") from exc
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise PickleOpcodeInventoryError("Payload is not canonical base64")
    if not 1 <= len(raw) <= MAX_SOURCE_BYTES:
        raise PickleOpcodeInventoryError("Payload byte bound exceeded")
    return model, raw


def _derive(value: Any) -> dict:
    model, raw = _source(value)
    counts: dict[str, int] = {}
    positions: dict[str, list[int]] = {
        "resolution": [], "construction": [], "persistent_id": [], "state_application": []
    }
    declared_protocol: int | None = None
    last_name = None
    last_position = -1
    opcode_count = 0
    try:
        for opcode, argument, position in pickletools.genops(raw):
            if opcode_count >= MAX_OPCODES:
                raise PickleOpcodeInventoryError("Opcode count exceeds bound")
            opcode_count += 1
            name = opcode.name
            counts[name] = counts.get(name, 0) + 1
            if name == "PROTO":
                if position != 0 or declared_protocol is not None:
                    raise PickleOpcodeInventoryError("Protocol marker is not unique at start")
                declared_protocol = argument
            if name in _RESOLUTION:
                positions["resolution"].append(position)
            if name in _CONSTRUCTION:
                positions["construction"].append(position)
            if name in _PERSISTENT:
                positions["persistent_id"].append(position)
            if name in _STATE:
                positions["state_application"].append(position)
            last_name, last_position = name, position
    except (ValueError, UnicodeError, IndexError, OverflowError) as exc:
        raise PickleOpcodeInventoryError("Supplied bytes are not supported pickle syntax") from exc
    if last_name != "STOP" or last_position + 1 != len(raw):
        raise PickleOpcodeInventoryError("Exactly one complete pickle stream is required")
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": model,
        "source_byte_count": len(raw),
        "declared_protocol": declared_protocol,
        "opcode_count": opcode_count,
        "opcode_inventory": [
            {"opcode": name, "count": count} for name, count in sorted(counts.items())
        ],
        "review_positions": positions,
        "review_disposition": (
            "candidate_dynamic_behavior_opcodes"
            if any(positions.values()) else "no_tracked_dynamic_behavior_opcodes"
        ),
        "flags": {
            "pickle_loaded": False,
            "target_deserializer_behavior_verified": False,
            "exploitability_verified": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Opcode syntax inventory does not validate stack semantics or application behavior.",
            "Tracked opcodes are review candidates, not evidence of an exploit.",
            "The source is never unpickled or supplied to an application.",
            "No file, credential, network, process, or target is accessed.",
        ],
    }
    digest = "sha256:" + hashlib.sha256(
        (DOMAIN + "\n" + _canonical(body)).encode("ascii")
    ).hexdigest()
    return json.loads(_canonical({
        **body, "analysis_id": "POI-" + digest[7:39].upper(), "analysis_sha256": digest
    }))


@dataclass(frozen=True, slots=True, init=False)
class PickleOpcodeInventory:
    """Immutable report replayed from supplied pickle bytes."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise PickleOpcodeInventoryError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise PickleOpcodeInventoryError("Report differs from embedded source replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_pickle_opcodes(model: Any) -> PickleOpcodeInventory:
    """Inventory opcode names and positions without invoking a deserializer."""
    return PickleOpcodeInventory(_derive(model))


def verify_supplied_pickle_opcodes(
    report: Any, *, model: Any
) -> PickleOpcodeInventory:
    if type(report) is not PickleOpcodeInventory:
        raise PickleOpcodeInventoryError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise PickleOpcodeInventoryError("Report differs from supplied source replay")
    return PickleOpcodeInventory(expected)
