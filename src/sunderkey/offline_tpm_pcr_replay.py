"""Replay supplied SHA-256 PCR extensions without TPM or platform access."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "tpm_supplied_sha256_pcr_replay"
PROFILE_ID = "AOE-GD-D24-S08"
CAPABILITY_ID = "army.gd.d24.s08"
VECTOR_ID = "AV-GD-D24-S08-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D24-S08"
WAVE_ID = "IW2-008"
COMMANDER_ID = "AOE-GD-D24-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:dfe98483f2e34bdbc37740ef402e6213d2c5808239802dad346d3e424fe398dc"
DOMAIN = "sunderkey.offline-tpm-pcr-replay.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
_HEX_256 = re.compile(r"[0-9a-f]{64}\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class TpmPcrReplayError(ValueError):
    """A supplied PCR model or original-model replay is invalid."""


def _hex256(value: Any, label: str) -> str:
    if type(value) is not str or _HEX_256.fullmatch(value) is None:
        raise TpmPcrReplayError(f"{label} must be 64 lowercase hex characters")
    return value


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "log_complete", "pcr_index",
            "initial_pcr_hex", "expected_pcr_hex", "events",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise TpmPcrReplayError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["log_complete"], "log completeness")
    if type(model["pcr_index"]) is not int or not 0 <= model["pcr_index"] <= 23:
        raise TpmPcrReplayError("PCR index must be within 0 through 23")
    _hex256(model["initial_pcr_hex"], "initial PCR")
    _hex256(model["expected_pcr_hex"], "expected PCR")
    events = core.bounded_list(model["events"], 64, "events")
    if not events:
        raise TpmPcrReplayError("At least one event digest is required")
    seen: set[str] = set()
    for item in events:
        row = core.exact(item, {"event_id", "digest_hex"}, "event")
        event_id = core.identifier(row["event_id"], "event ID")
        _hex256(row["digest_hex"], "event digest")
        if event_id in seen:
            raise TpmPcrReplayError("Duplicate event ID")
        seen.add(event_id)
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    pcr = bytes.fromhex(model["initial_pcr_hex"])
    for event in model["events"]:
        pcr = hashlib.sha256(pcr + bytes.fromhex(event["digest_hex"])).digest()
    computed_hex = pcr.hex()
    matches = computed_hex == model["expected_pcr_hex"]
    disposition = (
        "unknown"
        if not model["log_complete"]
        else "candidate_supplied_pcr_replay_mismatch"
        if not matches
        else "supplied_pcr_replay_matches"
    )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "pcr_index": model["pcr_index"],
        "bank_algorithm": "sha256",
        "event_count": len(model["events"]),
        "computed_pcr_hex": computed_hex,
        "expected_pcr_matches": matches,
        "disposition": disposition,
        "candidate_count": int(model["log_complete"] and not matches),
        "unknown_count": int(not model["log_complete"]),
        "source_authenticated": False,
        "tpm_contacted": False,
        "quote_verified": False,
        "boot_integrity_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "PCR index, initial value, digests, expected value and completeness are supplied.",
            "Event data and log binary structure are not parsed or authenticated.",
            "No TPM quote, nonce, certificate, platform measurement or live PCR is verified.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="PCR-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class TpmPcrReplayReport:
    """Unsigned PCR arithmetic projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise TpmPcrReplayError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> TpmPcrReplayReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_tpm_pcr(model: Any) -> TpmPcrReplayReport:
    return TpmPcrReplayReport._owned(_derive(model))


def verify_supplied_tpm_pcr(report: Any, *, model: Any) -> TpmPcrReplayReport:
    if type(report) is not TpmPcrReplayReport:
        raise TpmPcrReplayError("Exact TPM PCR wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise TpmPcrReplayError("Report differs from separate original model")
    return TpmPcrReplayReport._owned(expected)


def verify_supplied_tpm_pcr_bytes(report_bytes: bytes, *, model: Any) -> TpmPcrReplayReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise TpmPcrReplayError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise TpmPcrReplayError("Exported report differs from original replay")
    return TpmPcrReplayReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-pcr-events",
        "log_complete": True,
        "pcr_index": 7,
        "initial_pcr_hex": "00" * 32,
        "expected_pcr_hex": "00" * 32,
        "events": [{"event_id": "boot-event-a", "digest_hex": "11" * 32}],
    }
