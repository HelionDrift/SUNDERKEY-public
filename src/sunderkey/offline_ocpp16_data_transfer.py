"""Project a bounded synthetic OCPP 1.6 DataTransfer request envelope."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "transport_supplied_ocpp16_data_transfer_projection"
PROFILE_ID = "AOE-GD-D25-S04"
CAPABILITY_ID = "army.gd.d25.s04"
VECTOR_ID = "AV-GD-D25-S04-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D25-S04"
WAVE_ID = "IW2-004"
COMMANDER_ID = "AOE-GD-D25-CMD"
GROUP_OWNER_ID = "AOE-HQ-06"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:c1a88a3d898cb33e6d408c2d35871fea52db790fdc3123da9b829757b52b3bb6"
DOMAIN = "sunderkey.offline-ocpp16-data-transfer.v1"
MAX_MODEL_BYTES = 4_096
MAX_REPORT_BYTES = 32_768
VENDOR_ID = re.compile(
    r"[a-z0-9]+(?:-[a-z0-9]+)*(?:\.[a-z0-9]+(?:-[a-z0-9]+)*)+\Z"
)
MESSAGE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class Ocpp16DataTransferError(ValueError):
    """A supplied request model or original-model replay is invalid."""


def _canonical(value: Any) -> str:
    try:
        result = json.dumps(
            value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise Ocpp16DataTransferError("Model must be bounded native JSON") from exc
    if len(result) > MAX_MODEL_BYTES:
        raise Ocpp16DataTransferError("Model exceeds byte bound")
    return result


def _hash_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _derive(value: Any) -> dict:
    model_text = _canonical(value)
    model = core.exact(
        json.loads(model_text),
        {"schema_version", "source_id", "synthetic_fixture", "request"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise Ocpp16DataTransferError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise Ocpp16DataTransferError("Only synthetic fixtures are accepted")
    request = model["request"]
    if type(request) is not list or len(request) != 4:
        raise Ocpp16DataTransferError("Four-element OCPP CALL request required")
    message_type, unique_id, action, payload = request
    if type(message_type) is not int or message_type != 2 or action != "DataTransfer":
        raise Ocpp16DataTransferError("OCPP 1.6 DataTransfer CALL required")
    if type(unique_id) is not str or MESSAGE_ID.fullmatch(unique_id) is None:
        raise Ocpp16DataTransferError("Bounded synthetic unique ID required")
    if type(payload) is not dict or not {"vendorId"} <= payload.keys():
        raise Ocpp16DataTransferError("DataTransfer vendorId is required")
    if not payload.keys() <= {"vendorId", "messageId", "data"}:
        raise Ocpp16DataTransferError("DataTransfer payload fields are invalid")
    vendor_id = payload["vendorId"]
    if type(vendor_id) is not str or len(vendor_id) > 255 or VENDOR_ID.fullmatch(vendor_id) is None:
        raise Ocpp16DataTransferError("Bounded reverse-domain vendorId required")
    message_id = payload.get("messageId")
    if message_id is not None and (
        type(message_id) is not str or MESSAGE_ID.fullmatch(message_id) is None
    ):
        raise Ocpp16DataTransferError("Optional messageId is invalid")
    data = payload.get("data")
    if data is not None and (type(data) is not str or len(data) > 1_024):
        raise Ocpp16DataTransferError("Optional bounded data string is invalid")
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_id": COMMANDER_ID,
        "group_owner_id": GROUP_OWNER_ID,
        "independent_validator_id": INDEPENDENT_VALIDATOR_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "synthetic_fixture_asserted": True,
        "call_message_type": message_type,
        "action": action,
        "unique_id_sha256": _hash_text(unique_id),
        "vendor_id_sha256": _hash_text(vendor_id),
        "message_id_present": message_id is not None,
        "message_id_sha256": _hash_text(message_id) if message_id is not None else None,
        "data_present": data is not None,
        "data_sha256": _hash_text(data) if data is not None else None,
        "request_envelope_valid": True,
        "vendor_identity_verified": False,
        "customization_agreement_verified": False,
        "receiver_support_verified": False,
        "response_observed": False,
        "charging_effect_verified": False,
        "candidate_count": 0,
        "uncertainty": [
            "vendor_and_station_identity_unverified",
            "customization_contract_and_receiver_support_unverified",
            "response_and_charging_effect_unobserved",
        ],
        "unknown_count": 3,
        "disposition": "unknown",
        "source_authenticated": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Only a synthetic supplied OCPP 1.6 DataTransfer CALL envelope is inspected.",
            "Vendor, message, unique IDs and data are hashed rather than retained.",
            "Reverse-domain syntax does not authenticate a vendor or customization agreement.",
            "Data meaning, receiver support, response and charging state are unverified.",
            "No message is transmitted to a charging station or management system.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="ODT-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class Ocpp16DataTransferReport:
    """Unsigned OCPP request projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise Ocpp16DataTransferError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> Ocpp16DataTransferReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_ocpp16_data_transfer(model: Any) -> Ocpp16DataTransferReport:
    return Ocpp16DataTransferReport._owned(_derive(model))


def verify_supplied_ocpp16_data_transfer(
    report: Any, *, model: Any
) -> Ocpp16DataTransferReport:
    if type(report) is not Ocpp16DataTransferReport:
        raise Ocpp16DataTransferError("Exact OCPP wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise Ocpp16DataTransferError("Report differs from separate original model")
    return Ocpp16DataTransferReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-ocpp16-data-transfer",
        "synthetic_fixture": True,
        "request": [
            2, "synthetic-request-1", "DataTransfer",
            {
                "vendorId": "com.synthetic.example",
                "messageId": "offlineReview",
                "data": "synthetic-data",
            },
        ],
    }
