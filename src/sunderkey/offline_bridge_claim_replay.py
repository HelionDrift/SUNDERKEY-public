"""Group supplied accepted bridge claims by finalized source message."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "bridge_supplied_duplicate_accepted_claims"
PROFILE_ID = "AOE-GB-D10-S04"
CAPABILITY_ID = "army.gb.d10.s04"
VECTOR_ID = "AV-GB-D10-S04-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D10-S04"
WAVE_ID = "IW2-004"
COMMANDER_ID = "AOE-GB-D10-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:d1bd2043ed30610d299b9dd33b5acf68dff8104fe56263256bb773c8cf8f584a"
DOMAIN = "sunderkey.offline-bridge-claim-replay.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority",
        "execution",
        "filesystem",
        "network",
        "process",
        "provider",
        "credentials",
        "target_interaction",
        "finding_publication",
        "qualification",
    )
}


class BridgeClaimReplayError(ValueError):
    """A supplied bridge claim ledger or replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "context_complete", "messages"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise BridgeClaimReplayError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["context_complete"], "context completeness")
    messages = core.bounded_list(model["messages"], 32, "messages")
    if not messages:
        raise BridgeClaimReplayError("At least one message is required")
    message_keys: set[tuple[str, str]] = set()
    for item in messages:
        message = core.exact(
            item,
            {"source_chain_id", "message_id", "payload_sha256", "finalized", "claims"},
            "message",
        )
        source_chain_id = core.identifier(message["source_chain_id"], "source chain ID")
        message_id = core.identifier(message["message_id"], "message ID")
        key = (source_chain_id, message_id)
        if key in message_keys:
            raise BridgeClaimReplayError("Duplicate source message identity")
        message_keys.add(key)
        digest = message["payload_sha256"]
        if type(digest) is not str or _DIGEST.fullmatch(digest) is None:
            raise BridgeClaimReplayError("Payload digest must be lowercase SHA-256")
        if message["finalized"] is not None:
            core.boolean(message["finalized"], "finality")
        claims = core.bounded_list(message["claims"], 16, "claims")
        for item_claim in claims:
            claim = core.exact(item_claim, {"claim_id", "destination_chain_id", "outcome"}, "claim")
            core.identifier(claim["claim_id"], "claim ID")
            core.identifier(claim["destination_chain_id"], "destination chain ID")
            core.choice(claim["outcome"], {"accepted", "rejected", "unknown"}, "claim outcome")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    projections = []
    for message in model["messages"]:
        by_destination: dict[str, list[str]] = defaultdict(list)
        uncertain = False
        for claim in message["claims"]:
            if claim["outcome"] == "accepted":
                by_destination[claim["destination_chain_id"]].append(claim["claim_id"])
            elif claim["outcome"] == "unknown":
                uncertain = True
        duplicates = [
            {"destination_chain_id": destination, "accepted_claim_ids": sorted(ids)}
            for destination, ids in sorted(by_destination.items())
            if len(ids) > 1
        ]
        disposition = (
            "unknown"
            if not model["context_complete"] or message["finalized"] is not True or uncertain
            else "candidate_declared_duplicate_accepted_claim"
            if duplicates
            else "no_declared_duplicate_accepted_claim"
        )
        projections.append(
            {
                "source_chain_id": message["source_chain_id"],
                "message_id": message["message_id"],
                "accepted_claim_count": sum(map(len, by_destination.values())),
                "duplicate_destination_groups": duplicates,
                "disposition": disposition,
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "message_count": len(model["messages"]),
        "message_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"] == "unknown" for row in projections),
        "source_authenticated": False,
        "chain_queried": False,
        "finality_verified": False,
        "asset_effect_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Message identity, payload digests, finality and claim outcomes are caller-supplied.",
            "Only repeated accepted claims for one source message and destination are compared.",
            "Legitimate retries, idempotent claims and bridge-specific rules are not evaluated.",
            "A duplicate candidate does not prove minted assets, loss or chain execution.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="BCR-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class BridgeClaimReplayReport:
    """Unsigned claim projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise BridgeClaimReplayError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> BridgeClaimReplayReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_bridge_claims(model: Any) -> BridgeClaimReplayReport:
    return BridgeClaimReplayReport._owned(_derive(model))


def verify_supplied_bridge_claims(report: Any, *, model: Any) -> BridgeClaimReplayReport:
    if type(report) is not BridgeClaimReplayReport:
        raise BridgeClaimReplayError("Exact bridge-claim wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise BridgeClaimReplayError("Report differs from separate original model")
    return BridgeClaimReplayReport._owned(expected)


def verify_supplied_bridge_claims_bytes(
    report_bytes: bytes, *, model: Any
) -> BridgeClaimReplayReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise BridgeClaimReplayError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise BridgeClaimReplayError("Exported report differs from original replay")
    return BridgeClaimReplayReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-bridge-claims",
        "context_complete": True,
        "messages": [
            {
                "source_chain_id": "chain-a",
                "message_id": "message-one",
                "payload_sha256": "sha256:" + "1" * 64,
                "finalized": True,
                "claims": [
                    {
                        "claim_id": "claim-one",
                        "destination_chain_id": "chain-b",
                        "outcome": "accepted",
                    },
                    {
                        "claim_id": "claim-two",
                        "destination_chain_id": "chain-b",
                        "outcome": "accepted",
                    },
                    {
                        "claim_id": "claim-three",
                        "destination_chain_id": "chain-c",
                        "outcome": "rejected",
                    },
                ],
            }
        ],
    }
