"""Compare supplied IEC 61850 publication and subscription references."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "iec61850_supplied_subscription_reference_consistency"
PROFILE_ID = "AOE-GD-D19-S19"
CAPABILITY_ID = "army.gd.d19.s19"
VECTOR_ID = "AV-GD-D19-S19-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D19-S19"
WAVE_ID = "IW2-003"
COMMANDER_ID = "AOE-GD-D19-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:0d360bfdc5b91f6fdddbf76cb5eb9ef8dfc10fcff67379ac6db139c7e264762e"
DOMAIN = "sunderkey.offline-iec61850-subscription-refs.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
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


class Iec61850SubscriptionRefError(ValueError):
    """A supplied IED relation model or original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version",
            "source_id",
            "station_id",
            "context_complete",
            "publications",
            "subscriptions",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise Iec61850SubscriptionRefError("Unsupported model version")
    for key in ("source_id", "station_id"):
        core.identifier(model[key], key)
    core.boolean(model["context_complete"], "context completeness")
    publications = core.bounded_list(model["publications"], 64, "publications")
    subscriptions = core.bounded_list(model["subscriptions"], 64, "subscriptions")
    if not publications or not subscriptions:
        raise Iec61850SubscriptionRefError("Publications and subscriptions are required")
    seen_publications: set[str] = set()
    for item in publications:
        row = core.exact(
            item,
            {"publication_id", "publisher_ied_id", "dataset_id"},
            "publication",
        )
        publication_id = core.identifier(row["publication_id"], "publication ID")
        if publication_id in seen_publications:
            raise Iec61850SubscriptionRefError("Duplicate publication ID")
        seen_publications.add(publication_id)
        core.identifier(row["publisher_ied_id"], "publisher IED ID")
        core.identifier(row["dataset_id"], "dataset ID")
    seen_subscriptions: set[str] = set()
    for item in subscriptions:
        row = core.exact(
            item,
            {"subscription_id", "subscriber_ied_id", "publication_id", "dataset_id"},
            "subscription",
        )
        subscription_id = core.identifier(row["subscription_id"], "subscription ID")
        if subscription_id in seen_subscriptions:
            raise Iec61850SubscriptionRefError("Duplicate subscription ID")
        seen_subscriptions.add(subscription_id)
        for key in ("subscriber_ied_id", "publication_id", "dataset_id"):
            core.identifier(row[key], key)
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    publications = {row["publication_id"]: row for row in model["publications"]}
    projections = []
    for row in model["subscriptions"]:
        publisher = publications.get(row["publication_id"])
        mismatch = (
            "missing_declared_publication"
            if publisher is None
            else "dataset_reference_mismatch"
            if row["dataset_id"] != publisher["dataset_id"]
            else "none"
        )
        disposition = (
            "unknown"
            if not model["context_complete"]
            else "candidate_declared_subscription_reference_gap"
            if mismatch != "none"
            else "no_declared_subscription_reference_gap"
        )
        projections.append(
            {
                "subscription_id": row["subscription_id"],
                "subscriber_ied_id": row["subscriber_ied_id"],
                "publication_id": row["publication_id"],
                "mismatch": mismatch,
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
        "station_id": model["station_id"],
        "publication_count": len(model["publications"]),
        "subscription_count": len(model["subscriptions"]),
        "subscription_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"] == "unknown" for row in projections),
        "source_authenticated": False,
        "scl_parsed": False,
        "ied_queried": False,
        "goose_traffic_observed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Station, IED, publication, dataset and subscription IDs are caller-supplied.",
            "No SCL document, IED configuration or GOOSE traffic is parsed or observed.",
            "A declared reference gap does not prove a protection failure or exploit path.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="ISR-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class Iec61850SubscriptionRefReport:
    """Unsigned IED relation projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise Iec61850SubscriptionRefError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> Iec61850SubscriptionRefReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_iec61850_subscriptions(model: Any) -> Iec61850SubscriptionRefReport:
    return Iec61850SubscriptionRefReport._owned(_derive(model))


def verify_supplied_iec61850_subscriptions(
    report: Any, *, model: Any
) -> Iec61850SubscriptionRefReport:
    if type(report) is not Iec61850SubscriptionRefReport:
        raise Iec61850SubscriptionRefError("Exact IED relation wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise Iec61850SubscriptionRefError("Report differs from separate original model")
    return Iec61850SubscriptionRefReport._owned(expected)


def verify_supplied_iec61850_subscriptions_bytes(
    report_bytes: bytes, *, model: Any
) -> Iec61850SubscriptionRefReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise Iec61850SubscriptionRefError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise Iec61850SubscriptionRefError("Exported report differs from original replay")
    return Iec61850SubscriptionRefReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-iec61850-bindings",
        "station_id": "substation-one",
        "context_complete": True,
        "publications": [
            {"publication_id": "pub-one", "publisher_ied_id": "ied-a", "dataset_id": "set-a"}
        ],
        "subscriptions": [
            {
                "subscription_id": "sub-one",
                "subscriber_ied_id": "ied-b",
                "publication_id": "pub-one",
                "dataset_id": "set-b",
            }
        ],
    }
