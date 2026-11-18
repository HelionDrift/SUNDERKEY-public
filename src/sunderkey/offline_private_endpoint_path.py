"""Compare supplied private-endpoint intent with DNS and route scope labels."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "cloud_supplied_private_endpoint_path_scope"
PROFILE_ID = "AOE-GC-D14-S12"
CAPABILITY_ID = "army.gc.d14.s12"
VECTOR_ID = "AV-GC-D14-S12-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D14-S12"
WAVE_ID = "IW2-015"
COMMANDER_ID = "AOE-GC-D14-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:78a6745b36e9d9030878c84d3bef7347c3703a00f9ae93d690325b2a278d1e58"
DOMAIN = "sunderkey.offline-private-endpoint-path.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
SCOPES = {"private", "public", "unknown"}
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


class PrivateEndpointPathError(ValueError):
    """A supplied private-endpoint path or original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "paths"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise PrivateEndpointPathError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    paths = core.bounded_list(model["paths"], 32, "paths")
    if not paths:
        raise PrivateEndpointPathError("At least one path is required")
    seen: set[str] = set()
    for item in paths:
        row = core.exact(
            item,
            {
                "path_id",
                "service_id",
                "private_only_required",
                "dns_target_scope",
                "route_scope",
                "context_complete",
            },
            "path",
        )
        path_id = core.identifier(row["path_id"], "path ID")
        if path_id in seen:
            raise PrivateEndpointPathError("Duplicate path ID")
        seen.add(path_id)
        core.identifier(row["service_id"], "service ID")
        core.boolean(row["private_only_required"], "private-only requirement")
        core.boolean(row["context_complete"], "context completeness")
        for key in ("dns_target_scope", "route_scope"):
            core.choice(row[key], SCOPES, key)
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    projections = []
    for row in model["paths"]:
        public_label = "public" in (row["dns_target_scope"], row["route_scope"])
        uncertain = "unknown" in (row["dns_target_scope"], row["route_scope"])
        disposition = (
            "unknown"
            if not row["context_complete"] or uncertain
            else "candidate_declared_private_path_public_scope"
            if row["private_only_required"] and public_label
            else "no_declared_private_path_public_scope"
        )
        projections.append(
            {
                "path_id": row["path_id"],
                "service_id": row["service_id"],
                "dns_target_scope": row["dns_target_scope"],
                "route_scope": row["route_scope"],
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
        "path_count": len(model["paths"]),
        "path_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"] == "unknown" for row in projections),
        "source_authenticated": False,
        "dns_queried": False,
        "routes_queried": False,
        "reachability_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Service policy, DNS scope and route scope are caller-supplied labels.",
            "No provider configuration, DNS answer, route table or packet is inspected.",
            "Public scope labels do not prove reachability, exposure or unauthorized access.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="PEP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class PrivateEndpointPathReport:
    """Unsigned path projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise PrivateEndpointPathError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> PrivateEndpointPathReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_private_endpoint_paths(model: Any) -> PrivateEndpointPathReport:
    return PrivateEndpointPathReport._owned(_derive(model))


def verify_supplied_private_endpoint_paths(report: Any, *, model: Any) -> PrivateEndpointPathReport:
    if type(report) is not PrivateEndpointPathReport:
        raise PrivateEndpointPathError("Exact private-path wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise PrivateEndpointPathError("Report differs from separate original model")
    return PrivateEndpointPathReport._owned(expected)


def verify_supplied_private_endpoint_paths_bytes(
    report_bytes: bytes, *, model: Any
) -> PrivateEndpointPathReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise PrivateEndpointPathError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise PrivateEndpointPathError("Exported report differs from original replay")
    return PrivateEndpointPathReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-private-endpoints",
        "paths": [
            {
                "path_id": "path-one",
                "service_id": "service-one",
                "private_only_required": True,
                "dns_target_scope": "public",
                "route_scope": "private",
                "context_complete": True,
            },
            {
                "path_id": "path-two",
                "service_id": "service-two",
                "private_only_required": True,
                "dns_target_scope": "private",
                "route_scope": "private",
                "context_complete": True,
            },
        ],
    }
