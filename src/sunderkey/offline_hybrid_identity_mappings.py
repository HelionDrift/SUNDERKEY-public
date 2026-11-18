"""Compare supplied AD FS and AD Connect mapping declarations."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "supplied_hybrid_identity_mappings"
PROFILE_ID = "AOE-GC-D11-S17"
CAPABILITY_ID = "army.gc.d11.s17"
VECTOR_ID = "AV-GC-D11-S17-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D11-S17"
WAVE_ID = "IW2-017"
COMMANDER_ID = "AOE-GC-D11-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:892143e0c607804a6d72cffedef3683a70580c90e88225d50ee82be4bc716c8a"
DOMAIN = "sunderkey.offline-hybrid-identity-mappings.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
REF = re.compile(r"(?:source-anchor|target-anchor|issuer|relying-party):sha256:[0-9a-f]{64}\Z")
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class HybridIdentityMappingsError(ValueError):
    """A supplied hybrid-identity declaration or replay was refused."""


def _ref(value: Any, kind: str) -> str:
    if type(value) is not str or REF.fullmatch(value) is None or not value.startswith(kind + ":"):
        raise HybridIdentityMappingsError(f"{kind} reference must be an opaque digest")
    return value


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "policy", "sync_mappings",
         "federation_routes"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise HybridIdentityMappingsError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    policy = core.exact(
        model["policy"],
        {"require_unique_source_anchor", "require_unique_target_anchor", "allowed_issuer_refs"},
        "policy",
    )
    core.boolean(policy["require_unique_source_anchor"], "source anchor policy")
    core.boolean(policy["require_unique_target_anchor"], "target anchor policy")
    issuers = core.bounded_list(policy["allowed_issuer_refs"], 32, "allowed issuers")
    for issuer in issuers:
        _ref(issuer, "issuer")
    if len(issuers) != len(set(issuers)):
        raise HybridIdentityMappingsError("Duplicate allowed issuer")
    mappings = core.bounded_list(model["sync_mappings"], 64, "sync mappings")
    routes = core.bounded_list(model["federation_routes"], 64, "federation routes")
    if not mappings and not routes:
        raise HybridIdentityMappingsError("At least one mapping or route is required")
    mapping_ids: set[str] = set()
    for item in mappings:
        mapping = core.exact(
            item, {"mapping_id", "source_anchor_ref", "target_anchor_ref", "enabled"},
            "mapping",
        )
        mapping_id = core.identifier(mapping["mapping_id"], "mapping ID")
        if mapping_id in mapping_ids:
            raise HybridIdentityMappingsError("Duplicate mapping ID")
        mapping_ids.add(mapping_id)
        _ref(mapping["source_anchor_ref"], "source-anchor")
        _ref(mapping["target_anchor_ref"], "target-anchor")
        core.boolean(mapping["enabled"], "mapping enabled")
    route_ids: set[str] = set()
    for item in routes:
        route = core.exact(
            item, {"route_id", "issuer_ref", "relying_party_ref", "enabled"}, "route"
        )
        route_id = core.identifier(route["route_id"], "route ID")
        if route_id in route_ids:
            raise HybridIdentityMappingsError("Duplicate route ID")
        route_ids.add(route_id)
        _ref(route["issuer_ref"], "issuer")
        _ref(route["relying_party_ref"], "relying-party")
        core.boolean(route["enabled"], "route enabled")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    complete = model["inventory_complete"]
    policy = model["policy"]
    sources: dict[str, int] = {}
    targets: dict[str, int] = {}
    for mapping in model["sync_mappings"]:
        if mapping["enabled"]:
            source = mapping["source_anchor_ref"]
            target = mapping["target_anchor_ref"]
            sources[source] = sources.get(source, 0) + 1
            targets[target] = targets.get(target, 0) + 1
    rows: list[dict] = []
    candidates: list[dict] = []
    for mapping in model["sync_mappings"]:
        issues: list[str] = []
        if mapping["enabled"]:
            if policy["require_unique_source_anchor"] and sources[mapping["source_anchor_ref"]] > 1:
                issues.append("source_anchor_reused_across_enabled_mappings")
            if policy["require_unique_target_anchor"] and targets[mapping["target_anchor_ref"]] > 1:
                issues.append("target_anchor_reused_across_enabled_mappings")
        row = {
            "kind": "sync_mapping", "item_id": mapping["mapping_id"],
            "policy_issues": issues if complete and mapping["enabled"] else None,
            "row_disposition": (
                "unknown_incomplete_inventory" if not complete else
                "evaluated" if mapping["enabled"] else "not_applicable"
            ),
        }
        rows.append(row)
        if complete and issues:
            candidates.append({"kind": "sync_mapping", "item_id": mapping["mapping_id"],
                               "policy_issues": issues})
    allowed = set(policy["allowed_issuer_refs"])
    for route in model["federation_routes"]:
        issues = []
        if route["enabled"] and route["issuer_ref"] not in allowed:
            issues.append("issuer_outside_supplied_allowlist")
        row = {
            "kind": "federation_route", "item_id": route["route_id"],
            "policy_issues": issues if complete and route["enabled"] else None,
            "row_disposition": (
                "unknown_incomplete_inventory" if not complete else
                "evaluated" if route["enabled"] else "not_applicable"
            ),
        }
        rows.append(row)
        if complete and issues:
            candidates.append({"kind": "federation_route", "item_id": route["route_id"],
                               "policy_issues": issues})
    applicable_count = sum(row["row_disposition"] == "evaluated" for row in rows)
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "mapping_count": len(model["sync_mappings"]),
        "route_count": len(model["federation_routes"]),
        "applicable_declaration_count": applicable_count,
        "rows": rows,
        "candidates": candidates,
        "candidate_count": len(candidates),
        "unknown_count": len(rows) if not complete else 0,
        "disposition": "unknown" if not complete else (
            "no_applicable_supplied_declarations" if not applicable_count else
            "candidate_supplied_mapping_mismatch" if candidates else "supplied_mappings_match"
        ),
        "federation_or_sync_state_authenticated": False,
        "token_or_claim_validated": False,
        "effective_access_verified": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Mappings, routes, issuer allowlist and completeness are caller-supplied.",
            "Opaque anchor and issuer labels are compared without resolving identities or tokens.",
            "No signing key, token, credential, identity provider, network or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="HIM-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class HybridIdentityMappingsReport:
    """Unsigned mapping projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise HybridIdentityMappingsError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> HybridIdentityMappingsReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_hybrid_identity_mappings(model: Any) -> HybridIdentityMappingsReport:
    return HybridIdentityMappingsReport._owned(_derive(model))


def verify_supplied_hybrid_identity_mappings(
    report: Any, *, model: Any
) -> HybridIdentityMappingsReport:
    if type(report) is not HybridIdentityMappingsReport:
        raise HybridIdentityMappingsError("Exact hybrid-identity wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise HybridIdentityMappingsError("Report differs from original-model replay")
    return HybridIdentityMappingsReport._owned(expected)


def verify_supplied_hybrid_identity_mappings_bytes(
    report_bytes: bytes, *, model: Any
) -> HybridIdentityMappingsReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    expected = _derive(model)
    if type(report) is not dict or core.canonical(report) != core.canonical(expected):
        raise HybridIdentityMappingsError("Exported report differs from original-model replay")
    return HybridIdentityMappingsReport._owned(expected)


def component_fixture() -> dict:
    issuer_a = "issuer:sha256:" + "a" * 64
    issuer_b = "issuer:sha256:" + "b" * 64
    target = "target-anchor:sha256:" + "c" * 64
    return {
        "schema_version": 1,
        "source_id": "synthetic-hybrid-identity",
        "inventory_complete": True,
        "policy": {
            "require_unique_source_anchor": True,
            "require_unique_target_anchor": True,
            "allowed_issuer_refs": [issuer_a],
        },
        "sync_mappings": [
            {"mapping_id": "map-a", "source_anchor_ref": "source-anchor:sha256:" + "d" * 64,
             "target_anchor_ref": target, "enabled": True},
            {"mapping_id": "map-b", "source_anchor_ref": "source-anchor:sha256:" + "e" * 64,
             "target_anchor_ref": target, "enabled": True},
        ],
        "federation_routes": [
            {"route_id": "route-a", "issuer_ref": issuer_b,
             "relying_party_ref": "relying-party:sha256:" + "f" * 64, "enabled": True},
        ],
    }
