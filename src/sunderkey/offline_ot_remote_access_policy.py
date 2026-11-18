"""Project supplied OT remote-access paths against a declared control policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "ot_supplied_remote_access_policy_projection"
PROFILE_ID = "AOE-GD-D19-S15"
CAPABILITY_ID = "army.gd.d19.s15"
VECTOR_ID = "AV-GD-D19-S15-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D19-S15"
WAVE_ID = "IW2-025"
COMMANDER_ID = "AOE-GD-D19-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:c2a9d65799a29ab91ee20f5497651e1570a3c56a4230c0e34a86e004d922c67f"
DOMAIN = "sunderkey.offline-ot-remote-access-policy.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
ACTOR_KINDS = {"operator", "vendor", "iiot_gateway"}
CONTROLS = {"approved_identity", "mfa", "brokered", "session_logged"}
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class OtRemoteAccessPolicyError(ValueError):
    """A supplied remote-access model or original-model replay is invalid."""


def _choice_list(value: Any, allowed: set[str], maximum: int, label: str) -> list[str]:
    values = core.bounded_list(value, maximum, label)
    if not values:
        raise OtRemoteAccessPolicyError(f"{label} must be nonempty")
    for item in values:
        core.choice(item, allowed, label)
    if len(values) != len(set(values)):
        raise OtRemoteAccessPolicyError(f"{label} contains a duplicate")
    return values


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "policy", "paths"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise OtRemoteAccessPolicyError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    policy = core.exact(
        model["policy"],
        {"allowed_actor_kinds", "required_controls", "maximum_session_minutes"},
        "policy",
    )
    _choice_list(policy["allowed_actor_kinds"], ACTOR_KINDS, 3, "allowed actor kinds")
    required = _choice_list(policy["required_controls"], CONTROLS, 4, "required controls")
    if "approved_identity" not in required:
        raise OtRemoteAccessPolicyError("Policy must require approved identity")
    maximum = policy["maximum_session_minutes"]
    if type(maximum) is not int or not 1 <= maximum <= 1_440:
        raise OtRemoteAccessPolicyError("Maximum session minutes is out of bounds")
    paths = core.bounded_list(model["paths"], 64, "paths")
    if not paths:
        raise OtRemoteAccessPolicyError("At least one path is required")
    path_ids: set[str] = set()
    for item in paths:
        row = core.exact(
            item,
            {
                "path_id", "actor_kind", "principal_id", "destination_zone",
                "controls", "session_minutes", "expected_allowed",
            },
            "path",
        )
        path_id = core.identifier(row["path_id"], "path ID")
        if path_id in path_ids:
            raise OtRemoteAccessPolicyError("Duplicate path ID")
        path_ids.add(path_id)
        core.choice(row["actor_kind"], ACTOR_KINDS, "actor kind")
        core.identifier(row["principal_id"], "principal ID")
        core.identifier(row["destination_zone"], "destination zone")
        controls = core.bounded_list(row["controls"], 4, "path controls")
        for control in controls:
            core.choice(control, CONTROLS, "path control")
        if len(controls) != len(set(controls)):
            raise OtRemoteAccessPolicyError("Duplicate path control")
        minutes = row["session_minutes"]
        if type(minutes) is not int or not 1 <= minutes <= 1_440:
            raise OtRemoteAccessPolicyError("Session minutes is out of bounds")
        core.boolean(row["expected_allowed"], "expected allowed")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    policy = model["policy"]
    required = set(policy["required_controls"])
    allowed_kinds = set(policy["allowed_actor_kinds"])
    rows = []
    mismatches = []
    for path in model["paths"]:
        missing = sorted(required - set(path["controls"]))
        actor_allowed = path["actor_kind"] in allowed_kinds
        duration_allowed = path["session_minutes"] <= policy["maximum_session_minutes"]
        computed = actor_allowed and duration_allowed and not missing
        rows.append({
            "path_id": path["path_id"],
            "actor_kind": path["actor_kind"],
            "destination_zone": path["destination_zone"],
            "missing_required_controls": missing,
            "actor_kind_allowed": actor_allowed,
            "duration_within_limit": duration_allowed,
            "computed_allowed": computed,
            "expected_allowed": path["expected_allowed"],
        })
        if computed != path["expected_allowed"]:
            mismatches.append({
                "path_id": path["path_id"],
                "issue": "unexpected_declared_allow"
                if computed else "declared_path_missing_policy_controls",
            })
    disposition = (
        "unknown"
        if not model["inventory_complete"]
        else "candidate_supplied_remote_access_policy_mismatch"
        if mismatches
        else "supplied_remote_access_paths_match"
    )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "path_count": len(rows),
        "rows": rows,
        "mismatches": mismatches,
        "disposition": disposition,
        "candidate_count": len(mismatches) if model["inventory_complete"] else 0,
        "unknown_count": int(not model["inventory_complete"]),
        "source_authenticated": False,
        "policy_authenticated": False,
        "ot_network_contacted": False,
        "actual_access_or_session_verified": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Actor kinds, identities, zones, controls and expectations are caller-supplied.",
            "The policy is a supplied local rule, not a universal OT standard requirement.",
            "Authentication, session logging, enforcement and reachability are not verified.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="OTR-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class OtRemoteAccessPolicyReport:
    """Unsigned policy projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise OtRemoteAccessPolicyError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> OtRemoteAccessPolicyReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_ot_remote_access(model: Any) -> OtRemoteAccessPolicyReport:
    return OtRemoteAccessPolicyReport._owned(_derive(model))


def verify_supplied_ot_remote_access(
    report: Any, *, model: Any
) -> OtRemoteAccessPolicyReport:
    if type(report) is not OtRemoteAccessPolicyReport:
        raise OtRemoteAccessPolicyError("Exact OT remote-access wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise OtRemoteAccessPolicyError("Report differs from separate original model")
    return OtRemoteAccessPolicyReport._owned(expected)


def verify_supplied_ot_remote_access_bytes(
    report_bytes: bytes, *, model: Any
) -> OtRemoteAccessPolicyReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise OtRemoteAccessPolicyError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise OtRemoteAccessPolicyError("Exported report differs from original replay")
    return OtRemoteAccessPolicyReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-ot-remote-access",
        "inventory_complete": True,
        "policy": {
            "allowed_actor_kinds": ["operator", "vendor"],
            "required_controls": ["approved_identity", "mfa", "brokered", "session_logged"],
            "maximum_session_minutes": 60,
        },
        "paths": [{
            "path_id": "vendor-session-a",
            "actor_kind": "vendor",
            "principal_id": "vendor-a",
            "destination_zone": "control",
            "controls": ["approved_identity", "brokered", "session_logged"],
            "session_minutes": 30,
            "expected_allowed": True,
        }],
    }
