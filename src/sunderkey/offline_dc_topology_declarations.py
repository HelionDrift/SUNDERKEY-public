"""Compare supplied domain-controller topology and backup declarations."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "supplied_dc_topology_declarations"
PROFILE_ID = "AOE-GC-D11-S07"
CAPABILITY_ID = "army.gc.d11.s07"
VECTOR_ID = "AV-GC-D11-S07-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D11-S07"
WAVE_ID = "IW2-007"
COMMANDER_ID = "AOE-GC-D11-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:4cd9ce1c79785640defbc424cebec29d20b4688b7370b45738a0a5074a5ebf3d"
DOMAIN = "sunderkey.offline-dc-topology-declarations.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
CONTROLLER_REF = re.compile(r"controller:sha256:[0-9a-f]{64}\Z")
ROLES = {"writable", "read_only"}
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class DcTopologyDeclarationsError(ValueError):
    """A topology declaration or replay comparison was refused."""


def _controller_ref(value: Any) -> str:
    if type(value) is not str or CONTROLLER_REF.fullmatch(value) is None:
        raise DcTopologyDeclarationsError("Controller reference must be an opaque digest")
    return value


def _link(value: Any, label: str) -> tuple[str, str, bool]:
    if label == "expected":
        item = core.exact(value, {"from_ref", "to_ref"}, "expected link")
        enabled = True
    else:
        item = core.exact(value, {"from_ref", "to_ref", "enabled"}, "declared link")
        enabled = core.boolean(item["enabled"], "declared link enabled")
    source = _controller_ref(item["from_ref"])
    target = _controller_ref(item["to_ref"])
    if source == target:
        raise DcTopologyDeclarationsError("Self-link is unsupported")
    return source, target, enabled


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "policy", "controllers",
         "expected_links", "declared_links"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise DcTopologyDeclarationsError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    policy = core.exact(model["policy"], {"max_backup_age_days"}, "policy")
    age_limit = policy["max_backup_age_days"]
    if type(age_limit) is not int or not 0 <= age_limit <= 3650:
        raise DcTopologyDeclarationsError("Backup age policy must be a bounded integer")
    controllers = core.bounded_list(model["controllers"], 64, "controllers")
    if not controllers:
        raise DcTopologyDeclarationsError("At least one controller is required")
    refs: set[str] = set()
    for item in controllers:
        controller = core.exact(
            item, {"controller_ref", "role", "backup_age_days"}, "controller"
        )
        ref = _controller_ref(controller["controller_ref"])
        if ref in refs:
            raise DcTopologyDeclarationsError("Duplicate controller")
        refs.add(ref)
        core.choice(controller["role"], ROLES, "controller role")
        age = controller["backup_age_days"]
        if type(age) is not int or not 0 <= age <= 3650:
            raise DcTopologyDeclarationsError("Backup age must be a bounded integer")
    for key, label in (("expected_links", "expected"), ("declared_links", "declared")):
        links = core.bounded_list(model[key], 256, key)
        seen: set[tuple[str, str]] = set()
        for link in links:
            source, target, _enabled = _link(link, label)
            if source not in refs or target not in refs:
                raise DcTopologyDeclarationsError("Link refers to an undeclared controller")
            pair = (source, target)
            if pair in seen:
                raise DcTopologyDeclarationsError("Duplicate directed link")
            seen.add(pair)
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    complete = model["inventory_complete"]
    rows: list[dict] = []
    candidates: list[dict] = []
    for controller in model["controllers"]:
        issues = []
        if controller["backup_age_days"] > model["policy"]["max_backup_age_days"]:
            issues.append("backup_age_exceeds_supplied_policy")
        row = {
            "kind": "controller", "controller_ref": controller["controller_ref"],
            "policy_issues": issues if complete else None,
            "row_disposition": "evaluated" if complete else "unknown_incomplete_inventory",
        }
        rows.append(row)
        if complete and issues:
            candidates.append({"kind": "controller", "controller_ref": controller["controller_ref"],
                               "policy_issues": issues})
    declared = {
        (link["from_ref"], link["to_ref"]): link["enabled"]
        for link in model["declared_links"]
    }
    for link in model["expected_links"]:
        pair = (link["from_ref"], link["to_ref"])
        issues = []
        if pair not in declared:
            issues.append("expected_link_not_declared")
        elif not declared[pair]:
            issues.append("expected_link_declared_disabled")
        row = {
            "kind": "expected_link", "from_ref": pair[0], "to_ref": pair[1],
            "policy_issues": issues if complete else None,
            "row_disposition": "evaluated" if complete else "unknown_incomplete_inventory",
        }
        rows.append(row)
        if complete and issues:
            candidates.append({"kind": "expected_link", "from_ref": pair[0], "to_ref": pair[1],
                               "policy_issues": issues})
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "controller_count": len(model["controllers"]),
        "expected_link_count": len(model["expected_links"]),
        "declared_link_count": len(model["declared_links"]),
        "rows": rows,
        "candidates": candidates,
        "candidate_count": len(candidates),
        "unknown_count": len(rows) if not complete else 0,
        "disposition": "unknown" if not complete else (
            "candidate_supplied_topology_mismatch" if candidates else "supplied_topology_matches"
        ),
        "controller_or_backup_state_authenticated": False,
        "replication_observed": False,
        "directory_database_read": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Controllers, backup ages, links, policy and completeness are caller-supplied.",
            "A declared link does not establish replication, reachability or directory health.",
            "No directory database, backup content, credential, network or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="DCT-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class DcTopologyDeclarationsReport:
    """Unsigned topology projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise DcTopologyDeclarationsError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> DcTopologyDeclarationsReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_dc_topology(model: Any) -> DcTopologyDeclarationsReport:
    return DcTopologyDeclarationsReport._owned(_derive(model))


def verify_supplied_dc_topology(
    report: Any, *, model: Any
) -> DcTopologyDeclarationsReport:
    if type(report) is not DcTopologyDeclarationsReport:
        raise DcTopologyDeclarationsError("Exact DC topology wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise DcTopologyDeclarationsError("Report differs from original-model replay")
    return DcTopologyDeclarationsReport._owned(expected)


def verify_supplied_dc_topology_bytes(
    report_bytes: bytes, *, model: Any
) -> DcTopologyDeclarationsReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    expected = _derive(model)
    if type(report) is not dict or core.canonical(report) != core.canonical(expected):
        raise DcTopologyDeclarationsError("Exported report differs from original-model replay")
    return DcTopologyDeclarationsReport._owned(expected)


def component_fixture() -> dict:
    a = "controller:sha256:" + "a" * 64
    b = "controller:sha256:" + "b" * 64
    return {
        "schema_version": 1,
        "source_id": "synthetic-dc-topology",
        "inventory_complete": True,
        "policy": {"max_backup_age_days": 7},
        "controllers": [
            {"controller_ref": a, "role": "writable", "backup_age_days": 2},
            {"controller_ref": b, "role": "read_only", "backup_age_days": 12},
        ],
        "expected_links": [{"from_ref": a, "to_ref": b}],
        "declared_links": [{"from_ref": a, "to_ref": b, "enabled": False}],
    }
