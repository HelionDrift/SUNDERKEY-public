"""Build the deterministic Phase186A plan replacement authority artifact."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

from sunderkey.collaboration import CollaborationPlan, load_collaboration_plan
from sunderkey.collaboration_mission_policy import (
    CollaborationMissionReconfigurationPolicy,
    build_collaboration_mission_reconfiguration_policy,
    collaboration_mission_reconfiguration_selection_sha256,
)
from sunderkey.collaboration_plan_replacement_authority import (
    CollaborationPlanReplacementAuthorityPlan,
    build_collaboration_plan_replacement_authority_plan,
)
from sunderkey.collaboration_plan_replacement_preflight import (
    CollaborationPlanReplacementPreflight,
    build_collaboration_plan_replacement_preflight,
)
from sunderkey.collaboration_reconfiguration_policy import (
    CollaborationReconfigurationAuthorityPolicy,
    load_collaboration_reconfiguration_authority_policy,
)
from sunderkey.registry import ExpertRegistry, load_registry

READINESS_ID = "WIT-READY-1188D3BAEA783AC2"
SPECIALIST_ID = "WIT-SPEC-1CAF2AB02D2C94DE"
CANCELLED_SPECIALIST_ID = "WIT-SPEC-D57CD37EC6645295"
CONTROL_ID = "WIT-CONTROL-EC5AD22B18CDADD8"
ASSURANCE_ID = "WIT-ASSURE-23CF2FC03BD84EF5"
NEW_SPECIALIST_ID = "WIT-SPEC-AAAAAAAAAAAAAAAA"
PRIOR_PLAN_ID = "CLP-111111111111111111111111"
REPLACEMENT_PLAN_ID = "CLP-222222222222222222222222"


def _canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _assertion(profile_id: str, marker: str) -> dict[str, str]:
    return {
        "profile_id": profile_id,
        "assertion_id": "PAS-" + marker * 32,
        "assertion_sha256": "sha256:" + marker.lower() * 64,
    }


def _plan(
    template: CollaborationPlan,
    *,
    plan_id: str,
    item_ids: tuple[str, ...],
    changes: dict[str, dict[str, object]],
) -> CollaborationPlan:
    template_items = {item["work_item_id"]: item for item in template.to_dict()["work_items"]}
    items: list[dict[str, object]] = []
    for item_id in item_ids:
        source_id = CANCELLED_SPECIALIST_ID if item_id == NEW_SPECIALIST_ID else item_id
        item = copy.deepcopy(template_items[source_id])
        if item_id == NEW_SPECIALIST_ID:
            item["work_item_id"] = NEW_SPECIALIST_ID
        item.update(changes.get(item_id, {}))
        items.append(item)
    layers: dict[int, list[str]] = {}
    for item in items:
        layer = int(item["layer"])
        layers.setdefault(layer, []).append(str(item["work_item_id"]))
    document = template.unsigned_dict()
    document.update(
        {
            "plan_id": plan_id,
            "work_items": items,
            "topological_layers": [sorted(layers[layer]) for layer in sorted(layers)],
        }
    )
    document["content_sha256"] = _canonical_sha256(document)
    return CollaborationPlan.from_dict(document)


def _policy_commit(
    policy: CollaborationMissionReconfigurationPolicy,
) -> dict[str, str]:
    approvals = policy.to_dict()["approval_bindings"]
    return {
        "policy_id": policy.policy_id,
        "policy_sha256": policy.policy_sha256,
        "policy_selection_sha256": (collaboration_mission_reconfiguration_selection_sha256(policy)),
        "authentication_id": "MPA-" + "A" * 32,
        "authentication_sha256": "sha256:" + "a" * 64,
        "committed_at": "2026-08-03T00:01:00Z",
        "mission_owner_assertion_id": approvals["mission_owner"]["assertion_id"],
        "mission_owner_assertion_sha256": approvals["mission_owner"]["assertion_sha256"],
        "mission_owner_ledger_entry_sha256": "sha256:" + "b" * 64,
        "independent_control_assertion_id": approvals["independent_control"]["assertion_id"],
        "independent_control_assertion_sha256": approvals["independent_control"][
            "assertion_sha256"
        ],
        "independent_control_ledger_entry_sha256": "sha256:" + "c" * 64,
        "commit_status": "committed_inactive",
    }


def _mapping(
    source_id: str,
    replacement_id: str,
    *,
    cross_command: bool = False,
) -> dict[str, object]:
    evidence = None
    if cross_command:
        evidence = {
            "capability_catalog_sha256": "sha256:" + "6" * 64,
            "capability_revalidation_sha256": "sha256:" + "d" * 64,
            "proposed_owner_qualification_sha256": "sha256:" + "7" * 64,
            "source_command_review_sha256": "sha256:" + "8" * 64,
            "destination_command_review_sha256": "sha256:" + "9" * 64,
        }
    return {
        "source_work_item_id": source_id,
        "replacement_work_item_id": replacement_id,
        "source_state": "not_completed",
        "disposition": "restart_in_replacement",
        "completed_result_sha256": None,
        "cross_command_evidence": evidence,
    }


def build_sources(
    args: argparse.Namespace,
) -> tuple[
    CollaborationPlanReplacementPreflight,
    CollaborationPlan,
    CollaborationPlan,
    CollaborationReconfigurationAuthorityPolicy,
    CollaborationMissionReconfigurationPolicy,
    ExpertRegistry,
    bytes,
]:
    template = load_collaboration_plan(args.plan_template)
    authority_policy = load_collaboration_reconfiguration_authority_policy(args.authority_policy)
    registry = load_registry(args.registry)
    registry_bytes = Path(args.registry).read_bytes()

    common_changes = {
        CONTROL_ID: {"dependency_ids": [READINESS_ID], "layer": 1},
        ASSURANCE_ID: {"dependency_ids": [CONTROL_ID], "layer": 2},
    }
    prior = _plan(
        template,
        plan_id=PRIOR_PLAN_ID,
        item_ids=(
            READINESS_ID,
            SPECIALIST_ID,
            CANCELLED_SPECIALIST_ID,
            CONTROL_ID,
            ASSURANCE_ID,
        ),
        changes=common_changes,
    )
    replacement_changes = {
        **common_changes,
        SPECIALIST_ID: {
            "command_id": "AOE-GC-D11",
            "group_id": "GC",
            "owner_profile_id": "AOE-GC-D11-S09",
            "supporting_profile_ids": [
                "AOE-GC-D11-CMD",
                "AOE-HQ-04",
                "AOE-HQ-18",
            ],
        },
        NEW_SPECIALIST_ID: {
            "dependency_ids": [READINESS_ID],
            "layer": 1,
        },
        CONTROL_ID: {
            "dependency_ids": [READINESS_ID],
            "layer": 1,
            "owner_profile_id": "AOE-HQ-15",
        },
    }
    replacement = _plan(
        template,
        plan_id=REPLACEMENT_PLAN_ID,
        item_ids=(
            READINESS_ID,
            SPECIALIST_ID,
            NEW_SPECIALIST_ID,
            CONTROL_ID,
            ASSURANCE_ID,
        ),
        changes=replacement_changes,
    )
    mission_policy = build_collaboration_mission_reconfiguration_policy(
        authority_policy=authority_policy,
        policy_version=1,
        previous_policy_sha256=None,
        mission_id=prior.mission_id,
        collaboration_plan_id=prior.plan_id,
        collaboration_plan_sha256=prior.content_sha256,
        maximum_delegation_depth=3,
        reconfiguration_validity_seconds=3600,
        execution_ack_timeout_seconds=300,
        maximum_plan_replacement_items=100,
        transition_activation={
            "privileged_role_reassignment": False,
            "delegation_return_and_revocation": False,
            "cross_command_transfer": True,
            "activated_plan_replacement": True,
            "distributed_execution_transfer_or_cancellation": False,
        },
        mission_owner_approval=_assertion("AOE-HQ-08", "A"),
        independent_control_approval=_assertion("AOE-HQ-14", "B"),
        effective_at="2026-08-03T00:00:00Z",
        expires_at="2026-08-03T01:00:00Z",
    )
    source_state = {
        "mission_revision": 7,
        "active_plan_id": prior.plan_id,
        "active_plan_sha256": prior.content_sha256,
        "ownership_snapshot_sha256": "sha256:" + "1" * 64,
        "work_snapshot_sha256": "sha256:" + "2" * 64,
        "cancellation_snapshot_sha256": "sha256:" + "3" * 64,
        "execution_session_snapshot_sha256": "sha256:" + "4" * 64,
        "terminal_custody_snapshot_sha256": "sha256:" + "5" * 64,
        "observed_at": "2026-08-03T00:02:00Z",
    }
    preflight = build_collaboration_plan_replacement_preflight(
        prior_plan=prior,
        replacement_plan=replacement,
        mission_policy=mission_policy,
        mission_policy_commit=_policy_commit(mission_policy),
        source_state=source_state,
        mapping_inputs=[
            _mapping(READINESS_ID, READINESS_ID),
            _mapping(SPECIALIST_ID, SPECIALIST_ID, cross_command=True),
            _mapping(CONTROL_ID, CONTROL_ID),
            _mapping(ASSURANCE_ID, ASSURANCE_ID),
        ],
        independent_assurance_profile_id="AOE-HQ-20",
        second_control_profile_id="AOE-HQ-16",
    )
    return (
        preflight,
        prior,
        replacement,
        authority_policy,
        mission_policy,
        registry,
        registry_bytes,
    )


def build_artifact(args: argparse.Namespace) -> dict[str, object]:
    (
        preflight,
        _,
        _,
        authority_policy,
        mission_policy,
        registry,
        registry_bytes,
    ) = build_sources(args)
    artifact: CollaborationPlanReplacementAuthorityPlan = (
        build_collaboration_plan_replacement_authority_plan(
            preflight=preflight,
            authority_policy=authority_policy,
            mission_policy=mission_policy,
            registry=registry,
            registry_source=registry_bytes,
            issued_at="2026-08-03T00:03:00Z",
            expires_at="2026-08-03T00:33:00Z",
        )
    )
    document = artifact.to_dict()
    source_requirement_count = len(preflight.to_dict()["authority_requirements"])
    if document["authority_requirement_coverage"]["requirement_count"] != source_requirement_count:
        raise RuntimeError("Authority requirement coverage does not match the Phase184 source")
    return document


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Build the Phase186A plan replacement authority artifact"
    )
    parser.add_argument(
        "--plan-template",
        default=str(root / "examples/collaboration/internet-api-to-data.json"),
    )
    parser.add_argument(
        "--authority-policy",
        default=str(root / "registry/collaboration-reconfiguration-policy-d001-d005.json"),
    )
    parser.add_argument(
        "--registry",
        default=str(root / "registry/army-v2.json"),
    )
    parser.add_argument(
        "--output",
        default=str(root / "registry/collaboration-plan-replacement-authority-plan-v1.json"),
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    artifact = build_artifact(args)
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(artifact, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Wrote {artifact['authority_plan_id']}: {output}")


if __name__ == "__main__":
    main()
