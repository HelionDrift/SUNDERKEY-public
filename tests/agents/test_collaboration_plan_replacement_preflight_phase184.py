"""Phase 184 collaboration plan replacement preflight coverage."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import unittest
from pathlib import Path

from sunderkey.collaboration import CollaborationPlan, load_collaboration_plan
from sunderkey.collaboration_mission_policy import (
    build_collaboration_mission_reconfiguration_policy,
    collaboration_mission_reconfiguration_selection_sha256,
)
from sunderkey.collaboration_plan_replacement_preflight import (
    PREFLIGHT_DOMAIN,
    CollaborationPlanReplacementPreflight,
    build_collaboration_plan_replacement_preflight,
    verify_collaboration_plan_replacement_preflight,
)
from sunderkey.collaboration_reconfiguration_policy import (
    load_collaboration_reconfiguration_authority_policy,
)
from sunderkey.errors import CollaborationPlanError

ROOT = Path(__file__).resolve().parents[2]
PLAN_PATH = ROOT / "examples" / "collaboration" / "internet-api-to-data.json"
AUTHORITY_PATH = ROOT / "registry" / "collaboration-reconfiguration-policy-d001-d005.json"
MODULE_PATH = ROOT / "src" / "sunderkey" / "collaboration_plan_replacement_preflight.py"

READINESS_ID = "WIT-READY-1188D3BAEA783AC2"
SPECIALIST_ID = "WIT-SPEC-1CAF2AB02D2C94DE"
CONTROL_ID = "WIT-CONTROL-EC5AD22B18CDADD8"
ASSURANCE_ID = "WIT-ASSURE-23CF2FC03BD84EF5"
NEW_SPECIALIST_ID = "WIT-SPEC-AAAAAAAAAAAAAAAA"
PRIOR_PLAN_ID = "CLP-111111111111111111111111"
REPLACEMENT_PLAN_ID = "CLP-222222222222222222222222"


def canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def assertion(profile_id: str, marker: str) -> dict[str, str]:
    return {
        "profile_id": profile_id,
        "assertion_id": "PAS-" + marker * 32,
        "assertion_sha256": "sha256:" + marker.lower() * 64,
    }


def source_state(plan: CollaborationPlan, **overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "mission_revision": 7,
        "active_plan_id": plan.plan_id,
        "active_plan_sha256": plan.content_sha256,
        "ownership_snapshot_sha256": "sha256:" + "1" * 64,
        "work_snapshot_sha256": "sha256:" + "2" * 64,
        "cancellation_snapshot_sha256": "sha256:" + "3" * 64,
        "execution_session_snapshot_sha256": "sha256:" + "4" * 64,
        "terminal_custody_snapshot_sha256": "sha256:" + "5" * 64,
        "observed_at": "2026-08-03T00:02:00Z",
    }
    value.update(overrides)
    return value


def committed_policy_binding(policy: object, **overrides: str) -> dict[str, str]:
    approvals = policy.to_dict()["approval_bindings"]
    value = {
        "policy_id": policy.policy_id,
        "policy_sha256": policy.policy_sha256,
        "policy_selection_sha256": (
            collaboration_mission_reconfiguration_selection_sha256(policy)
        ),
        "authentication_id": "MPA-" + "A" * 32,
        "authentication_sha256": "sha256:" + "a" * 64,
        "committed_at": "2026-08-03T00:01:00Z",
        "mission_owner_assertion_id": approvals["mission_owner"]["assertion_id"],
        "mission_owner_assertion_sha256": approvals["mission_owner"][
            "assertion_sha256"
        ],
        "mission_owner_ledger_entry_sha256": "sha256:" + "b" * 64,
        "independent_control_assertion_id": approvals["independent_control"][
            "assertion_id"
        ],
        "independent_control_assertion_sha256": approvals["independent_control"][
            "assertion_sha256"
        ],
        "independent_control_ledger_entry_sha256": "sha256:" + "c" * 64,
        "commit_status": "committed_inactive",
    }
    value.update(overrides)
    return value


def cross_command_evidence() -> dict[str, str]:
    return {
        "capability_catalog_sha256": "sha256:" + "6" * 64,
        "capability_revalidation_sha256": "sha256:" + "d" * 64,
        "proposed_owner_qualification_sha256": "sha256:" + "7" * 64,
        "source_command_review_sha256": "sha256:" + "8" * 64,
        "destination_command_review_sha256": "sha256:" + "9" * 64,
    }


class CollaborationPlanReplacementPreflightPhase184Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.template = load_collaboration_plan(PLAN_PATH)
        cls.authority = load_collaboration_reconfiguration_authority_policy(AUTHORITY_PATH)

    def _plan(
        self,
        *,
        plan_id: str,
        item_ids: tuple[str, ...] = (READINESS_ID, SPECIALIST_ID),
        changes: dict[str, dict[str, object]] | None = None,
    ) -> CollaborationPlan:
        changes = changes or {}
        template_items = {
            item["work_item_id"]: item
            for item in self.template.to_dict()["work_items"]
        }
        items = []
        for item_id in item_ids:
            source_id = (
                SPECIALIST_ID if item_id == NEW_SPECIALIST_ID else item_id
            )
            item = copy.deepcopy(template_items[source_id])
            if item_id == NEW_SPECIALIST_ID:
                item["work_item_id"] = NEW_SPECIALIST_ID
            item.update(changes.get(item_id, {}))
            items.append(item)
        layers: dict[int, list[str]] = {}
        for item in items:
            layers.setdefault(item["layer"], []).append(item["work_item_id"])
        document = self.template.unsigned_dict()
        document.update(
            {
                "plan_id": plan_id,
                "work_items": items,
                "topological_layers": [
                    sorted(layers[layer]) for layer in sorted(layers)
                ],
            }
        )
        document["content_sha256"] = canonical_sha256(document)
        return CollaborationPlan.from_dict(document)

    def _review_plan(
        self,
        *,
        plan_id: str,
        change_control_owner: bool = False,
    ) -> CollaborationPlan:
        changes: dict[str, dict[str, object]] = {
            CONTROL_ID: {
                "dependency_ids": [READINESS_ID],
                "layer": 1,
            },
            ASSURANCE_ID: {
                "dependency_ids": [CONTROL_ID],
                "layer": 2,
            },
        }
        if change_control_owner:
            changes[CONTROL_ID]["owner_profile_id"] = "AOE-HQ-15"
        return self._plan(
            plan_id=plan_id,
            item_ids=(READINESS_ID, CONTROL_ID, ASSURANCE_ID),
            changes=changes,
        )

    def _policy(
        self,
        prior: CollaborationPlan,
        *,
        replacement_active: bool = True,
        cross_command_active: bool = False,
        mission_owner: str = "AOE-HQ-08",
        maximum_items: int = 100,
    ):
        return build_collaboration_mission_reconfiguration_policy(
            authority_policy=self.authority,
            policy_version=1,
            previous_policy_sha256=None,
            mission_id=prior.mission_id,
            collaboration_plan_id=prior.plan_id,
            collaboration_plan_sha256=prior.content_sha256,
            maximum_delegation_depth=3,
            reconfiguration_validity_seconds=3600,
            execution_ack_timeout_seconds=300,
            maximum_plan_replacement_items=maximum_items,
            transition_activation={
                "privileged_role_reassignment": False,
                "delegation_return_and_revocation": not replacement_active,
                "cross_command_transfer": cross_command_active,
                "activated_plan_replacement": replacement_active,
                "distributed_execution_transfer_or_cancellation": False,
            },
            mission_owner_approval=assertion(mission_owner, "A"),
            independent_control_approval=assertion("AOE-HQ-14", "B"),
            effective_at="2026-08-03T00:00:00Z",
            expires_at="2026-08-03T01:00:00Z",
        )

    @staticmethod
    def _mapping(
        source_id: str,
        target_id: str,
        *,
        completed: bool = False,
        evidence: dict[str, str] | None = None,
    ) -> dict[str, object]:
        return {
            "source_work_item_id": source_id,
            "replacement_work_item_id": target_id,
            "source_state": "completed" if completed else "not_completed",
            "disposition": (
                "preserve_completed_result" if completed else "restart_in_replacement"
            ),
            "completed_result_sha256": (
                "sha256:" + "c" * 64 if completed else None
            ),
            "cross_command_evidence": evidence,
        }

    def _build(
        self,
        prior: CollaborationPlan,
        replacement: CollaborationPlan,
        *,
        mappings: list[dict[str, object]],
        policy=None,
        policy_commit: dict[str, str] | None = None,
        state: dict[str, object] | None = None,
        assurance: str | None = None,
        second_control: str | None = None,
    ) -> CollaborationPlanReplacementPreflight:
        selected_policy = policy or self._policy(prior)
        return build_collaboration_plan_replacement_preflight(
            prior_plan=prior,
            replacement_plan=replacement,
            mission_policy=selected_policy,
            mission_policy_commit=(
                policy_commit or committed_policy_binding(selected_policy)
            ),
            source_state=state or source_state(prior),
            mapping_inputs=mappings,
            independent_assurance_profile_id=assurance,
            second_control_profile_id=second_control,
        )

    def test_same_command_preservation_is_content_addressed_and_inactive(self) -> None:
        prior = self._plan(plan_id=PRIOR_PLAN_ID)
        replacement = self._plan(plan_id=REPLACEMENT_PLAN_ID)
        mappings = [
            self._mapping(READINESS_ID, READINESS_ID, completed=True),
            self._mapping(SPECIALIST_ID, SPECIALIST_ID, completed=True),
        ]

        preflight = self._build(prior, replacement, mappings=mappings)
        document = preflight.to_dict()

        self.assertEqual(document["runtime_effect"], "none")
        self.assertEqual(document["authentication_status"], "authority_assertions_required")
        self.assertTrue(document["atomic_commit_required"])
        self.assertEqual(document["history_policy"], "append_only_no_rewrite")
        self.assertTrue(all(item["preservation_eligible"] for item in document["item_mappings"]))
        self.assertTrue(
            all(
                item["disposition"] == "preserve_completed_result"
                for item in document["item_mappings"]
            )
        )
        verified = verify_collaboration_plan_replacement_preflight(
            preflight,
            prior_plan=prior,
            replacement_plan=replacement,
            mission_policy=self._policy(prior),
        )
        self.assertEqual(verified.to_dict(), document)
        self.assertEqual(self._build(prior, replacement, mappings=mappings).to_dict(), document)

    def test_completed_result_preservation_requires_semantic_equivalence(self) -> None:
        prior = self._plan(plan_id=PRIOR_PLAN_ID)
        replacement = self._plan(
            plan_id=REPLACEMENT_PLAN_ID,
            changes={
                SPECIALIST_ID: {
                    "deliverable": "A materially different replacement deliverable."
                }
            },
        )
        mappings = [
            self._mapping(READINESS_ID, READINESS_ID),
            self._mapping(SPECIALIST_ID, SPECIALIST_ID, completed=True),
        ]
        with self.assertRaisesRegex(CollaborationPlanError, "preservation"):
            self._build(prior, replacement, mappings=mappings)

        mappings[1] = self._mapping(SPECIALIST_ID, SPECIALIST_ID)
        restarted = self._build(prior, replacement, mappings=mappings).to_dict()
        specialist = next(
            item
            for item in restarted["item_mappings"]
            if item["source_work_item_id"] == SPECIALIST_ID
        )
        self.assertFalse(specialist["preservation_eligible"])
        self.assertEqual(specialist["disposition"], "restart_in_replacement")

    def test_cross_command_mapping_requires_activation_and_exact_evidence(self) -> None:
        prior = self._plan(plan_id=PRIOR_PLAN_ID)
        replacement = self._plan(
            plan_id=REPLACEMENT_PLAN_ID,
            changes={
                SPECIALIST_ID: {
                    "command_id": "AOE-GC-D06",
                    "group_id": "GC",
                    "owner_profile_id": "AOE-GC-D06-S09",
                }
            },
        )
        mappings = [
            self._mapping(READINESS_ID, READINESS_ID),
            self._mapping(SPECIALIST_ID, SPECIALIST_ID),
        ]
        policy = self._policy(prior, cross_command_active=True)
        with self.assertRaisesRegex(CollaborationPlanError, "revalidation"):
            self._build(prior, replacement, mappings=mappings, policy=policy)

        mappings[1] = self._mapping(
            SPECIALIST_ID,
            SPECIALIST_ID,
            evidence=cross_command_evidence(),
        )
        preflight = self._build(prior, replacement, mappings=mappings, policy=policy)
        roles = {item["role"] for item in preflight.to_dict()["authority_requirements"]}
        self.assertIn("source_technical_command", roles)
        self.assertIn("destination_technical_command", roles)

        disabled_policy = self._policy(prior, cross_command_active=False)
        with self.assertRaises(CollaborationPlanError):
            self._build(
                prior,
                replacement,
                mappings=mappings,
                policy=disabled_policy,
            )

    def test_unmapped_items_derive_cancellation_and_new_start_actions(self) -> None:
        prior = self._plan(plan_id=PRIOR_PLAN_ID)
        replacement = self._plan(
            plan_id=REPLACEMENT_PLAN_ID,
            item_ids=(READINESS_ID, NEW_SPECIALIST_ID),
            changes={
                NEW_SPECIALIST_ID: {
                    "dependency_ids": [READINESS_ID],
                    "layer": 1,
                }
            },
        )
        preflight = self._build(
            prior,
            replacement,
            mappings=[self._mapping(READINESS_ID, READINESS_ID)],
        ).to_dict()

        self.assertEqual(
            preflight["cancellation_actions"],
            [
                {
                    "source_work_item_id": SPECIALIST_ID,
                    "current_owner_id": "AOE-GB-D06-S09",
                    "disposition": "cancel_without_history_rewrite",
                    "terminal_custody_required": True,
                }
            ],
        )
        self.assertEqual(
            preflight["new_item_actions"],
            [
                {
                    "replacement_work_item_id": NEW_SPECIALIST_ID,
                    "proposed_owner_id": "AOE-GB-D06-S09",
                    "disposition": "start_new_after_atomic_commit",
                }
            ],
        )

    def test_assurance_and_control_changes_require_independent_roles(self) -> None:
        prior = self._review_plan(plan_id=PRIOR_PLAN_ID)
        replacement = self._review_plan(
            plan_id=REPLACEMENT_PLAN_ID,
            change_control_owner=True,
        )
        mappings = [
            self._mapping(READINESS_ID, READINESS_ID),
            self._mapping(CONTROL_ID, CONTROL_ID),
            self._mapping(ASSURANCE_ID, ASSURANCE_ID),
        ]
        with self.assertRaisesRegex(CollaborationPlanError, "Assurance"):
            self._build(prior, replacement, mappings=mappings)
        with self.assertRaisesRegex(CollaborationPlanError, "second Control"):
            self._build(
                prior,
                replacement,
                mappings=mappings,
                assurance="AOE-HQ-20",
            )

        preflight = self._build(
            prior,
            replacement,
            mappings=mappings,
            assurance="AOE-HQ-20",
            second_control="AOE-HQ-16",
        ).to_dict()
        requirements = {
            (item["role"], item["authority_id"])
            for item in preflight["authority_requirements"]
        }
        self.assertIn(("independent_assurance", "AOE-HQ-20"), requirements)
        self.assertIn(("second_control", "AOE-HQ-16"), requirements)

        with self.assertRaises(CollaborationPlanError):
            self._build(
                prior,
                replacement,
                mappings=mappings,
                assurance="AOE-HQ-19",
                second_control="AOE-HQ-16",
            )
        with self.assertRaises(CollaborationPlanError):
            self._build(
                prior,
                replacement,
                mappings=mappings,
                assurance="AOE-HQ-20",
                second_control="AOE-HQ-15",
            )

    def test_policy_commit_and_source_state_fail_closed(self) -> None:
        prior = self._plan(plan_id=PRIOR_PLAN_ID)
        replacement = self._plan(plan_id=REPLACEMENT_PLAN_ID)
        mappings = [
            self._mapping(READINESS_ID, READINESS_ID),
            self._mapping(SPECIALIST_ID, SPECIALIST_ID),
        ]
        inactive = self._policy(prior, replacement_active=False)
        with self.assertRaisesRegex(CollaborationPlanError, "does not activate"):
            self._build(prior, replacement, mappings=mappings, policy=inactive)

        wrong_owner = self._policy(prior, mission_owner="AOE-HQ-09")
        with self.assertRaises(CollaborationPlanError):
            self._build(prior, replacement, mappings=mappings, policy=wrong_owner)

        policy = self._policy(prior)
        stale_commit = committed_policy_binding(
            policy,
            policy_sha256="sha256:" + "f" * 64,
        )
        with self.assertRaisesRegex(CollaborationPlanError, "stale"):
            self._build(
                prior,
                replacement,
                mappings=mappings,
                policy=policy,
                policy_commit=stale_commit,
            )
        stale_provenance = committed_policy_binding(
            policy,
            mission_owner_assertion_sha256="sha256:" + "d" * 64,
        )
        with self.assertRaisesRegex(CollaborationPlanError, "provenance is stale"):
            self._build(
                prior,
                replacement,
                mappings=mappings,
                policy=policy,
                policy_commit=stale_provenance,
            )
        invalid_status = committed_policy_binding(
            policy,
            commit_status="committed_active",
        )
        with self.assertRaisesRegex(CollaborationPlanError, "commit status"):
            self._build(
                prior,
                replacement,
                mappings=mappings,
                policy=policy,
                policy_commit=invalid_status,
            )
        with self.assertRaisesRegex(CollaborationPlanError, "active prior plan"):
            self._build(
                prior,
                replacement,
                mappings=mappings,
                policy=policy,
                state=source_state(
                    prior,
                    active_plan_sha256="sha256:" + "e" * 64,
                ),
            )
        with self.assertRaisesRegex(CollaborationPlanError, "predates"):
            self._build(
                prior,
                replacement,
                mappings=mappings,
                policy=policy,
                state=source_state(prior, observed_at="2026-08-03T00:00:30Z"),
            )

    def test_mapping_limit_counts_actions_not_distinct_plan_item_ids(self) -> None:
        prior = self._plan(plan_id=PRIOR_PLAN_ID)
        replacement = self._plan(
            plan_id=REPLACEMENT_PLAN_ID,
            item_ids=(READINESS_ID, NEW_SPECIALIST_ID),
            changes={
                NEW_SPECIALIST_ID: {
                    "dependency_ids": [READINESS_ID],
                    "layer": 1,
                }
            },
        )
        policy = self._policy(prior, maximum_items=2)
        preflight = self._build(
            prior,
            replacement,
            mappings=[
                self._mapping(READINESS_ID, READINESS_ID),
                self._mapping(SPECIALIST_ID, NEW_SPECIALIST_ID),
            ],
            policy=policy,
        )
        self.assertEqual(len(preflight.to_dict()["item_mappings"]), 2)

    def test_hash_tampering_and_semantic_rehash_fail_closed(self) -> None:
        prior = self._plan(plan_id=PRIOR_PLAN_ID)
        replacement = self._plan(
            plan_id=REPLACEMENT_PLAN_ID,
            item_ids=(READINESS_ID, NEW_SPECIALIST_ID),
            changes={
                NEW_SPECIALIST_ID: {
                    "dependency_ids": [READINESS_ID],
                    "layer": 1,
                }
            },
        )
        policy = self._policy(prior)
        preflight = self._build(
            prior,
            replacement,
            mappings=[self._mapping(READINESS_ID, READINESS_ID)],
            policy=policy,
        )
        changed = copy.deepcopy(preflight.to_dict())
        changed["selection_sha256"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(CollaborationPlanError, "hash"):
            CollaborationPlanReplacementPreflight.from_dict(changed)

        changed = copy.deepcopy(preflight.to_dict())
        changed["cancellation_actions"][0]["terminal_custody_required"] = False
        body = {
            key: value
            for key, value in changed.items()
            if key not in {"preflight_id", "preflight_sha256"}
        }
        digest = canonical_sha256({"domain": PREFLIGHT_DOMAIN, "preflight": body})
        changed["preflight_sha256"] = digest
        changed["preflight_id"] = "PRF-" + digest.removeprefix("sha256:")[:32].upper()
        parsed = CollaborationPlanReplacementPreflight.from_dict(changed)
        with self.assertRaisesRegex(CollaborationPlanError, "semantic verification"):
            verify_collaboration_plan_replacement_preflight(
                parsed,
                prior_plan=prior,
                replacement_plan=replacement,
                mission_policy=policy,
            )

    def test_contract_has_no_runtime_side_effect_dependencies(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_roots: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".")[0])
        self.assertTrue(
            imported_roots.isdisjoint(
                {"httpx", "requests", "socket", "sqlite3", "subprocess", "urllib"}
            )
        )
        self.assertNotIn("MissionStore", source)
        self.assertNotIn("execution_credentials", source)
        self.assertNotIn("network_call_performed = True", source)


if __name__ == "__main__":
    unittest.main()
