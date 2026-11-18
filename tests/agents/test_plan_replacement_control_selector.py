"""Source-bound replacement review Control selection without policy reassignment."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path
from unittest import mock

from scripts.build_collaboration_plan_replacement_authority_plan import (
    build_parser as authority_parser,
)
from scripts.build_collaboration_plan_replacement_authority_plan import (
    build_sources,
)
from sunderkey.cli import build_parser
from sunderkey.collaboration_mission_policy import (
    build_collaboration_mission_reconfiguration_policy,
)
from sunderkey.collaboration_plan_replacement_authority import (
    build_collaboration_plan_replacement_authority_plan,
    validate_verified_collaboration_plan_replacement_authority_plan,
    verify_collaboration_plan_replacement_authority_plan_offline,
)
from sunderkey.collaboration_plan_replacement_authority_upgrade import (
    build_collaboration_plan_replacement_authority_upgrade,
)
from sunderkey.collaboration_plan_replacement_operations import (
    CollaborationPlanReplacementOperationsService,
)
from sunderkey.collaboration_plan_replacement_preflight import (
    PREFLIGHT_DOMAIN,
    CollaborationPlanReplacementPreflight,
    build_collaboration_plan_replacement_preflight,
    verify_collaboration_plan_replacement_preflight,
)
from sunderkey.errors import CollaborationPlanError
from sunderkey.store import MissionStore, canonical_json, sha256_text

from .test_collaboration_plan_replacement_preflight_phase184 import committed_policy_binding


class PlanReplacementControlSelectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        (
            cls.legacy,
            cls.prior,
            cls.replacement,
            cls.authority,
            cls.policy,
            cls.registry,
            cls.registry_bytes,
        ) = build_sources(authority_parser().parse_args([]))

    def arguments(self, *, policy=None) -> dict[str, object]:
        document = self.legacy.to_dict()
        return {
            "prior_plan": self.prior,
            "replacement_plan": self.replacement,
            "mission_policy": policy or self.policy,
            "mission_policy_commit": document["mission_policy_commit"]
            if policy is None
            else committed_policy_binding(policy),
            "source_state": document["source_state"],
            "mapping_inputs": [
                {
                    key: item[key]
                    for key in (
                        "source_work_item_id",
                        "replacement_work_item_id",
                        "source_state",
                        "disposition",
                        "completed_result_sha256",
                        "cross_command_evidence",
                    )
                }
                for item in document["item_mappings"]
            ],
            "independent_assurance_profile_id": "AOE-HQ-20",
            "second_control_profile_id": "AOE-HQ-16",
        }

    def policy_with_assigned_control(self):
        document = self.policy.to_dict()
        return build_collaboration_mission_reconfiguration_policy(
            authority_policy=self.authority,
            policy_version=1,
            previous_policy_sha256=None,
            mission_id=self.prior.mission_id,
            collaboration_plan_id=self.prior.plan_id,
            collaboration_plan_sha256=self.prior.content_sha256,
            **document["selected_parameters"],
            transition_activation=document["transition_activation"],
            mission_owner_approval=document["approval_bindings"]["mission_owner"],
            independent_control_approval={
                **document["approval_bindings"]["independent_control"],
                "profile_id": "AOE-HQ-12",
            },
            effective_at=document["effective_at"],
            expires_at=document["expires_at"],
        )

    def verify(self, preflight, *, policy=None):
        return verify_collaboration_plan_replacement_preflight(
            preflight,
            prior_plan=self.prior,
            replacement_plan=self.replacement,
            mission_policy=policy or self.policy,
        )

    @staticmethod
    def readdress(document):
        body = {
            key: value
            for key, value in document.items()
            if key not in {"preflight_id", "preflight_sha256"}
        }
        digest = sha256_text(canonical_json({"domain": PREFLIGHT_DOMAIN, "preflight": body}))
        return CollaborationPlanReplacementPreflight.from_dict(
            {
                **body,
                "preflight_sha256": digest,
                "preflight_id": "PRF-" + digest.removeprefix("sha256:")[:32].upper(),
            }
        )

    def test_default_and_explicit_policy_control_preserve_legacy_exact_identity(self) -> None:
        implicit = build_collaboration_plan_replacement_preflight(**self.arguments())
        explicit = build_collaboration_plan_replacement_preflight(
            **self.arguments(),
            independent_control_profile_id="AOE-HQ-14",
        )
        self.assertEqual(implicit, self.legacy)
        self.assertEqual(explicit, self.legacy)
        self.assertEqual(self.verify(explicit), self.legacy)

    def test_initial_native_revision_zero_is_semantically_reproducible(self) -> None:
        arguments = self.arguments()
        arguments["source_state"] = {**arguments["source_state"], "mission_revision": 0}
        preflight = build_collaboration_plan_replacement_preflight(**arguments)
        self.assertEqual(preflight.to_dict()["source_state"]["mission_revision"], 0)
        self.assertEqual(self.verify(preflight), preflight)
        self.assertEqual(
            CollaborationPlanReplacementPreflight.from_dict(preflight.to_dict()), preflight
        )

    def test_revision_boolean_float_and_negative_aliases_are_denied_before_replay(self) -> None:
        for value in (False, True, 0.0, 1.0, -1):
            with self.subTest(value=value, kind=type(value).__name__):
                arguments = self.arguments()
                arguments["source_state"] = {**arguments["source_state"], "mission_revision": value}
                with self.assertRaisesRegex(CollaborationPlanError, "native nonnegative"):
                    build_collaboration_plan_replacement_preflight(**arguments)
                document = self.legacy.to_dict()
                document["source_state"]["mission_revision"] = value
                with self.assertRaisesRegex(CollaborationPlanError, "native nonnegative"):
                    self.readdress(document)

    def test_selected_reviewer_differs_from_assigned_policy_approver_without_reassignment(
        self,
    ) -> None:
        policy = self.policy_with_assigned_control()
        with self.assertRaisesRegex(CollaborationPlanError, "own work affected"):
            build_collaboration_plan_replacement_preflight(**self.arguments(policy=policy))
        preflight = build_collaboration_plan_replacement_preflight(
            **self.arguments(policy=policy),
            independent_control_profile_id="AOE-HQ-14",
        )
        self.assertEqual(self.verify(preflight, policy=policy), preflight)
        self.assertEqual(
            policy.to_dict()["approval_bindings"]["independent_control"]["profile_id"], "AOE-HQ-12"
        )
        self.assertEqual(
            preflight.to_dict()["mission_policy_commit"]["independent_control_assertion_id"],
            policy.to_dict()["approval_bindings"]["independent_control"]["assertion_id"],
        )
        self.assertEqual(
            [
                item["authority_id"]
                for item in preflight.to_dict()["authority_requirements"]
                if item["role"] == "independent_control"
            ],
            ["AOE-HQ-14"],
        )
        plan = build_collaboration_plan_replacement_authority_plan(
            preflight=preflight,
            authority_policy=self.authority,
            mission_policy=policy,
            registry=self.registry,
            registry_source=self.registry_bytes,
            issued_at="2026-08-03T00:03:00Z",
            expires_at="2026-08-03T00:25:00Z",
        )
        verified = verify_collaboration_plan_replacement_authority_plan_offline(
            plan,
            preflight=preflight,
            prior_plan=self.prior,
            replacement_plan=self.replacement,
            authority_policy=self.authority,
            mission_policy=policy,
            registry=self.registry,
            registry_source=self.registry_bytes,
            verified_at="2026-08-03T00:03:00Z",
        )
        self.assertEqual(
            validate_verified_collaboration_plan_replacement_authority_plan(
                verified
            ).authority_plan_id,
            plan.authority_plan_id,
        )
        upgrade = build_collaboration_plan_replacement_authority_upgrade(
            preflight=preflight, army_registry=self.registry
        )
        self.assertEqual(
            [
                item["principal_profile_id"]
                for item in upgrade.to_dict()["authority_requirements"]
                if item["role"] == "independent_control"
            ],
            ["AOE-HQ-14"],
        )

    def test_nondefault_control_is_selection_hash_and_authority_bound(self) -> None:
        selected = build_collaboration_plan_replacement_preflight(
            **self.arguments(), independent_control_profile_id="AOE-HQ-13"
        )
        self.assertNotEqual(selected.selection_sha256, self.legacy.selection_sha256)
        self.assertNotEqual(selected.preflight_id, self.legacy.preflight_id)
        self.assertEqual(self.verify(selected), selected)
        self.assertEqual(
            selected.to_dict()["mission_policy_commit"],
            self.legacy.to_dict()["mission_policy_commit"],
        )

    def test_owner_assurance_and_second_control_cannot_be_selected_control(self) -> None:
        for profile in ("AOE-HQ-08", "AOE-HQ-12", "AOE-HQ-15", "AOE-HQ-20", "AOE-HQ-16"):
            with self.subTest(profile=profile), self.assertRaises(CollaborationPlanError):
                build_collaboration_plan_replacement_preflight(
                    **self.arguments(), independent_control_profile_id=profile
                )

    def test_missing_or_duplicate_control_role_cannot_be_rehashed_into_valid_preflight(
        self,
    ) -> None:
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate):
                document = self.legacy.to_dict()
                control = next(
                    item
                    for item in document["authority_requirements"]
                    if item["role"] == "independent_control"
                )
                if duplicate:
                    copied = copy.deepcopy(control)
                    copied["requirement_id"] = "PAR-" + "F" * 32
                    document["authority_requirements"].append(copied)
                else:
                    document["authority_requirements"].remove(control)
                with self.assertRaisesRegex(CollaborationPlanError, "exactly one"):
                    self.verify(self.readdress(document))

    def test_rehashed_control_substitution_does_not_rebind_original_selection(self) -> None:
        document = self.legacy.to_dict()
        next(
            item
            for item in document["authority_requirements"]
            if item["role"] == "independent_control"
        )["authority_id"] = "AOE-HQ-13"
        with self.assertRaisesRegex(CollaborationPlanError, "semantic verification"):
            self.verify(self.readdress(document))

    def test_control_category_is_still_enforced_by_registry_identity_upgrade(self) -> None:
        preflight = build_collaboration_plan_replacement_preflight(
            **self.arguments(), independent_control_profile_id="AOE-HQ-21"
        )
        with self.assertRaisesRegex(CollaborationPlanError, "invalid registry role"):
            build_collaboration_plan_replacement_authority_upgrade(
                preflight=preflight, army_registry=self.registry
            )

    def test_cli_and_operator_readiness_thread_optional_control_selection(self) -> None:
        for command in (
            "collaboration-plan-replacement-readiness",
            "collaboration-plan-replacement-prepare",
        ):
            args = [
                command,
                "--store",
                "sentinel.sqlite3",
                "--registry",
                "registry.json",
                "--authority-policy",
                "policy.json",
                "--replacement-plan",
                "plan.json",
                "--mapping-intents",
                "mappings.json",
                "--independent-assurance-profile-id",
                "AOE-HQ-20",
                "--second-control-profile-id",
                "AOE-HQ-16",
            ]
            if command.endswith("prepare"):
                args += [
                    "--output",
                    "output.json",
                    "--issued-at",
                    "2026-08-03T00:03:00Z",
                    "--expires-at",
                    "2026-08-03T00:25:00Z",
                ]
            self.assertIsNone(build_parser().parse_args(args).independent_control_profile_id)
            self.assertEqual(
                build_parser()
                .parse_args([*args, "--independent-control-profile-id", "AOE-HQ-13"])
                .independent_control_profile_id,
                "AOE-HQ-13",
            )
        service = CollaborationPlanReplacementOperationsService(
            MissionStore(Path("nonexistent-selector-sentinel.sqlite3")),
            self.registry,
            self.authority,
            registry_source=self.registry_bytes,
        )
        with mock.patch.object(service, "_assess", return_value="selected") as assess:
            self.assertEqual(
                service.assess(
                    replacement_plan=self.replacement,
                    mapping_intents=[],
                    independent_control_profile_id="AOE-HQ-13",
                ),
                "selected",
            )
        self.assertEqual(assess.call_args.kwargs["independent_control_profile_id"], "AOE-HQ-13")
        with mock.patch.object(
            service, "assess", side_effect=RuntimeError("stop before producers")
        ) as assess:
            with self.assertRaisesRegex(RuntimeError, "stop before producers"):
                service.prepare(
                    replacement_plan=self.replacement,
                    mapping_intents=[],
                    issued_at="2026-08-03T00:03:00Z",
                    expires_at="2026-08-03T00:25:00Z",
                    independent_control_profile_id="AOE-HQ-13",
                )
        self.assertEqual(assess.call_args.kwargs["independent_control_profile_id"], "AOE-HQ-13")


if __name__ == "__main__":
    unittest.main()
