"""Phase186B1 authenticated collaboration plan replacement identity tests."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from sunderkey.collaboration_plan_replacement_authority_upgrade import (
    COMMAND_AUTHORITY_BINDING_DOMAIN,
    REQUIREMENT_DOMAIN,
    SOURCE_REQUIREMENT_DOMAIN,
    UPGRADE_DOMAIN,
    CollaborationPlanReplacementAuthorityUpgrade,
    build_collaboration_plan_replacement_authority_upgrade,
    load_collaboration_plan_replacement_authority_upgrade,
    verify_collaboration_plan_replacement_authority_upgrade,
)
from sunderkey.collaboration_plan_replacement_preflight import (
    AUTHORITY_INTENT_DOMAIN,
    PREFLIGHT_DOMAIN,
    CollaborationPlanReplacementPreflight,
)
from sunderkey.errors import CollaborationPlanError, PrincipalAuthenticationError
from sunderkey.identity import PrincipalOperation, compute_operation_intent_hash
from sunderkey.registry import ExpertRegistry, load_registry

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "registry" / "army-v2.json"
SCHEMA_PATH = (
    ROOT
    / "registry"
    / "schemas"
    / "collaboration-plan-replacement-authority-upgrade-v2.schema.json"
)
PRIOR_PLAN_ID = "CLP-111111111111111111111111"
REPLACEMENT_PLAN_ID = "CLP-222222222222222222222222"
PRIOR_PLAN_SHA256 = "sha256:" + "1" * 64
REPLACEMENT_PLAN_SHA256 = "sha256:" + "2" * 64
SELECTION_SHA256 = "sha256:" + "3" * 64
MISSION_ID = "MISSION-PLAN-REPLACEMENT"


def canonical_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def source_authority_intent(requirement: dict[str, object]) -> str:
    body = {
        "role": requirement["role"],
        "authority_id": requirement["authority_id"],
        "authority_kind": requirement["authority_kind"],
        "operation": requirement["operation"],
        "work_item_id": requirement["work_item_id"],
        "selection_sha256": SELECTION_SHA256,
    }
    return canonical_sha256({"domain": AUTHORITY_INTENT_DOMAIN, "authority_intent": body})


def source_requirement(
    index: int,
    *,
    role: str,
    authority_id: str,
    authority_kind: str,
    operation: PrincipalOperation,
    work_item_id: str | None,
) -> dict[str, object]:
    requirement: dict[str, object] = {
        "role": role,
        "authority_id": authority_id,
        "authority_kind": authority_kind,
        "operation": operation.value,
        "work_item_id": work_item_id,
    }
    requirement["operation_intent_sha256"] = source_authority_intent(requirement)
    digest = canonical_sha256(
        {
            "domain": SOURCE_REQUIREMENT_DOMAIN,
            "requirement": {
                **requirement,
                "selection_sha256": SELECTION_SHA256,
            },
        }
    )
    requirement["requirement_id"] = "PAR-" + digest.removeprefix("sha256:")[:32].upper()
    return requirement


def make_preflight(
    *,
    independent_control_id: str = "AOE-HQ-14",
    independent_assurance_id: str = "AOE-HQ-18",
    second_control_id: str = "AOE-HQ-15",
) -> CollaborationPlanReplacementPreflight:
    requirements = [
        source_requirement(
            1,
            role="mission_owner",
            authority_id="AOE-HQ-08",
            authority_kind="principal_profile",
            operation=PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_OWNER_AUTHORIZE,
            work_item_id=None,
        ),
        source_requirement(
            2,
            role="independent_control",
            authority_id=independent_control_id,
            authority_kind="principal_profile",
            operation=PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_CONTROL_APPROVE,
            work_item_id=None,
        ),
        source_requirement(
            3,
            role="current_owner",
            authority_id="AOE-GA-D01-S01",
            authority_kind="principal_profile",
            operation=(PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_CURRENT_OWNER_AUTHORIZE),
            work_item_id="WIT-SPEC-1111111111111111",
        ),
        source_requirement(
            4,
            role="proposed_owner",
            authority_id="AOE-GB-D06-S01",
            authority_kind="principal_profile",
            operation=(PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_PROPOSED_OWNER_ACCEPT),
            work_item_id="WIT-SPEC-2222222222222222",
        ),
        source_requirement(
            5,
            role="source_technical_command",
            authority_id="AOE-GA-D01",
            authority_kind="command",
            operation=PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_SOURCE_COMMAND_REVIEW,
            work_item_id="WIT-SPEC-1111111111111111",
        ),
        source_requirement(
            6,
            role="destination_technical_command",
            authority_id="AOE-GB-D06",
            authority_kind="command",
            operation=(
                PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_DESTINATION_COMMAND_REVIEW
            ),
            work_item_id="WIT-SPEC-2222222222222222",
        ),
        source_requirement(
            7,
            role="current_owner",
            authority_id="AOE-GA-D01-S02",
            authority_kind="principal_profile",
            operation=PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_CURRENT_OWNER_CANCEL,
            work_item_id="WIT-SPEC-3333333333333333",
        ),
        source_requirement(
            8,
            role="independent_assurance",
            authority_id=independent_assurance_id,
            authority_kind="principal_profile",
            operation=PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_ASSURANCE_APPROVE,
            work_item_id=None,
        ),
        source_requirement(
            9,
            role="second_control",
            authority_id=second_control_id,
            authority_kind="principal_profile",
            operation=(PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_SECOND_CONTROL_APPROVE),
            work_item_id=None,
        ),
    ]
    body = {
        "schema_version": 1,
        "selection_sha256": SELECTION_SHA256,
        "mission_id": MISSION_ID,
        "prior_plan": {
            "plan_id": PRIOR_PLAN_ID,
            "plan_sha256": PRIOR_PLAN_SHA256,
        },
        "replacement_plan": {
            "plan_id": REPLACEMENT_PLAN_ID,
            "plan_sha256": REPLACEMENT_PLAN_SHA256,
        },
        "mission_policy_commit": {
            "policy_id": "CRP-11111111111111111111111111111111",
            "policy_sha256": "sha256:" + "4" * 64,
            "policy_selection_sha256": "sha256:" + "5" * 64,
            "authentication_id": "MPA-" + "1" * 32,
            "authentication_sha256": "sha256:" + "6" * 64,
            "committed_at": "2026-09-20T00:00:00Z",
            "mission_owner_assertion_id": "PAS-" + "1" * 32,
            "mission_owner_assertion_sha256": "sha256:" + "7" * 64,
            "mission_owner_ledger_entry_sha256": "sha256:" + "8" * 64,
            "independent_control_assertion_id": "PAS-" + "2" * 32,
            "independent_control_assertion_sha256": "sha256:" + "9" * 64,
            "independent_control_ledger_entry_sha256": "sha256:" + "a" * 64,
            "commit_status": "committed_inactive",
        },
        "source_state": {
            "mission_revision": 1,
            "active_plan_id": PRIOR_PLAN_ID,
            "active_plan_sha256": PRIOR_PLAN_SHA256,
            "ownership_snapshot_sha256": "sha256:" + "b" * 64,
            "work_snapshot_sha256": "sha256:" + "c" * 64,
            "cancellation_snapshot_sha256": "sha256:" + "d" * 64,
            "execution_session_snapshot_sha256": "sha256:" + "e" * 64,
            "terminal_custody_snapshot_sha256": "sha256:" + "f" * 64,
            "observed_at": "2026-09-20T00:01:00Z",
        },
        "item_mappings": [],
        "cancellation_actions": [],
        "new_item_actions": [],
        "authority_requirements": requirements,
        "maximum_mapping_items": 100,
        "atomic_commit_required": True,
        "history_policy": "append_only_no_rewrite",
        "authentication_status": "authority_assertions_required",
        "runtime_effect": "none",
    }
    digest = canonical_sha256({"domain": PREFLIGHT_DOMAIN, "preflight": body})
    return CollaborationPlanReplacementPreflight.from_dict(
        {
            **body,
            "preflight_id": "PRF-" + digest.removeprefix("sha256:")[:32].upper(),
            "preflight_sha256": digest,
        }
    )


def reseal_upgrade(document: dict[str, object]) -> dict[str, object]:
    body = {
        key: value for key, value in document.items() if key not in {"upgrade_id", "upgrade_sha256"}
    }
    digest = canonical_sha256({"domain": UPGRADE_DOMAIN, "upgrade": body})
    document["upgrade_id"] = "PRU-" + digest.removeprefix("sha256:")[:32].upper()
    document["upgrade_sha256"] = digest
    return document


def reseal_requirement(requirement: dict[str, object]) -> None:
    body = {key: value for key, value in requirement.items() if key != "requirement_id"}
    digest = canonical_sha256({"domain": REQUIREMENT_DOMAIN, "requirement": body})
    requirement["requirement_id"] = "PRA-" + digest.removeprefix("sha256:")[:32].upper()


class CollaborationPlanReplacementAuthorityUpgradePhase186Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.preflight = make_preflight()
        cls.registry = load_registry(REGISTRY_PATH)
        cls.upgrade = build_collaboration_plan_replacement_authority_upgrade(
            preflight=cls.preflight,
            army_registry=cls.registry,
        )
        cls.validator = Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))

    def test_all_nine_operations_have_identity_intent_contracts(self) -> None:
        document = self.upgrade.to_dict()
        requirements = document["authority_requirements"]
        self.assertEqual(len(requirements), 9)
        expected_operations = {
            item.value
            for item in PrincipalOperation
            if "collaboration.plan-replacement" in item.value
            and ".reviewer-admission." not in item.value
        }
        self.assertEqual(
            {item["operation"] for item in requirements},
            expected_operations,
        )
        for item in requirements:
            intent = {
                "authority_intent_sha256": item["authority_intent_sha256"],
                "mission_id": MISSION_ID,
                "principal_profile_id": item["principal_profile_id"],
                "prior_plan_id": PRIOR_PLAN_ID,
                "prior_plan_sha256": PRIOR_PLAN_SHA256,
                "replacement_plan_id": REPLACEMENT_PLAN_ID,
                "replacement_plan_sha256": REPLACEMENT_PLAN_SHA256,
                "role": item["role"],
                "selection_sha256": SELECTION_SHA256,
                "work_item_id": item["work_item_id"],
            }
            if item["authority_kind"] == "command":
                intent["command_authority_binding_sha256"] = item[
                    "command_authority_binding_sha256"
                ]
            self.assertEqual(
                compute_operation_intent_hash(item["operation"], intent),
                item["principal_operation_intent_sha256"],
            )

    def test_independent_roles_require_exact_registry_categories(self) -> None:
        invalid = (
            {"independent_control_id": "AOE-HQ-22"},
            {"independent_assurance_id": "AOE-HQ-11"},
            {"second_control_id": "AOE-HQ-25"},
        )
        for override in invalid:
            with self.subTest(override=override), self.assertRaisesRegex(
                CollaborationPlanError,
                "invalid registry role",
            ):
                build_collaboration_plan_replacement_authority_upgrade(
                    preflight=make_preflight(**override),
                    army_registry=self.registry,
                )

    def test_build_is_deterministic_closed_inactive_and_offline_verifiable(self) -> None:
        document = self.upgrade.to_dict()
        self.assertEqual(document["schema_version"], 2)
        self.assertEqual(document["runtime_effect"], "none")
        self.assertEqual(document["authentication_status"], "principal_assertions_required")
        self.assertEqual(
            document,
            build_collaboration_plan_replacement_authority_upgrade(
                preflight=self.preflight,
                army_registry=self.registry,
            ).to_dict(),
        )
        self.assertEqual(
            verify_collaboration_plan_replacement_authority_upgrade(
                self.upgrade,
                preflight=self.preflight,
                army_registry=self.registry,
            ).to_dict(),
            document,
        )
        self.assertEqual(list(self.validator.iter_errors(document)), [])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "upgrade.json"
            path.write_text(json.dumps(document), encoding="ascii")
            self.assertEqual(
                load_collaboration_plan_replacement_authority_upgrade(path).to_dict(),
                document,
            )

    def test_profile_authorities_are_self_bound_and_prohibit_command_binding(self) -> None:
        profile_requirements = [
            item
            for item in self.upgrade.to_dict()["authority_requirements"]
            if item["authority_kind"] == "principal_profile"
        ]
        self.assertEqual(len(profile_requirements), 7)
        for item in profile_requirements:
            self.assertEqual(item["principal_profile_id"], item["authority_id"])
            self.assertNotIn("command_authority_binding_sha256", item)
        tampered = copy.deepcopy(self.upgrade.to_dict())
        profile = next(
            item
            for item in tampered["authority_requirements"]
            if item["authority_kind"] == "principal_profile"
        )
        profile["command_authority_binding_sha256"] = "sha256:" + "0" * 64
        with self.assertRaises(CollaborationPlanError):
            CollaborationPlanReplacementAuthorityUpgrade.from_dict(tampered)
        self.assertTrue(list(self.validator.iter_errors(tampered)))

    def test_command_authorities_resolve_exact_army_v2_commanders_and_bind_context(self) -> None:
        document = self.upgrade.to_dict()
        registry_sha256 = document["army_registry"]["registry_sha256"]
        commands = {
            item["authority_id"]: item
            for item in document["authority_requirements"]
            if item["authority_kind"] == "command"
        }
        self.assertEqual(commands["AOE-GA-D01"]["principal_profile_id"], "AOE-GA-D01-CMD")
        self.assertEqual(commands["AOE-GB-D06"]["principal_profile_id"], "AOE-GB-D06-CMD")
        for command_id, item in commands.items():
            binding = {
                "command_id": command_id,
                "commander_profile_id": item["principal_profile_id"],
                "army_registry_sha256": registry_sha256,
                "mission_id": MISSION_ID,
                "prior_plan_id": PRIOR_PLAN_ID,
                "prior_plan_sha256": PRIOR_PLAN_SHA256,
                "replacement_plan_id": REPLACEMENT_PLAN_ID,
                "replacement_plan_sha256": REPLACEMENT_PLAN_SHA256,
                "operation": item["operation"],
                "role": item["role"],
                "work_item_id": item["work_item_id"],
                "selection_sha256": SELECTION_SHA256,
            }
            self.assertEqual(
                item["command_authority_binding_sha256"],
                canonical_sha256({"domain": COMMAND_AUTHORITY_BINDING_DOMAIN, "binding": binding}),
            )

    def test_source_role_kind_and_authority_intent_drift_fail_closed(self) -> None:
        source = self.preflight.to_dict()
        source["authority_requirements"][0]["role"] = "second_control"
        source["authority_requirements"][0]["operation_intent_sha256"] = source_authority_intent(
            source["authority_requirements"][0]
        )
        source = self._reseal_preflight(source)
        with self.assertRaisesRegex(CollaborationPlanError, "role does not match"):
            build_collaboration_plan_replacement_authority_upgrade(
                preflight=CollaborationPlanReplacementPreflight.from_dict(source),
                army_registry=self.registry,
            )

        source = self.preflight.to_dict()
        source["authority_requirements"][0]["authority_kind"] = "command"
        source["authority_requirements"][0]["operation_intent_sha256"] = source_authority_intent(
            source["authority_requirements"][0]
        )
        source = self._reseal_preflight(source)
        with self.assertRaisesRegex(CollaborationPlanError, "kind is invalid"):
            build_collaboration_plan_replacement_authority_upgrade(
                preflight=CollaborationPlanReplacementPreflight.from_dict(source),
                army_registry=self.registry,
            )

        source = self.preflight.to_dict()
        source["authority_requirements"][0]["operation_intent_sha256"] = "sha256:" + "0" * 64
        source = self._reseal_preflight(source)
        with self.assertRaisesRegex(CollaborationPlanError, "intent binding is invalid"):
            build_collaboration_plan_replacement_authority_upgrade(
                preflight=CollaborationPlanReplacementPreflight.from_dict(source),
                army_registry=self.registry,
            )

        source = self.preflight.to_dict()
        source["authority_requirements"][0]["requirement_id"] = (
            "PAR-FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        )
        source = self._reseal_preflight(source)
        with self.assertRaisesRegex(CollaborationPlanError, "source_requirement_id"):
            build_collaboration_plan_replacement_authority_upgrade(
                preflight=CollaborationPlanReplacementPreflight.from_dict(source),
                army_registry=self.registry,
            )

    def test_resealed_substitutions_and_intent_drift_fail_offline_verification(self) -> None:
        document = copy.deepcopy(self.upgrade.to_dict())
        document["source_preflight"]["preflight_sha256"] = "sha256:" + "0" * 64
        parsed = CollaborationPlanReplacementAuthorityUpgrade.from_dict(reseal_upgrade(document))
        with self.assertRaisesRegex(CollaborationPlanError, "semantic verification failed"):
            verify_collaboration_plan_replacement_authority_upgrade(
                parsed,
                preflight=self.preflight,
                army_registry=self.registry,
            )

    def test_parser_recomputes_every_requirement_identity_binding(self) -> None:
        for field, value in (
            ("principal_profile_id", "AOE-GA-D02-CMD"),
            ("authority_id", "AOE-GA-D02"),
            ("work_item_id", "WIT-SPEC-9999999999999999"),
            ("source_requirement_id", "PAR-FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
            ("authority_intent_sha256", "sha256:" + "0" * 64),
            ("principal_operation_intent_sha256", "sha256:" + "0" * 64),
            ("command_authority_binding_sha256", "sha256:" + "0" * 64),
        ):
            document = copy.deepcopy(self.upgrade.to_dict())
            requirement = next(
                item
                for item in document["authority_requirements"]
                if item["authority_kind"] == "command"
            )
            requirement[field] = value
            reseal_requirement(requirement)
            document["authority_requirements"].sort(key=lambda item: item["requirement_id"])
            with self.assertRaises(CollaborationPlanError):
                CollaborationPlanReplacementAuthorityUpgrade.from_dict(reseal_upgrade(document))

        for field, value in (
            ("mission_id", "MISSION-SUBSTITUTED"),
            ("selection_sha256", "sha256:" + "0" * 64),
        ):
            document = copy.deepcopy(self.upgrade.to_dict())
            document[field] = value
            with self.assertRaises(CollaborationPlanError):
                CollaborationPlanReplacementAuthorityUpgrade.from_dict(reseal_upgrade(document))

    def test_replay_domains_separate_every_replacement_operation(self) -> None:
        requirements = self.upgrade.to_dict()["authority_requirements"]
        hashes = {item["principal_operation_intent_sha256"] for item in requirements}
        self.assertEqual(len(hashes), len(requirements))
        current_owner = {
            item["operation"]: item for item in requirements if item["role"] == "current_owner"
        }
        authorize = current_owner[
            PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_CURRENT_OWNER_AUTHORIZE.value
        ]
        cancel = current_owner[
            PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_CURRENT_OWNER_CANCEL.value
        ]
        cancel_intent = {
            "authority_intent_sha256": authorize["authority_intent_sha256"],
            "mission_id": MISSION_ID,
            "principal_profile_id": authorize["principal_profile_id"],
            "prior_plan_id": PRIOR_PLAN_ID,
            "prior_plan_sha256": PRIOR_PLAN_SHA256,
            "replacement_plan_id": REPLACEMENT_PLAN_ID,
            "replacement_plan_sha256": REPLACEMENT_PLAN_SHA256,
            "role": authorize["role"],
            "selection_sha256": SELECTION_SHA256,
            "work_item_id": authorize["work_item_id"],
        }
        self.assertNotEqual(
            authorize["principal_operation_intent_sha256"],
            compute_operation_intent_hash(cancel["operation"], cancel_intent),
        )

    def test_duplicate_json_keys_are_rejected_at_file_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "upgrade.json"
            payload = json.dumps(self.upgrade.to_dict(), sort_keys=True)
            path.write_text(
                payload[:-1] + ',"runtime_effect":"none"}',
                encoding="ascii",
            )
            with self.assertRaisesRegex(CollaborationPlanError, "Could not load"):
                load_collaboration_plan_replacement_authority_upgrade(path)

    def test_identity_rejects_role_work_item_and_command_binding_shape_errors(self) -> None:
        requirement = next(
            item
            for item in self.upgrade.to_dict()["authority_requirements"]
            if item["operation"]
            == PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_OWNER_AUTHORIZE.value
        )
        intent = {
            "authority_intent_sha256": requirement["authority_intent_sha256"],
            "mission_id": MISSION_ID,
            "principal_profile_id": requirement["principal_profile_id"],
            "prior_plan_id": PRIOR_PLAN_ID,
            "prior_plan_sha256": PRIOR_PLAN_SHA256,
            "replacement_plan_id": REPLACEMENT_PLAN_ID,
            "replacement_plan_sha256": REPLACEMENT_PLAN_SHA256,
            "role": "second_control",
            "selection_sha256": SELECTION_SHA256,
            "work_item_id": None,
        }
        with self.assertRaises(PrincipalAuthenticationError):
            compute_operation_intent_hash(requirement["operation"], intent)
        intent["role"] = "mission_owner"
        intent["work_item_id"] = "WIT-SPEC-1111111111111111"
        with self.assertRaises(PrincipalAuthenticationError):
            compute_operation_intent_hash(requirement["operation"], intent)
        intent["work_item_id"] = None
        intent["command_authority_binding_sha256"] = "sha256:" + "0" * 64
        with self.assertRaises(PrincipalAuthenticationError):
            compute_operation_intent_hash(requirement["operation"], intent)

    def test_non_v2_registry_and_unknown_fields_are_rejected(self) -> None:
        raw_registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        raw_registry["catalog_version"] = "2.0.1"
        with self.assertRaisesRegex(CollaborationPlanError, "exact Army v2"):
            build_collaboration_plan_replacement_authority_upgrade(
                preflight=self.preflight,
                army_registry=ExpertRegistry.from_dict(raw_registry),
            )
        raw_registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        raw_registry["profiles"][0]["mission"] = "Substituted commander mission"
        with self.assertRaisesRegex(CollaborationPlanError, "exact Army v2 registry"):
            build_collaboration_plan_replacement_authority_upgrade(
                preflight=self.preflight,
                army_registry=ExpertRegistry.from_dict(raw_registry),
            )
        document = copy.deepcopy(self.upgrade.to_dict())
        document["army_registry"]["registry_sha256"] = "sha256:" + "0" * 64
        with self.assertRaises(CollaborationPlanError):
            CollaborationPlanReplacementAuthorityUpgrade.from_dict(reseal_upgrade(document))
        document = self.upgrade.to_dict()
        document["unexpected"] = True
        with self.assertRaises(CollaborationPlanError):
            CollaborationPlanReplacementAuthorityUpgrade.from_dict(document)
        self.assertTrue(list(self.validator.iter_errors(document)))

    def test_phase_files_meet_repository_text_hygiene(self) -> None:
        paths = (
            ROOT / "src" / "sunderkey" / "collaboration_plan_replacement_authority_upgrade.py",
            ROOT / "scripts" / "build_collaboration_plan_replacement_authority_upgrade.py",
            SCHEMA_PATH,
            ROOT / "docs" / "phase186b1-plan-replacement-principal-identity.md",
            Path(__file__),
        )
        marker_terms = (
            "generated" + " by",
            "written" + " by (?:an )?ai",
            "as" + " an ai",
            "chat" + "gpt",
            "co" + "dex",
            "clau" + "de",
            "gem" + "ini",
            "co-authored" + "-by",
        )
        marker = re.compile("|".join(marker_terms), re.IGNORECASE)
        for path in paths:
            text = path.read_text(encoding="utf-8")
            self.assertTrue(text.isascii(), path)
            self.assertIsNone(marker.search(text), path)
            self.assertNotRegex(text, "[\u2013\u2014]")

    @staticmethod
    def _reseal_preflight(document: dict[str, object]) -> dict[str, object]:
        body = {
            key: value
            for key, value in document.items()
            if key not in {"preflight_id", "preflight_sha256"}
        }
        digest = canonical_sha256({"domain": PREFLIGHT_DOMAIN, "preflight": body})
        document["preflight_id"] = "PRF-" + digest.removeprefix("sha256:")[:32].upper()
        document["preflight_sha256"] = digest
        return document


if __name__ == "__main__":
    unittest.main()
