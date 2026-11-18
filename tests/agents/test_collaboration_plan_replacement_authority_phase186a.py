"""Phase 186A authenticated plan replacement authority contract coverage."""

from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import jsonschema

from scripts.build_collaboration_plan_replacement_authority_plan import (
    build_artifact,
    build_parser,
    build_sources,
)
from sunderkey import collaboration_plan_replacement_authority as authority_module
from sunderkey.collaboration_plan_replacement_authority import (
    OPERATION_CONTRACTS,
    CollaborationPlanReplacementAuthorityPlan,
    PlanReplacementPrincipalOperation,
    VerifiedCollaborationPlanReplacementAuthorityPlan,
    load_collaboration_plan_replacement_authority_plan,
    validate_verified_collaboration_plan_replacement_authority_plan,
    verify_collaboration_plan_replacement_authority_plan_offline,
)
from sunderkey.errors import CollaborationPlanError

ROOT = Path(__file__).resolve().parents[2]
ARTIFACT_PATH = ROOT / "registry/collaboration-plan-replacement-authority-plan-v1.json"
SCHEMA_PATH = ROOT / "registry/schemas/collaboration-plan-replacement-authority-plan-v1.schema.json"
MODULE_PATH = ROOT / "src/sunderkey/collaboration_plan_replacement_authority.py"


def _rehash(
    document: dict[str, object],
    *,
    refresh_coverage: bool = False,
) -> dict[str, object]:
    requirements = []
    for item in document["assertion_requirements"]:
        base = copy.deepcopy(item)
        del base["principal_operation_intent_sha256"]
        del base["replay_key_sha256"]
        requirements.append(base)
    coverage = (
        authority_module._authority_requirement_coverage(requirements)
        if refresh_coverage
        else copy.deepcopy(document["authority_requirement_coverage"])
    )
    core = authority_module._core_document(
        source_preflight=copy.deepcopy(document["source_preflight"]),
        source_policies=copy.deepcopy(document["source_policies"]),
        source_registry=copy.deepcopy(document["source_registry"]),
        mission_id=str(document["mission_id"]),
        issued_at=str(document["issued_at"]),
        expires_at=str(document["expires_at"]),
        authority_requirement_coverage=coverage,
        requirements=requirements,
    )
    plan_id, plan_sha256 = authority_module._plan_identity(core)
    body = {
        **core,
        "authority_plan_id": plan_id,
        "authority_plan_sha256": plan_sha256,
        "assertion_requirements": authority_module._expand_requirements(core, plan_id, plan_sha256),
    }
    document_sha256 = authority_module._canonical_sha256(
        {
            "domain": authority_module.AUTHORITY_DOCUMENT_DOMAIN,
            "document": body,
        }
    )
    return {**body, "document_sha256": document_sha256}


class CollaborationPlanReplacementAuthorityPhase186ATests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.args: argparse.Namespace = build_parser().parse_args([])
        (
            cls.preflight,
            cls.prior_plan,
            cls.replacement_plan,
            cls.authority_policy,
            cls.mission_policy,
            cls.registry,
            cls.registry_bytes,
        ) = build_sources(cls.args)
        cls.checked = json.loads(ARTIFACT_PATH.read_text(encoding="utf-8"))
        cls.plan = CollaborationPlanReplacementAuthorityPlan.from_dict(cls.checked)

    def _verify(
        self,
        plan: CollaborationPlanReplacementAuthorityPlan | None = None,
        *,
        verified_at: str = "2026-08-03T00:03:00Z",
        consumed_replay_keys: tuple[str, ...] = (),
        registry_source: bytes | Path | None = None,
    ) -> VerifiedCollaborationPlanReplacementAuthorityPlan:
        return verify_collaboration_plan_replacement_authority_plan_offline(
            plan or self.plan,
            preflight=self.preflight,
            prior_plan=self.prior_plan,
            replacement_plan=self.replacement_plan,
            authority_policy=self.authority_policy,
            mission_policy=self.mission_policy,
            registry=self.registry,
            registry_source=(self.registry_bytes if registry_source is None else registry_source),
            verified_at=verified_at,
            consumed_replay_keys=consumed_replay_keys,
        )

    def test_checked_artifact_rebuilds_exactly_and_validates_schema(self) -> None:
        self.assertEqual(build_artifact(self.args), self.checked)
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(self.checked)
        self.assertEqual(self._verify().to_dict(), self.checked)

    def test_schema_rejects_non_profile_principal_authorities(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(schema)
        requirement = next(
            item
            for item in self.checked["assertion_requirements"]
            if item["authority_kind"] == "principal_profile"
        )
        coverage_tuple = next(
            item
            for item in self.checked["authority_requirement_coverage"]["ordered_requirement_tuples"]
            if item["requirement_id"] == requirement["requirement_id"]
        )
        for collection, item in (
            ("assertion_requirements", requirement),
            ("authority_requirement_coverage", coverage_tuple),
        ):
            changed = copy.deepcopy(self.checked)
            if collection == "assertion_requirements":
                target = next(
                    candidate
                    for candidate in changed[collection]
                    if candidate["requirement_id"] == item["requirement_id"]
                )
            else:
                target = next(
                    candidate
                    for candidate in changed[collection]["ordered_requirement_tuples"]
                    if candidate["requirement_id"] == item["requirement_id"]
                )
            target["authority_id"] = "principal:not-a-profile"
            with self.subTest(collection=collection):
                self.assertTrue(tuple(validator.iter_errors(changed)))

    def test_exact_phase184_and_source_policy_bindings_are_published(self) -> None:
        document = self.checked
        self.assertEqual(
            document["source_preflight"],
            {
                "preflight_id": self.preflight.preflight_id,
                "preflight_sha256": self.preflight.preflight_sha256,
                "selection_sha256": self.preflight.selection_sha256,
            },
        )
        self.assertEqual(
            document["source_policies"]["reconfiguration_authority_policy"],
            {
                "policy_id": self.authority_policy.policy_id,
                "policy_sha256": self.authority_policy.policy_sha256,
            },
        )
        mission_reference = document["source_policies"]["mission_reconfiguration_policy"]
        self.assertEqual(mission_reference["policy_id"], self.mission_policy.policy_id)
        self.assertEqual(mission_reference["policy_sha256"], self.mission_policy.policy_sha256)
        self.assertEqual(
            document["source_registry"]["file_sha256"],
            "sha256:" + hashlib.sha256(self.registry_bytes).hexdigest(),
        )
        self.assertEqual(
            document["source_registry"]["content_sha256"],
            authority_module._canonical_sha256(self.registry.to_dict()),
        )
        self.assertEqual(
            document["source_policies"]["mission_policy_commit"],
            self.preflight.to_dict()["mission_policy_commit"],
        )
        self.assertEqual(
            self._verify(registry_source=Path(self.args.registry)).to_dict(),
            self.checked,
        )
        expected_tuples = [
            {
                "requirement_id": item["requirement_id"],
                "operation": item["operation"],
                "role": item["role"],
                "authority_id": item["authority_id"],
                "authority_kind": item["authority_kind"],
                "work_item_id": item["work_item_id"],
            }
            for item in self.preflight.to_dict()["authority_requirements"]
        ]
        coverage = document["authority_requirement_coverage"]
        self.assertEqual(coverage["requirement_count"], len(expected_tuples))
        self.assertEqual(coverage["ordered_requirement_tuples"], expected_tuples)
        self.assertEqual(document["verification_status"], "source_verification_required")

    def test_all_nine_identity_operations_and_command_profiles_are_exact(self) -> None:
        expected = {operation.value for operation in PlanReplacementPrincipalOperation}
        self.assertEqual({contract["operation"] for contract in OPERATION_CONTRACTS}, expected)
        requirements = self.checked["assertion_requirements"]
        self.assertEqual({item["operation"] for item in requirements}, expected)
        commands = {
            item["authority_id"]: item["resolved_profile_id"]
            for item in requirements
            if item["authority_kind"] == "command"
        }
        self.assertEqual(
            commands,
            {
                "AOE-GB-D06": "AOE-GB-D06-CMD",
                "AOE-GC-D11": "AOE-GC-D11-CMD",
            },
        )

    def test_exact_role_separation_and_zero_authority_boundary(self) -> None:
        requirements = self.checked["assertion_requirements"]
        profiles_by_role: dict[str, set[str]] = {}
        for item in requirements:
            profiles_by_role.setdefault(item["role"], set()).add(item["resolved_profile_id"])
        independent = (
            profiles_by_role["independent_control"]
            | profiles_by_role["independent_assurance"]
            | profiles_by_role["second_control"]
        )
        affected_owners = profiles_by_role["current_owner"] | profiles_by_role["proposed_owner"]
        self.assertTrue(independent.isdisjoint(affected_owners))
        self.assertEqual(len(independent), 3)
        self.assertEqual(self.checked["runtime_authority_effect"], "none")
        self.assertEqual(self.checked["runtime_effect"], "none")
        self.assertFalse(self.checked["assertions_authenticated"])

        changed = copy.deepcopy(self.checked)
        control = next(
            item
            for item in changed["assertion_requirements"]
            if item["role"] == "independent_control"
        )
        control["authority_id"] = "AOE-HQ-12"
        control["resolved_profile_id"] = "AOE-HQ-12"
        with self.assertRaisesRegex(CollaborationPlanError, "owns affected work"):
            CollaborationPlanReplacementAuthorityPlan.from_dict(
                _rehash(changed, refresh_coverage=True)
            )

    def test_intent_tampering_and_semantic_rehash_fail_closed(self) -> None:
        changed = copy.deepcopy(self.checked)
        changed["assertion_requirements"][0]["principal_operation_intent_sha256"] = (
            "sha256:" + "0" * 64
        )
        with self.assertRaisesRegex(CollaborationPlanError, "intents"):
            CollaborationPlanReplacementAuthorityPlan.from_dict(changed)

        changed = copy.deepcopy(self.checked)
        changed["source_preflight"]["selection_sha256"] = "sha256:" + "e" * 64
        rehashed = CollaborationPlanReplacementAuthorityPlan.from_dict(_rehash(changed))
        with self.assertRaisesRegex(CollaborationPlanError, "offline verification"):
            self._verify(rehashed)

    def test_requirement_coverage_rejects_rehashed_requirement_changes(self) -> None:
        mutations = []

        removed = copy.deepcopy(self.checked)
        removed["assertion_requirements"] = removed["assertion_requirements"][1:]
        mutations.append(removed)

        duplicated = copy.deepcopy(self.checked)
        duplicate = copy.deepcopy(duplicated["assertion_requirements"][-1])
        duplicate["requirement_id"] = "PAR-" + "F" * 32
        duplicated["assertion_requirements"].append(duplicate)
        mutations.append(duplicated)

        substituted_operation = copy.deepcopy(self.checked)
        operation_item = next(
            item
            for item in substituted_operation["assertion_requirements"]
            if item["operation"]
            == "sunderkey.collaboration.plan-replacement.current-owner-authorize.v1"
        )
        operation_item["operation"] = (
            "sunderkey.collaboration.plan-replacement.current-owner-cancel.v1"
        )
        mutations.append(substituted_operation)

        substituted_work_item = copy.deepcopy(self.checked)
        work_item = next(
            item
            for item in substituted_work_item["assertion_requirements"]
            if item["work_item_id"] is not None
        )
        work_item["work_item_id"] = next(
            item["work_item_id"]
            for item in substituted_work_item["assertion_requirements"]
            if item["work_item_id"] is not None
            and item["work_item_id"] != work_item["work_item_id"]
        )
        mutations.append(substituted_work_item)

        with tempfile.TemporaryDirectory() as directory:
            for index, changed in enumerate(mutations):
                with self.subTest(index=index):
                    path = Path(directory) / f"changed-{index}.json"
                    path.write_text(json.dumps(_rehash(changed)), encoding="utf-8")
                    with self.assertRaisesRegex(
                        CollaborationPlanError,
                        "coverage",
                    ):
                        load_collaboration_plan_replacement_authority_plan(path)

    def test_requirement_intervals_must_equal_plan_window(self) -> None:
        for field, value in (
            ("assertion_valid_after", "2026-08-03T00:04:00Z"),
            ("assertion_expires_at", "2026-08-03T00:32:00Z"),
            ("assertion_expires_at", "2026-08-03T00:02:00Z"),
        ):
            changed = copy.deepcopy(self.checked)
            changed["assertion_requirements"][0][field] = value
            with (
                self.subTest(field=field, value=value),
                self.assertRaisesRegex(CollaborationPlanError, "equal.*plan window"),
            ):
                CollaborationPlanReplacementAuthorityPlan.from_dict(_rehash(changed))

    def test_only_offline_verification_creates_verified_wrapper(self) -> None:
        verified = self._verify()
        self.assertIs(type(verified), VerifiedCollaborationPlanReplacementAuthorityPlan)
        self.assertIs(type(verified.plan), CollaborationPlanReplacementAuthorityPlan)
        self.assertEqual(verified.to_dict(), self.checked)
        self.assertEqual(
            validate_verified_collaboration_plan_replacement_authority_plan(verified).to_dict(),
            self.checked,
        )

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authority-plan.json"
            path.write_text(json.dumps(self.checked), encoding="utf-8")
            loaded = load_collaboration_plan_replacement_authority_plan(path)
        self.assertIs(type(loaded), CollaborationPlanReplacementAuthorityPlan)

        with self.assertRaisesRegex(TypeError, "only by"):
            VerifiedCollaborationPlanReplacementAuthorityPlan(
                plan=self.plan,
                verified_at="2026-08-03T00:03:00Z",
                _proof=b"not-a-valid-proof",
            )

        changed = copy.deepcopy(self.checked)
        changed["source_preflight"]["selection_sha256"] = "sha256:" + "e" * 64
        alternate_plan = CollaborationPlanReplacementAuthorityPlan.from_dict(_rehash(changed))
        forged = object.__new__(VerifiedCollaborationPlanReplacementAuthorityPlan)
        object.__setattr__(
            forged,
            "_plan_json",
            authority_module._canonical_json(alternate_plan.to_dict()),
        )
        object.__setattr__(forged, "_verified_at", verified.verified_at)
        object.__setattr__(forged, "_proof", object.__getattribute__(verified, "_proof"))
        with self.assertRaisesRegex(TypeError, "proof is invalid"):
            validate_verified_collaboration_plan_replacement_authority_plan(forged)

        proof_clone = object.__new__(VerifiedCollaborationPlanReplacementAuthorityPlan)
        for attribute in ("_plan_json", "_verified_at", "_proof"):
            object.__setattr__(
                proof_clone,
                attribute,
                object.__getattribute__(verified, attribute),
            )
        with self.assertRaisesRegex(TypeError, "proof is invalid"):
            validate_verified_collaboration_plan_replacement_authority_plan(proof_clone)

        rebound = self._verify()
        object.__setattr__(
            rebound,
            "_plan_json",
            authority_module._canonical_json(alternate_plan.to_dict()),
        )
        for access in (
            lambda: rebound.plan,
            lambda: rebound.verified_at,
            rebound.to_dict,
        ):
            with self.assertRaisesRegex(TypeError, "proof is invalid"):
                access()
        for attribute in ("plan", "document_json"):
            with self.assertRaises(AttributeError):
                object.__setattr__(rebound, attribute, alternate_plan)

        for name in (
            "_VERIFICATION_PROOF_KEY",
            "_verified_plan_proof",
            "_issue_verified_authority_plan",
            "_build_verified_authority_plan_boundary",
            "issue",
            "proof_for",
        ):
            with self.subTest(module_attribute=name):
                self.assertFalse(hasattr(authority_module, name))

        changed = copy.deepcopy(self.checked)
        changed["assertion_requirements"] = changed["assertion_requirements"][:-1]
        self_consistent_alternate = CollaborationPlanReplacementAuthorityPlan.from_dict(
            _rehash(changed, refresh_coverage=True)
        )
        self.assertEqual(
            self_consistent_alternate.to_dict()["verification_status"],
            "source_verification_required",
        )
        with self.assertRaisesRegex(CollaborationPlanError, "offline verification"):
            self._verify(self_consistent_alternate)

    def test_expiry_and_replay_fail_closed_without_consuming_state(self) -> None:
        for moment in (
            "2026-08-03T00:02:59Z",
            "2026-08-03T00:33:00Z",
            "2026-08-03T00:33:01Z",
        ):
            with (
                self.subTest(moment=moment),
                self.assertRaisesRegex(CollaborationPlanError, "validity window"),
            ):
                self._verify(verified_at=moment)

        replay_key = self.checked["assertion_requirements"][0]["replay_key_sha256"]
        with self.assertRaisesRegex(CollaborationPlanError, "already consumed"):
            self._verify(consumed_replay_keys=(replay_key,))
        other = "sha256:" + "f" * 64
        with self.assertRaisesRegex(CollaborationPlanError, "duplicates"):
            self._verify(consumed_replay_keys=(other, other))
        self.assertEqual(self._verify().to_dict(), self.checked)

    def test_stale_preflight_policy_and_registry_bindings_are_rejected(self) -> None:
        mutations = (
            lambda value: value["source_preflight"].update(
                {"preflight_sha256": "sha256:" + "e" * 64}
            ),
            lambda value: (
                value["source_policies"]["mission_reconfiguration_policy"].update(
                    {"policy_sha256": "sha256:" + "e" * 64}
                ),
                value["source_policies"]["mission_policy_commit"].update(
                    {"policy_sha256": "sha256:" + "e" * 64}
                ),
            ),
            lambda value: value["source_registry"].update({"file_sha256": "sha256:" + "e" * 64}),
        )
        for mutate in mutations:
            changed = copy.deepcopy(self.checked)
            mutate(changed)
            parsed = CollaborationPlanReplacementAuthorityPlan.from_dict(_rehash(changed))
            with self.assertRaisesRegex(CollaborationPlanError, "offline verification"):
                self._verify(parsed)

        with self.assertRaisesRegex(CollaborationPlanError, "offline verification"):
            self._verify(registry_source=self.registry_bytes + b"\n")

        different_registry = json.loads(self.registry_bytes.decode("utf-8"))
        different_registry["catalog_version"] = "2.0.1"
        with self.assertRaisesRegex(CollaborationPlanError, "source and supplied registry differ"):
            self._verify(
                registry_source=(
                    json.dumps(different_registry, separators=(",", ":")).encode("utf-8")
                )
            )

        duplicate_key_registry = self.registry_bytes.replace(
            b'"schema_version": 1',
            b'"schema_version": 1, "schema_version": 1',
            1,
        )
        with self.assertRaisesRegex(CollaborationPlanError, "source bytes are invalid"):
            self._verify(registry_source=duplicate_key_registry)

    def test_loader_rejects_duplicate_keys(self) -> None:
        source = ARTIFACT_PATH.read_text(encoding="utf-8")
        duplicate = source.replace(
            '"schema_version": 1',
            '"schema_version": 1, "schema_version": 1',
            1,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text(duplicate, encoding="utf-8")
            with self.assertRaises(CollaborationPlanError):
                load_collaboration_plan_replacement_authority_plan(path)

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
                {
                    "httpx",
                    "requests",
                    "socket",
                    "sqlite3",
                    "subprocess",
                    "urllib",
                }
            )
        )
        for forbidden in (
            "MissionStore",
            "execution_credentials",
            "network_call_performed = True",
            "consume_replay_key",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
