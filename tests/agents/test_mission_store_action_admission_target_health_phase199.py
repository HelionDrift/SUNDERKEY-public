"""Phase 199D action admission target-health gate integration tests."""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest import mock

from sunderkey.action_resolution import ActionResolutionError, ActionTier
from sunderkey.authenticated_action_admission import ActionAdmissionCommand
from sunderkey.authorized_target_health_runtime import TargetHealthStatus
from sunderkey.errors import StoreConflictError, StoreError
from sunderkey.identity import PrincipalOperation
from sunderkey.mission_store_action_admission import (
    MissionStoreAuthenticatedActionAdmissionService,
    verify_authenticated_action_admission_store,
)
from sunderkey.mission_store_target_health_gate import (
    MissionStoreTargetHealthGateService,
)
from sunderkey.registry import ExpertRegistry
from sunderkey.store import MissionStore
from sunderkey.target_health_custody import (
    TargetHealthCustodyConflictError,
    TargetHealthCustodyIntegrityError,
    TargetHealthCustodyNotFoundError,
)
from sunderkey.target_health_gate_contracts import (
    TargetHealthGateContractError,
    TargetHealthGateState,
    execution_binding_sha256,
)

from . import test_mission_store_action_admission_phase195b as phase195b


class MissionStoreActionAdmissionTargetHealthPhase199Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        phase195b.MissionStoreActionAdmissionPhase195bTests.setUpClass()

    def setUp(self) -> None:
        fixture = phase195b.MissionStoreActionAdmissionPhase195bTests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.service = fixture.service
        self.health_gate = fixture.health_gate
        self.custody = fixture.health_custody

    def _publication_assertion(self, sources):  # type: ignore[no-untyped-def]
        publication = sources["publication"]
        return self.fixture._assertion(
            "control",
            "51",
            PrincipalOperation.ACTION_AUTHORITY_PUBLISH,
            {
                "idempotency_key_sha256": publication.to_dict()[
                    "idempotency_key_sha256"
                ],
                "mission_id": self.fixture.mission_id,
                "principal_profile_id": self.fixture.control_profile,
                "publication_sha256": publication.publication_sha256,
            },
        )

    def _publish_exact(self, sources):  # type: ignore[no-untyped-def]
        published_at = datetime(2026, 7, 30, 10, 13, tzinfo=UTC)
        if self.fixture.root.now < published_at:
            self.fixture.root.now = published_at
        return self.service.publish_authority_sources(
            self._publication_assertion(sources),
            sources["publication"],
            policy=sources["policy"],
            catalog=sources["catalog"],
            target=sources["target"],
            budget=sources["budget"],
            safety=sources["safety"],
            proposal=sources["proposal"],
            source_bundle=sources["source_bundle"],
            material=sources["material"],
            observations=sources["observations"],
        )

    def _command(self, label: str = "phase199d-admit") -> ActionAdmissionCommand:
        return ActionAdmissionCommand(
            tenant_id=phase195b.TENANT_ID,
            mission_id=self.fixture.mission_id,
            proposal_product_id=self.fixture.product.product_id,
            action_type="api.request",
            action_tier=ActionTier.R2,
            idempotency_key_sha256=phase195b._canonical_sha256(
                {"command": label}
            ),
        )

    def _binding(self, sources):  # type: ignore[no-untyped-def]
        return self.service._target_health_binding_from_material(sources["material"])

    def _append_health(self, sources, *, healthy: bool):  # type: ignore[no-untyped-def]
        binding = self._binding(sources)
        binding_sha256 = execution_binding_sha256(binding)
        current = self.fixture.health_envelopes[binding_sha256]
        policy = self.fixture.health_policies[binding_sha256]
        self.fixture.root.now += timedelta(seconds=1)
        observed_at = self.fixture.root.now.strftime("%Y-%m-%dT%H:%M:%SZ")
        receipt = phase195b._healthy_target_receipt(binding, observed_at)
        if not healthy:
            receipt = replace(
                receipt,
                status=TargetHealthStatus.REJECTED,
                reason="missing_attestation",
                overall_health=None,
                safety_attestation=None,
                safety_attestation_sha256=None,
                budget_state=None,
                budget_state_sha256=None,
                source_receipts=(),
                observations=(),
                source_validation_performed=False,
                receipt_id="",
                receipt_sha256="",
            )
        receipt = replace(
            receipt,
            monotonic_tick=current.receipt.monotonic_tick + 1,
            receipt_id="",
            receipt_sha256="",
        )
        envelope = self.fixture.health_custody_factory.make_envelope(
            policy,
            sequence=current.sequence + 1,
            predecessor=current,
            observed_at=observed_at,
            monotonic_tick=receipt.monotonic_tick,
            receipt=receipt,
        )
        self.custody.append_envelope(envelope)
        self.fixture.health_envelopes[binding_sha256] = envelope
        return envelope

    def _action_counts(self) -> tuple[int, ...]:
        statements = (
            "SELECT COUNT(*) FROM principal_assertion_uses",
            "SELECT COUNT(*) FROM principal_assertion_effects",
            "SELECT COUNT(*) FROM action_authority_publications",
            "SELECT COUNT(*) FROM action_authority_grant_submissions",
            "SELECT COUNT(*) FROM action_admission_receipts",
            "SELECT COUNT(*) FROM action_budget_account_events",
        )
        with self.fixture.store._read_connection() as connection:
            return tuple(connection.execute(value).fetchone()[0] for value in statements)

    def _gate_counts(self) -> tuple[int, ...]:
        with self.fixture.store._read_connection() as connection:
            return tuple(
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in (
                    "target_health_gate_observations",
                    "target_health_gate_resumptions",
                    "target_health_gate_transitions",
                    "target_health_gate_heads",
                )
            )

    def test_constructor_requires_exact_same_store_and_registry_gate(self) -> None:
        with self.assertRaisesRegex(TypeError, "health_gate"):
            MissionStoreAuthenticatedActionAdmissionService(
                self.fixture.store,
                self.fixture.review_adapter,
                self.fixture.registry,
                clock=lambda: self.fixture.root.now,
            )

        foreign_store = MissionStore(
            self.fixture.root.directory / "phase199d-foreign.sqlite3",
            clock=lambda: self.fixture.root.now,
        )
        foreign_store_gate = MissionStoreTargetHealthGateService(
            foreign_store,
            self.custody,
            self.fixture.registry,
            clock=lambda: self.fixture.root.now,
        )
        with self.assertRaisesRegex(TypeError, "share one MissionStore"):
            MissionStoreAuthenticatedActionAdmissionService(
                self.fixture.store,
                self.fixture.review_adapter,
                self.fixture.registry,
                health_gate=foreign_store_gate,
                clock=lambda: self.fixture.root.now,
            )

        foreign_registry = ExpertRegistry.from_dict(self.fixture.registry.to_dict())
        foreign_registry_gate = MissionStoreTargetHealthGateService(
            self.fixture.store,
            self.custody,
            foreign_registry,
            clock=lambda: self.fixture.root.now,
        )
        with self.assertRaisesRegex(TypeError, "share one registry"):
            MissionStoreAuthenticatedActionAdmissionService(
                self.fixture.store,
                self.fixture.review_adapter,
                self.fixture.registry,
                health_gate=foreign_registry_gate,
                clock=lambda: self.fixture.root.now,
            )

        with self.assertRaisesRegex(TypeError, "share one trusted clock"):
            MissionStoreAuthenticatedActionAdmissionService(
                self.fixture.store,
                self.fixture.review_adapter,
                self.fixture.registry,
                health_gate=self.health_gate,
                clock=lambda: self.fixture.root.now,
            )

    def test_healthy_publication_replay_admission_replay_and_verify_current(self) -> None:
        sources = self.fixture._authority_sources()
        publication = self._publish_exact(sources)
        self.fixture.root.now += timedelta(seconds=1)
        self.assertEqual(self._publish_exact(sources), publication)

        command = self._command()
        self.fixture._stage_admission_grants(sources, command)
        self.fixture.root.now = datetime(2026, 7, 30, 10, 13, 2, tzinfo=UTC)
        receipt = self.service.admit(command)
        self.fixture.root.now += timedelta(seconds=1)
        self.assertEqual(self.service.admit(command), receipt)
        self.fixture.root.now += timedelta(seconds=1)
        current = self.service.verify_current(receipt.receipt_id)
        self.assertEqual(current.receipt, receipt)
        self.assertEqual(self._gate_counts(), (5, 0, 5, 1))
        self.assertEqual(
            self.health_gate.load_head(self._binding(sources)).latch_state,
            TargetHealthGateState.ACTIVE,
        )

    def test_same_second_publication_replay_uses_distinct_live_decisions(self) -> None:
        sources = self.fixture._authority_sources()
        publication = self._publish_exact(sources)
        replay = self._publish_exact(sources)
        self.assertEqual(replay, publication)
        with self.fixture.store._read_connection() as connection:
            observations = connection.execute(
                "SELECT inspection_sha256 FROM target_health_gate_observations "
                "ORDER BY observation_sequence"
            ).fetchall()
            uses = connection.execute(
                "SELECT decision_sha256 FROM action_target_health_gate_uses "
                "ORDER BY rowid"
            ).fetchall()
        self.assertEqual(len(observations), 2)
        self.assertNotEqual(
            observations[0]["inspection_sha256"],
            observations[1]["inspection_sha256"],
        )
        self.assertEqual(len(uses), 2)
        self.assertNotEqual(
            uses[0]["decision_sha256"],
            uses[1]["decision_sha256"],
        )

    def test_adverse_publication_replay_commits_pause_before_denial(self) -> None:
        sources = self.fixture._authority_sources()
        self._publish_exact(sources)
        action_baseline = self._action_counts()
        gate_baseline = self._gate_counts()
        self._append_health(sources, healthy=False)

        with self.assertRaisesRegex(ActionResolutionError, "Target health gate denied"):
            self._publish_exact(sources)

        self.assertEqual(self._action_counts(), action_baseline)
        self.assertEqual(
            self._gate_counts(),
            (gate_baseline[0] + 1, 0, gate_baseline[2] + 1, 1),
        )
        self.assertEqual(
            self.health_gate.load_head(self._binding(sources)).latch_state,
            TargetHealthGateState.PAUSED,
        )

    def test_adverse_clock_mismatch_still_commits_pause_before_denial(self) -> None:
        sources = self.fixture._authority_sources()
        self._publish_exact(sources)
        action_baseline = self._action_counts()
        gate_baseline = self._gate_counts()
        self._append_health(sources, healthy=False)
        with mock.patch.object(
            self.custody,
            "_trusted_clock",
            side_effect=lambda: self.fixture.root.now + timedelta(seconds=1),
        ), self.assertRaisesRegex(ActionResolutionError, "Target health gate denied"):
            self._publish_exact(sources)
        self.assertEqual(self._action_counts(), action_baseline)
        self.assertEqual(
            self._gate_counts(),
            (gate_baseline[0] + 1, 0, gate_baseline[2] + 1, 1),
        )
        self.assertEqual(
            self.health_gate.load_head(self._binding(sources)).latch_state,
            TargetHealthGateState.PAUSED,
        )

    def test_adverse_admission_commits_pause_without_admission_mutation(self) -> None:
        sources = self.fixture._authority_sources()
        self._publish_exact(sources)
        command = self._command("phase199d-adverse-admit")
        self.fixture._stage_admission_grants(sources, command)
        action_baseline = self._action_counts()
        gate_baseline = self._gate_counts()
        self._append_health(sources, healthy=False)

        with self.assertRaisesRegex(ActionResolutionError, "Target health gate denied"):
            self.service.admit(command)

        self.assertEqual(self._action_counts(), action_baseline)
        self.assertEqual(
            self._gate_counts(),
            (gate_baseline[0] + 1, 0, gate_baseline[2] + 1, 1),
        )
        with self.fixture.store._read_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_admission_receipts"
                ).fetchone()[0],
                0,
            )

    def test_missing_stale_and_tampered_custody_fail_closed_without_mutation(self) -> None:
        sources = self.fixture._authority_sources()
        action_baseline = self._action_counts()
        gate_baseline = self._gate_counts()
        errors = (
            TargetHealthCustodyNotFoundError("missing"),
            TargetHealthCustodyConflictError("stale"),
            TargetHealthCustodyIntegrityError("tampered"),
        )
        for error in errors:
            with self.subTest(error=str(error)), mock.patch.object(
                self.custody,
                "inspect_unique_current_binding_head",
                side_effect=error,
            ), self.assertRaises(type(error)):
                self._publish_exact(sources)
            self.assertEqual(self._action_counts(), action_baseline)
            self.assertEqual(self._gate_counts(), gate_baseline)

    def test_binding_substitution_fails_before_mutation(self) -> None:
        sources = self.fixture._authority_sources()
        binding = self._binding(sources)
        inspection = self.custody.inspect_unique_current_binding_head(
            tenant_id=binding.tenant_id,
            mission_id=binding.context_id,
            binding_sha256=execution_binding_sha256(binding),
        )
        substituted = replace(binding, target_sha256="sha256:" + "e" * 64)
        action_baseline = self._action_counts()
        gate_baseline = self._gate_counts()
        with mock.patch.object(
            self.service,
            "_target_health_binding_from_material",
            return_value=substituted,
        ), mock.patch.object(
            self.custody,
            "inspect_unique_current_binding_head",
            return_value=inspection,
        ), self.assertRaises(StoreConflictError):
            self._publish_exact(sources)
        self.assertEqual(self._action_counts(), action_baseline)
        self.assertEqual(self._gate_counts(), gate_baseline)

    def test_material_binding_rejects_nested_target_identity_substitution(self) -> None:
        sources = self.fixture._authority_sources()
        material_document = sources["material"].to_dict()
        target_document = sources["action_target"].to_dict()
        substituted_target = phase195b.build_target_action_descriptor(
            tenant_id="tenant:substituted",
            mission_id="MISSION-SUBSTITUTED",
            target_scope_sha256=target_document["target_scope_sha256"],
            authority_snapshot_sha256=target_document[
                "authority_snapshot_sha256"
            ],
            target_id=target_document["target_id"],
            target_sha256=target_document["target_sha256"],
            environment=target_document["environment"],
        )
        substituted_material = phase195b.build_action_authority_material_snapshot(
            tenant_id=material_document["tenant_id"],
            mission_id=material_document["mission_id"],
            plan_id=material_document["plan_id"],
            proposal=sources["proposal"],
            catalog=sources["executable_catalog"],
            parameters=sources["parameters"],
            target=substituted_target,
            resolver_profile_id=material_document["resolver_profile_id"],
            resolver_subject=material_document["resolver_subject"],
            context=sources["context"],
            worker_session=sources["worker"],
            credential_lease=sources["credential"],
            health=sources["health"],
            budget=sources["budget_binding"],
            monitor_observation_sha256=material_document[
                "monitor_observation_sha256"
            ],
            evidence_obligations=sources["evidence_obligations"],
            stop_conditions=sources["stop"],
            restoration_duties=sources["restoration"],
            resolved_at=material_document["resolved_at"],
            approved_at=material_document["approved_at"],
            quorum_expires_at=material_document["quorum_expires_at"],
            requested_at=material_document["requested_at"],
            expires_at=material_document["expires_at"],
            observed_at=material_document["observed_at"],
            valid_until=material_document["valid_until"],
        )
        with self.assertRaises(TargetHealthGateContractError):
            self.service._target_health_binding_from_material(substituted_material)

    def test_healthy_gate_observation_rolls_back_on_later_failure(self) -> None:
        sources = self.fixture._authority_sources()
        action_baseline = self._action_counts()
        gate_baseline = self._gate_counts()
        with mock.patch.object(
            self.service._principal_custody,
            "consume",
            side_effect=StoreError("injected late failure"),
        ), self.assertRaisesRegex(StoreError, "injected late failure"):
            self._publish_exact(sources)
        self.assertEqual(self._action_counts(), action_baseline)
        self.assertEqual(self._gate_counts(), gate_baseline)

    def test_historical_verifiers_do_not_depend_on_live_custody(self) -> None:
        _sources, _command, _resolution, _quorum, _request, receipt = (
            self.fixture._admit_complete_sources()
        )
        with mock.patch.object(
            self.custody,
            "inspect_unique_current_binding_head",
            side_effect=TargetHealthCustodyIntegrityError("offline"),
        ):
            with self.fixture.store._read_connection() as connection:
                verify_authenticated_action_admission_store(
                    connection,
                    mission_id=self.fixture.mission_id,
                )
            report = self.health_gate.verify_store(self.fixture.mission_id)
        self.assertEqual(report.observation_count, 2)
        self.assertEqual(receipt.to_dict()["mission_id"], self.fixture.mission_id)


if __name__ == "__main__":
    unittest.main()
