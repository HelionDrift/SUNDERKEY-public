"""Phase 164 high-availability coordination contract coverage."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

import sunderkey
from sunderkey.ha_coordination_contracts import (
    NO_EFFECTS,
    ClusterMemberDeclaration,
    DegradedServiceMode,
    HACoordinationContractError,
    QuorumObservation,
    QuorumObservationSet,
    RecoveryEvidence,
    RecoveryEvidenceKind,
    RecoveryEvidenceRequirements,
    assess_split_brain,
    declare_leader_epoch,
    evaluate_safe_write_admission,
    issue_fencing_grant,
    observe_failover,
    parse_contract,
    plan_failover,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "ha-coordination-contract-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "ha_coordination_contracts.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "ha-coordination-contracts.md",
)
DIGESTS = tuple("sha256:" + character * 64 for character in "0123456789abcdef")


class HACoordinationContractsPhase164Tests(unittest.TestCase):
    def test_public_package_exports_are_available(self) -> None:
        self.assertIs(sunderkey.assess_split_brain, assess_split_brain)
        self.assertIs(
            sunderkey.evaluate_safe_write_admission,
            evaluate_safe_write_admission,
        )

    def member(self, name: str = "node_a") -> ClusterMemberDeclaration:
        return ClusterMemberDeclaration(
            tenant_ref="tenantref:acme",
            service_ref="serviceref:control-plane",
            cluster_ref="clusterref:primary",
            member_ref=f"memberref:{name}",
            service_version="4.2.0",
            cluster_version="7.1.0",
            declaration_version=3,
            role="voter",
            state="active",
            region="us-east-1",
            eligible_for_leadership=True,
            declared_at="2026-09-20T12:00:00Z",
        )

    def epoch(
        self,
        name: str = "node_a",
        number: int = 5,
        *,
        issued_at: str = "2026-09-20T12:00:00Z",
        lease_expires_at: str = "2026-09-20T12:05:00Z",
    ):
        return declare_leader_epoch(
            self.member(name),
            epoch=number,
            expected_prior_epoch=number - 1,
            lease_ref=f"leaseref:leader-{number}",
            issued_at=issued_at,
            lease_expires_at=lease_expires_at,
            maximum_clock_skew_seconds=30,
        )

    def observations(
        self,
        epoch=None,
        *,
        leader: str = "node_a",
        number: int = 5,
        evaluated_at: str = "2026-09-20T12:01:00Z",
    ) -> QuorumObservationSet:
        epoch = epoch or self.epoch()
        return QuorumObservationSet(
            tenant_ref=epoch.tenant_ref,
            service_ref=epoch.service_ref,
            cluster_ref=epoch.cluster_ref,
            service_version=epoch.service_version,
            cluster_version=epoch.cluster_version,
            expected_epoch_id=epoch.epoch_id,
            expected_epoch_sha256=epoch.epoch_sha256,
            voter_member_refs=("memberref:node_a", "memberref:node_b", "memberref:node_c"),
            quorum_size=2,
            maximum_clock_skew_seconds=30,
            evaluated_at=evaluated_at,
            observations=tuple(
                QuorumObservation(
                    observer_ref=f"observerref:{observer}",
                    observed_leader_ref=f"memberref:{leader}",
                    observed_epoch=number,
                    observed_at=evaluated_at,
                    observed_lease_expires_at=epoch.lease_expires_at,
                )
                for observer in ("node_a", "node_b", "node_c")
            ),
        )

    def clear_chain(self):
        epoch = self.epoch()
        observations = self.observations(epoch)
        assessment = assess_split_brain(epoch, (observations,), assessed_at="2026-09-20T12:01:00Z")
        grant = issue_fencing_grant(
            epoch,
            observations,
            assessment,
            resource_ref="resourceref:mission-state",
            expected_resource_version=18,
            granted_at="2026-09-20T12:01:01Z",
        )
        return epoch, observations, assessment, grant

    def requirements(self) -> RecoveryEvidenceRequirements:
        return RecoveryEvidenceRequirements(
            tenant_ref="tenantref:acme",
            service_ref="serviceref:control-plane",
            cluster_ref="clusterref:primary",
            service_version="4.2.0",
            cluster_version="7.1.0",
            requirement_ref="requirementref:production-failover",
            requirement_version="2.0.0",
            required_evidence_kinds=tuple(RecoveryEvidenceKind),
            minimum_distinct_observers=3,
            requires_mission_stop_reconciliation=True,
            requires_execution_session_reconciliation=True,
            effective_at="2026-09-20T12:00:00Z",
        )

    def recovery_evidence(self) -> tuple[RecoveryEvidence, ...]:
        return tuple(
            RecoveryEvidence(
                evidence_kind=kind,
                evidence_ref=f"evidenceref:{kind.value}",
                evidence_sha256=DIGESTS[index],
                observer_ref=f"observerref:node_{'abc'[index % 3]}",
                observed_at="2026-09-20T12:03:00Z",
            )
            for index, kind in enumerate(RecoveryEvidenceKind)
        )

    def test_records_are_immutable_content_addressed_and_round_trip(self) -> None:
        member = self.member()
        epoch, observations, assessment, grant = self.clear_chain()
        records = (member, epoch, observations, assessment, grant, self.requirements())
        for record in records:
            with self.subTest(kind=record.KIND):
                self.assertEqual(parse_contract(record.to_dict()), record)
                self.assertEqual(parse_contract(record.to_json()), record)
                self.assertTrue(record.to_json().isascii())
        with self.assertRaises(FrozenInstanceError):
            member.cluster_version = "8.0.0"
        changed = copy.deepcopy(epoch.to_dict())
        changed["epoch"] = 9
        with self.assertRaises(HACoordinationContractError):
            parse_contract(changed)

    def test_leader_epoch_requires_active_voter_and_monotonic_epoch(self) -> None:
        with self.assertRaisesRegex(HACoordinationContractError, "only an active voter"):
            replace(self.member(), role="learner")
        with self.assertRaisesRegex(HACoordinationContractError, "advance exactly once"):
            declare_leader_epoch(
                self.member(),
                epoch=5,
                expected_prior_epoch=2,
                lease_ref="leaseref:bad-epoch",
                issued_at="2026-09-20T12:00:00Z",
                lease_expires_at="2026-09-20T12:05:00Z",
                maximum_clock_skew_seconds=30,
            )

    def test_observations_require_distinct_voters_quorum_and_bounded_skew(self) -> None:
        epoch = self.epoch()
        observations = list(self.observations(epoch).observations)
        observations[1] = replace(observations[1], observer_ref="observerref:node_a")
        with self.assertRaisesRegex(HACoordinationContractError, "distinct"):
            replace(self.observations(epoch), observations=tuple(observations))
        with self.assertRaisesRegex(HACoordinationContractError, "clock skew"):
            replace(
                self.observations(epoch),
                evaluated_at="2026-09-20T12:02:00Z",
            )

    def test_split_brain_assessment_is_clear_only_for_exact_quorum_epoch(self) -> None:
        epoch = self.epoch()
        clear = assess_split_brain(
            epoch, (self.observations(epoch),), assessed_at="2026-09-20T12:01:00Z"
        )
        self.assertEqual(clear.status, "clear")
        wrong = self.observations(epoch, leader="node_b")
        conflict = assess_split_brain(epoch, (wrong,), assessed_at="2026-09-20T12:01:00Z")
        self.assertEqual(conflict.status, "conflicting_leaders")
        self.assertIn("unexpected_quorum_leader", conflict.blocker_codes)
        stale = assess_split_brain(
            epoch,
            (self.observations(epoch),),
            assessed_at="2026-09-20T12:06:00Z",
        )
        self.assertEqual(stale.status, "stale_epoch")
        with self.assertRaisesRegex(HACoordinationContractError, "clock skew"):
            assess_split_brain(
                epoch,
                (replace(self.observations(epoch), maximum_clock_skew_seconds=31),),
                assessed_at="2026-09-20T12:01:00Z",
            )
        wrong_expiry = replace(
            self.observations(epoch),
            observations=tuple(
                replace(item, observed_lease_expires_at="2026-09-20T12:04:00Z")
                for item in self.observations(epoch).observations
            ),
        )
        expiry_conflict = assess_split_brain(
            epoch, (wrong_expiry,), assessed_at="2026-09-20T12:01:00Z"
        )
        self.assertEqual(expiry_conflict.status, "conflicting_leaders")

    def test_fencing_requires_clear_quorum_and_rejects_stale_epoch(self) -> None:
        epoch, observations, assessment, grant = self.clear_chain()
        conflict = assess_split_brain(
            epoch,
            (self.observations(epoch, leader="node_b"),),
            assessed_at="2026-09-20T12:01:00Z",
        )
        with self.assertRaisesRegex(HACoordinationContractError, "clear"):
            issue_fencing_grant(
                epoch,
                observations,
                conflict,
                resource_ref="resourceref:mission-state",
                expected_resource_version=18,
                granted_at="2026-09-20T12:01:01Z",
            )
        with self.assertRaisesRegex(HACoordinationContractError, "stale leader epoch"):
            issue_fencing_grant(
                epoch,
                observations,
                assessment,
                resource_ref="resourceref:mission-state",
                expected_resource_version=18,
                granted_at="2026-09-20T12:01:01Z",
                prior_grant=grant,
            )

    def test_safe_write_admission_denies_ambiguity_staleness_and_degraded_dispatch(self) -> None:
        epoch, observations, assessment, grant = self.clear_chain()
        allowed = evaluate_safe_write_admission(
            epoch,
            observations,
            assessment,
            grant,
            operation_ref="operationref:write-001",
            operation="target_action_dispatch",
            resource_ref="resourceref:mission-state",
            expected_resource_version=18,
            evaluated_at="2026-09-20T12:01:02Z",
        )
        self.assertEqual(allowed.status, "eligible_for_separate_authorization")
        self.assertEqual(allowed.authorization_effect, "none")
        degraded = DegradedServiceMode(
            tenant_ref=epoch.tenant_ref,
            service_ref=epoch.service_ref,
            cluster_ref=epoch.cluster_ref,
            service_version=epoch.service_version,
            cluster_version=epoch.cluster_version,
            mode="control_plane_only",
            reason_codes=("regional_partition",),
            entered_at="2026-09-20T12:00:00Z",
            expires_at="2026-09-20T12:10:00Z",
            allowed_write_operations=("control_plane_write",),
            enforcement_status="external_enforcement_required",
        )
        denied = evaluate_safe_write_admission(
            epoch,
            observations,
            assessment,
            grant,
            operation_ref="operationref:dispatch-001",
            operation="target_action_dispatch",
            resource_ref="resourceref:mission-state",
            expected_resource_version=18,
            evaluated_at="2026-09-20T12:01:02Z",
            degraded_mode=degraded,
        )
        self.assertEqual(denied.status, "denied")
        self.assertIn("degraded_mode_denies_operation", denied.blocker_codes)
        expired = evaluate_safe_write_admission(
            epoch,
            observations,
            assessment,
            grant,
            operation_ref="operationref:write-002",
            operation="metadata_write",
            resource_ref="resourceref:mission-state",
            expected_resource_version=18,
            evaluated_at="2026-09-20T12:06:00Z",
        )
        self.assertIn("leader_lease_expired", expired.blocker_codes)
        self.assertIn("fencing_grant_expired", expired.blocker_codes)
        future = evaluate_safe_write_admission(
            epoch,
            observations,
            assessment,
            grant,
            operation_ref="operationref:write-004",
            operation="metadata_write",
            resource_ref="resourceref:mission-state",
            expected_resource_version=18,
            evaluated_at="2026-09-20T12:00:30Z",
        )
        self.assertIn("future_coordination_evidence", future.blocker_codes)

    def test_failover_is_planned_and_recovery_evidence_remains_unqualified(self) -> None:
        prior_epoch = self.epoch()
        plan = plan_failover(
            prior_epoch,
            self.member("node_b"),
            reason="member_unavailable",
            quorum_size=2,
            resource_ref="resourceref:mission-state",
            expected_resource_version=18,
            planned_at="2026-09-20T12:02:00Z",
        )
        self.assertEqual(plan.plan_status, "planned_only")
        new_epoch = self.epoch(
            "node_b",
            6,
            issued_at="2026-09-20T12:02:01Z",
            lease_expires_at="2026-09-20T12:07:00Z",
        )
        observations = self.observations(
            new_epoch,
            leader="node_b",
            number=6,
            evaluated_at="2026-09-20T12:03:00Z",
        )
        assessment = assess_split_brain(
            new_epoch, (observations,), assessed_at="2026-09-20T12:03:00Z"
        )
        grant = issue_fencing_grant(
            new_epoch,
            observations,
            assessment,
            resource_ref="resourceref:mission-state",
            expected_resource_version=18,
            granted_at="2026-09-20T12:03:01Z",
        )
        complete = observe_failover(
            plan,
            new_epoch,
            grant,
            self.requirements(),
            self.recovery_evidence(),
            observed_at="2026-09-20T12:04:00Z",
        )
        self.assertEqual(complete.status, "evidence_complete_unqualified")
        self.assertEqual(complete.blocker_codes, ())
        incomplete = observe_failover(
            plan,
            new_epoch,
            grant,
            self.requirements(),
            self.recovery_evidence()[:2],
            observed_at="2026-09-20T12:04:00Z",
        )
        self.assertEqual(incomplete.status, "rejected")
        self.assertIn("recovery_evidence_incomplete", incomplete.blocker_codes)
        wrong_resource_grant = issue_fencing_grant(
            new_epoch,
            observations,
            assessment,
            resource_ref="resourceref:outbox-state",
            expected_resource_version=18,
            granted_at="2026-09-20T12:03:01Z",
        )
        wrong_resource = observe_failover(
            plan,
            new_epoch,
            wrong_resource_grant,
            self.requirements(),
            self.recovery_evidence(),
            observed_at="2026-09-20T12:04:00Z",
        )
        self.assertIn("resource_binding_mismatch", wrong_resource.blocker_codes)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is unavailable")
    def test_schema_is_closed_for_every_top_level_record(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        epoch, observations, assessment, grant = self.clear_chain()
        mode = DegradedServiceMode(
            tenant_ref=epoch.tenant_ref,
            service_ref=epoch.service_ref,
            cluster_ref=epoch.cluster_ref,
            service_version=epoch.service_version,
            cluster_version=epoch.cluster_version,
            mode="read_only",
            reason_codes=("quorum_loss",),
            entered_at="2026-09-20T12:00:00Z",
            expires_at="2026-09-20T12:10:00Z",
            allowed_write_operations=(),
            enforcement_status="external_enforcement_required",
        )
        admission = evaluate_safe_write_admission(
            epoch,
            observations,
            assessment,
            grant,
            operation_ref="operationref:write-003",
            operation="metadata_write",
            resource_ref="resourceref:mission-state",
            expected_resource_version=18,
            evaluated_at="2026-09-20T12:01:02Z",
            degraded_mode=mode,
        )
        plan = plan_failover(
            epoch,
            self.member("node_b"),
            reason="member_unavailable",
            quorum_size=2,
            resource_ref="resourceref:mission-state",
            expected_resource_version=18,
            planned_at="2026-09-20T12:02:00Z",
        )
        new_epoch = self.epoch(
            "node_b",
            6,
            issued_at="2026-09-20T12:02:01Z",
            lease_expires_at="2026-09-20T12:07:00Z",
        )
        new_observations = self.observations(
            new_epoch,
            leader="node_b",
            number=6,
            evaluated_at="2026-09-20T12:03:00Z",
        )
        new_assessment = assess_split_brain(
            new_epoch, (new_observations,), assessed_at="2026-09-20T12:03:00Z"
        )
        new_grant = issue_fencing_grant(
            new_epoch,
            new_observations,
            new_assessment,
            resource_ref="resourceref:mission-state",
            expected_resource_version=18,
            granted_at="2026-09-20T12:03:01Z",
        )
        failover = observe_failover(
            plan,
            new_epoch,
            new_grant,
            self.requirements(),
            self.recovery_evidence(),
            observed_at="2026-09-20T12:04:00Z",
        )
        records = (
            self.member(),
            epoch,
            observations,
            assessment,
            grant,
            plan,
            self.requirements(),
            failover,
            mode,
            admission,
        )
        for record in records:
            with self.subTest(kind=record.KIND):
                validator.validate(record.to_dict())
                self.assertEqual(parse_contract(record.to_dict()), record)
                changed = copy.deepcopy(record.to_dict())
                changed["unexpected"] = True
                self.assertTrue(list(validator.iter_errors(changed)))

    def test_increment_has_no_runtime_clients_unicode_dashes_or_markers(self) -> None:
        markers = (
            "generated " + "by",
            "written " + "by " + "an " + "ai",
            "as " + "an " + "ai",
            "chat" + "gpt",
            "co-authored" + "-by",
        )
        source = FILES[0].read_text(encoding="utf-8")
        for forbidden in (
            "import " + "sqlite3",
            "import " + "psycopg",
            "import " + "socket",
            "import " + "requests",
            "import " + "threading",
            "import " + "subprocess",
        ):
            self.assertNotIn(forbidden, source)
        self.assertEqual(dict(NO_EFFECTS)["consensus"], "none")
        self.assertEqual(dict(NO_EFFECTS)["dispatch"], "none")
        for path in FILES:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2013", text, path)
            self.assertNotIn("\u2014", text, path)
            lowered = text.lower()
            for marker in markers:
                self.assertNotIn(marker, lowered, path)


if __name__ == "__main__":
    unittest.main()
