"""Phase 37 reviewed qualification registry revision coverage."""

from __future__ import annotations

import ast
import copy
import unittest
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sunderkey.errors import QualificationError, RegistryError
from sunderkey.qualification_lifecycle import (
    QualificationStatus,
    QualificationStatusTransitionKind,
    VerifiedQualificationStatus,
    verify_qualification_status_transition,
)
from sunderkey.qualification_registry import (
    QUALIFICATION_REGISTRY_REVIEW_SIGNING_DOMAIN,
    QUALIFICATION_REGISTRY_REVISION_SIGNING_DOMAIN,
    QualificationRegistryRevision,
    QualificationRegistryRevisionReview,
    VerifiedQualificationRegistryRevision,
    VerifiedQualificationRegistryRevisionReview,
    propose_qualification_registry,
    verify_qualification_registry_revision,
    verify_qualification_registry_revision_review,
)
from sunderkey.qualification_trust import (
    QualificationReviewerRole,
    verify_qualification_reviewer_credential,
)
from sunderkey.registry import ExpertRegistry
from tests.agents import test_qualification_decisions_phase35 as phase35
from tests.agents import test_qualification_lifecycle_phase36 as phase36

ROOT = Path(__file__).resolve().parents[2]
PROFILE_ID = "AOE-GA-D01-S01"
INITIAL_REVIEW_CLOCK = datetime(2026, 2, 5, 12, tzinfo=UTC)
INITIAL_REVISION_CLOCK = datetime(2026, 2, 6, tzinfo=UTC)
LATER_REVIEW_CLOCK = datetime(2026, 2, 7, 12, tzinfo=UTC)
LATER_REVISION_CLOCK = datetime(2026, 2, 7, 18, tzinfo=UTC)


class QualificationRegistryPhase37Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        phase36.QualificationLifecyclePhase36Tests.setUpClass()
        cls.lifecycle = phase36.QualificationLifecyclePhase36Tests()

    def _base_registry(self) -> ExpertRegistry:
        return ExpertRegistry.from_dict(
            self.lifecycle.decisions.registry.to_dict()
        )

    @staticmethod
    def _registry_binding(registry: ExpertRegistry) -> dict[str, str]:
        from sunderkey.qualification_registry import _registry_sha256

        return {
            "catalog_id": registry.catalog_id,
            "catalog_version": registry.catalog_version,
            "sha256": _registry_sha256(registry),
        }

    def _verified_reviewer_credentials(
        self,
        policy: Any,
        verified_policy: Any,
        *,
        clock: datetime,
    ) -> tuple[Any, Any]:
        specifications = (
            (
                41,
                "reviewer-registry-control",
                QualificationReviewerRole.INDEPENDENT_CONTROL,
                13,
            ),
            (
                42,
                "reviewer-registry-assurance",
                QualificationReviewerRole.INDEPENDENT_ASSURANCE,
                14,
            ),
        )
        credentials = []
        for ordinal, reviewer_id, role, seed in specifications:
            credential = self.lifecycle.decisions._reviewer_credential(
                policy,
                ordinal=ordinal,
                reviewer_id=reviewer_id,
                role=role,
                reviewer_seed=seed,
            )
            credentials.append(
                verify_qualification_reviewer_credential(
                    credential,
                    verified_policy,
                    expected_reviewer_id=reviewer_id,
                    expected_role=role,
                    expected_profile_id=PROFILE_ID,
                    clock=lambda: clock,
                )
            )
        return credentials[0], credentials[1]

    def _signed_review(
        self,
        policy: Any,
        credential: Any,
        base_registry: ExpertRegistry,
        proposed_registry: ExpertRegistry,
        status: VerifiedQualificationStatus,
        *,
        revision_ordinal: int = 1,
        review_ordinal: int,
        reviewer_seed: int,
        reviewed_at: str,
        review_id: str | None = None,
        document: dict[str, Any] | None = None,
    ) -> QualificationRegistryRevisionReview:
        raw = copy.deepcopy(
            document
            or {
                "schema_version": 1,
                "review_id": review_id or f"QRV-{review_ordinal:032X}",
                "revision_id": f"QRR-{revision_ordinal:032X}",
                "policy": {
                    "policy_id": policy.policy_id,
                    "policy_version": policy.policy_version,
                    "sha256": policy.content_sha256,
                },
                "base_registry": self._registry_binding(base_registry),
                "proposed_registry": self._registry_binding(
                    proposed_registry
                ),
                "status_binding_sha256": status.binding_sha256,
                "profile_id": status.binding.profile_id,
                "reviewer_credential": {
                    "id": credential.credential.credential_id,
                    "sha256": credential.credential_sha256,
                },
                "reviewer_id": credential.credential.reviewer_id,
                "reviewer_role": credential.credential.reviewer_role.value,
                "conclusion": "approve_registry_revision",
                "reason_sha256": phase35._digest(
                    f"registry-review:{review_ordinal}"
                ),
                "reviewed_at": reviewed_at,
                "algorithm": "Ed25519",
                "signature": phase35._dummy_signature(),
            }
        )
        unsigned = QualificationRegistryRevisionReview.from_dict(raw)
        raw["signature"] = phase35._encoded(
            phase35._private_key(reviewer_seed).sign(
                unsigned.signing_bytes()
            )
        )
        return QualificationRegistryRevisionReview.from_dict(raw)

    def _verified_reviews(
        self,
        policy: Any,
        verified_policy: Any,
        base_registry: ExpertRegistry,
        proposed_registry: ExpertRegistry,
        status: VerifiedQualificationStatus,
        *,
        review_clock: datetime,
        revision_ordinal: int = 1,
        shared_review_id: str | None = None,
    ) -> tuple[VerifiedQualificationRegistryRevisionReview, ...]:
        credentials = self._verified_reviewer_credentials(
            policy,
            verified_policy,
            clock=review_clock,
        )
        results = []
        reviewed_at = review_clock.strftime("%Y-%m-%dT%H:%M:%SZ")
        for index, (credential, seed) in enumerate(
            zip(credentials, (13, 14), strict=True),
            start=1,
        ):
            review = self._signed_review(
                policy,
                credential,
                base_registry,
                proposed_registry,
                status,
                revision_ordinal=revision_ordinal,
                review_ordinal=50 + index,
                reviewer_seed=seed,
                reviewed_at=reviewed_at,
                review_id=shared_review_id,
            )
            results.append(
                verify_qualification_registry_revision_review(
                    review,
                    credential,
                    verified_policy,
                    clock=lambda: review_clock,
                )
            )
        return tuple(results)

    def _signed_revision(
        self,
        policy: Any,
        base_registry: ExpertRegistry,
        proposed_registry: ExpertRegistry,
        status: VerifiedQualificationStatus,
        reviews: tuple[VerifiedQualificationRegistryRevisionReview, ...],
        *,
        revision_ordinal: int = 1,
        issued_at: str,
        signer_seed: int | None = None,
        signer_key_id: str | None = None,
        document: dict[str, Any] | None = None,
    ) -> QualificationRegistryRevision:
        restrictive = status.binding.status is not QualificationStatus.ACTIVE
        signer_seed = signer_seed or (2 if restrictive else 1)
        signer_key_id = signer_key_id or (
            "qualification-revocation-v1"
            if restrictive
            else "qualification-decision-v1"
        )
        bindings = [
            {
                "review_id": item.review.review_id,
                "reviewer_id": item.review.reviewer_id,
                "reviewer_role": item.review.reviewer_role.value,
                "review_sha256": item.review_sha256,
                "credential_sha256": item.credential_sha256,
                "reviewer_key_sha256": item.reviewer_key_sha256,
            }
            for item in reviews
        ]
        bindings.sort(key=lambda item: str(item["reviewer_role"]))
        binding = status.binding
        raw = copy.deepcopy(
            document
            or {
                "schema_version": 1,
                "revision_id": f"QRR-{revision_ordinal:032X}",
                "revision_version": binding.sequence,
                "policy": {
                    "policy_id": policy.policy_id,
                    "policy_version": policy.policy_version,
                    "sha256": policy.content_sha256,
                },
                "decision_record": dict(policy.decision_record),
                "base_registry": self._registry_binding(base_registry),
                "proposed_registry": self._registry_binding(
                    proposed_registry
                ),
                "profile_id": binding.profile_id,
                "candidate": binding.candidate.to_dict(),
                "qualification_status": {
                    "binding_sha256": status.binding_sha256,
                    "sequence": binding.sequence,
                    "lifecycle_status": binding.status.value,
                    "source_event_id": binding.source_event["id"],
                    "source_event_sha256": binding.source_event["sha256"],
                    "previous_binding_sha256": (
                        status.previous_binding_sha256
                    ),
                },
                "profile_change": {
                    "from_status": base_registry.profile(
                        binding.profile_id
                    ).status,
                    "to_status": proposed_registry.profile(
                        binding.profile_id
                    ).status,
                },
                "reviews": bindings,
                "issued_at": issued_at,
                "signer_id": policy.issuer,
                "signer_key_id": signer_key_id,
                "application_effect": "proposed_registry_only",
                "algorithm": "Ed25519",
                "signature": phase35._dummy_signature(),
            }
        )
        unsigned = QualificationRegistryRevision.from_dict(raw)
        raw["signature"] = phase35._encoded(
            phase35._private_key(signer_seed).sign(
                unsigned.signing_bytes()
            )
        )
        return QualificationRegistryRevision.from_dict(raw)

    def _revision_bundle(
        self,
        policy: Any,
        verified_policy: Any,
        status: VerifiedQualificationStatus,
        base_registry: ExpertRegistry,
        *,
        proposed_version: str,
        review_clock: datetime,
        revision_clock: datetime,
        revision_ordinal: int = 1,
        signer_seed: int | None = None,
        signer_key_id: str | None = None,
        shared_review_id: str | None = None,
    ) -> tuple[Any, ...]:
        proposed = propose_qualification_registry(
            base_registry,
            status,
            proposed_catalog_version=proposed_version,
        )
        reviews = self._verified_reviews(
            policy,
            verified_policy,
            base_registry,
            proposed,
            status,
            review_clock=review_clock,
            revision_ordinal=revision_ordinal,
            shared_review_id=shared_review_id,
        )
        revision = self._signed_revision(
            policy,
            base_registry,
            proposed,
            status,
            reviews,
            revision_ordinal=revision_ordinal,
            issued_at=revision_clock.strftime("%Y-%m-%dT%H:%M:%SZ"),
            signer_seed=signer_seed,
            signer_key_id=signer_key_id,
        )
        return proposed, reviews, revision

    def _verify_revision(
        self,
        revision: QualificationRegistryRevision,
        status: VerifiedQualificationStatus,
        verified_policy: Any,
        reviews: tuple[VerifiedQualificationRegistryRevisionReview, ...],
        base_registry: ExpertRegistry,
        proposed_registry: ExpertRegistry,
        *,
        clock: datetime,
    ) -> VerifiedQualificationRegistryRevision:
        return verify_qualification_registry_revision(
            revision,
            status,
            verified_policy,
            reviews,
            base_registry=base_registry,
            proposed_registry=proposed_registry,
            clock=lambda: clock,
        )

    def _transitioned_status(
        self,
        kind: QualificationStatusTransitionKind,
    ) -> tuple[Any, ...]:
        policy, verified_policy, _, active, control = (
            self.lifecycle._initial_chain()
        )
        transition = self.lifecycle._signed_transition(
            policy,
            active,
            kind=kind,
            issued_at="2026-02-07T00:00:00Z",
            reason_code=(
                "operational_safety"
                if kind is QualificationStatusTransitionKind.SUSPEND
                else "qualification_withdrawn"
            ),
            control_credential=(
                control
                if kind is QualificationStatusTransitionKind.SUSPEND
                else None
            ),
        )
        status = verify_qualification_status_transition(
            transition,
            active,
            verified_policy,
            clock=lambda: datetime(2026, 2, 7, tzinfo=UTC),
            control_credential=(
                control
                if kind is QualificationStatusTransitionKind.SUSPEND
                else None
            ),
        )
        return policy, verified_policy, active, status

    def test_reviewed_initial_revision_is_deterministic_and_non_mutating(
        self,
    ) -> None:
        policy, verified_policy, _, active, _ = self.lifecycle._initial_chain()
        base = self._base_registry()
        base_before = base.to_dict()
        proposed, reviews, revision = self._revision_bundle(
            policy,
            verified_policy,
            active,
            base,
            proposed_version="1.0.1",
            review_clock=INITIAL_REVIEW_CLOCK,
            revision_clock=INITIAL_REVISION_CLOCK,
        )
        verified = self._verify_revision(
            revision,
            active,
            verified_policy,
            reviews,
            base,
            proposed,
            clock=INITIAL_REVISION_CLOCK,
        )

        self.assertEqual(base.to_dict(), base_before)
        self.assertEqual(base.profile(PROFILE_ID).status, "defined")
        profile = proposed.profile(PROFILE_ID)
        self.assertEqual(profile.status, "qualified")
        self.assertIsNotNone(profile.qualification)
        self.assertEqual(
            profile.qualification.status_binding_sha256,
            active.binding_sha256,
        )
        self.assertEqual(
            verified.proposed_registry.to_dict(),
            proposed.to_dict(),
        )
        self.assertEqual(revision.application_effect, "proposed_registry_only")
        self.assertTrue(
            reviews[0].review.signing_bytes().startswith(
                QUALIFICATION_REGISTRY_REVIEW_SIGNING_DOMAIN
            )
        )
        self.assertTrue(
            revision.signing_bytes().startswith(
                QUALIFICATION_REGISTRY_REVISION_SIGNING_DOMAIN
            )
        )

    def test_revision_rejects_unrelated_proposed_registry_change(self) -> None:
        policy, verified_policy, _, active, _ = self.lifecycle._initial_chain()
        base = self._base_registry()
        proposed = propose_qualification_registry(
            base,
            active,
            proposed_catalog_version="1.0.1",
        )
        raw = proposed.to_dict()
        raw["profiles"][1]["mission"] += " Altered."
        unrelated = ExpertRegistry.from_dict(raw)
        reviews = self._verified_reviews(
            policy,
            verified_policy,
            base,
            unrelated,
            active,
            review_clock=INITIAL_REVIEW_CLOCK,
        )
        revision = self._signed_revision(
            policy,
            base,
            unrelated,
            active,
            reviews,
            issued_at="2026-02-06T00:00:00Z",
        )

        with self.assertRaisesRegex(QualificationError, "unrelated changes"):
            self._verify_revision(
                revision,
                active,
                verified_policy,
                reviews,
                base,
                unrelated,
                clock=INITIAL_REVISION_CLOCK,
            )

    def test_later_revision_requires_exact_predecessor_chain(self) -> None:
        policy, verified_policy, active, suspended = self._transitioned_status(
            QualificationStatusTransitionKind.SUSPEND
        )
        base = propose_qualification_registry(
            self._base_registry(),
            active,
            proposed_catalog_version="1.0.1",
        )
        proposed = propose_qualification_registry(
            base,
            suspended,
            proposed_catalog_version="1.0.2",
        )
        self.assertEqual(proposed.profile(PROFILE_ID).status, "suspended")
        self.assertEqual(
            proposed.profile(PROFILE_ID).qualification.sequence,
            2,
        )

        stale_raw = base.to_dict()
        target = next(
            item for item in stale_raw["profiles"] if item["id"] == PROFILE_ID
        )
        target["qualification"]["status_binding_sha256"] = phase35._digest(
            "stale-chain-head"
        )
        stale = ExpertRegistry.from_dict(stale_raw)
        with self.assertRaisesRegex(QualificationError, "predecessor is stale"):
            propose_qualification_registry(
                stale,
                suspended,
                proposed_catalog_version="1.0.2",
            )

    def test_revision_signer_key_use_tracks_resulting_status(self) -> None:
        policy, verified_policy, _, active, _ = self.lifecycle._initial_chain()
        base = self._base_registry()
        proposed, reviews, wrong_active = self._revision_bundle(
            policy,
            verified_policy,
            active,
            base,
            proposed_version="1.0.1",
            review_clock=INITIAL_REVIEW_CLOCK,
            revision_clock=INITIAL_REVISION_CLOCK,
            signer_seed=2,
            signer_key_id="qualification-revocation-v1",
        )
        with self.assertRaisesRegex(QualificationError, "key use"):
            self._verify_revision(
                wrong_active,
                active,
                verified_policy,
                reviews,
                base,
                proposed,
                clock=INITIAL_REVISION_CLOCK,
            )

        policy, verified_policy, active, suspended = self._transitioned_status(
            QualificationStatusTransitionKind.SUSPEND
        )
        base = propose_qualification_registry(
            self._base_registry(),
            active,
            proposed_catalog_version="1.0.1",
        )
        proposed, reviews, wrong_suspended = self._revision_bundle(
            policy,
            verified_policy,
            suspended,
            base,
            proposed_version="1.0.2",
            review_clock=LATER_REVIEW_CLOCK,
            revision_clock=LATER_REVISION_CLOCK,
            revision_ordinal=2,
            signer_seed=1,
            signer_key_id="qualification-decision-v1",
        )
        with self.assertRaisesRegex(QualificationError, "key use"):
            self._verify_revision(
                wrong_suspended,
                suspended,
                verified_policy,
                reviews,
                base,
                proposed,
                clock=LATER_REVISION_CLOCK,
            )

    def test_revision_requires_distinct_control_and_assurance_reviews(self) -> None:
        policy, verified_policy, _, active, _ = self.lifecycle._initial_chain()
        base = self._base_registry()
        shared_id = "QRV-99999999999999999999999999999999"
        proposed, reviews, revision = self._revision_bundle(
            policy,
            verified_policy,
            active,
            base,
            proposed_version="1.0.1",
            review_clock=INITIAL_REVIEW_CLOCK,
            revision_clock=INITIAL_REVISION_CLOCK,
            shared_review_id=shared_id,
        )
        with self.assertRaisesRegex(QualificationError, "must be distinct"):
            self._verify_revision(
                revision,
                active,
                verified_policy,
                reviews,
                base,
                proposed,
                clock=INITIAL_REVISION_CLOCK,
            )

        raw = revision.to_dict()
        raw["reviews"][1]["reviewer_role"] = "independent_assurance"
        with self.assertRaisesRegex(QualificationError, "Control and Assurance"):
            QualificationRegistryRevision.from_dict(raw)

    def test_review_and_revision_reject_bad_signatures_and_stale_time(self) -> None:
        policy, verified_policy, _, active, _ = self.lifecycle._initial_chain()
        base = self._base_registry()
        proposed = propose_qualification_registry(
            base,
            active,
            proposed_catalog_version="1.0.1",
        )
        credentials = self._verified_reviewer_credentials(
            policy,
            verified_policy,
            clock=INITIAL_REVIEW_CLOCK,
        )
        review = self._signed_review(
            policy,
            credentials[0],
            base,
            proposed,
            active,
            review_ordinal=51,
            reviewer_seed=13,
            reviewed_at="2026-02-05T12:00:00Z",
        )
        tampered_review_raw = review.to_dict()
        tampered_review_raw["reason_sha256"] = phase35._digest("tampered")
        tampered_review = QualificationRegistryRevisionReview.from_dict(
            tampered_review_raw
        )
        with self.assertRaisesRegex(QualificationError, "signature"):
            verify_qualification_registry_revision_review(
                tampered_review,
                credentials[0],
                verified_policy,
                clock=lambda: INITIAL_REVIEW_CLOCK,
            )

        proposed, reviews, revision = self._revision_bundle(
            policy,
            verified_policy,
            active,
            base,
            proposed_version="1.0.1",
            review_clock=INITIAL_REVIEW_CLOCK,
            revision_clock=INITIAL_REVISION_CLOCK,
        )
        tampered_revision_raw = revision.to_dict()
        tampered_revision_raw["revision_version"] = 2
        tampered_revision = QualificationRegistryRevision.from_dict(
            tampered_revision_raw
        )
        with self.assertRaisesRegex(QualificationError, "signature"):
            self._verify_revision(
                tampered_revision,
                active,
                verified_policy,
                reviews,
                base,
                proposed,
                clock=INITIAL_REVISION_CLOCK,
            )

        early_clock = datetime(2026, 2, 2, tzinfo=UTC)
        early_reviews = self._verified_reviews(
            policy,
            verified_policy,
            base,
            proposed,
            active,
            review_clock=early_clock,
        )
        early_revision = self._signed_revision(
            policy,
            base,
            proposed,
            active,
            early_reviews,
            issued_at="2026-02-06T00:00:00Z",
        )
        with self.assertRaisesRegex(QualificationError, "predates qualification"):
            self._verify_revision(
                early_revision,
                active,
                verified_policy,
                early_reviews,
                base,
                proposed,
                clock=INITIAL_REVISION_CLOCK,
            )

    def test_expired_active_revision_fails_but_revocation_remains_applicable(
        self,
    ) -> None:
        policy, verified_policy, _, active, _ = self.lifecycle._initial_chain()
        base = self._base_registry()
        proposed, reviews, revision = self._revision_bundle(
            policy,
            verified_policy,
            active,
            base,
            proposed_version="1.0.1",
            review_clock=INITIAL_REVIEW_CLOCK,
            revision_clock=INITIAL_REVISION_CLOCK,
        )
        expiry = datetime(2026, 8, 2, tzinfo=UTC)
        with self.assertRaisesRegex(QualificationError, "has expired"):
            self._verify_revision(
                revision,
                active,
                verified_policy,
                reviews,
                base,
                proposed,
                clock=expiry,
            )

        policy, verified_policy, active, revoked = self._transitioned_status(
            QualificationStatusTransitionKind.REVOKE
        )
        base = propose_qualification_registry(
            self._base_registry(),
            active,
            proposed_catalog_version="1.0.1",
        )
        proposed, reviews, revision = self._revision_bundle(
            policy,
            verified_policy,
            revoked,
            base,
            proposed_version="1.0.2",
            review_clock=LATER_REVIEW_CLOCK,
            revision_clock=LATER_REVISION_CLOCK,
            revision_ordinal=2,
        )
        verified = self._verify_revision(
            revision,
            revoked,
            verified_policy,
            reviews,
            base,
            proposed,
            clock=expiry,
        )
        self.assertEqual(
            verified.proposed_registry.profile(PROFILE_ID).status,
            "revoked",
        )

    def test_registry_qualification_shape_fails_closed(self) -> None:
        _, _, _, active, _ = self.lifecycle._initial_chain()
        proposed = propose_qualification_registry(
            self._base_registry(),
            active,
            proposed_catalog_version="1.0.1",
        )
        self.assertEqual(
            ExpertRegistry.from_dict(proposed.to_dict()).to_dict(),
            proposed.to_dict(),
        )

        mismatch = proposed.to_dict()
        target = next(
            item for item in mismatch["profiles"] if item["id"] == PROFILE_ID
        )
        target["status"] = "suspended"
        with self.assertRaisesRegex(RegistryError, "does not match"):
            ExpertRegistry.from_dict(mismatch)

        commander = proposed.to_dict()
        source = next(
            item for item in commander["profiles"] if item["id"] == PROFILE_ID
        )
        target = next(
            item
            for item in commander["profiles"]
            if item["kind"] == "domain_commander"
        )
        target["qualification"] = source["qualification"]
        target["status"] = "qualified"
        with self.assertRaisesRegex(RegistryError, "cannot carry"):
            ExpertRegistry.from_dict(commander)

        explicit_null = self._base_registry().to_dict()
        target = next(
            item
            for item in explicit_null["profiles"]
            if item["id"] == PROFILE_ID
        )
        target["qualification"] = None
        with self.assertRaisesRegex(RegistryError, "must be an object"):
            ExpertRegistry.from_dict(explicit_null)

    def test_verified_wrappers_cannot_be_constructed_directly(self) -> None:
        policy, verified_policy, _, active, _ = self.lifecycle._initial_chain()
        base = self._base_registry()
        proposed, reviews, revision = self._revision_bundle(
            policy,
            verified_policy,
            active,
            base,
            proposed_version="1.0.1",
            review_clock=INITIAL_REVIEW_CLOCK,
            revision_clock=INITIAL_REVISION_CLOCK,
        )
        review = reviews[0]
        with self.assertRaisesRegex(TypeError, "can be created only"):
            VerifiedQualificationRegistryRevisionReview(
                review=review.review,
                review_sha256=review.review_sha256,
                credential_sha256=review.credential_sha256,
                reviewer_key_sha256=review.reviewer_key_sha256,
                policy_sha256=review.policy_sha256,
                verified_at=review.verified_at,
                _proof=b"invalid",
            )
        with self.assertRaisesRegex(TypeError, "can be created only"):
            VerifiedQualificationRegistryRevision(
                revision=revision,
                revision_sha256=revision.content_sha256,
                base_registry_sha256=self._registry_binding(base)["sha256"],
                proposed_registry=proposed,
                proposed_registry_sha256=self._registry_binding(proposed)[
                    "sha256"
                ],
                status_binding_sha256=active.binding_sha256,
                reviewer_ids=("one", "two"),
                signer_key_sha256=phase35._digest("signer-key"),
                verified_at="2026-02-06T00:00:00Z",
                _proof=b"invalid",
            )

    def test_module_has_no_network_storage_or_execution_imports(self) -> None:
        path = ROOT / "src" / "sunderkey" / "qualification_registry.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        prohibited = {
            "asyncio",
            "http",
            "requests",
            "socket",
            "sqlite3",
            "subprocess",
            "urllib",
        }
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            str(node.module).split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )
        self.assertFalse(imported & prohibited)


def qualification_registry_contract_documents() -> tuple[dict[str, Any], ...]:
    QualificationRegistryPhase37Tests.setUpClass()
    case = QualificationRegistryPhase37Tests()
    policy, verified_policy, _, active, _ = case.lifecycle._initial_chain()
    base = case._base_registry()
    _, reviews, revision = case._revision_bundle(
        policy,
        verified_policy,
        active,
        base,
        proposed_version="1.0.1",
        review_clock=INITIAL_REVIEW_CLOCK,
        revision_clock=INITIAL_REVISION_CLOCK,
    )
    return reviews[0].review.to_dict(), revision.to_dict()


if __name__ == "__main__":
    unittest.main()
