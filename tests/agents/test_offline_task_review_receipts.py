"""Local task work-product signatures remain non-authoritative."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from dataclasses import replace
from types import MappingProxyType

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import tests.agents.test_offline_api_planning_bundle as planning_fixture
from sunderkey.coverage_scheduler import CoverageSchedule
from sunderkey.offline_api_planning_bundle import build_offline_api_planning_bundle
from sunderkey.offline_task_review_receipts import (
    OfflineTaskReviewReceiptError,
    ReviewerKeyBinding,
    build_offline_task_review_packet,
    build_offline_task_work_product,
    sign_offline_task_review_attestation,
    verify_offline_task_review_packet,
    verify_offline_task_work_product,
)
from tests.agents._public_test_values import ForgedString


class NoopPublicKey:
    """Expose an unvalidated key method without performing cryptography."""

    def __init__(self):
        self.calls = 0

    def verify(self, signature, payload):
        self.calls += 1


class AliasedField(str):
    """Serialize a different key while matching a native field at lookup."""

    def __new__(cls, field):
        value = str.__new__(cls, "renamed_" + field)
        value.field = field
        value.hooks = []
        return value

    def __hash__(self):
        self.hooks.append("hash")
        return hash(self.field)

    def __eq__(self, other):
        self.hooks.append("equality")
        return other == self.field


def aliased_mapping(document, field):
    value = dict(document)
    item = value.pop(field)
    alias = AliasedField(field)
    value[alias] = item
    alias.hooks.clear()
    return value, alias


def packet_digest(packet):
    body = {key: value for key, value in packet.items() if key != "packet_sha256"}
    payload = {"domain": "sunderkey.offline-task-review-packet.v1", "body": body}
    return (
        "sha256:"
        + hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        ).hexdigest()
    )


class OfflineTaskReviewReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        planning_fixture.OfflineApiPlanningBundleTests.setUpClass()

    def setUp(self) -> None:
        fixture = planning_fixture.OfflineApiPlanningBundleTests(
            "test_synthetic_signal_reaches_bound_rehearsal_only"
        )
        fixture.setUp()
        bundle = build_offline_api_planning_bundle(**fixture.options())
        self.schedule = CoverageSchedule.from_dict(bundle["schedule"])
        self.task = self.schedule.tasks[0]
        self.candidate = build_offline_task_work_product(
            schedule=self.schedule,
            task_id=self.task.task_id,
            work_result_sha256="sha256:" + "a" * 64,
            evidence_sha256s=["sha256:" + "b" * 64],
            completed_at="2026-09-24T12:05:00Z",
        )
        self.keys = [Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()]
        self.bindings = {
            "review.key.control": ReviewerKeyBinding(
                "review.key.control",
                "reviewer.control.001",
                "independent_control",
                self.keys[0].public_key(),
            ),
            "review.key.assurance": ReviewerKeyBinding(
                "review.key.assurance",
                "reviewer.assurance.001",
                "independent_assurance",
                self.keys[1].public_key(),
            ),
        }

    def attestation(self, position: int, *, decision: str = "accepted", reviewer_id=None):
        binding = list(self.bindings.values())[position]
        return sign_offline_task_review_attestation(
            schedule=self.schedule,
            candidate=self.candidate,
            reviewer_id=reviewer_id or binding.reviewer_id,
            role=binding.role,
            key_id=binding.key_id,
            reviewed_at="2026-09-24T12:06:00Z",
            decision=decision,
            private_key=self.keys[position],
        )

    def packet(self, first=None, second=None):
        return build_offline_task_review_packet(
            schedule=self.schedule,
            candidate=self.candidate,
            attestations=(first or self.attestation(0), second or self.attestation(1)),
        )

    def test_signed_reviews_bind_work_product_but_grant_no_positive_use(self) -> None:
        self.assertEqual(
            verify_offline_task_work_product(self.schedule, self.candidate), self.candidate
        )
        packet = self.packet()
        self.assertEqual(
            verify_offline_task_review_packet(
                schedule=self.schedule, packet=packet, reviewer_keys=self.bindings
            ),
            packet,
        )
        self.assertEqual(packet["review_state"], "locally_accepted")
        self.assertEqual(packet["key_binding_assurance"], "caller_provided")
        self.assertFalse(packet["positive_use_approved"])
        self.assertEqual(packet["effects"]["source_authentication"], "none")

    def test_tamper_wrong_key_and_self_review_fail(self) -> None:
        packet = self.packet()
        changed = copy.deepcopy(packet)
        changed["work_product"]["work_result_sha256"] = "sha256:" + "f" * 64
        with self.assertRaises(OfflineTaskReviewReceiptError):
            verify_offline_task_review_packet(
                schedule=self.schedule, packet=changed, reviewer_keys=self.bindings
            )
        changed = copy.deepcopy(packet)
        changed["attestations"][0]["decision"] = "rejected"
        with self.assertRaises(OfflineTaskReviewReceiptError):
            verify_offline_task_review_packet(
                schedule=self.schedule, packet=changed, reviewer_keys=self.bindings
            )
        wrong = dict(self.bindings)
        wrong["review.key.control"] = ReviewerKeyBinding(
            "review.key.control",
            "reviewer.control.001",
            "independent_control",
            Ed25519PrivateKey.generate().public_key(),
        )
        with self.assertRaisesRegex(OfflineTaskReviewReceiptError, "signature"):
            verify_offline_task_review_packet(
                schedule=self.schedule, packet=packet, reviewer_keys=wrong
            )
        self_review = self.packet(
            first=self.attestation(0, reviewer_id=self.task.required_specialist_profile_id)
        )
        with self.assertRaisesRegex(OfflineTaskReviewReceiptError, "binding"):
            verify_offline_task_review_packet(
                schedule=self.schedule, packet=self_review, reviewer_keys=self.bindings
            )

    def test_rejected_review_is_verifiable_but_not_accepted(self) -> None:
        packet = self.packet(second=self.attestation(1, decision="rejected"))
        verified = verify_offline_task_review_packet(
            schedule=self.schedule, packet=packet, reviewer_keys=self.bindings
        )
        self.assertEqual(verified["review_state"], "locally_declined")
        self.assertFalse(verified["positive_use_approved"])

    def test_work_product_cannot_precede_schedule(self) -> None:
        with self.assertRaisesRegex(OfflineTaskReviewReceiptError, "precedes"):
            build_offline_task_work_product(
                schedule=self.schedule,
                task_id=self.task.task_id,
                work_result_sha256="sha256:" + "a" * 64,
                evidence_sha256s=["sha256:" + "b" * 64],
                completed_at="2026-09-24T12:00:00Z",
            )

    def test_late_key_replacement_cannot_accept_invalid_signature(self) -> None:
        packet = self.packet()
        packet["attestations"][0]["signature_base64"] = base64.b64encode(bytes(64)).decode()
        packet["packet_sha256"] = packet_digest(packet)
        with self.assertRaises(OfflineTaskReviewReceiptError):
            verify_offline_task_review_packet(
                schedule=self.schedule, packet=packet, reviewer_keys=self.bindings
            )
        bindings = dict(self.bindings)
        key_id = packet["attestations"][0]["key_id"]
        bindings[key_id] = replace(bindings[key_id])
        fake = NoopPublicKey()
        object.__setattr__(bindings[key_id], "public_key", fake)
        with self.assertRaises(OfflineTaskReviewReceiptError):
            verify_offline_task_review_packet(
                schedule=self.schedule, packet=packet, reviewer_keys=bindings
            )
        self.assertEqual(fake.calls, 0)

    def test_current_binding_scalars_are_native_before_comparison(self) -> None:
        packet = self.packet()
        for field in ("key_id", "reviewer_id", "role"):
            with self.subTest(field=field):
                bindings = dict(self.bindings)
                key_id = packet["attestations"][0]["key_id"]
                binding = replace(bindings[key_id])
                forged = ForgedString(getattr(binding, field))
                object.__setattr__(binding, field, forged)
                bindings[key_id] = binding
                with self.assertRaises(OfflineTaskReviewReceiptError):
                    verify_offline_task_review_packet(
                        schedule=self.schedule, packet=packet, reviewer_keys=bindings
                    )
                self.assertEqual(forged.hooks, [])

    def test_review_primitives_are_native_before_sort_sets_and_state(self) -> None:
        packet = self.packet()
        fields = (
            "work_product_sha256",
            "reviewer_id",
            "role",
            "key_id",
            "reviewed_at",
            "decision",
            "signature_base64",
        )
        for field in fields:
            with self.subTest(field=field):
                changed = copy.deepcopy(packet)
                forged = ForgedString(changed["attestations"][0][field])
                changed["attestations"][0][field] = forged
                with self.assertRaises(OfflineTaskReviewReceiptError):
                    verify_offline_task_review_packet(
                        schedule=self.schedule, packet=changed, reviewer_keys=self.bindings
                    )
                self.assertEqual(forged.hooks, [])

    def test_review_aliased_fields_reject_before_lookup(self) -> None:
        packet = self.packet()
        for location in ("packet", "candidate", "attestation", "keys"):
            with self.subTest(location=location):
                changed = copy.deepcopy(packet)
                bindings = self.bindings
                if location == "packet":
                    changed, alias = aliased_mapping(changed, "attestations")
                elif location == "candidate":
                    changed["work_product"], alias = aliased_mapping(
                        changed["work_product"], "work_result_sha256"
                    )
                elif location == "attestation":
                    changed["attestations"][0], alias = aliased_mapping(
                        changed["attestations"][0], "role"
                    )
                else:
                    bindings, alias = aliased_mapping(bindings, "review.key.control")
                with self.assertRaises(OfflineTaskReviewReceiptError):
                    verify_offline_task_review_packet(
                        schedule=self.schedule, packet=changed, reviewer_keys=bindings
                    )
                self.assertEqual(alias.hooks, [])

    def test_work_product_builder_rejects_caller_scalar_hooks(self) -> None:
        options = dict(
            schedule=self.schedule,
            task_id=self.task.task_id,
            work_result_sha256="sha256:" + "a" * 64,
            evidence_sha256s=["sha256:" + "b" * 64],
            completed_at="2026-09-24T12:05:00Z",
        )
        for field in ("task_id", "work_result_sha256", "completed_at", "evidence_sha256s"):
            with self.subTest(field=field):
                changed = dict(options)
                raw = changed[field][0] if field == "evidence_sha256s" else changed[field]
                forged = ForgedString(raw)
                changed[field] = [forged] if field == "evidence_sha256s" else forged
                with self.assertRaises(OfflineTaskReviewReceiptError):
                    build_offline_task_work_product(**changed)
                self.assertEqual(forged.hooks, [])

    def test_signer_and_binding_constructor_reject_scalar_hooks(self) -> None:
        binding = self.bindings["review.key.control"]
        for field in ("key_id", "reviewer_id", "role"):
            with self.subTest(constructor=field):
                options = dict(
                    key_id=binding.key_id,
                    reviewer_id=binding.reviewer_id,
                    role=binding.role,
                    public_key=binding.public_key,
                )
                forged = ForgedString(options[field])
                options[field] = forged
                with self.assertRaises(OfflineTaskReviewReceiptError):
                    ReviewerKeyBinding(**options)
                self.assertEqual(forged.hooks, [])
        for field in ("reviewer_id", "role", "key_id", "reviewed_at", "decision"):
            with self.subTest(signer=field):
                options = dict(
                    schedule=self.schedule,
                    candidate=self.candidate,
                    reviewer_id=binding.reviewer_id,
                    role=binding.role,
                    key_id=binding.key_id,
                    reviewed_at="2026-09-24T12:06:00Z",
                    decision="accepted",
                    private_key=self.keys[0],
                )
                forged = ForgedString(options[field])
                options[field] = forged
                with self.assertRaises(OfflineTaskReviewReceiptError):
                    sign_offline_task_review_attestation(**options)
                self.assertEqual(forged.hooks, [])

    def test_native_mapping_views_preserve_packet_identity(self) -> None:
        packet = self.packet()
        original = json.dumps(packet, sort_keys=True, separators=(",", ":"))
        verified = verify_offline_task_review_packet(
            schedule=self.schedule,
            packet=MappingProxyType(packet),
            reviewer_keys=MappingProxyType(self.bindings),
        )
        self.assertEqual(json.dumps(verified, sort_keys=True, separators=(",", ":")), original)
        verified["attestations"][0]["decision"] = "changed_after_verification"
        self.assertEqual(packet["attestations"][0]["decision"], "accepted")

    def test_binding_subclass_rejects_before_attribute_hooks(self) -> None:
        class HookBinding(ReviewerKeyBinding):
            def __getattribute__(self, name):
                raise AssertionError("binding attribute hook was invoked")

        bindings = dict(self.bindings)
        bindings["review.key.control"] = object.__new__(HookBinding)
        with self.assertRaises(OfflineTaskReviewReceiptError):
            verify_offline_task_review_packet(
                schedule=self.schedule,
                packet=self.packet(),
                reviewer_keys=bindings,
            )

    def test_schedule_owned_identities_cannot_suppress_self_review(self) -> None:
        class DenyingString(str):
            __hash__ = str.__hash__

            def __eq__(self, other):
                return False

            def __ne__(self, other):
                return False

        for field in ("required_specialist_profile_id", "required_commander_id"):
            with self.subTest(field=field):
                task = replace(self.task)
                reviewer = getattr(task, field)
                packet = self.packet(first=self.attestation(0, reviewer_id=reviewer))
                bindings = dict(self.bindings)
                bindings["review.key.control"] = replace(
                    bindings["review.key.control"],
                    reviewer_id=reviewer,
                )
                with self.assertRaises(OfflineTaskReviewReceiptError):
                    verify_offline_task_review_packet(
                        schedule=self.schedule,
                        packet=packet,
                        reviewer_keys=bindings,
                    )
                object.__setattr__(task, field, DenyingString(reviewer))
                schedule = replace(
                    self.schedule,
                    tasks=(task, *self.schedule.tasks[1:]),
                )
                with self.assertRaises(OfflineTaskReviewReceiptError):
                    verify_offline_task_review_packet(
                        schedule=schedule,
                        packet=packet,
                        reviewer_keys=bindings,
                    )

    def test_schedule_and_task_context_primitives_are_native_before_replay(self) -> None:
        for field in ("schedule_id", "schedule_sha256", "scope_sha256", "world_snapshot_sha256"):
            with self.subTest(schedule=field):
                schedule = replace(self.schedule)
                forged = ForgedString(getattr(schedule, field))
                object.__setattr__(schedule, field, forged)
                with self.assertRaises(OfflineTaskReviewReceiptError):
                    verify_offline_task_work_product(schedule, self.candidate)
                self.assertEqual(forged.hooks, [])
        for field in (
            "task_id",
            "task_key",
            "task_sha256",
            "scope_sha256",
            "world_snapshot_sha256",
            "required_specialist_profile_id",
            "required_commander_id",
        ):
            with self.subTest(task=field):
                task = replace(self.task)
                forged = ForgedString(getattr(task, field))
                object.__setattr__(task, field, forged)
                schedule = replace(self.schedule, tasks=(task, *self.schedule.tasks[1:]))
                with self.assertRaises(OfflineTaskReviewReceiptError):
                    verify_offline_task_work_product(schedule, self.candidate)
                self.assertEqual(forged.hooks, [])


if __name__ == "__main__":
    unittest.main()
