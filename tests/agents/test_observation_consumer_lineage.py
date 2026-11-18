"""Exact declared-source joins for effect-free observation consumers."""

from __future__ import annotations

import hashlib
import json
import unittest
from dataclasses import replace
from unittest.mock import patch

import tests.agents.test_api_service_contracts_phase162 as api_fixtures
import tests.agents.test_egress_proxy_contracts_phase165 as egress_fixtures
from sunderkey import api_service_contracts, egress_proxy_contracts
from sunderkey.api_service_contracts import (
    ApiContractError,
    ReplayWindow,
    WebhookAcknowledgement,
    WebhookDelivery,
    WebhookSubscription,
    accept_webhook_delivery,
    verify_webhook_acknowledgement,
)
from sunderkey.egress_proxy_contracts import validate_enforcement_observation

OTHER_DIGEST = "sha256:" + "f" * 64


def _pair_changes(id_name: str, digest_name: str, prefix: str):
    changed_id = prefix + "-" + "F" * 32
    return (
        ("id", {id_name: changed_id}),
        ("digest", {digest_name: OTHER_DIGEST}),
        ("both", {id_name: changed_id, digest_name: OTHER_DIGEST}),
    )


def _assert_egress_address(test, record, id_name: str, digest_name: str, prefix: str):
    document = record.to_dict()
    body = {
        key: value
        for key, value in document.items()
        if key not in {"schema_version", "kind", id_name, digest_name}
    }
    encoded = json.dumps(
        {"kind": document["kind"], "body": body},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
    test.assertEqual(document[digest_name], digest)
    test.assertEqual(document[id_name], prefix + "-" + digest[7:39].upper())


class EgressObservationConsumerLineageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = egress_fixtures.EgressProxyContractsPhase165Tests()
        self.policy, self.request, self.decision = self.fixture.decision()
        self.observation = self.fixture.observation(self.decision)

    def assert_addressed(self, *, policy=None, request=None, decision=None, observation=None):
        for record, id_name, digest_name, prefix in (
            (policy or self.policy, "policy_id", "policy_sha256", "EGP"),
            (request or self.request, "request_id", "request_sha256", "EGR"),
            (decision or self.decision, "decision_id", "decision_sha256", "EAD"),
            (
                observation or self.observation,
                "observation_id",
                "observation_sha256",
                "EEO",
            ),
        ):
            _assert_egress_address(self, record, id_name, digest_name, prefix)

    def assert_join_rejected(self, *, policy=None, request=None, decision=None):
        selected_policy = policy or self.policy
        selected_request = request or self.request
        selected_decision = decision or self.decision
        observation = self.fixture.observation(selected_decision)
        self.assert_addressed(
            policy=selected_policy,
            request=selected_request,
            decision=selected_decision,
            observation=observation,
        )
        before = tuple(
            record.to_dict()
            for record in (selected_policy, selected_request, selected_decision, observation)
        )
        blockers = validate_enforcement_observation(
            selected_policy, selected_request, selected_decision, observation
        )
        self.assertEqual(blockers, tuple(sorted(set(blockers))))
        self.assertEqual(
            validate_enforcement_observation(
                selected_policy, selected_request, selected_decision, observation
            ),
            blockers,
        )
        self.assertEqual(
            tuple(
                record.to_dict()
                for record in (selected_policy, selected_request, selected_decision, observation)
            ),
            before,
        )
        self.assertNotEqual(blockers, (), "a different declared source must not validate cleanly")

    def test_original_literal_addresses_and_valid_observation_remain(self) -> None:
        goldens = (
            (
                self.policy,
                "policy_id",
                "policy_sha256",
                "EGP-2108B3362A119A8C0A983A322AC91B4C",
                "sha256:2108b3362a119a8c0a983a322ac91b4c8c12cd7410b35deefb87e049007dbd98",
            ),
            (
                self.request,
                "request_id",
                "request_sha256",
                "EGR-4C1CEC0ADA9035CF060A1F7C7B244893",
                "sha256:4c1cec0ada9035cf060a1f7c7b2448930aa8c67c2e3d77dc374d0369b38faa08",
            ),
            (
                self.decision,
                "decision_id",
                "decision_sha256",
                "EAD-645D77627A3431A58615DEA95C6F8F98",
                "sha256:645d77627a3431a58615dea95c6f8f98412614e1ee9799438fdbeff2cd22f1b5",
            ),
            (
                self.observation,
                "observation_id",
                "observation_sha256",
                "EEO-FC57E6C8233F55920A8EA4399C57CC89",
                "sha256:fc57e6c8233f55920a8ea4399c57cc89f006e0f234256a6075be5d4828636e44",
            ),
        )
        self.assert_addressed()
        for record, id_name, digest_name, expected_id, expected_digest in goldens:
            with self.subTest(kind=record.to_dict()["kind"]):
                self.assertEqual(record.to_dict()[id_name], expected_id)
                self.assertEqual(record.to_dict()[digest_name], expected_digest)
        self.assertEqual(
            validate_enforcement_observation(
                self.policy, self.request, self.decision, self.observation
            ),
            (),
        )

    def test_truthfully_changed_request_cannot_reuse_original_decision(self) -> None:
        changes = (
            ("path", "/v1/files"),
            ("tenant_ref", "tenant:other"),
            ("body_sha256", egress_fixtures.ONE),
            ("operation_ref", "operation:other"),
            ("request_bytes", 8193),
            ("credential_lease_ref", "credentiallease:other"),
            ("method", "GET"),
        )
        for field, value in changes:
            with self.subTest(field=field):
                request = replace(self.request, **{field: value})
                self.assertNotEqual(request.to_dict(), self.request.to_dict())
                self.assert_join_rejected(request=request)

    def test_decision_request_binding_requires_each_half_and_complete_pair(self) -> None:
        for label, changes in _pair_changes("request_id", "request_sha256", "EGR"):
            with self.subTest(changed=label):
                self.assert_join_rejected(decision=replace(self.decision, **changes))

    def test_decision_policy_binding_requires_each_half_and_complete_pair(self) -> None:
        for label, changes in _pair_changes("policy_id", "policy_sha256", "EGP"):
            with self.subTest(changed=label):
                self.assert_join_rejected(decision=replace(self.decision, **changes))

    def test_request_policy_binding_requires_each_half_and_complete_pair(self) -> None:
        for label, changes in _pair_changes("policy_id", "policy_sha256", "EGP"):
            with self.subTest(changed=label):
                request = replace(self.request, **changes)
                request_document = request.to_dict()
                decision = replace(
                    self.decision,
                    request_id=request_document["request_id"],
                    request_sha256=request_document["request_sha256"],
                )
                self.assert_join_rejected(request=request, decision=decision)

    def test_decision_resolution_binding_requires_each_half_and_complete_pair(self) -> None:
        for label, changes in _pair_changes(
            "resolution_attestation_id", "resolution_attestation_sha256", "ERA"
        ):
            with self.subTest(changed=label):
                self.assert_join_rejected(decision=replace(self.decision, **changes))

    def test_truthfully_changed_policy_cannot_reuse_original_sources(self) -> None:
        policy = replace(self.policy, tenant_ref="tenant:other")
        self.assertNotEqual(policy.to_dict()["policy_id"], self.policy.to_dict()["policy_id"])
        self.assertNotEqual(
            policy.to_dict()["policy_sha256"], self.policy.to_dict()["policy_sha256"]
        )
        self.assert_join_rejected(policy=policy)

    def test_lineage_blockers_compose_with_existing_adverse_observation_blockers(self) -> None:
        observation = self.fixture.observation(
            self.decision,
            resolved_address="198.51.100.44",
            tls_spki_sha256=egress_fixtures.ZERO,
            response_bytes=2_000_001,
            redirect_blocked=False,
            outcome="failed",
        )
        existing = validate_enforcement_observation(
            self.policy, self.request, self.decision, observation
        )
        self.assertEqual(
            existing,
            (
                "egress_not_completed",
                "observed_address_not_allowed",
                "redirect_block_not_observed",
                "response_size_exceeded",
                "tls_pin_mismatch",
            ),
        )
        changed = validate_enforcement_observation(
            self.policy, replace(self.request, path="/v1/files"), self.decision, observation
        )
        self.assertEqual(changed, tuple(sorted(set(changed))))
        self.assertTrue(set(existing) < set(changed))

    def test_existing_adverse_boundary_blockers_are_preserved(self) -> None:
        for changes, expected in (
            ({"observed_host": "other.example.com"}, "observed_endpoint_mismatch"),
            ({"resolved_address": "198.51.100.44"}, "observed_address_not_allowed"),
            ({"tls_spki_sha256": egress_fixtures.ZERO}, "tls_pin_mismatch"),
            ({"response_bytes": 2_000_001}, "response_size_exceeded"),
            ({"redirect_blocked": False}, "redirect_block_not_observed"),
            ({"outcome": "failed"}, "egress_not_completed"),
        ):
            with self.subTest(expected=expected):
                observation = self.fixture.observation(self.decision, **changes)
                self.assertEqual(
                    validate_enforcement_observation(
                        self.policy, self.request, self.decision, observation
                    ),
                    (expected,),
                )
        denied = replace(self.decision, disposition="deny", blocker_codes=("path_not_allowed",))
        self.assertEqual(
            validate_enforcement_observation(
                self.policy, self.request, denied, self.fixture.observation(denied)
            ),
            ("request_not_admitted",),
        )

    def test_existing_observation_decision_pair_checks_remain(self) -> None:
        for label, changes in _pair_changes("decision_id", "decision_sha256", "EAD"):
            with self.subTest(changed=label):
                observation = replace(self.observation, **changes)
                self.assert_addressed(observation=observation)
                self.assertEqual(
                    validate_enforcement_observation(
                        self.policy, self.request, self.decision, observation
                    ),
                    ("decision_binding_mismatch",),
                )

    def test_declared_join_does_not_reevaluate_admission_or_claim_currentness(self) -> None:
        before = tuple(
            record.to_dict()
            for record in (self.policy, self.request, self.decision, self.observation)
        )
        with patch.object(
            egress_proxy_contracts,
            "evaluate_egress_request",
            side_effect=AssertionError("observation validation must not reevaluate admission"),
        ) as evaluator:
            self.assertEqual(
                validate_enforcement_observation(
                    self.policy, self.request, self.decision, self.observation
                ),
                (),
            )
            evaluator.assert_not_called()
        self.assertEqual(
            tuple(
                record.to_dict()
                for record in (self.policy, self.request, self.decision, self.observation)
            ),
            before,
        )
        self.assertIs(egress_proxy_contracts.NO_EFFECTS, True)


class WebhookAcknowledgementConsumerLineageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = api_fixtures.ApiServiceContractsPhase162Tests()
        self.subscription = self.fixture.subscription()
        self.delivery = self.fixture.delivery()
        self.acknowledgement = WebhookAcknowledgement(
            acknowledgement_id="ack.001",
            subscription_id=self.subscription.subscription_id,
            delivery_id=self.delivery.delivery_id,
            delivery_sha256=self.delivery.delivery_sha256,
            sequence=self.delivery.sequence,
            acknowledged_at="2026-09-20T12:02:00Z",
            signature=self.fixture.signature(),
        )

    def assert_round_trip(self, record) -> None:
        self.assertIn(type(record), (WebhookSubscription, WebhookDelivery, WebhookAcknowledgement))
        self.assertEqual(type(record).from_dict(record.to_dict()).to_dict(), record.to_dict())
        self.assertEqual(type(record).from_json(record.to_json()).to_json(), record.to_json())

    def changed_subscriptions(self):
        return (
            ("endpoint", replace(self.subscription, endpoint_ref="endpointref:tenant.acme.other")),
            (
                "tenant",
                replace(
                    self.subscription,
                    binding=replace(self.subscription.binding, tenant_id="tenant.other"),
                ),
            ),
            ("filter", replace(self.subscription, event_filters=("report.available",))),
        )

    def test_original_literal_hashes_and_valid_native_round_trips_remain(self) -> None:
        for record, digest_name, expected_digest in (
            (
                self.subscription,
                "subscription_sha256",
                "sha256:b4dd6319d9bcd49d2bbea5cbee427209bca4599cb821818890b19bac611863b9",
            ),
            (
                self.delivery,
                "delivery_sha256",
                "sha256:9d3fc2f8373b291c8b0620ae4df40e6df32f476fdab4149ba8db851201c1e98d",
            ),
            (
                self.acknowledgement,
                "acknowledgement_sha256",
                "sha256:bfbfef3dc9691df6dd474ac4622bf1279eb9877bfce469154f3eea2056b9e072",
            ),
        ):
            with self.subTest(kind=record.to_dict()["kind"]):
                self.assert_round_trip(record)
                self.assertEqual(record.to_dict()[digest_name], expected_digest)
                self.assertEqual(
                    record.to_dict()["effects"], dict(api_service_contracts.NO_EFFECTS)
                )
        verify_webhook_acknowledgement(self.subscription, self.delivery, self.acknowledgement)

    def test_truthfully_changed_subscription_cannot_reuse_original_delivery_ack(self) -> None:
        for label, subscription in self.changed_subscriptions():
            with self.subTest(changed=label):
                self.assertEqual(subscription.subscription_id, self.subscription.subscription_id)
                self.assertNotEqual(
                    subscription.subscription_sha256, self.subscription.subscription_sha256
                )
                for record in (subscription, self.delivery, self.acknowledgement):
                    self.assert_round_trip(record)
                with self.assertRaises(ApiContractError):
                    verify_webhook_acknowledgement(
                        subscription, self.delivery, self.acknowledgement
                    )

    def test_coherently_readdressed_delivery_still_requires_subscription_digest(self) -> None:
        delivery = replace(self.delivery, subscription_sha256=OTHER_DIGEST)
        acknowledgement = replace(self.acknowledgement, delivery_sha256=delivery.delivery_sha256)
        self.assertNotEqual(delivery.delivery_sha256, self.delivery.delivery_sha256)
        for record in (self.subscription, delivery, acknowledgement):
            self.assert_round_trip(record)
        with self.assertRaises(ApiContractError):
            verify_webhook_acknowledgement(self.subscription, delivery, acknowledgement)

    def test_changed_subscription_can_verify_its_own_exact_delivery_and_ack(self) -> None:
        # This join does not assess receiver filter eligibility or signature authenticity.
        for label, subscription in self.changed_subscriptions():
            with self.subTest(changed=label):
                delivery = replace(
                    self.delivery, subscription_sha256=subscription.subscription_sha256
                )
                acknowledgement = replace(
                    self.acknowledgement, delivery_sha256=delivery.delivery_sha256
                )
                for record in (subscription, delivery, acknowledgement):
                    self.assert_round_trip(record)
                verify_webhook_acknowledgement(subscription, delivery, acknowledgement)

    def test_existing_ack_id_digest_sequence_key_and_time_checks_remain(self) -> None:
        changes = (
            ("subscription_id", "subscription.other"),
            ("delivery_id", "delivery.other"),
            ("delivery_sha256", OTHER_DIGEST),
            ("sequence", 2),
            ("signature", self.fixture.signature("secretref:webhooks.acme.other")),
            ("acknowledged_at", "2026-09-20T12:00:59Z"),
        )
        for field, value in changes:
            with self.subTest(field=field):
                acknowledgement = replace(self.acknowledgement, **{field: value})
                self.assert_round_trip(acknowledgement)
                with self.assertRaises(ApiContractError):
                    verify_webhook_acknowledgement(
                        self.subscription, self.delivery, acknowledgement
                    )
        delivery = replace(self.delivery, subscription_id="subscription.other")
        acknowledgement = replace(self.acknowledgement, delivery_sha256=delivery.delivery_sha256)
        self.assert_round_trip(delivery)
        self.assert_round_trip(acknowledgement)
        with self.assertRaises(ApiContractError):
            verify_webhook_acknowledgement(self.subscription, delivery, acknowledgement)

    def test_ack_verification_does_not_accept_delivery_or_mutate_replay_window(self) -> None:
        window = ReplayWindow(self.subscription.subscription_id, 0)
        before = (
            self.subscription.to_json(),
            self.delivery.to_json(),
            self.acknowledgement.to_json(),
            window.to_dict(),
        )
        with patch.object(
            api_service_contracts,
            "accept_webhook_delivery",
            side_effect=AssertionError("acknowledgement verification must not accept delivery"),
        ) as receiver:
            verify_webhook_acknowledgement(self.subscription, self.delivery, self.acknowledgement)
            receiver.assert_not_called()
        self.assertEqual(
            (
                self.subscription.to_json(),
                self.delivery.to_json(),
                self.acknowledgement.to_json(),
                window.to_dict(),
            ),
            before,
        )
        self.assertEqual(
            dict(api_service_contracts.NO_EFFECTS),
            {
                "authorization": "external",
                "authority": "none",
                "client": "none",
                "delivery": "none",
                "execution": "none",
                "network": "none",
                "routing": "none",
                "scheduling": "none",
                "server": "none",
            },
        )

    def test_receiver_independently_rejects_each_changed_subscription_hash(self) -> None:
        for label, subscription in self.changed_subscriptions():
            with self.subTest(changed=label):
                with self.assertRaisesRegex(ApiContractError, "subscription hash does not match"):
                    accept_webhook_delivery(
                        subscription,
                        self.delivery,
                        ReplayWindow(subscription.subscription_id, 0),
                        received_at="2026-09-20T12:02:00Z",
                    )


if __name__ == "__main__":
    unittest.main()
