"""Local producer signatures never promote synthetic source custody to live use."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from dataclasses import replace
from types import MappingProxyType

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import tests.agents.test_offline_api_source_ledger as ledger_fixture
from sunderkey.offline_api_source_attestation import (
    ATTESTATION_DOMAIN,
    OfflineApiSourceAttestationError,
    OfflineSourceKeyBinding,
    rehearse_offline_api_source_freshness,
    sign_offline_api_source_attestation,
    verify_offline_api_source_attestation_historical,
)
from tests.agents._public_test_values import ForgedString
from tests.agents.test_offline_task_review_receipts import NoopPublicKey, aliased_mapping

ISSUED = "2026-09-24T12:00:00Z"
EXPIRES = "2026-09-24T13:00:00Z"


class OfflineApiSourceAttestationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ledger_fixture.OfflineApiSourceLedgerTests.setUpClass()

    def setUp(self) -> None:
        fixture = ledger_fixture.OfflineApiSourceLedgerTests(
            "test_distinct_retest_batches_retain_order_and_identity"
        )
        self.fixture = fixture
        source = fixture.sourced(fixture.sources[0], "response.synthetic.first")
        self.ledger = fixture.append(source)
        self.key = Ed25519PrivateKey.generate()
        self.binding = OfflineSourceKeyBinding(
            "key.synthetic.source.001",
            "producer.synthetic.001",
            self.key.public_key(),
        )
        self.document = sign_offline_api_source_attestation(
            ledger=self.ledger,
            producer_id=self.binding.producer_id,
            key_id=self.binding.key_id,
            issued_at=ISSUED,
            expires_at=EXPIRES,
            private_key=self.key,
        )

    def freshness(self, **overrides):
        options = {
            "document": self.document,
            "ledger": self.ledger,
            "key_binding": self.binding,
            "as_of": "2026-09-24T12:30:00Z",
            "expected_mission_id": self.ledger["mission_id"],
            "expected_scope_id": self.ledger["scope_id"],
            "expected_scope_sha256": self.ledger["source_scope_sha256"],
        }
        return rehearse_offline_api_source_freshness(**{**options, **overrides})

    def test_historical_signature_and_local_freshness_remain_non_authoritative(self) -> None:
        verified = verify_offline_api_source_attestation_historical(
            document=self.document, ledger=self.ledger, key_binding=self.binding
        )
        self.assertEqual(verified, self.document)
        rehearsal = self.freshness()
        self.assertEqual(rehearsal["ledger_sha256"], self.ledger["ledger_sha256"])
        self.assertEqual(rehearsal["freshness_status"], "within_local_signed_window_only")
        self.assertFalse(rehearsal["live_currentness_verified"])
        self.assertFalse(rehearsal["positive_use_approved"])
        self.assertEqual(rehearsal["effects"]["source_authentication"], "caller_provided_key_only")

    def test_historical_integrity_survives_expiry_but_freshness_does_not(self) -> None:
        self.assertEqual(
            verify_offline_api_source_attestation_historical(
                document=self.document, ledger=self.ledger, key_binding=self.binding
            ),
            self.document,
        )
        for instant in ("2026-09-24T11:59:59Z", EXPIRES):
            with (
                self.subTest(instant=instant),
                self.assertRaisesRegex(OfflineApiSourceAttestationError, "freshness"),
            ):
                self.freshness(as_of=instant)

    def test_key_scope_and_ledger_rebinding_fail_closed(self) -> None:
        wrong_key = OfflineSourceKeyBinding(
            self.binding.key_id,
            self.binding.producer_id,
            Ed25519PrivateKey.generate().public_key(),
        )
        with self.assertRaises(OfflineApiSourceAttestationError):
            self.freshness(key_binding=wrong_key)
        with self.assertRaisesRegex(OfflineApiSourceAttestationError, "freshness"):
            self.freshness(expected_scope_sha256="sha256:" + "a" * 64)
        other_source = self.fixture.sourced(self.fixture.sources[1], "response.synthetic.second")
        other_ledger = self.fixture.append(other_source)
        with self.assertRaisesRegex(OfflineApiSourceAttestationError, "context"):
            self.freshness(ledger=other_ledger)

    def test_tampered_signature_and_positive_use_claim_fail_closed(self) -> None:
        changed = copy.deepcopy(self.document)
        changed["positive_use_approved"] = True
        with self.assertRaises(OfflineApiSourceAttestationError):
            self.freshness(document=changed)
        changed = copy.deepcopy(self.document)
        changed["signature_base64"] = "AAAA"
        with self.assertRaises(OfflineApiSourceAttestationError):
            self.freshness(document=changed)

    def test_unsourced_ledger_and_unbounded_window_are_rejected(self) -> None:
        unsourced = self.fixture.append(self.fixture.sources[0])
        with self.assertRaisesRegex(OfflineApiSourceAttestationError, "receipt-sourced"):
            sign_offline_api_source_attestation(
                ledger=unsourced,
                producer_id=self.binding.producer_id,
                key_id=self.binding.key_id,
                issued_at=ISSUED,
                expires_at=EXPIRES,
                private_key=self.key,
            )
        with self.assertRaisesRegex(OfflineApiSourceAttestationError, "window"):
            sign_offline_api_source_attestation(
                ledger=self.ledger,
                producer_id=self.binding.producer_id,
                key_id=self.binding.key_id,
                issued_at=ISSUED,
                expires_at="2026-09-26T12:00:00Z",
                private_key=self.key,
            )

    def test_late_key_replacement_cannot_verify_invalid_signature(self) -> None:
        changed = dict(self.document)
        changed["signature_base64"] = base64.b64encode(bytes(64)).decode()
        signed = {key: value for key, value in changed.items() if key != "attestation_sha256"}
        changed["attestation_sha256"] = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(
                    {"domain": ATTESTATION_DOMAIN, "signed": signed},
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode()
            ).hexdigest()
        )
        with self.assertRaises(OfflineApiSourceAttestationError):
            self.freshness(document=changed)
        binding = replace(self.binding)
        fake = NoopPublicKey()
        object.__setattr__(binding, "public_key", fake)
        with self.assertRaises(OfflineApiSourceAttestationError):
            self.freshness(document=changed, key_binding=binding)
        self.assertEqual(fake.calls, 0)

    def test_current_binding_and_document_scalars_reject_hooks(self) -> None:
        for field in ("producer_id", "key_id"):
            with self.subTest(binding=field):
                binding = replace(self.binding)
                forged = ForgedString(getattr(binding, field))
                object.__setattr__(binding, field, forged)
                with self.assertRaises(OfflineApiSourceAttestationError):
                    self.freshness(key_binding=binding)
                self.assertEqual(forged.hooks, [])
        for field, raw in self.document.items():
            if type(raw) is not str:
                continue
            with self.subTest(document=field):
                changed = dict(self.document)
                forged = ForgedString(raw)
                changed[field] = forged
                with self.assertRaises(OfflineApiSourceAttestationError):
                    self.freshness(document=changed)
                self.assertEqual(forged.hooks, [])

    def test_freshness_context_rejects_serialized_wrong_native_and_hook_values(self) -> None:
        for field in ("expected_mission_id", "expected_scope_id", "expected_scope_sha256"):
            with self.subTest(field=field):
                raw = "sha256:" + "f" * 64 if field.endswith("sha256") else "unrelated.synthetic"
                with self.assertRaises(OfflineApiSourceAttestationError):
                    self.freshness(**{field: raw})
                forged = ForgedString(raw)
                with self.assertRaises(OfflineApiSourceAttestationError):
                    self.freshness(**{field: forged})
                self.assertEqual(forged.hooks, [])
        forged = ForgedString("2026-09-24T12:30:00Z")
        with self.assertRaises(OfflineApiSourceAttestationError):
            self.freshness(as_of=forged)
        self.assertEqual(forged.hooks, [])

    def test_aliased_fields_and_effect_hooks_reject_before_comparison(self) -> None:
        changed, alias = aliased_mapping(self.document, "producer_id")
        with self.assertRaises(OfflineApiSourceAttestationError):
            self.freshness(document=changed)
        self.assertEqual(alias.hooks, [])
        changed = copy.deepcopy(self.document)
        changed["effects"], alias = aliased_mapping(changed["effects"], "authority")
        with self.assertRaises(OfflineApiSourceAttestationError):
            self.freshness(document=changed)
        self.assertEqual(alias.hooks, [])
        changed = copy.deepcopy(self.document)
        forged = ForgedString("none")
        changed["effects"]["authority"] = forged
        with self.assertRaises(OfflineApiSourceAttestationError):
            self.freshness(document=changed)
        self.assertEqual(forged.hooks, [])

    def test_signing_and_constructor_primitives_are_native(self) -> None:
        for field in ("key_id", "producer_id"):
            with self.subTest(constructor=field):
                options = dict(
                    key_id=self.binding.key_id,
                    producer_id=self.binding.producer_id,
                    public_key=self.binding.public_key,
                )
                forged = ForgedString(options[field])
                options[field] = forged
                with self.assertRaises(OfflineApiSourceAttestationError):
                    OfflineSourceKeyBinding(**options)
                self.assertEqual(forged.hooks, [])
        for field in ("key_id", "producer_id", "issued_at", "expires_at"):
            with self.subTest(signer=field):
                options = dict(
                    ledger=self.ledger,
                    producer_id=self.binding.producer_id,
                    key_id=self.binding.key_id,
                    issued_at=ISSUED,
                    expires_at=EXPIRES,
                    private_key=self.key,
                )
                forged = ForgedString(options[field])
                options[field] = forged
                with self.assertRaises(OfflineApiSourceAttestationError):
                    sign_offline_api_source_attestation(**options)
                self.assertEqual(forged.hooks, [])

    def test_native_mapping_views_preserve_historical_identity(self) -> None:
        checked = verify_offline_api_source_attestation_historical(
            document=MappingProxyType(self.document),
            ledger=self.ledger,
            key_binding=self.binding,
        )
        self.assertEqual(
            json.dumps(checked, sort_keys=True), json.dumps(self.document, sort_keys=True)
        )
        checked["effects"]["authority"] = "changed_after_verification"
        self.assertEqual(self.document["effects"]["authority"], "none")

    def test_binding_and_effect_subclasses_reject_before_hooks(self) -> None:
        class HookBinding(OfflineSourceKeyBinding):
            def __getattribute__(self, name):
                raise AssertionError("binding attribute hook was invoked")

        class HookEffects(dict):
            def __ne__(self, other):
                raise AssertionError("effects comparison hook was invoked")

        with self.assertRaises(OfflineApiSourceAttestationError):
            self.freshness(key_binding=object.__new__(HookBinding))
        changed = dict(self.document)
        changed["effects"] = HookEffects(self.document["effects"])
        with self.assertRaises(OfflineApiSourceAttestationError):
            self.freshness(document=changed)

    def test_ledger_context_cannot_hide_a_mismatched_signed_mission(self) -> None:
        changed = copy.deepcopy(self.ledger)
        changed["mission_id"] = "mission.unrelated"
        with self.assertRaises(OfflineApiSourceAttestationError):
            self.freshness(ledger=changed)
        forged = []
        for field in ("ledger_id", "ledger_sha256", "mission_id"):
            changed[field] = ForgedString(changed[field])
            forged.append(changed[field])
        with self.assertRaises(OfflineApiSourceAttestationError):
            self.freshness(ledger=changed)
        self.assertTrue(all(value.hooks == [] for value in forged))

    def test_ledger_context_fields_are_native_before_source_replay(self) -> None:
        for field in (
            "source_mode",
            "ledger_id",
            "ledger_sha256",
            "mission_id",
            "scope_id",
            "source_scope_sha256",
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.ledger)
                forged = ForgedString(changed[field])
                changed[field] = forged
                with self.assertRaises(OfflineApiSourceAttestationError):
                    self.freshness(ledger=changed)
                self.assertEqual(forged.hooks, [])


if __name__ == "__main__":
    unittest.main()
