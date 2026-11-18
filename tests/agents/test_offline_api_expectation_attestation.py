"""Local access-policy signatures remain non-authoritative and replay-bound."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from dataclasses import replace
from types import MappingProxyType

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sunderkey.offline_api_assessment import OfflineApiCaseSource, evaluate_offline_api_case
from sunderkey.offline_api_expectation_attestation import (
    ATTESTATION_DOMAIN,
    OfflineAccessPolicyKeyBinding,
    OfflineApiExpectationAttestationError,
    bind_offline_api_case_to_signed_access_expectations,
    bind_offline_api_retest_to_signed_access_expectations,
    sign_offline_api_access_expectations,
    verify_offline_api_access_expectation_attestation,
    verify_offline_api_signed_access_expectation_binding,
    verify_offline_api_signed_retest_expectation_binding,
)
from tests.agents import test_offline_api_access_expectations as fixture_module
from tests.agents._public_test_values import ForgedString
from tests.agents.test_offline_api_assessment import invocation, response
from tests.agents.test_offline_task_review_receipts import NoopPublicKey, aliased_mapping


class OfflineApiExpectationAttestationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture_module.OfflineApiAccessExpectationTests.setUpClass()

    def setUp(self) -> None:
        fixture = fixture_module.OfflineApiAccessExpectationTests(
            "test_exact_policy_binding_is_reproducible_and_non_authorizing"
        )
        self.adapter = fixture.adapter
        self.source, self.expectations = fixture.fixture()
        self.key = Ed25519PrivateKey.generate()
        self.binding = OfflineAccessPolicyKeyBinding(
            policy_owner_id="policy.owner.synthetic",
            key_id="key.synthetic.policy.001",
            public_key=self.key.public_key(),
        )
        self.attestation = sign_offline_api_access_expectations(
            expectations=self.expectations,
            policy_owner_id=self.binding.policy_owner_id,
            key_id=self.binding.key_id,
            private_key=self.key,
        )

    def test_signed_assertions_bind_exact_case_without_authority(self) -> None:
        self.assertEqual(
            verify_offline_api_access_expectation_attestation(
                expectations=self.expectations,
                document=self.attestation,
                binding=self.binding,
            ),
            self.attestation,
        )
        result = bind_offline_api_case_to_signed_access_expectations(
            adapter=self.adapter,
            source=self.source,
            expectations=self.expectations,
            attestation=self.attestation,
            binding=self.binding,
        )
        self.assertEqual(result["case_result_sha256"], self.source.result["result_sha256"])
        self.assertEqual(result["attestation_sha256"], self.attestation["attestation_sha256"])
        self.assertFalse(result["policy_authority_verified"])
        self.assertFalse(result["pre_observation_commitment_verified"])
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(result["effects"]["target_interaction"], "none")
        self.assertEqual(
            verify_offline_api_signed_access_expectation_binding(
                adapter=self.adapter,
                source=self.source,
                expectations=self.expectations,
                attestation=self.attestation,
                binding=self.binding,
                document=result,
            ),
            result,
        )

    def test_key_label_and_positive_claim_rebinding_fail(self) -> None:
        wrong = OfflineAccessPolicyKeyBinding(
            policy_owner_id=self.binding.policy_owner_id,
            key_id=self.binding.key_id,
            public_key=Ed25519PrivateKey.generate().public_key(),
        )
        with self.assertRaisesRegex(OfflineApiExpectationAttestationError, "signature"):
            bind_offline_api_case_to_signed_access_expectations(
                adapter=self.adapter,
                source=self.source,
                expectations=self.expectations,
                attestation=self.attestation,
                binding=wrong,
            )
        changed = copy.deepcopy(self.expectations)
        changed["principal_expectations"][0]["expected_access"] = True
        with self.assertRaisesRegex(OfflineApiExpectationAttestationError, "replay"):
            bind_offline_api_case_to_signed_access_expectations(
                adapter=self.adapter,
                source=self.source,
                expectations=changed,
                attestation=self.attestation,
                binding=self.binding,
            )
        changed = copy.deepcopy(self.attestation)
        changed["positive_use_approved"] = True
        with self.assertRaisesRegex(OfflineApiExpectationAttestationError, "context"):
            bind_offline_api_case_to_signed_access_expectations(
                adapter=self.adapter,
                source=self.source,
                expectations=self.expectations,
                attestation=changed,
                binding=self.binding,
            )

    def test_signed_context_rejects_json_type_substitution(self) -> None:
        substitutions = {
            "schema_version": True,
            "policy_authority_verified": 0,
            "pre_observation_commitment_verified": 0,
            "positive_use_approved": 0,
        }
        for field, replacement in substitutions.items():
            with self.subTest(field=field):
                changed = copy.deepcopy(self.attestation)
                changed[field] = replacement
                with self.assertRaisesRegex(OfflineApiExpectationAttestationError, "context"):
                    verify_offline_api_access_expectation_attestation(
                        expectations=self.expectations,
                        document=changed,
                        binding=self.binding,
                    )

    def test_late_key_replacement_cannot_verify_invalid_signature(self) -> None:
        changed = copy.deepcopy(self.attestation)
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
        with self.assertRaises(OfflineApiExpectationAttestationError):
            verify_offline_api_access_expectation_attestation(
                expectations=self.expectations,
                document=changed,
                binding=self.binding,
            )
        binding = replace(self.binding)
        fake = NoopPublicKey()
        object.__setattr__(binding, "public_key", fake)
        with self.assertRaises(OfflineApiExpectationAttestationError):
            bind_offline_api_case_to_signed_access_expectations(
                adapter=self.adapter,
                source=self.source,
                expectations=self.expectations,
                attestation=changed,
                binding=binding,
            )
        self.assertEqual(fake.calls, 0)

    def test_current_binding_and_document_strings_reject_hooks(self) -> None:
        for field in ("policy_owner_id", "key_id"):
            with self.subTest(binding=field):
                binding = replace(self.binding)
                forged = ForgedString(getattr(binding, field))
                object.__setattr__(binding, field, forged)
                with self.assertRaises(OfflineApiExpectationAttestationError):
                    verify_offline_api_access_expectation_attestation(
                        expectations=self.expectations,
                        document=self.attestation,
                        binding=binding,
                    )
                self.assertEqual(forged.hooks, [])
        for field, raw in self.attestation.items():
            if type(raw) is not str:
                continue
            with self.subTest(document=field):
                changed = copy.deepcopy(self.attestation)
                forged = ForgedString(raw)
                changed[field] = forged
                with self.assertRaises(OfflineApiExpectationAttestationError):
                    verify_offline_api_access_expectation_attestation(
                        expectations=self.expectations,
                        document=changed,
                        binding=self.binding,
                    )
                self.assertEqual(forged.hooks, [])

    def test_aliased_fields_and_effect_hooks_reject_before_lookup(self) -> None:
        changed, alias = aliased_mapping(self.attestation, "policy_owner_id")
        with self.assertRaises(OfflineApiExpectationAttestationError):
            verify_offline_api_access_expectation_attestation(
                expectations=self.expectations,
                document=changed,
                binding=self.binding,
            )
        self.assertEqual(alias.hooks, [])
        changed = copy.deepcopy(self.attestation)
        changed["effects"], alias = aliased_mapping(changed["effects"], "authorization")
        with self.assertRaises(OfflineApiExpectationAttestationError):
            verify_offline_api_access_expectation_attestation(
                expectations=self.expectations,
                document=changed,
                binding=self.binding,
            )
        self.assertEqual(alias.hooks, [])
        changed = copy.deepcopy(self.attestation)
        forged = ForgedString("none")
        changed["effects"]["authorization"] = forged
        with self.assertRaises(OfflineApiExpectationAttestationError):
            verify_offline_api_access_expectation_attestation(
                expectations=self.expectations,
                document=changed,
                binding=self.binding,
            )
        self.assertEqual(forged.hooks, [])

    def test_signing_and_constructor_strings_are_native(self) -> None:
        for field in ("policy_owner_id", "key_id"):
            with self.subTest(field=field):
                options = dict(
                    policy_owner_id=self.binding.policy_owner_id,
                    key_id=self.binding.key_id,
                    public_key=self.binding.public_key,
                )
                forged = ForgedString(options[field])
                options[field] = forged
                with self.assertRaises(OfflineApiExpectationAttestationError):
                    OfflineAccessPolicyKeyBinding(**options)
                self.assertEqual(forged.hooks, [])
                options.pop("public_key")
                options.update(expectations=self.expectations, private_key=self.key)
                with self.assertRaises(OfflineApiExpectationAttestationError):
                    sign_offline_api_access_expectations(**options)
                self.assertEqual(forged.hooks, [])

    def test_native_mapping_views_return_detached_identical_evidence(self) -> None:
        checked = verify_offline_api_access_expectation_attestation(
            expectations=self.expectations,
            document=MappingProxyType(self.attestation),
            binding=self.binding,
        )
        self.assertEqual(
            json.dumps(checked, sort_keys=True), json.dumps(self.attestation, sort_keys=True)
        )
        checked["effects"]["authorization"] = "changed_after_verification"
        self.assertEqual(self.attestation["effects"]["authorization"], "none")

    def test_binding_and_effect_subclasses_reject_before_hooks(self) -> None:
        class HookBinding(OfflineAccessPolicyKeyBinding):
            def __getattribute__(self, name):
                raise AssertionError("binding attribute hook was invoked")

        class HookEffects(dict):
            def __eq__(self, other):
                raise AssertionError("effects comparison hook was invoked")

        with self.assertRaises(OfflineApiExpectationAttestationError):
            verify_offline_api_access_expectation_attestation(
                expectations=self.expectations,
                document=self.attestation,
                binding=object.__new__(HookBinding),
            )
        changed = dict(self.attestation)
        changed["effects"] = HookEffects(self.attestation["effects"])
        with self.assertRaises(OfflineApiExpectationAttestationError):
            verify_offline_api_access_expectation_attestation(
                expectations=self.expectations,
                document=changed,
                binding=self.binding,
            )

    def test_expectation_context_is_native_before_replay_or_signing(self) -> None:
        paths = [
            (field,)
            for field in (
                "expectation_id",
                "mission_id",
                "target_id",
                "scope_id",
                "object_id",
                "action",
                "expectations_sha256",
            )
        ]
        paths += [("principal_expectations", 0, "principal_id")]
        for path in paths:
            with self.subTest(path=path):
                changed = copy.deepcopy(self.expectations)
                parent = changed
                for key in path[:-1]:
                    parent = parent[key]
                forged = ForgedString(parent[path[-1]])
                parent[path[-1]] = forged
                with self.assertRaises(OfflineApiExpectationAttestationError):
                    sign_offline_api_access_expectations(
                        expectations=changed,
                        policy_owner_id=self.binding.policy_owner_id,
                        key_id=self.binding.key_id,
                        private_key=self.key,
                    )
                self.assertEqual(forged.hooks, [])

    def test_expectation_aliased_fields_reject_before_source_replay(self) -> None:
        for nested in (False, True):
            with self.subTest(nested=nested):
                changed = copy.deepcopy(self.expectations)
                if nested:
                    changed["principal_expectations"][0], alias = aliased_mapping(
                        changed["principal_expectations"][0],
                        "principal_id",
                    )
                else:
                    changed, alias = aliased_mapping(changed, "mission_id")
                with self.assertRaises(OfflineApiExpectationAttestationError):
                    verify_offline_api_access_expectation_attestation(
                        expectations=changed,
                        document=self.attestation,
                        binding=self.binding,
                    )
                self.assertEqual(alias.hooks, [])

    def test_signed_retest_uses_one_exact_policy_assertion(self) -> None:
        records = (
            response("owner-second", "principal.owner", True, 200, b'"owner-data"'),
            response("other-second", "principal.other", False, 403, b'"denied"'),
        )
        run = replace(
            invocation(self.adapter, records),
            invocation_id="INV-SYNTHETIC-API-SIGNED-002",
        )
        case = evaluate_offline_api_case(
            adapter=self.adapter,
            case_id="case.signed.retest.002",
            invocation=run,
            evidence=records,
        )
        second = OfflineApiCaseSource("case.signed.retest.002", run, records, case.to_dict())
        result = bind_offline_api_retest_to_signed_access_expectations(
            adapter=self.adapter,
            prior_source=self.source,
            second_source=second,
            expectations=self.expectations,
            attestation=self.attestation,
            binding=self.binding,
        )
        self.assertEqual(
            result["observation_change"],
            "prior_signal_not_observed_in_second_synthetic_case",
        )
        self.assertFalse(result["pre_observation_commitment_verified"])
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            verify_offline_api_signed_retest_expectation_binding(
                adapter=self.adapter,
                prior_source=self.source,
                second_source=second,
                expectations=self.expectations,
                attestation=self.attestation,
                binding=self.binding,
                document=result,
            ),
            result,
        )
        changed = copy.deepcopy(result)
        changed["positive_use_approved"] = True
        with self.assertRaisesRegex(OfflineApiExpectationAttestationError, "replay"):
            verify_offline_api_signed_retest_expectation_binding(
                adapter=self.adapter,
                prior_source=self.source,
                second_source=second,
                expectations=self.expectations,
                attestation=self.attestation,
                binding=self.binding,
                document=changed,
            )


if __name__ == "__main__":
    unittest.main()
