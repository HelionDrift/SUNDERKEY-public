"""A signed local access baseline can accompany a nonfinding reviewer dossier."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace
from types import MappingProxyType
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import sunderkey.offline_api_signed_expectation_dossier as companion_module
import tests.agents.test_offline_api_reviewer_dossier as dossier_fixture
from sunderkey.offline_api_access_expectations import build_offline_api_access_expectations
from sunderkey.offline_api_expectation_attestation import (
    OfflineAccessPolicyKeyBinding,
    bind_offline_api_retest_to_signed_access_expectations,
    sign_offline_api_access_expectations,
)
from sunderkey.offline_api_reviewer_dossier import build_offline_api_reviewer_dossier
from sunderkey.offline_api_signed_expectation_dossier import (
    OfflineApiSignedExpectationDossierError,
    build_offline_api_signed_expectation_dossier,
    verify_offline_api_signed_expectation_dossier,
)


class OfflineApiSignedExpectationDossierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        dossier_fixture.OfflineApiReviewerDossierTests.setUpClass()

    def setUp(self) -> None:
        fixture = dossier_fixture.OfflineApiReviewerDossierTests(
            "test_dossier_binds_review_and_retest_without_finding"
        )
        fixture.setUp()
        self.dossier_options = fixture.options
        self.dossier = build_offline_api_reviewer_dossier(**self.dossier_options)
        transition = self.dossier_options["transition_options"]
        prior = transition["prior_source"]
        first_attributes = prior.evidence[0].attributes
        principals = {
            record.attributes["principal_id"]: record.attributes["expected_access"]
            for record in prior.evidence
        }
        self.expectations = build_offline_api_access_expectations(
            expectation_id="expectation.synthetic.reviewer.001",
            mission_id=prior.invocation.mission_id,
            target_id=prior.invocation.target_id,
            scope_id=prior.invocation.scope_id,
            object_id=first_attributes["object_id"],
            action=first_attributes["action"],
            principal_expectations=[
                {"principal_id": principal_id, "expected_access": principals[principal_id]}
                for principal_id in sorted(principals)
            ],
        )
        self.private_key = Ed25519PrivateKey.generate()
        self.key_binding = OfflineAccessPolicyKeyBinding(
            policy_owner_id="policy.owner.synthetic",
            key_id="key.synthetic.reviewer.001",
            public_key=self.private_key.public_key(),
        )
        self.attestation = sign_offline_api_access_expectations(
            expectations=self.expectations,
            policy_owner_id=self.key_binding.policy_owner_id,
            key_id=self.key_binding.key_id,
            private_key=self.private_key,
        )
        self.signed_binding = bind_offline_api_retest_to_signed_access_expectations(
            adapter=transition["adapter"],
            prior_source=prior,
            second_source=transition["second_source"],
            expectations=self.expectations,
            attestation=self.attestation,
            binding=self.key_binding,
        )

    def options(self, **changes: object) -> dict:
        return {
            "dossier": self.dossier,
            "dossier_options": self.dossier_options,
            "signed_retest_binding": self.signed_binding,
            "expectations": self.expectations,
            "attestation": self.attestation,
            "policy_key_binding": self.key_binding,
            "expected_tenant_id": "tenant.synthetic.001",
            **changes,
        }

    def test_exact_signed_retest_joins_nonfinding_dossier(self) -> None:
        packet = build_offline_api_signed_expectation_dossier(**self.options())
        self.assertEqual(
            verify_offline_api_signed_expectation_dossier(document=packet, **self.options()),
            packet,
        )
        self.assertEqual(packet["dossier_sha256"], self.dossier["dossier_sha256"])
        self.assertEqual(
            packet["signed_retest_binding_sha256"], self.signed_binding["binding_sha256"]
        )
        self.assertEqual(packet["prior_result_sha256"], self.dossier["prior_result_sha256"])
        self.assertEqual(packet["second_result_sha256"], self.dossier["second_result_sha256"])
        self.assertEqual(packet["observation_change"], self.dossier["observation_change"])
        self.assertTrue(packet["signed_scope_id_binding_verified"])
        self.assertFalse(packet["signed_scope_digest_binding_verified"])
        self.assertFalse(packet["policy_owner_authority_verified"])
        self.assertFalse(packet["pre_observation_commitment_verified"])
        self.assertFalse(packet["finding_verified"])
        self.assertFalse(packet["finding_publication_verified"])
        self.assertFalse(packet["report_publication_verified"])
        self.assertFalse(packet["positive_use_approved"])
        rendered = json.dumps(packet)
        self.assertNotIn(self.expectations["object_id"], rendered)
        self.assertNotIn("principal.other", rendered)
        self.assertNotIn("tenant.synthetic.001", rendered)

    def test_wrong_key_or_changed_assertion_is_rejected(self) -> None:
        wrong_key = OfflineAccessPolicyKeyBinding(
            policy_owner_id=self.key_binding.policy_owner_id,
            key_id=self.key_binding.key_id,
            public_key=Ed25519PrivateKey.generate().public_key(),
        )
        with self.assertRaises(OfflineApiSignedExpectationDossierError):
            build_offline_api_signed_expectation_dossier(
                **self.options(policy_key_binding=wrong_key)
            )
        changed = copy.deepcopy(self.expectations)
        changed["principal_expectations"][0]["expected_access"] = not changed[
            "principal_expectations"
        ][0]["expected_access"]
        with self.assertRaises(OfflineApiSignedExpectationDossierError):
            build_offline_api_signed_expectation_dossier(**self.options(expectations=changed))

    def test_wrong_tenant_case_or_retest_observation_is_rejected(self) -> None:
        with self.assertRaises(OfflineApiSignedExpectationDossierError):
            build_offline_api_signed_expectation_dossier(
                **self.options(expected_tenant_id="tenant.other")
            )
        transition = self.dossier_options["transition_options"]
        wrong_source = {
            **self.dossier_options,
            "transition_options": {
                **transition,
                "second_source": transition["prior_source"],
            },
        }
        with self.assertRaises(OfflineApiSignedExpectationDossierError):
            build_offline_api_signed_expectation_dossier(
                **self.options(dossier_options=wrong_source)
            )
        changed = copy.deepcopy(self.signed_binding)
        changed["observation_change"] = "forged_change"
        with self.assertRaises(OfflineApiSignedExpectationDossierError):
            build_offline_api_signed_expectation_dossier(
                **self.options(signed_retest_binding=changed)
            )

    def test_saved_companion_requires_fresh_original_replay(self) -> None:
        packet = build_offline_api_signed_expectation_dossier(**self.options())
        changed = copy.deepcopy(packet)
        changed["finding_verified"] = True
        with self.assertRaisesRegex(
            OfflineApiSignedExpectationDossierError, "does not match originals"
        ):
            verify_offline_api_signed_expectation_dossier(document=changed, **self.options())

    def test_saved_companion_rejects_large_or_nested_native_values(self) -> None:
        packet = build_offline_api_signed_expectation_dossier(**self.options())
        oversized = copy.deepcopy(packet)
        oversized["companion_sha256"] = "x" * 2_000_001
        with self.assertRaises(OfflineApiSignedExpectationDossierError):
            verify_offline_api_signed_expectation_dossier(document=oversized, **self.options())
        nested = copy.deepcopy(packet)
        nested["effects"]["module_direct_network"] = ["x"] * 100_000
        with self.assertRaises(OfflineApiSignedExpectationDossierError):
            verify_offline_api_signed_expectation_dossier(document=nested, **self.options())

    def test_direct_documents_are_bounded_before_upstream_replay(self) -> None:
        nested: list = []
        for _ in range(2_000):
            nested = [nested]
        cases = (
            ("dossier", "tenant_id", "x" * 2_000_001, None),
            ("signed_retest_binding", "effects", nested, "network"),
            ("expectations", "principal_expectations", nested, None),
            ("attestation", "policy_owner_id", "x" * 2_000_001, None),
        )
        for name, field, replacement, effect_key in cases:
            with self.subTest(document=name):
                options = self.options()
                options[name] = copy.deepcopy(options[name])
                if effect_key is None:
                    options[name][field] = replacement
                else:
                    options[name][field][effect_key] = replacement
                with (
                    patch.object(
                        companion_module, "_case_result", side_effect=AssertionError
                    ) as case_replay,
                    patch.object(
                        companion_module,
                        "verify_offline_api_reviewer_dossier",
                        side_effect=AssertionError,
                    ) as dossier_replay,
                    patch.object(
                        companion_module,
                        "verify_offline_api_signed_retest_expectation_binding",
                        side_effect=AssertionError,
                    ) as signed_replay,
                    self.assertRaisesRegex(OfflineApiSignedExpectationDossierError, "preflight"),
                ):
                    build_offline_api_signed_expectation_dossier(**options)
                case_replay.assert_not_called()
                dossier_replay.assert_not_called()
                signed_replay.assert_not_called()

    def test_nested_dossier_options_are_bounded_before_upstream_replay(self) -> None:
        deep: list = []
        for _ in range(companion_module.MAX_OPTIONS_DEPTH + 2):
            deep = [deep]
        cases = (
            ("oversized", "x" * 2_000_001),
            ("deep", deep),
            ("total_string_bytes", ["x" * 900_000 for _ in range(10)]),
            ("node_count", [[None] * 1_000 for _ in range(101)]),
            ("unexpected_mapping", MappingProxyType({"value": "local"})),
        )
        for label, value in cases:
            with self.subTest(label=label):
                options = {
                    **self.dossier_options,
                    "review_bridge": copy.deepcopy(self.dossier_options["review_bridge"]),
                }
                options["review_bridge"]["untrusted_extra"] = value
                with (
                    patch.object(
                        companion_module, "_case_result", side_effect=AssertionError
                    ) as case_replay,
                    patch.object(
                        companion_module,
                        "verify_offline_api_reviewer_dossier",
                        side_effect=AssertionError,
                    ) as dossier_replay,
                    self.assertRaisesRegex(
                        OfflineApiSignedExpectationDossierError, "dossier options"
                    ),
                ):
                    build_offline_api_signed_expectation_dossier(
                        **self.options(dossier_options=options)
                    )
                case_replay.assert_not_called()
                dossier_replay.assert_not_called()

    def test_case_source_payloads_are_bounded_before_upstream_replay(self) -> None:
        original = self.dossier_options["transition_options"]
        prior = original["prior_source"]
        cases = (
            (
                "result",
                replace(prior, result={**prior.result, "oversized": "x" * 2_000_001}),
            ),
            (
                "invocation_input",
                replace(
                    prior,
                    invocation=replace(
                        prior.invocation,
                        input_data={**prior.invocation.input_data, "oversized": "x" * 2_000_001},
                    ),
                ),
            ),
        )
        for label, changed_source in cases:
            with self.subTest(label=label):
                options = {
                    **self.dossier_options,
                    "transition_options": {**original, "prior_source": changed_source},
                }
                with (
                    patch.object(
                        companion_module, "_case_result", side_effect=AssertionError
                    ) as case_replay,
                    patch.object(
                        companion_module,
                        "verify_offline_api_reviewer_dossier",
                        side_effect=AssertionError,
                    ) as dossier_replay,
                    self.assertRaisesRegex(
                        OfflineApiSignedExpectationDossierError, "dossier options"
                    ),
                ):
                    build_offline_api_signed_expectation_dossier(
                        **self.options(dossier_options=options)
                    )
                case_replay.assert_not_called()
                dossier_replay.assert_not_called()

    def test_typed_source_documents_are_bounded_before_replay(self) -> None:
        transition = self.dossier_options["transition_options"]
        bridge = self.dossier_options["review_bridge_options"]
        planning = bridge["planning_options"]
        scope = planning["scope"]
        adapter = transition["adapter"]
        context_fixture = dossier_fixture.planning_fixture.OfflineApiPlanningBundleTests(
            "test_synthetic_signal_reaches_bound_rehearsal_only"
        )
        context = context_fixture.context("mission.synthetic.001")
        cases = (
            (
                "scope_document",
                "review_bridge_options",
                {
                    **bridge,
                    "planning_options": {
                        **planning,
                        "scope": replace(
                            scope,
                            signed_scope=replace(
                                scope.signed_scope,
                                document_json="x" * (companion_module.MAX_SCOPE_DOCUMENT_BYTES + 1),
                            ),
                        ),
                    },
                },
            ),
            (
                "adapter_manifest",
                "transition_options",
                {
                    **transition,
                    "adapter": replace(
                        adapter,
                        manifest=replace(
                            adapter.manifest,
                            document_json="x" * (companion_module.MAX_SCOPE_DOCUMENT_BYTES + 1),
                        ),
                    ),
                },
            ),
            (
                "target_context_document",
                "review_bridge_options",
                {
                    **bridge,
                    "context": replace(
                        context,
                        document_json="x" * (companion_module.MAX_OPTIONS_TOTAL_STRING_BYTES + 1),
                    ),
                },
            ),
            (
                "registry_population",
                "review_bridge_options",
                {
                    **bridge,
                    "planning_options": {
                        **planning,
                        "registry": replace(
                            planning["registry"],
                            policies=(planning["registry"].policies[0],)
                            * (companion_module.MAX_REGISTRY_ITEMS + 1),
                        ),
                    },
                },
            ),
        )
        for label, location, value in cases:
            with self.subTest(label=label):
                options = {**self.dossier_options, location: value}
                with (
                    patch.object(
                        companion_module, "_case_result", side_effect=AssertionError
                    ) as case_replay,
                    self.assertRaises(OfflineApiSignedExpectationDossierError),
                ):
                    build_offline_api_signed_expectation_dossier(
                        **self.options(dossier_options=options)
                    )
                case_replay.assert_not_called()

    def test_injected_analyzer_cannot_rebind_transition_source_dictionary(self) -> None:
        original = self.dossier_options["transition_options"]
        original_adapter = original["adapter"]
        changed_options = {
            **self.dossier_options,
            "transition_options": {**original},
        }
        calls = []

        def mutating_analyzer(data):
            if not calls:
                changed_options["transition_options"]["second_source"] = original["prior_source"]
            calls.append(1)
            return original_adapter.analyzer(data)

        changed_options["transition_options"]["adapter"] = replace(
            original_adapter, analyzer=mutating_analyzer
        )
        with self.assertRaises(OfflineApiSignedExpectationDossierError):
            build_offline_api_signed_expectation_dossier(
                **self.options(dossier_options=changed_options)
            )
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
