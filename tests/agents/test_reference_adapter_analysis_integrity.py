"""Pure synthetic regressions for the existing reference analysis algorithms."""

from __future__ import annotations

import copy
import hashlib
import unittest
from pathlib import Path

from scripts.build_candidate_adapter_catalog import load_blueprints
from sunderkey.candidate_adapter_sdk import (
    SOURCE_PATH,
    AdapterResult,
    build_candidate_adapter_catalog,
)
from sunderkey.candidate_implementation_strategy import load_candidate_implementation_strategy
from sunderkey.reference_adapters import build_reference_adapters
from tests.agents.test_candidate_adapter_sdk_phase157 import invocation

ROOT = Path(__file__).resolve().parents[2]
PASSIVE = "AOE-GA-D01-S01"
IDENTITY = "AOE-GA-D03-S14"
CLOUD = "AOE-GC-D14-S01"
ENDPOINT = "AOE-GC-D11-S08"


class NativeStringAlias(str):
    pass


class NativeListAlias(list):
    def __iter__(self):
        raise AssertionError("Nonnative array hooks must not run")


class ReferenceAdapterAnalysisIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        strategy = load_candidate_implementation_strategy(
            ROOT / "registry/candidate-implementation-strategy-v1.json"
        )
        source_sha256 = "sha256:" + hashlib.sha256((ROOT / SOURCE_PATH).read_bytes()).hexdigest()
        catalog = build_candidate_adapter_catalog(strategy, load_blueprints(), source_sha256)
        cls.adapters = build_reference_adapters(catalog)

    def execute(self, profile: str, data: dict) -> AdapterResult:
        adapter = self.adapters[profile]
        return adapter.execute(invocation(profile, adapter.manifest.vector_id, data))

    def assert_abstained(self, profile: str, data: dict) -> None:
        result = self.execute(profile, data)
        self.assertEqual(result.status, "failed_closed")
        self.assertEqual(result.disposition, "abstention")
        self.assertEqual(result.observations, ())
        self.assertFalse(result.evidence[0].content["input_accepted"])

    def test_identity_continues_through_each_privileged_goal(self) -> None:
        result = self.execute(
            IDENTITY,
            {
                "edges": [
                    {"source": "user-a", "target": "role-admin"},
                    {"source": "role-admin", "target": "domain-admin"},
                ],
                "start_principals": ["user-a"],
                "privileged_entitlements": ["role-admin", "domain-admin"],
            },
        )
        self.assertEqual(
            [item["path"] for item in result.observations],
            [["user-a", "role-admin"], ["user-a", "role-admin", "domain-admin"]],
        )

    def test_each_start_principal_retains_its_shared_goal_witness(self) -> None:
        result = self.execute(
            IDENTITY,
            {
                "edges": [
                    {"source": "user-b", "target": "role-admin"},
                    {"source": "user-a", "target": "role-admin"},
                ],
                "start_principals": ["user-b", "user-a"],
                "privileged_entitlements": ["role-admin"],
            },
        )
        self.assertEqual(
            [item["path"] for item in result.observations],
            [["user-a", "role-admin"], ["user-b", "role-admin"]],
        )

    def test_endpoint_continues_through_privileged_contexts(self) -> None:
        result = self.execute(
            ENDPOINT,
            {
                "edges": [
                    {"source": "user", "target": "administrator"},
                    {"source": "administrator", "target": "local-system"},
                ],
                "start_context": "user",
                "privileged_contexts": ["administrator", "local-system"],
            },
        )
        self.assertEqual(
            [item["path"] for item in result.observations],
            [["user", "administrator"], ["user", "administrator", "local-system"]],
        )

    def test_shortest_witnesses_are_deterministic_and_do_not_enumerate_simple_paths(self) -> None:
        data = {
            "edges": [
                {"source": "user", "target": "route-b"},
                {"source": "user", "target": "route-a"},
                {"source": "user", "target": "longer"},
                {"source": "longer", "target": "route-a"},
                {"source": "route-b", "target": "admin"},
                {"source": "route-a", "target": "admin"},
                {"source": "route-a", "target": "admin"},
                {"source": "admin", "target": "user"},
            ],
            "start_principals": ["user", "user"],
            "privileged_entitlements": ["admin", "admin"],
        }
        original = self.execute(IDENTITY, data)
        reordered = copy.deepcopy(data)
        reordered["edges"].reverse()
        self.assertEqual(original.to_dict(), self.execute(IDENTITY, reordered).to_dict())
        self.assertEqual(
            [item["path"] for item in original.observations], [["user", "route-a", "admin"]]
        )

    def test_privileged_start_does_not_hide_a_later_privileged_goal(self) -> None:
        result = self.execute(
            ENDPOINT,
            {
                "edges": [{"source": "administrator", "target": "local-system"}],
                "start_context": "administrator",
                "privileged_contexts": ["administrator", "local-system"],
            },
        )
        self.assertEqual(
            [item["path"] for item in result.observations],
            [["administrator"], ["administrator", "local-system"]],
        )

    def test_disconnected_native_identity_and_endpoint_controls_remain_negative(self) -> None:
        for profile, data, finding in (
            (
                IDENTITY,
                {
                    "edges": [{"source": "user", "target": "reader"}],
                    "start_principals": ["user"],
                    "privileged_entitlements": ["admin"],
                },
                "no_privileged_path",
            ),
            (
                ENDPOINT,
                {
                    "edges": [{"source": "user", "target": "reader"}],
                    "start_context": "user",
                    "privileged_contexts": ["local-system"],
                },
                "no_endpoint_privilege_path",
            ),
        ):
            with self.subTest(profile=profile):
                result = self.execute(profile, data)
                self.assertEqual(result.status, "completed")
                self.assertEqual(result.disposition, "negative_result")
                self.assertEqual(result.observations[0]["finding"], finding)

    def test_identity_requires_native_principal_and_entitlement_arrays(self) -> None:
        baseline = {
            "edges": [{"source": "user-a", "target": "role-admin"}],
            "start_principals": ["user-a"],
            "privileged_entitlements": ["role-admin"],
        }
        for field in ("start_principals", "privileged_entitlements"):
            for value in ("user-a", ("user-a",), {"user-a": True}, None, True, 1):
                data = copy.deepcopy(baseline)
                data[field] = value
                with self.subTest(field=field, family=type(value)):
                    self.assert_abstained(IDENTITY, data)

    def test_endpoint_requires_native_privileged_context_array(self) -> None:
        for value in ("local-system", ("local-system",), {"local-system": True}, None, False):
            with self.subTest(family=type(value)):
                self.assert_abstained(
                    ENDPOINT,
                    {"edges": [], "start_context": "user", "privileged_contexts": value},
                )

    def test_principal_and_context_elements_are_native_nonempty_ascii_text(self) -> None:
        for value in (
            None,
            True,
            7,
            1.0,
            {},
            [],
            b"user",
            "",
            " ",
            "u\u00e9",
            NativeStringAlias("user"),
        ):
            for profile, field in (
                (IDENTITY, "start_principals"),
                (IDENTITY, "privileged_entitlements"),
                (ENDPOINT, "privileged_contexts"),
                (ENDPOINT, "start_context"),
            ):
                data = {
                    "edges": [],
                    "start_principals": ["user"],
                    "privileged_entitlements": ["admin"],
                    "start_context": "user",
                    "privileged_contexts": ["admin"],
                }
                data[field] = value if field == "start_context" else [value]
                with self.subTest(profile=profile, field=field, family=type(value)):
                    self.assert_abstained(profile, data)

    def test_nonnative_array_hooks_are_rejected_before_iteration(self) -> None:
        for profile, data in (
            (
                IDENTITY,
                {
                    "edges": [],
                    "start_principals": NativeListAlias(["user"]),
                    "privileged_entitlements": ["admin"],
                },
            ),
            (
                ENDPOINT,
                {
                    "edges": [],
                    "start_context": "user",
                    "privileged_contexts": NativeListAlias(["admin"]),
                },
            ),
            (
                CLOUD,
                {
                    "statements": [
                        {
                            "statement_id": "stmt",
                            "effect": "Allow",
                            "actions": NativeListAlias(["*"]),
                            "resources": ["*"],
                        }
                    ]
                },
            ),
        ):
            with self.subTest(profile=profile):
                self.assert_abstained(profile, data)

    def test_cloud_validates_every_action_and_resource_before_classification(self) -> None:
        for field in ("actions", "resources"):
            for value in (
                7,
                1.0,
                False,
                None,
                {},
                [],
                b"*",
                "",
                " ",
                "\u00e9",
                NativeStringAlias("*"),
            ):
                statement = {
                    "statement_id": "stmt-1",
                    "effect": "Allow",
                    "actions": ["*"],
                    "resources": ["*"],
                }
                statement[field] = ["*", value]
                with self.subTest(field=field, family=type(value)):
                    self.assert_abstained(CLOUD, {"statements": [statement]})

    def test_cloud_requires_native_action_and_resource_arrays(self) -> None:
        for field in ("actions", "resources"):
            for value in ("*", ("*",), {"*": True}, None, NativeListAlias(["*"])):
                statement = {
                    "statement_id": "stmt-1",
                    "effect": "Allow",
                    "actions": ["*"],
                    "resources": ["*"],
                }
                statement[field] = value
                with self.subTest(field=field, family=type(value)):
                    self.assert_abstained(CLOUD, {"statements": [statement]})

    def test_cloud_effect_is_native_closed_text_before_vocabulary_membership(self) -> None:
        for effect in (
            [],
            {},
            None,
            True,
            1,
            1.0,
            b"Allow",
            "",
            "allow",
            " Allow",
            NativeStringAlias("Allow"),
            NativeStringAlias("Deny"),
        ):
            with self.subTest(effect=effect, family=type(effect)):
                self.assert_abstained(
                    CLOUD,
                    {
                        "statements": [
                            {
                                "statement_id": "stmt-effect",
                                "effect": effect,
                                "actions": ["*"],
                                "resources": ["*"],
                            }
                        ]
                    },
                )

    def test_cloud_literal_indicator_semantics_remain_nonoperational(self) -> None:
        statements = [
            {
                "statement_id": "literal-star",
                "effect": "Allow",
                "actions": ["*"],
                "resources": ["*"],
            },
            {"statement_id": "denied-star", "effect": "Deny", "actions": ["*"], "resources": ["*"]},
            {
                "statement_id": "service-star",
                "effect": "Allow",
                "actions": ["iam:*"],
                "resources": ["*"],
            },
            {
                "statement_id": "object",
                "effect": "Allow",
                "actions": ["read"],
                "resources": ["resource:one"],
            },
        ]
        result = self.execute(CLOUD, {"statements": statements})
        self.assertEqual(
            [item["finding"] for item in result.observations],
            ["unbounded_cloud_iam_allow"] + ["bounded_cloud_iam_statement"] * 3,
        )
        self.assertEqual(result.restoration_status, "not_required")
        self.assertEqual(result.residual_effects, ())

    def test_passive_duplicate_cites_both_supporting_sources_in_sorted_order(self) -> None:
        data = {
            "assets": [
                {"asset_id": "asset-a", "source_id": "source:z", "fingerprint": "fp-1"},
                {"asset_id": "asset-b", "source_id": "source:a", "fingerprint": "fp-1"},
            ]
        }
        original = self.execute(PASSIVE, data)
        reversed_data = {"assets": list(reversed(data["assets"]))}
        self.assertEqual(original.observations[0]["evidence_ids"], ["source:a", "source:z"])
        self.assertEqual(original.to_dict(), self.execute(PASSIVE, reversed_data).to_dict())

    def test_passive_same_asset_repeat_preserves_the_initial_fingerprint_source(self) -> None:
        result = self.execute(
            PASSIVE,
            {
                "assets": [
                    {"asset_id": "asset-a", "source_id": "src:first", "fingerprint": "fp-1"},
                    {"asset_id": "asset-a", "source_id": "src:repeat", "fingerprint": "fp-1"},
                    {"asset_id": "asset-b", "source_id": "src:other", "fingerprint": "fp-1"},
                ]
            },
        )
        self.assertEqual(result.observations[0]["evidence_ids"], ["src:first", "src:other"])
        self.assertEqual(result.observations[0]["asset_ids"], ["asset-a", "asset-b"])
        self.assertEqual(result.observations[1]["asset_count"], 3)

    def test_passive_distinct_fingerprints_remain_negative_and_inputs_are_untouched(self) -> None:
        data = {
            "assets": [
                {"asset_id": "asset-a", "source_id": "src:a", "fingerprint": "fp-1"},
                {"asset_id": "asset-b", "source_id": "src:b", "fingerprint": "fp-2"},
            ]
        }
        before = copy.deepcopy(data)
        result = self.execute(PASSIVE, data)
        self.assertEqual(data, before)
        self.assertEqual(result.disposition, "negative_result")
        self.assertEqual(result.observations[0]["unique_fingerprint_count"], 2)


if __name__ == "__main__":
    unittest.main()
