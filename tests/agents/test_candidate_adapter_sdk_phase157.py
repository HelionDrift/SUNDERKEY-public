"""Technical strategy, SDK, and cross-domain reference adapter tests."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import unittest
from pathlib import Path
from typing import Any

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from scripts.build_candidate_adapter_catalog import build_schema, load_blueprints
from sunderkey.candidate_adapter_sdk import (
    CATALOG_DOMAIN,
    MANIFEST_DOMAIN,
    SOURCE_PATH,
    AdapterInvocation,
    CandidateAdapterCatalog,
    build_candidate_adapter_catalog,
    load_candidate_adapter_catalog,
)
from sunderkey.candidate_implementation_strategy import (
    CandidateImplementationStrategy,
    build_candidate_implementation_strategy,
    load_candidate_implementation_strategy,
)
from sunderkey.errors import QualificationError
from sunderkey.qualification import _canonical_sha256
from sunderkey.reference_adapters import build_reference_adapters

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_DIR = ROOT / "registry"
STRATEGY_PATH = REGISTRY_DIR / "candidate-implementation-strategy-v1.json"
CATALOG_PATH = REGISTRY_DIR / "candidate-adapters-reference-v1.json"
SCHEMA_PATH = REGISTRY_DIR / "schemas" / "candidate-adapter-catalog-v1.schema.json"


def invocation(profile_id: str, vector_id: str, input_data: dict[str, Any]) -> AdapterInvocation:
    return AdapterInvocation(
        invocation_id="INV-SYNTHETIC-001",
        mission_id="MISSION-SYNTHETIC-001",
        authority_ref="AUTH-SYNTHETIC-001",
        profile_id=profile_id,
        vector_id=vector_id,
        target_id="TARGET-SYNTHETIC-001",
        scope_id="SCOPE-SYNTHETIC-001",
        action_tier="R0",
        environment="synthetic",
        dry_run=True,
        credential_refs=(),
        input_data=input_data,
    )


def rebind_manifest(manifest: dict[str, Any]) -> None:
    body = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    manifest["manifest_sha256"] = _canonical_sha256({"domain": MANIFEST_DOMAIN, "manifest": body})


def rebind_catalog(catalog: dict[str, Any]) -> None:
    body = {key: value for key, value in catalog.items() if key != "catalog_sha256"}
    catalog["catalog_sha256"] = _canonical_sha256({"domain": CATALOG_DOMAIN, "catalog": body})


class CandidateAdapterSdkPhase157Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.strategy = load_candidate_implementation_strategy(STRATEGY_PATH)
        cls.blueprints = load_blueprints()
        cls.catalog = load_candidate_adapter_catalog(
            CATALOG_PATH, cls.strategy, cls.blueprints, ROOT
        )
        cls.adapters = build_reference_adapters(cls.catalog)

    def test_strategy_is_exact_content_addressed_and_non_operational(self) -> None:
        expected = build_candidate_implementation_strategy()
        self.assertEqual(self.strategy.to_dict(), expected.to_dict())
        self.assertEqual(
            self.strategy.strategy_id,
            "CIS-956EA1C0F87FCB4D0445A8860FB0189D",
        )
        self.assertNotIn("decision", self.strategy.to_dict())
        self.assertIn("target_authority", self.strategy.to_dict()["no_effects"])

    def test_strategy_tampering_fails_even_when_rehashed(self) -> None:
        changed = copy.deepcopy(self.strategy.to_dict())
        changed["phase157_scope"]["real_target_access"] = "authorized"
        body_fields = set(changed) - {"strategy_id", "strategy_sha256"}
        body = {key: changed[key] for key in body_fields}
        digest = _canonical_sha256(
            {"domain": "sunderkey.candidate-implementation-strategy.v1", "strategy": body}
        )
        changed["strategy_sha256"] = digest
        changed["strategy_id"] = f"CIS-{digest.removeprefix('sha256:')[:32].upper()}"
        with self.assertRaisesRegex(QualificationError, "versioned reference"):
            CandidateImplementationStrategy.from_dict(changed)

    def test_catalog_matches_deterministic_builder_and_schema(self) -> None:
        source_sha256 = "sha256:" + hashlib.sha256((ROOT / SOURCE_PATH).read_bytes()).hexdigest()
        expected = build_candidate_adapter_catalog(self.strategy, self.blueprints, source_sha256)
        self.assertEqual(
            CATALOG_PATH.read_text(encoding="utf-8"),
            json.dumps(expected.to_dict(), ensure_ascii=True, indent=2) + "\n",
        )
        self.assertEqual(
            SCHEMA_PATH.read_text(encoding="utf-8"),
            json.dumps(build_schema(), ensure_ascii=True, indent=2) + "\n",
        )
        if Draft202012Validator is not None:
            Draft202012Validator(build_schema()).validate(self.catalog.to_dict())

    def test_reference_slice_has_six_exact_deny_all_manifests(self) -> None:
        self.assertEqual(len(self.catalog.manifests), 6)
        self.assertEqual(
            set(self.catalog.manifests_by_profile_id),
            {
                "AOE-GA-D01-S01",
                "AOE-GB-D06-S09",
                "AOE-GA-D03-S14",
                "AOE-GC-D14-S01",
                "AOE-GC-D11-S08",
                "AOE-GD-D19-S01",
            },
        )
        self.assertTrue(all(item.resource_policy.is_deny_all for item in self.catalog.manifests))
        self.assertEqual(
            [item.required_isolation for item in self.catalog.manifests].count("microvm"),
            3,
        )

    def test_rehashed_source_or_capability_substitution_fails_closed(self) -> None:
        changed = copy.deepcopy(self.catalog.to_dict())
        changed["manifests"][0]["source_provenance"]["source_sha256"] = "sha256:" + "0" * 64
        rebind_manifest(changed["manifests"][0])
        rebind_catalog(changed)
        source_sha256 = "sha256:" + hashlib.sha256((ROOT / SOURCE_PATH).read_bytes()).hexdigest()
        with self.assertRaisesRegex(QualificationError, "reviewed inputs"):
            CandidateAdapterCatalog.from_dict(
                changed, self.strategy, self.blueprints, source_sha256
            )

        changed = copy.deepcopy(self.catalog.to_dict())
        changed["manifests"][1]["primary_capability_id"] = "api.substituted"
        rebind_manifest(changed["manifests"][1])
        rebind_catalog(changed)
        with self.assertRaisesRegex(QualificationError, "reviewed inputs"):
            CandidateAdapterCatalog.from_dict(
                changed, self.strategy, self.blueprints, source_sha256
            )

    def test_six_reference_adapters_produce_deterministic_evidence(self) -> None:
        inputs = {
            "AOE-GA-D01-S01": {
                "assets": [
                    {"asset_id": "asset-a", "source_id": "src-1", "fingerprint": "fp-1"},
                    {"asset_id": "asset-b", "source_id": "src-2", "fingerprint": "fp-1"},
                ]
            },
            "AOE-GB-D06-S09": {
                "exchanges": [
                    {
                        "evidence_id": "http-1",
                        "subject_id": "user-a",
                        "object_id": "object-b",
                        "expected_permitted": False,
                        "status_code": 200,
                    }
                ]
            },
            "AOE-GA-D03-S14": {
                "edges": [{"source": "user-a", "target": "role-admin"}],
                "start_principals": ["user-a"],
                "privileged_entitlements": ["role-admin"],
            },
            "AOE-GC-D14-S01": {
                "statements": [
                    {
                        "statement_id": "stmt-1",
                        "effect": "Allow",
                        "actions": ["*"],
                        "resources": ["*"],
                    }
                ]
            },
            "AOE-GC-D11-S08": {
                "edges": [{"source": "standard-user", "target": "local-system"}],
                "start_context": "standard-user",
                "privileged_contexts": ["local-system"],
            },
            "AOE-GD-D19-S01": {
                "flows": [{"source_zone": "enterprise", "destination_zone": "safety"}],
                "allowed_pairs": [["enterprise", "dmz"]],
                "state_before": {"controller_mode": "run"},
                "state_after": {"controller_mode": "run"},
            },
        }
        for profile_id, input_data in inputs.items():
            with self.subTest(profile_id=profile_id):
                adapter = self.adapters[profile_id]
                request = invocation(profile_id, adapter.manifest.vector_id, input_data)
                first = adapter.execute(request)
                second = adapter.execute(request)
                self.assertEqual(first.status, "completed")
                self.assertEqual(first.disposition, "verified_finding")
                self.assertEqual(first.result_sha256, second.result_sha256)
                self.assertEqual(
                    first.evidence[0].content_sha256,
                    second.evidence[0].content_sha256,
                )

    def test_malformed_and_residual_effect_inputs_fail_closed(self) -> None:
        api = self.adapters["AOE-GB-D06-S09"]
        result = api.execute(invocation(api.manifest.profile_id, api.manifest.vector_id, {}))
        self.assertEqual(result.status, "failed_closed")
        self.assertEqual(result.disposition, "abstention")

        ics = self.adapters["AOE-GD-D19-S01"]
        result = ics.execute(
            invocation(
                ics.manifest.profile_id,
                ics.manifest.vector_id,
                {
                    "flows": [],
                    "allowed_pairs": [],
                    "state_before": {"mode": "run"},
                    "state_after": {"mode": "program"},
                },
            )
        )
        self.assertEqual(result.status, "failed_closed")
        self.assertEqual(result.restoration_status, "failed_closed")
        self.assertEqual(result.residual_effects, ("synthetic_state_delta_detected",))

    def test_authority_and_resource_boundary_fail_closed_before_analysis(self) -> None:
        adapter = self.adapters["AOE-GB-D06-S09"]
        valid = invocation(
            adapter.manifest.profile_id,
            adapter.manifest.vector_id,
            {"exchanges": []},
        )
        mutations = (
            {"profile_id": "AOE-GA-D01-S01"},
            {"action_tier": "R1"},
            {"environment": "production"},
            {"dry_run": False},
            {"credential_refs": ("secret:production",)},
        )
        for changes in mutations:
            with self.subTest(changes=changes):
                changed = AdapterInvocation(**{**valid.__dict__, **changes})
                with self.assertRaises(QualificationError):
                    adapter.execute(changed)

    def test_sdk_and_reference_implementations_have_no_execution_imports(self) -> None:
        forbidden = {"http", "requests", "socket", "subprocess", "urllib"}
        for relative in (
            "src/sunderkey/candidate_adapter_sdk.py",
            "src/sunderkey/reference_adapters.py",
        ):
            tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
            imported = {
                alias.name.split(".")[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.Import)
                for alias in node.names
            }
            imported.update(
                node.module.split(".")[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.module and not node.level
            )
            self.assertTrue(forbidden.isdisjoint(imported))


if __name__ == "__main__":
    unittest.main()
