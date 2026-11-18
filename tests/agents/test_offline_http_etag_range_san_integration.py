"""Three closed supplied-data components retain exact sources and no authority."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_specialist_components as component_module
from sunderkey.offline_http_byte_range_analysis import (
    analyze_supplied_http_byte_ranges,
    verify_supplied_http_byte_range_analysis,
)
from sunderkey.offline_http_etag_preconditions import (
    analyze_supplied_http_etag_preconditions,
    verify_supplied_http_etag_preconditions_analysis,
)
from sunderkey.offline_specialist_components import (
    PROFILE_DEFAULT_COMPONENTS,
    RESULT_DOMAIN,
    OfflineSpecialistComponentError,
    _address,
    build_offline_specialist_component_catalog,
    load_offline_specialist_component_request,
    run_offline_specialist_component,
    verify_offline_specialist_component_result,
)
from sunderkey.offline_x509_san_analysis import (
    analyze_supplied_x509_san,
    verify_supplied_x509_san_analysis,
)

ROOT = Path(__file__).resolve().parents[2]
COMPONENTS = (
    (
        "offline-http-byte-range-component.json",
        "http_supplied_byte_range_arithmetic",
        "AOE-GB-D05-S01",
        "analyze_supplied_http_byte_ranges",
        analyze_supplied_http_byte_ranges,
        verify_supplied_http_byte_range_analysis,
        "HBR-4AFC73E40EFC1614C2E08A2EE3641092",
        "sunderkey.offline-http-byte-range-analysis.v1",
        "HBR-",
    ),
    (
        "offline-http-etag-component.json",
        "http_supplied_etag_precondition_order",
        "AOE-GB-D05-S01",
        "analyze_supplied_http_etag_preconditions",
        analyze_supplied_http_etag_preconditions,
        verify_supplied_http_etag_preconditions_analysis,
        "HEP-7AB77A0513B521180797040AAB02728E",
        "sunderkey.offline-http-etag-preconditions.v1",
        "HEP-",
    ),
    (
        "offline-x509-san-component.json",
        "x509_supplied_san_reference_match",
        "AOE-GE-D22-S03",
        "analyze_supplied_x509_san",
        analyze_supplied_x509_san,
        verify_supplied_x509_san_analysis,
        "XSA-76A0DFE949EDB4BE18100769CAD0905E",
        "sunderkey.offline-x509-san-analysis.v1",
        "XSA-",
    ),
)


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class OfflineHttpEtagRangeSanIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = build_offline_specialist_component_catalog(repository_root=ROOT)

    def request(self, filename: str) -> dict:
        return load_offline_specialist_component_request(ROOT / "examples" / filename)

    def run_component(self, request: dict) -> dict:
        return run_offline_specialist_component(request, catalog=self.catalog, repository_root=ROOT)

    def verify(self, result: dict, request: dict) -> dict:
        return verify_offline_specialist_component_result(
            result, request=request, catalog=self.catalog, repository_root=ROOT
        )

    def test_three_example_dispatches_replay_exact_original_sources(self) -> None:
        descriptors = {row["component_id"]: row for row in self.catalog.to_dict()["components"]}
        for (
            filename,
            component_id,
            profile_id,
            _,
            analyzer,
            leaf_verifier,
            golden_id,
            _,
            _,
        ) in COMPONENTS:
            with self.subTest(component_id=component_id):
                original = self.request(filename)
                supplied = copy.deepcopy(original)
                result = self.run_component(supplied)
                source = original["payload"]["model"]
                analysis = result["analysis"]
                self.assertEqual(original["profile_id"], profile_id)
                self.assertEqual(result["component"], descriptors[component_id])
                self.assertEqual(result["component"]["profile_id"], profile_id)
                self.assertEqual(analysis["analysis_id"], golden_id)
                self.assertEqual(analysis, analyzer(source).to_dict())
                self.assertEqual(analysis["source_model"], source)
                self.assertEqual(leaf_verifier(analyzer(source), model=source).to_dict(), analysis)
                self.assertEqual(self.verify(result, original), result)
                self.assertEqual(supplied, original)
                self.assertEqual(set(result["operational_effects"].values()), {"none"})
                self.assertEqual(set(analysis["effects"].values()), {"none"})
                self.assertIs(result["full_candidate_assembled"], False)
                self.assertIs(result["positive_use_approved"], False)
                self.assertIs(analysis["flags"].get("service_authenticated", False), False)
                self.assertIs(analysis["flags"].get("server_response_verified", False), False)

    def test_range_default_and_explicit_selector_keep_distinct_envelopes(self) -> None:
        request = self.request("offline-http-byte-range-component.json")
        self.assertNotIn("component_id", request)
        self.assertEqual(
            PROFILE_DEFAULT_COMPONENTS["AOE-GB-D05-S01"],
            "http_supplied_byte_range_arithmetic",
        )
        self.assertEqual(
            PROFILE_DEFAULT_COMPONENTS["AOE-GE-D22-S03"],
            "supplied_x509_chain_structure",
        )
        explicit = request | {"component_id": "http_supplied_byte_range_arithmetic"}
        implicit_result, explicit_result = self.run_component(request), self.run_component(explicit)
        self.assertEqual(implicit_result["analysis"], explicit_result["analysis"])
        self.assertEqual(implicit_result["component"], explicit_result["component"])
        self.assertNotEqual(implicit_result["request_sha256"], explicit_result["request_sha256"])
        with self.assertRaises(OfflineSpecialistComponentError):
            self.verify(explicit_result, request)
        for filename, expected in (
            ("offline-http-etag-component.json", "http_supplied_etag_precondition_order"),
            ("offline-x509-san-component.json", "x509_supplied_san_reference_match"),
        ):
            with self.subTest(filename=filename):
                selected = self.request(filename)
                self.assertEqual(selected["component_id"], expected)
                result = self.run_component(selected)
                self.assertEqual(result["component"]["component_id"], expected)

    def test_resource_and_selector_denial_precedes_each_leaf(self) -> None:
        for filename, component_id, _, analyzer_name, _, _, _, _, _ in COMPONENTS:
            original = self.request(filename)
            cases = []
            for resource in ("network", "filesystem", "process", "credential"):
                altered = copy.deepcopy(original)
                altered["resources"][resource] = ["not-authorized"]
                cases.append(altered)
            for field, value in (
                ("action_tier", "R1"),
                ("dry_run", False),
                ("credential_refs", ["synthetic:not-authorized"]),
                ("component_id", "kubernetes_rbac_supplied_model"),
            ):
                altered = copy.deepcopy(original)
                altered[field] = value
                cases.append(altered)
            with self.subTest(component_id=component_id):
                with patch.object(component_module, analyzer_name) as analyzer:
                    for altered in cases:
                        with self.assertRaises(OfflineSpecialistComponentError):
                            self.run_component(altered)
                    analyzer.assert_not_called()

    def test_wrong_original_and_readdressed_false_result_are_rejected(self) -> None:
        for filename, component_id, _, _, _, _, _, domain, prefix in COMPONENTS:
            with self.subTest(component_id=component_id):
                original = self.request(filename)
                result = self.run_component(original)
                alternate = copy.deepcopy(original)
                alternate["payload"]["model"]["source_id"] = "different-source"
                self.assertNotEqual(
                    self.run_component(alternate)["request_sha256"], result["request_sha256"]
                )
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify(result, alternate)
                changed = copy.deepcopy(result)
                changed["analysis"]["effects"]["execution"] = "approved"
                leaf_body = {
                    key: value
                    for key, value in changed["analysis"].items()
                    if key not in {"analysis_id", "analysis_sha256"}
                }
                leaf_digest = hashlib.sha256(
                    (domain + "\n" + _canonical(leaf_body)).encode("ascii")
                ).hexdigest()
                changed["analysis"].update(
                    analysis_id=prefix + leaf_digest[:32].upper(),
                    analysis_sha256="sha256:" + leaf_digest,
                )
                outer_body = {
                    key: value
                    for key, value in changed.items()
                    if key not in {"result_id", "result_sha256"}
                }
                identity, digest = _address(outer_body, RESULT_DOMAIN, "OSR-")
                changed.update(result_id=identity, result_sha256=digest)
                with self.assertRaises(OfflineSpecialistComponentError):
                    self.verify(changed, original)

    def test_three_examples_express_distinct_offline_observations_only(self) -> None:
        range_body = self.run_component(self.request("offline-http-byte-range-component.json"))[
            "analysis"
        ]
        self.assertTrue(range_body["rfc_get_satisfiable_predicate"])
        self.assertEqual(
            [(row["selected_first"], row["selected_last"]) for row in range_body["members"]],
            [(0, 4), (10, 19), (17, 19)],
        )
        etag_body = self.run_component(self.request("offline-http-etag-component.json"))["analysis"]
        self.assertEqual(etag_body["analysis_status"], "conditional_304_predicate")
        san_body = self.run_component(self.request("offline-x509-san-component.json"))["analysis"]
        self.assertEqual(san_body["analysis_status"], "match_observed")
        self.assertFalse(san_body["flags"]["service_authenticated"])


if __name__ == "__main__":
    unittest.main()
