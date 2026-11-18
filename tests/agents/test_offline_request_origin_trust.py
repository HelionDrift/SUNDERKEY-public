"""Request-origin predicates remain source-bound and do not prove target behavior."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey import offline_specialist_components as components
from sunderkey.offline_request_origin_trust import (
    RequestOriginTrust,
    RequestOriginTrustError,
    analyze_supplied_request_origin_trust,
    verify_supplied_request_origin_trust,
)

ROOT = Path(__file__).resolve().parents[2]


def model() -> dict:
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-request-origin-trust-predicates-v1",
        "source_id": "source.synthetic-1",
        "policy": {
            "declaration_complete": True,
            "origin_required": True,
            "csrf_token_required": True,
            "allowed_origins": ["https://app.example"],
        },
        "observations": [
            {
                "observation_id": "a-candidate",
                "method": "POST",
                "origin": "https://other.example",
                "capture_complete": True,
                "csrf_token_present": False,
                "declared_outcome": "accepted",
            },
            {
                "observation_id": "b-reject",
                "method": "DELETE",
                "origin": None,
                "capture_complete": True,
                "csrf_token_present": True,
                "declared_outcome": "rejected",
            },
        ],
    }


class RequestOriginTrustTests(unittest.TestCase):
    def test_fixed_catalog_dispatch_and_negative_predicates(self) -> None:
        request = json.loads(
            (ROOT / "examples/offline-request-origin-trust-component.json").read_text(
                encoding="utf-8"
            )
        )
        catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)
        result = components.run_offline_specialist_component(
            request, catalog=catalog, repository_root=ROOT
        )
        self.assertEqual(result["component"]["profile_id"], "AOE-GE-D23-S09")
        self.assertEqual(
            result["component"]["component_id"], "supplied_request_origin_trust"
        )
        self.assertEqual(
            result["analysis"]["projections"][0]["disposition"],
            "candidate_declared_trust_boundary_conflict",
        )
        self.assertFalse(result["analysis"]["flags"]["request_forgery_verified"])

    def test_replay_preserves_source_and_does_not_promote_conflict(self) -> None:
        source = model()
        original = copy.deepcopy(source)
        report = analyze_supplied_request_origin_trust(source)
        body = report.to_dict()
        self.assertEqual(source, original)
        self.assertEqual(body["source_model"], original)
        self.assertEqual(body["observation_count"], 2)
        by_id = {row["observation_id"]: row for row in body["projections"]}
        self.assertEqual(
            by_id["a-candidate"]["negative_predicates"],
            ["origin_not_declared_allowed", "required_token_absent"],
        )
        self.assertEqual(
            by_id["b-reject"]["negative_predicates"], ["required_origin_absent"]
        )
        self.assertEqual(by_id["b-reject"]["disposition"], "declared_reject_consistent")
        self.assertFalse(any(body["flags"].values()))
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_request_origin_trust(report, model=source).to_json(),
            report.to_json(),
        )

    def test_incomplete_or_unknown_premises_withhold_conflict(self) -> None:
        source = model()
        source["policy"]["declaration_complete"] = False
        rows = analyze_supplied_request_origin_trust(source).to_dict()["projections"]
        self.assertEqual(rows[0]["disposition"], "unresolved_declaration_or_capture")
        source["policy"]["declaration_complete"] = True
        source["observations"][0]["capture_complete"] = False
        rows = analyze_supplied_request_origin_trust(source).to_dict()["projections"]
        self.assertEqual(rows[0]["disposition"], "unresolved_declaration_or_capture")
        source["observations"][0]["capture_complete"] = True
        source["observations"][0]["declared_outcome"] = "unknown"
        rows = analyze_supplied_request_origin_trust(source).to_dict()["projections"]
        self.assertEqual(rows[0]["disposition"], "unresolved_outcome")
        source["observations"][0]["origin"] = "https://app.example"
        source["observations"][0]["csrf_token_present"] = True
        source["observations"][0]["declared_outcome"] = "accepted"
        rows = analyze_supplied_request_origin_trust(source).to_dict()["projections"]
        self.assertEqual(rows[0]["disposition"], "no_declared_negative_invariant")

    def test_malformed_or_resource_bearing_sources_are_refused(self) -> None:
        cases = []
        source = model()
        source["policy"]["allowed_origins"] = ["https://APP.example"]
        cases.append(source)
        source = model()
        source["policy"]["allowed_origins"] = ["http://app.example"]
        cases.append(source)
        source = model()
        source["policy"]["allowed_origins"] = ["https://app.example:65536"]
        cases.append(source)
        source = model()
        source["policy"]["allowed_origins"] = ["https://app.example/path"]
        cases.append(source)
        source = model()
        source["observations"].append(copy.deepcopy(source["observations"][0]))
        cases.append(source)
        source = model()
        source["observations"][0]["csrf_token_present"] = "actual-token"
        cases.append(source)
        source = model()
        source["network_permission"] = True
        cases.append(source)
        source = model()
        source["cycle"] = source
        cases.append(source)
        source = model()
        source["observations"] = source["observations"] * 65
        cases.append(source)
        for item in cases:
            with self.subTest(case=repr(item.get("source_id"))):
                with self.assertRaises(RequestOriginTrustError):
                    analyze_supplied_request_origin_trust(item)

    def test_tampered_report_and_alternate_source_are_refused(self) -> None:
        source = model()
        report = analyze_supplied_request_origin_trust(source)
        changed = report.to_dict()
        changed["flags"]["request_forgery_verified"] = True
        with self.assertRaises(RequestOriginTrustError):
            RequestOriginTrust(changed)
        alternate = model()
        alternate["observations"][0]["declared_outcome"] = "rejected"
        with self.assertRaises(RequestOriginTrustError):
            verify_supplied_request_origin_trust(report, model=alternate)
        with self.assertRaises(RequestOriginTrustError):
            verify_supplied_request_origin_trust(report.to_dict(), model=source)


if __name__ == "__main__":
    unittest.main()
