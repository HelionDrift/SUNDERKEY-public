"""Supplied DNS scope timelines never perform resolution or prove SSRF."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey import offline_specialist_components as components
from sunderkey.offline_dns_scope_timeline import (
    DnsScopeTimeline,
    DnsScopeTimelineError,
    analyze_supplied_dns_scope_timeline,
    verify_supplied_dns_scope_timeline,
)

ROOT = Path(__file__).resolve().parents[2]


def model() -> dict:
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-dns-scope-timeline-v1",
        "hostname": "service.example.test",
        "snapshots": [
            {"snapshot_id": "first", "sequence": 1, "addresses": ["8.8.8.8"]},
            {"snapshot_id": "second", "sequence": 2, "addresses": ["127.0.0.1"]},
            {"snapshot_id": "third", "sequence": 3, "addresses": ["fc00::1"]},
        ],
    }


class DnsScopeTimelineTests(unittest.TestCase):
    def test_checked_example_uses_fixed_catalog_dispatch(self) -> None:
        request = json.loads(
            (ROOT / "examples/offline-dns-scope-timeline-component.json").read_text(
                encoding="utf-8"
            )
        )
        catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)
        result = components.run_offline_specialist_component(
            request, catalog=catalog, repository_root=ROOT
        )
        self.assertEqual(result["component"]["profile_id"], "AOE-GE-D23-S06")
        self.assertEqual(result["component"]["component_id"], "supplied_dns_scope_timeline")
        self.assertEqual(
            result["analysis"]["transitions"][0]["disposition"],
            "candidate_global_to_internal_shift",
        )
        self.assertFalse(result["analysis"]["flags"]["rebind_or_ssrf_proven"])

    def test_candidate_scope_shift_is_not_a_live_finding(self) -> None:
        source = model()
        original = copy.deepcopy(source)
        report = analyze_supplied_dns_scope_timeline(source)
        self.assertEqual(source, original)
        document = report.to_dict()
        self.assertEqual(
            [row["disposition"] for row in document["transitions"]],
            ["candidate_global_to_internal_shift", "no_declared_global_to_internal_shift"],
        )
        self.assertEqual(document["observations"][0]["scope_set"], ["global"])
        self.assertEqual(document["observations"][1]["scope_set"], ["loopback"])
        self.assertEqual(document["observations"][2]["scope_set"], ["private"])
        self.assertFalse(document["flags"]["dns_resolution_performed"])
        self.assertFalse(document["flags"]["rebind_or_ssrf_proven"])
        self.assertEqual(set(document["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_dns_scope_timeline(report, model=source).to_json(),
            report.to_json(),
        )

    def test_mixed_and_non_global_answers_abstain(self) -> None:
        source = model()
        source["snapshots"][1]["addresses"] = ["8.8.8.8", "10.0.0.4"]
        source["snapshots"][2]["addresses"] = ["::ffff:127.0.0.1"]
        document = analyze_supplied_dns_scope_timeline(source).to_dict()
        self.assertEqual(
            [row["disposition"] for row in document["transitions"]],
            ["unknown_mixed_answer_shift", "unknown_mixed_answer_shift"],
        )
        self.assertEqual(document["observations"][2]["answers"][0], {
            "address": "127.0.0.1",
            "scope": "loopback",
        })

    def test_invalid_scope_and_resource_fields_are_refused(self) -> None:
        invalid = []
        duplicate = model()
        duplicate["snapshots"][1]["snapshot_id"] = "first"
        invalid.append(duplicate)
        backwards = model()
        backwards["snapshots"][1]["sequence"] = 1
        invalid.append(backwards)
        zone = model()
        zone["snapshots"][0]["addresses"] = ["fe80::1%eth0"]
        invalid.append(zone)
        resource = model()
        resource["network_permission"] = True
        invalid.append(resource)
        unicode_host = model()
        unicode_host["hostname"] = "sérvice.example.test"
        invalid.append(unicode_host)
        duplicate_address = model()
        duplicate_address["snapshots"][0]["addresses"] = ["2001:db8::1", "2001:0db8::1"]
        invalid.append(duplicate_address)
        mapped_duplicate = model()
        mapped_duplicate["snapshots"][0]["addresses"] = ["8.8.8.8", "::ffff:8.8.8.8"]
        invalid.append(mapped_duplicate)
        for candidate in invalid:
            with self.subTest(candidate=candidate):
                with self.assertRaises(DnsScopeTimelineError):
                    analyze_supplied_dns_scope_timeline(candidate)
        cyclic = model()
        cyclic["snapshots"].append(cyclic)
        with self.assertRaises(DnsScopeTimelineError):
            analyze_supplied_dns_scope_timeline(cyclic)

    def test_tampered_report_and_alternate_model_are_refused(self) -> None:
        source = model()
        report = analyze_supplied_dns_scope_timeline(source)
        changed = report.to_dict()
        changed["transitions"][0]["disposition"] = "no_declared_global_to_internal_shift"
        with self.assertRaises(DnsScopeTimelineError):
            DnsScopeTimeline(changed)
        alternate = model()
        alternate["snapshots"][1]["addresses"] = ["192.168.1.1"]
        with self.assertRaises(DnsScopeTimelineError):
            verify_supplied_dns_scope_timeline(report, model=alternate)
        with self.assertRaises(DnsScopeTimelineError):
            verify_supplied_dns_scope_timeline(report.to_dict(), model=source)


if __name__ == "__main__":
    unittest.main()
