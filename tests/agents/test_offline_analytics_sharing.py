"""Managed-analytics shares remain supplied hypotheses, not exposure proof."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

from sunderkey import offline_specialist_components as components
from sunderkey.offline_analytics_sharing import (
    AnalyticsSharing,
    AnalyticsSharingError,
    analyze_supplied_analytics_sharing,
    verify_supplied_analytics_sharing,
)

ROOT = Path(__file__).resolve().parents[2]


def _ref(kind: str, letter: str) -> str:
    return f"{kind}:sha256:" + letter * 64


def model() -> dict:
    tenant_a = _ref("tenant", "a")
    tenant_b = _ref("tenant", "b")
    principals = [_ref("principal", letter) for letter in "cd"]
    workspaces = [_ref("workspace", letter) for letter in "ef"]
    sources = [_ref("source", letter) for letter in "12"]
    dashboards = [_ref("dashboard", letter) for letter in "345"]
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-analytics-sharing-v1",
        "sharing_complete": False,
        "principals": [
            {"principal_ref": principals[0], "tenant_ref": tenant_a},
            {"principal_ref": principals[1], "tenant_ref": tenant_b},
        ],
        "workspaces": [
            {"workspace_ref": workspaces[0], "tenant_ref": tenant_a},
            {"workspace_ref": workspaces[1], "tenant_ref": tenant_b},
        ],
        "data_sources": [
            {"source_ref": sources[0], "tenant_ref": tenant_a},
            {"source_ref": sources[1], "tenant_ref": tenant_b},
        ],
        "dashboards": [
            {
                "dashboard_ref": dashboards[0],
                "workspace_ref": workspaces[0],
                "source_refs": sources,
            },
            {
                "dashboard_ref": dashboards[1],
                "workspace_ref": workspaces[0],
                "source_refs": [sources[0]],
            },
            {
                "dashboard_ref": dashboards[2],
                "workspace_ref": workspaces[1],
                "source_refs": [sources[1]],
            },
        ],
        "shares": [
            {
                "share_id": "share-1",
                "principal_ref": principals[0],
                "dashboard_ref": dashboards[0],
                "permission": "view",
                "state": "declared_granted",
            },
            {
                "share_id": "share-2",
                "principal_ref": principals[1],
                "dashboard_ref": dashboards[0],
                "permission": "export",
                "state": "declared_granted",
            },
            {
                "share_id": "share-3",
                "principal_ref": principals[0],
                "dashboard_ref": dashboards[1],
                "permission": "view",
                "state": "declared_granted",
            },
            {
                "share_id": "share-4",
                "principal_ref": principals[0],
                "dashboard_ref": dashboards[2],
                "permission": "view",
                "state": "declared_denied",
            },
            {
                "share_id": "share-5",
                "principal_ref": principals[0],
                "dashboard_ref": dashboards[2],
                "permission": "export",
                "state": "unknown",
            },
        ],
        "objectives": [
            {"principal_ref": principal, "dashboard_ref": dashboard, "permission": permission}
            for principal, dashboard, permission in (
                (principals[0], dashboards[0], "view"),
                (principals[1], dashboards[0], "export"),
                (principals[0], dashboards[1], "view"),
                (principals[0], dashboards[2], "view"),
                (principals[0], dashboards[2], "export"),
                (principals[1], dashboards[2], "view"),
            )
        ],
    }


class AnalyticsSharingTests(unittest.TestCase):
    def test_declared_cross_tenant_aligned_denied_and_unknown(self) -> None:
        source = model()
        original = copy.deepcopy(source)
        report = analyze_supplied_analytics_sharing(source)
        self.assertEqual(source, original)
        findings = report.to_dict()["findings"]
        self.assertEqual(
            [row["disposition"] for row in findings],
            [
                "declared_cross_tenant_share",
                "declared_cross_tenant_share",
                "declared_aligned_share",
                "declared_denied",
                "unknown_share_state",
                "unknown_incomplete_sharing",
            ],
        )
        self.assertEqual(
            findings[0]["cross_tenant_source_refs"],
            [source["data_sources"][1]["source_ref"]],
        )
        self.assertFalse(findings[0]["workspace_tenant_mismatch"])
        self.assertTrue(findings[1]["workspace_tenant_mismatch"])
        self.assertEqual(findings[3]["cross_tenant_source_refs"], [])
        self.assertFalse(report.to_dict()["flags"]["exposure_proven"])
        self.assertEqual(set(report.to_dict()["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_analytics_sharing(report, model=source).to_json(),
            report.to_json(),
        )
        source["sharing_complete"] = True
        self.assertEqual(
            analyze_supplied_analytics_sharing(source).to_dict()["findings"][5]["disposition"],
            "no_supplied_share",
        )

    def test_invalid_declarations_and_non_native_permission_refused(self) -> None:
        source = model()
        source["dashboards"][0]["source_refs"].append(_ref("source", "0"))
        with self.assertRaises(AnalyticsSharingError):
            analyze_supplied_analytics_sharing(source)
        source = model()
        source["shares"][1]["share_id"] = "share-1"
        with self.assertRaises(AnalyticsSharingError):
            analyze_supplied_analytics_sharing(source)
        source = model()
        source["shares"][0]["permission"] = ["view"]
        with self.assertRaises(AnalyticsSharingError):
            analyze_supplied_analytics_sharing(source)
        source = model()
        source["objectives"][0]["permission"] = ["view"]
        with self.assertRaises(AnalyticsSharingError):
            analyze_supplied_analytics_sharing(source)
        source = model()
        source["principals"][0]["tenant_ref"] = object()
        with self.assertRaises(AnalyticsSharingError):
            analyze_supplied_analytics_sharing(source)

    def test_tamper_and_changed_source_refused(self) -> None:
        source = model()
        report = analyze_supplied_analytics_sharing(source)
        tampered = report.to_dict()
        tampered["flags"]["exposure_proven"] = True
        with self.assertRaises(AnalyticsSharingError):
            AnalyticsSharing(tampered)
        source["shares"][0]["state"] = "declared_denied"
        with self.assertRaises(AnalyticsSharingError):
            verify_supplied_analytics_sharing(report, model=source)

    def test_closed_component_dispatch_and_resource_denial(self) -> None:
        request = components.load_offline_specialist_component_request(
            ROOT / "examples" / "offline-analytics-sharing-component.json"
        )
        catalog = components.load_offline_specialist_component_catalog(repository_root=ROOT)
        result = components.run_offline_specialist_component(
            request, catalog=catalog, repository_root=ROOT
        )
        self.assertEqual(
            result["analysis"]["findings"][0]["disposition"],
            "declared_cross_tenant_share",
        )
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            components.verify_offline_specialist_component_result(
                result, request=request, catalog=catalog, repository_root=ROOT
            ),
            result,
        )
        request["resources"]["network"] = ["forbidden"]
        with self.assertRaises(components.OfflineSpecialistComponentError):
            components.run_offline_specialist_component(
                request, catalog=catalog, repository_root=ROOT
            )


if __name__ == "__main__":
    unittest.main()
