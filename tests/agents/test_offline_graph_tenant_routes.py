"""Graph tenant routes are supplied hypotheses, not database access proof."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

from sunderkey import offline_specialist_components as components

from sunderkey.offline_graph_tenant_routes import (
    GraphTenantRouteError,
    GraphTenantRoutes,
    analyze_supplied_graph_tenant_routes,
    verify_supplied_graph_tenant_routes,
)

ROOT = Path(__file__).resolve().parents[2]


def _ref(kind: str, letter: str) -> str:
    return f"{kind}:sha256:" + letter * 64


def model() -> dict:
    tenant_a = _ref("tenant", "a")
    tenant_b = _ref("tenant", "b")
    nodes = [_ref("node", letter) for letter in "cdef12"]
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-graph-tenant-routes-v1",
        "tenant_ref": tenant_a,
        "start_node_ref": nodes[0],
        "graph_complete": False,
        "nodes": [
            {"node_ref": nodes[0], "tenant_ref": tenant_a},
            {"node_ref": nodes[1], "tenant_ref": tenant_a},
            {"node_ref": nodes[2], "tenant_ref": tenant_b},
            {"node_ref": nodes[3], "tenant_ref": "shared"},
            {"node_ref": nodes[4], "tenant_ref": tenant_b},
            {"node_ref": nodes[5], "tenant_ref": tenant_b},
        ],
        "edges": [
            {
                "edge_id": "e1",
                "from_node_ref": nodes[0],
                "to_node_ref": nodes[1],
                "traversal": "declared_open",
            },
            {
                "edge_id": "e2",
                "from_node_ref": nodes[1],
                "to_node_ref": nodes[2],
                "traversal": "declared_open",
            },
            {
                "edge_id": "e3",
                "from_node_ref": nodes[0],
                "to_node_ref": nodes[3],
                "traversal": "unknown",
            },
            {
                "edge_id": "e4",
                "from_node_ref": nodes[3],
                "to_node_ref": nodes[4],
                "traversal": "declared_open",
            },
            {
                "edge_id": "e5",
                "from_node_ref": nodes[0],
                "to_node_ref": nodes[5],
                "traversal": "declared_blocked",
            },
        ],
        "objectives": [{"target_node_ref": node} for node in nodes[1:]],
    }


class GraphTenantRouteTests(unittest.TestCase):
    def test_declared_unknown_and_absent_routes(self) -> None:
        source = model()
        original = copy.deepcopy(source)
        report = analyze_supplied_graph_tenant_routes(source)
        self.assertEqual(source, original)
        findings = report.to_dict()["findings"]
        self.assertEqual(
            [row["disposition"] for row in findings],
            [
                "declared_same_tenant_route",
                "declared_cross_tenant_route",
                "unknown_traversal",
                "unknown_traversal",
                "unknown_incomplete_graph",
            ],
        )
        self.assertEqual(findings[1]["edge_ids"], ["e1", "e2"])
        self.assertEqual(findings[3]["unknown_edge_ids"], ["e3"])
        self.assertEqual(findings[4]["edge_ids"], [])
        self.assertFalse(report.to_dict()["flags"]["cross_tenant_exposure_proven"])
        self.assertEqual(set(report.to_dict()["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_graph_tenant_routes(report, model=source).to_json(),
            report.to_json(),
        )
        source["graph_complete"] = True
        self.assertEqual(
            analyze_supplied_graph_tenant_routes(source).to_dict()["findings"][4][
                "disposition"
            ],
            "no_supplied_route",
        )

    def test_invalid_references_duplicate_edges_and_non_native_values(self) -> None:
        source = model()
        source["edges"][0]["to_node_ref"] = _ref("node", "0")
        with self.assertRaises(GraphTenantRouteError):
            analyze_supplied_graph_tenant_routes(source)
        source = model()
        source["edges"][1]["edge_id"] = "e1"
        with self.assertRaises(GraphTenantRouteError):
            analyze_supplied_graph_tenant_routes(source)
        source = model()
        source["edges"][0]["traversal"] = "allow"
        with self.assertRaises(GraphTenantRouteError):
            analyze_supplied_graph_tenant_routes(source)
        source = model()
        source["nodes"][0]["tenant_ref"] = object()
        with self.assertRaises(GraphTenantRouteError):
            analyze_supplied_graph_tenant_routes(source)
        source = model()
        source["nodes"].append(source["nodes"][0])
        with self.assertRaises(GraphTenantRouteError):
            analyze_supplied_graph_tenant_routes(source)

    def test_replay_refuses_tampering_and_changed_input(self) -> None:
        source = model()
        report = analyze_supplied_graph_tenant_routes(source)
        tampered = report.to_dict()
        tampered["findings"][1]["disposition"] = "verified_exposure"
        with self.assertRaises(GraphTenantRouteError):
            GraphTenantRoutes(tampered)
        source["edges"][1]["traversal"] = "declared_blocked"
        with self.assertRaises(GraphTenantRouteError):
            verify_supplied_graph_tenant_routes(report, model=source)

    def test_closed_component_dispatch_and_resource_denial(self) -> None:
        request = components.load_offline_specialist_component_request(
            ROOT / "examples" / "offline-graph-tenant-routes-component.json"
        )
        catalog = components.load_offline_specialist_component_catalog(repository_root=ROOT)
        result = components.run_offline_specialist_component(
            request, catalog=catalog, repository_root=ROOT
        )
        self.assertEqual(
            result["analysis"]["findings"][0]["disposition"],
            "declared_cross_tenant_route",
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
