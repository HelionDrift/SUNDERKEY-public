"""Synthetic vector tenant-boundary projection and replay tests."""

from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_vector_tenant_boundary as vector


def _row(model: dict, record_id: str = "cross-tenant") -> dict:
    body = vector.analyze_supplied_vector_tenant_boundary(model).to_dict()
    return next(row for row in body["record_observations"] if row["record_id"] == record_id)


class VectorTenantBoundaryTests(unittest.TestCase):
    def _deny_before_address(self, model: dict) -> None:
        with patch.object(vector, "_address") as address:
            with self.assertRaises(vector.VectorTenantBoundaryAnalysisError):
                vector.analyze_supplied_vector_tenant_boundary(model)
            address.assert_not_called()

    def test_fixture_determinism_effects_and_original_replay(self) -> None:
        model = vector.component_fixture()
        report = vector.analyze_supplied_vector_tenant_boundary(model)
        body = report.to_dict()
        self.assertEqual(body["profile_id"], vector.PROFILE_ID)
        self.assertEqual(body["wave_id"], "IW2-004")
        self.assertEqual((body["query_count"], body["record_count"]), (1, 3))
        self.assertEqual((body["candidate_count"], body["unknown_count"]), (1, 1))
        self.assertEqual(
            [row["outcome"] for row in body["record_observations"]],
            [
                "candidate_declared_tenant_boundary_contradiction",
                "matches_declared_tenant_boundary",
                "unknown",
            ],
        )
        self.assertEqual(_row(model)["violated_declarations"], ["record_tenant_mismatch"])
        self.assertEqual(set(body["effects"].values()), {"none"})
        self.assertTrue(all(value is False for value in body["flags"].values()))
        self.assertEqual(
            report.to_json(), vector.analyze_supplied_vector_tenant_boundary(model).to_json()
        )
        detached = vector.VectorTenantBoundaryAnalysis.from_json(report.to_json())
        self.assertEqual(
            vector.verify_supplied_vector_tenant_boundary_analysis(detached, model=model).to_json(),
            report.to_json(),
        )
        model["queries"][0]["returned_records"][0]["tenant_id"] = "tenant-a"
        with self.assertRaises(vector.VectorTenantBoundaryAnalysisError):
            vector.verify_supplied_vector_tenant_boundary_analysis(report, model=model)

    def test_exact_namespace_mismatch_and_not_required(self) -> None:
        model = vector.component_fixture()
        model["queries"][0]["returned_records"][0]["tenant_id"] = "tenant-a"
        model["queries"][0]["returned_records"][0]["namespace_id"] = "tenant-b-index"
        self.assertEqual(_row(model)["violated_declarations"], ["record_namespace_mismatch"])
        model["namespaces"][0]["tenant_isolation_required"] = False
        self.assertEqual(_row(model)["outcome"], "isolation_not_required")
        self.assertEqual(
            vector.analyze_supplied_vector_tenant_boundary(model).to_dict()["candidate_count"], 0
        )

    def test_unknown_context_filter_and_result_never_promote(self) -> None:
        changes = (
            (
                lambda x: x.update(namespace_inventory_complete=False),
                "namespace_inventory_incomplete",
            ),
            (
                lambda x: x["namespaces"][0].update(mapping_complete=False),
                "namespace_mapping_incomplete",
            ),
            (
                lambda x: x["namespaces"][0].update(policy_complete=False),
                "namespace_policy_incomplete",
            ),
            (
                lambda x: x["queries"][0].update(filter_mode="dynamic_or_alias"),
                "filter_not_exact_or_incomplete",
            ),
            (
                lambda x: x["queries"][0].update(filter_mode="none"),
                "filter_not_exact_or_incomplete",
            ),
            (
                lambda x: x["queries"][0].update(filter_complete=False),
                "filter_not_exact_or_incomplete",
            ),
            (lambda x: x["queries"][0].update(context_complete=False), "query_context_incomplete"),
            (lambda x: x["queries"][0].update(result_complete=False), "result_snapshot_incomplete"),
            (
                lambda x: x["queries"][0].update(sharing_delegation_policy_complete=False),
                "sharing_delegation_policy_incomplete",
            ),
            (
                lambda x: x["queries"][0].update(sharing_delegation_exception="applies"),
                "sharing_delegation_exception_not_ruled_out",
            ),
            (
                lambda x: x["queries"][0].update(sharing_delegation_exception="unknown"),
                "sharing_delegation_exception_not_ruled_out",
            ),
            (
                lambda x: x["queries"][0].update(requester_tenant_id=None),
                "requester_tenant_unknown",
            ),
            (lambda x: x["queries"][0].update(filter_tenant_id=None), "filter_tenant_unknown"),
            (
                lambda x: x["queries"][0].update(filter_tenant_id="tenant-b"),
                "filter_requester_tenant_mismatch",
            ),
            (
                lambda x: x["queries"][0].update(requester_tenant_id="tenant-b"),
                "requester_namespace_owner_mismatch",
            ),
            (
                lambda x: x["queries"][0]["returned_records"][0].update(metadata_complete=False),
                "record_metadata_incomplete",
            ),
            (
                lambda x: x["queries"][0]["returned_records"][0].update(namespace_id=None),
                "record_namespace_unknown",
            ),
            (
                lambda x: x["queries"][0]["returned_records"][0].update(tenant_id=None),
                "record_tenant_unknown",
            ),
        )
        for change, reason in changes:
            with self.subTest(reason=reason):
                model = vector.component_fixture()
                change(model)
                row = _row(model)
                self.assertEqual(row["outcome"], "unknown")
                self.assertIn(reason, row["uncertainty"])

    def test_closed_schema_types_references_and_sorting(self) -> None:
        changes = (
            lambda x: x.update(extra=True),
            lambda x: x.update(schema_version=True),
            lambda x: x.update(namespace_inventory_complete=1),
            lambda x: x["namespaces"][0].update(owner_tenant_id="unknown"),
            lambda x: x["namespaces"][0].update(mapping_complete=1),
            lambda x: x["queries"][0].update(namespace_id="missing"),
            lambda x: x["queries"][0].update(filter_mode="wildcard"),
            lambda x: x["queries"][0].update(result_complete=1),
            lambda x: x["queries"][0].update(sharing_delegation_policy_complete=1),
            lambda x: x["queries"][0].update(sharing_delegation_exception="maybe"),
            lambda x: x["queries"][0]["returned_records"][0].update(namespace_id="missing"),
            lambda x: x["queries"][0]["returned_records"][0].update(metadata_complete=1),
            lambda x: x["queries"][0]["returned_records"].reverse(),
            lambda x: x["namespaces"].reverse(),
        )
        for change in changes:
            with self.subTest(change=change):
                model = vector.component_fixture()
                change(model)
                self._deny_before_address(model)

    def test_bytes_and_forgery_rejected(self) -> None:
        model = vector.component_fixture()
        raw = json.dumps(model, sort_keys=True, separators=(",", ":")).encode("ascii")
        report = vector.analyze_supplied_vector_tenant_boundary(model)
        self.assertEqual(
            vector.analyze_supplied_vector_tenant_boundary_bytes(model_bytes=raw).to_json(),
            report.to_json(),
        )
        for invalid in (
            b'{"schema_version":1,"schema_version":1}',
            raw.replace(b'"schema_version":1', b'"schema_version":1.0'),
            raw + b"x",
            b"\xff",
        ):
            with self.subTest(invalid=invalid[:30]):
                with self.assertRaises(vector.VectorTenantBoundaryAnalysisError):
                    vector.analyze_supplied_vector_tenant_boundary_bytes(model_bytes=invalid)
        forged = copy.deepcopy(report.to_dict())
        forged["candidate_count"] = 0
        with self.assertRaises(vector.VectorTenantBoundaryAnalysisError):
            vector.VectorTenantBoundaryAnalysis.from_dict(forged)
        with self.assertRaises(vector.VectorTenantBoundaryAnalysisError):
            vector.verify_supplied_vector_tenant_boundary_analysis(report.to_dict(), model=model)

    def test_cycles_and_bounds(self) -> None:
        model = vector.component_fixture()
        model["cycle"] = model
        self._deny_before_address(model)
        model = vector.component_fixture()
        model["queries"] *= vector.MAX_QUERIES + 1
        self._deny_before_address(model)
        model = vector.component_fixture()
        model["queries"][0]["query_id"] = "x" * (vector.MAX_STRING_BYTES + 1)
        self._deny_before_address(model)


if __name__ == "__main__":
    unittest.main()
