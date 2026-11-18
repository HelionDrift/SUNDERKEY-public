"""Supplied OT zone and conduit projection tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_ot_zone_conduit_projection import (
    OtZoneConduitProjectionError,
    analyze_supplied_ot_zone_conduits,
    component_fixture,
    verify_supplied_ot_zone_conduits,
    verify_supplied_ot_zone_conduits_bytes,
)


class OtZoneConduitProjectionTests(unittest.TestCase):
    def test_missing_conduit_is_inert_and_replayable(self) -> None:
        model = component_fixture()
        report = analyze_supplied_ot_zone_conduits(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["mismatches"][0]["issue"], "missing_declared_path")
        self.assertFalse(body["ot_network_contacted"])
        self.assertFalse(body["actual_reachability_proven"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_ot_zone_conduits(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_ot_zone_conduits_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_directed_service_conduit_and_incomplete_topology(self) -> None:
        model = component_fixture()
        model["conduits"] = [{
            "conduit_id": "approved-telemetry",
            "from_zone": "enterprise",
            "to_zone": "control",
            "services": ["telemetry"],
        }]
        body = analyze_supplied_ot_zone_conduits(model).to_dict()
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(
            body["rows"][0]["matching_conduit_ids"], ["approved-telemetry"]
        )
        model["conduits"][0]["services"] = ["management"]
        self.assertEqual(analyze_supplied_ot_zone_conduits(model).to_dict()["candidate_count"], 1)
        model["topology_complete"] = False
        self.assertEqual(
            analyze_supplied_ot_zone_conduits(model).to_dict()["disposition"], "unknown"
        )

    def test_rejects_unknown_asset_and_changed_replay(self) -> None:
        model = component_fixture()
        report = analyze_supplied_ot_zone_conduits(model)
        changed = copy.deepcopy(model)
        changed["flows"][0]["service_id"] = "management"
        with self.assertRaises(OtZoneConduitProjectionError):
            verify_supplied_ot_zone_conduits(report, model=changed)
        with self.assertRaises(OtZoneConduitProjectionError):
            verify_supplied_ot_zone_conduits(report.to_dict(), model=model)
        with self.assertRaises(OtZoneConduitProjectionError):
            verify_supplied_ot_zone_conduits_bytes(b"{}", model=model)
        model["flows"][0]["source_asset"] = "missing-asset"
        with self.assertRaises(OtZoneConduitProjectionError):
            analyze_supplied_ot_zone_conduits(model)


if __name__ == "__main__":
    unittest.main()
