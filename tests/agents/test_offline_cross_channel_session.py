"""Cross-channel session projections remain declared and non-operational."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey import offline_specialist_components as components
from sunderkey.offline_cross_channel_session import (
    CrossChannelSession,
    CrossChannelSessionError,
    analyze_supplied_cross_channel_session,
    verify_supplied_cross_channel_session,
)

ROOT = Path(__file__).resolve().parents[2]


def model() -> dict:
    return json.loads(
        (ROOT / "examples/offline-cross-channel-session-component.json").read_text(
            encoding="utf-8"
        )
    )["payload"]["model"]


class CrossChannelSessionTests(unittest.TestCase):
    def test_fixed_catalog_dispatch(self) -> None:
        request = json.loads(
            (ROOT / "examples/offline-cross-channel-session-component.json").read_text(
                encoding="utf-8"
            )
        )
        catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)
        result = components.run_offline_specialist_component(
            request, catalog=catalog, repository_root=ROOT
        )
        self.assertEqual(result["component"]["profile_id"], "AOE-GE-D23-S08")
        self.assertEqual(
            result["component"]["component_id"], "supplied_cross_channel_session"
        )
        self.assertEqual(
            result["analysis"]["projections"][0]["disposition"],
            "candidate_declared_cross_channel_conflict",
        )
        self.assertFalse(result["analysis"]["flags"]["cross_channel_bypass_verified"])

    def test_source_replay_and_negative_predicate(self) -> None:
        source = model()
        original = copy.deepcopy(source)
        report = analyze_supplied_cross_channel_session(source)
        body = report.to_dict()
        self.assertEqual(source, original)
        self.assertEqual(body["source_model"], original)
        self.assertEqual(body["observation_count"], 1)
        self.assertEqual(
            body["projections"][0]["negative_predicate"],
            "cross_channel_revocation_effective",
        )
        self.assertFalse(any(body["flags"].values()))
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_cross_channel_session(report, model=source).to_json(),
            report.to_json(),
        )

    def test_missing_premises_do_not_create_conflict(self) -> None:
        source = model()
        source["events_complete"] = False
        row = analyze_supplied_cross_channel_session(source).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "unresolved_declaration_or_capture")
        source["events_complete"] = True
        source["events"][2]["capture_complete"] = False
        row = analyze_supplied_cross_channel_session(source).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "unresolved_declaration_or_capture")
        source["events"][2]["capture_complete"] = True
        source["events"][2]["revocation_effective_before_observation"] = None
        row = analyze_supplied_cross_channel_session(source).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "unresolved_revocation_effect")
        source["events"][2]["revocation_effective_before_observation"] = True
        source["events"][2]["declared_outcome"] = "unknown"
        row = analyze_supplied_cross_channel_session(source).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "unresolved_session_or_outcome")
        source["events"][2]["declared_outcome"] = "rejected"
        row = analyze_supplied_cross_channel_session(source).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "declared_reject_consistent")
        source["events"][2]["channel_ref"] = "ref:web"
        row = analyze_supplied_cross_channel_session(source).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "no_declared_cross_channel_negative_invariant")

    def test_invalid_timeline_and_resource_bearing_sources_are_refused(self) -> None:
        cases = []
        source = model()
        source["events"][0]["session_ref"] = "actual-session-value"
        cases.append(source)
        source = model()
        source["events"][1]["session_ref"] = "ref:missing"
        cases.append(source)
        source = model()
        source["events"].append(copy.deepcopy(source["events"][1]))
        source["events"][3]["event_id"] = "e4"
        cases.append(source)
        source = model()
        source["events"][2]["declared_outcome"] = "actual-token"
        cases.append(source)
        source = model()
        source["network_permission"] = True
        cases.append(source)
        source = model()
        source["cycle"] = source
        cases.append(source)
        source = model()
        source["events"] = source["events"] * 43
        cases.append(source)
        for item in cases:
            with self.assertRaises(CrossChannelSessionError):
                analyze_supplied_cross_channel_session(item)

    def test_tampered_report_and_alternate_source_are_refused(self) -> None:
        source = model()
        report = analyze_supplied_cross_channel_session(source)
        changed = report.to_dict()
        changed["flags"]["token_replay_performed"] = True
        with self.assertRaises(CrossChannelSessionError):
            CrossChannelSession(changed)
        alternate = model()
        alternate["events"][2]["declared_outcome"] = "rejected"
        with self.assertRaises(CrossChannelSessionError):
            verify_supplied_cross_channel_session(report, model=alternate)
        with self.assertRaises(CrossChannelSessionError):
            verify_supplied_cross_channel_session(report.to_dict(), model=source)


if __name__ == "__main__":
    unittest.main()
