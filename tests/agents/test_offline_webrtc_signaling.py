"""Synthetic supplied WebRTC signaling declaration and replay tests."""

from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_webrtc_signaling as signaling

ERROR = signaling.WebRTCSignalingAnalysisError


def fixture() -> dict:
    return signaling.component_fixture()


def analyze(model: dict) -> dict:
    return signaling.analyze_supplied_webrtc_signaling(model).to_dict()


def observation(model: dict, event_id: str = "candidate-membership") -> dict:
    return next(row for row in analyze(model)["event_observations"] if row["event_id"] == event_id)


class WebRTCSignalingTests(unittest.TestCase):
    def deny_before_hash(self, model: dict) -> None:
        with patch.object(signaling, "_address") as address:
            with self.assertRaises(ERROR):
                signaling.analyze_supplied_webrtc_signaling(model)
            address.assert_not_called()

    def test_fixture_is_source_bound_nonqualifying_and_deterministic(self):
        source = fixture()
        report = signaling.analyze_supplied_webrtc_signaling(source)
        document = report.to_dict()
        self.assertEqual(document["profile_id"], "AOE-GB-D05-S18")
        self.assertEqual(document["blueprint_sha256"], signaling.BLUEPRINT_SHA256)
        self.assertEqual(document["event_count"], 5)
        self.assertEqual(document["candidate_count"], 2)
        self.assertEqual(document["unknown_count"], 1)
        self.assertEqual(
            [row["outcome"] for row in document["event_observations"]],
            [
                "candidate_forwarded_outside_declared_membership",
                "candidate_forwarded_payload_owner_mismatch",
                "declared_forwarding_denied",
                "consistent_with_declared_signaling_policy",
                "unknown",
            ],
        )
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertTrue(all(value is False for value in document["flags"].values()))
        self.assertEqual(
            report.to_json(), signaling.analyze_supplied_webrtc_signaling(source).to_json()
        )
        detached = signaling.WebRTCSignalingAnalysis.from_json(report.to_json())
        self.assertEqual(
            signaling.verify_supplied_webrtc_signaling_analysis(detached, model=source).to_json(),
            report.to_json(),
        )
        source["events"][0]["forwarding_decision"] = "deny"
        self.assertEqual(document["candidate_count"], 2)
        with self.assertRaises(ERROR):
            signaling.verify_supplied_webrtc_signaling_analysis(report, model=source)

    def test_denial_and_member_premises_prevent_candidate(self):
        source = fixture()
        source["events"][0]["forwarding_decision"] = "deny"
        self.assertEqual(observation(source)["outcome"], "declared_forwarding_denied")
        source["events"][0]["forwarding_decision"] = "allow"
        source["rooms"][0]["member_peer_ids"] = ["alice", "bob", "mallory"]
        self.assertEqual(
            observation(source)["outcome"], "consistent_with_declared_signaling_policy"
        )
        source["events"][1]["payload_owner_peer_id"] = "alice"
        self.assertEqual(
            observation(source, "candidate-owner")["outcome"],
            "consistent_with_declared_signaling_policy",
        )

    def test_corresponding_policy_must_explicitly_require_each_constraint(self):
        source = fixture()
        source["rooms"][0]["member_only_forwarding_required"] = False
        self.assertEqual(
            observation(source)["outcome"], "consistent_with_declared_signaling_policy"
        )
        self.assertEqual(
            observation(source, "candidate-owner")["outcome"],
            "candidate_forwarded_payload_owner_mismatch",
        )
        source = fixture()
        source["rooms"][0]["sender_owner_match_required"] = False
        self.assertEqual(
            observation(source, "candidate-owner")["outcome"],
            "consistent_with_declared_signaling_policy",
        )
        self.assertEqual(
            observation(source)["outcome"],
            "candidate_forwarded_outside_declared_membership",
        )
        source["rooms"][0]["forwarding_policy_complete"] = False
        self.assertEqual(observation(source)["outcome"], "unknown")
        self.assertEqual(observation(source, "candidate-owner")["outcome"], "unknown")

    def test_offer_answer_and_ice_labels_do_not_change_policy_projection(self):
        source = fixture()
        for kind in ("offer", "answer", "ice_candidate"):
            with self.subTest(kind=kind):
                source["events"][0]["artifact_kind"] = kind
                self.assertEqual(
                    observation(source)["outcome"],
                    "candidate_forwarded_outside_declared_membership",
                )

    def test_unknowns_and_relay_context_never_promote_to_candidate(self):
        cases = (
            (lambda x: x.update(rooms_complete=False), "rooms_incomplete"),
            (lambda x: x["rooms"][0].update(membership_complete=False), "membership_incomplete"),
            (
                lambda x: x["rooms"][0].update(forwarding_policy_complete=False),
                "forwarding_policy_incomplete",
            ),
            (
                lambda x: x["events"][0].update(direct_submission=False),
                "relay_or_server_submission",
            ),
            (
                lambda x: x["events"][0].update(identity_binding_complete=False),
                "identity_binding_incomplete",
            ),
            (lambda x: x["events"][0].update(context_complete=False), "event_context_incomplete"),
            (
                lambda x: x["events"][0].update(forwarding_decision="unknown"),
                "forwarding_decision_unknown",
            ),
            (lambda x: x["events"][0].update(sender_peer_id="unknown"), "sender_peer_id_unknown"),
            (
                lambda x: x["events"][0].update(recipient_peer_id="unknown"),
                "recipient_peer_id_unknown",
            ),
            (
                lambda x: x["events"][0].update(payload_owner_peer_id="unknown"),
                "payload_owner_peer_id_unknown",
            ),
        )
        for change, reason in cases:
            source = fixture()
            change(source)
            with self.subTest(reason=reason):
                row = observation(source)
                self.assertEqual(row["outcome"], "unknown")
                self.assertIn(reason, row["uncertainty"])

    def test_closed_model_exact_types_references_order_and_no_widening(self):
        changes = (
            lambda x: x.update(extra=True),
            lambda x: x.update(schema_version=True),
            lambda x: x.update(rooms_complete=1),
            lambda x: x["rooms"][0].update(member_peer_ids=["bob", "alice"]),
            lambda x: x["rooms"][0].update(member_peer_ids=["alice", "alice"]),
            lambda x: x["rooms"][0].update(membership_complete=1),
            lambda x: x["rooms"][0].update(member_only_forwarding_required=1),
            lambda x: x["rooms"][0].update(sender_owner_match_required=1),
            lambda x: x["rooms"][0].pop("member_only_forwarding_required"),
            lambda x: x["rooms"][0].update(room_id="unknown"),
            lambda x: x["events"][0].update(room_id="missing"),
            lambda x: x["events"][0].update(event_id="bad id"),
            lambda x: x["events"][0].update(artifact_kind="sdp"),
            lambda x: x["events"][0].update(forwarding_decision="forward"),
            lambda x: x["events"][0].update(direct_submission=1),
            lambda x: x["events"][0].update(identity_binding_complete=1),
            lambda x: x["events"][0].update(extra=True),
            lambda x: x["events"].reverse(),
        )
        for change in changes:
            source = fixture()
            change(source)
            with self.subTest(source=source):
                self.deny_before_hash(source)

    def test_bytes_duplicate_keys_numeric_fractions_and_report_forgery_rejected(self):
        source = fixture()
        raw = json.dumps(source, sort_keys=True, separators=(",", ":")).encode("ascii")
        direct = signaling.analyze_supplied_webrtc_signaling(source)
        self.assertEqual(
            signaling.analyze_supplied_webrtc_signaling_bytes(model_bytes=raw).to_json(),
            direct.to_json(),
        )
        bad = (
            b'{"schema_version":1,"schema_version":1}',
            raw.replace(b'"schema_version":1', b'"schema_version":1.0'),
            raw + b"x",
            b"\xff",
        )
        for data in bad:
            with self.subTest(data=data[:40]):
                with self.assertRaises(ERROR):
                    signaling.analyze_supplied_webrtc_signaling_bytes(model_bytes=data)
        forged = copy.deepcopy(direct.to_dict())
        forged["candidate_count"] = 3
        with self.assertRaises(ERROR):
            signaling.WebRTCSignalingAnalysis.from_dict(forged)
        forged = copy.deepcopy(direct.to_dict())
        forged["source_model"]["events"][0]["forwarding_decision"] = "deny"
        with self.assertRaises(ERROR):
            signaling.WebRTCSignalingAnalysis.from_dict(forged)
        with self.assertRaises(ERROR):
            signaling.verify_supplied_webrtc_signaling_analysis(direct.to_dict(), model=source)

    def test_native_cycle_and_bounded_inputs(self):
        source = fixture()
        source["cycle"] = source
        self.deny_before_hash(source)
        source = fixture()
        source["events"] = source["events"] * (signaling.MAX_EVENTS + 1)
        self.deny_before_hash(source)
        source = fixture()
        source["events"][0]["event_id"] = "x" * (signaling.MAX_STRING_BYTES + 1)
        self.deny_before_hash(source)


if __name__ == "__main__":
    unittest.main()
