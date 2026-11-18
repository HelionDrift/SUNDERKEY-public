"""Synthetic source-bound tests for declared multi-agent relay trust."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_multi_agent_coordination as coordination


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def readdress(document: dict) -> dict:
    changed = copy.deepcopy(document)
    body = {k: v for k, v in changed.items() if k not in {"report_id", "report_sha256"}}
    digest = hashlib.sha256(encoded({"domain": coordination.DOMAIN, "analysis": body})).hexdigest()
    changed["report_id"] = "MAC-" + digest[:32].upper()
    changed["report_sha256"] = "sha256:" + digest
    return changed


class BytesAlias(bytes):
    pass


class StringAlias(str):
    pass


class DictAlias(dict):
    pass


class ReportAlias(coordination.MultiAgentCoordinationReport):
    pass


class OfflineMultiAgentCoordinationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = coordination.component_fixture()
        self.source_id = "synthetic:coordination"

    def analyze(self, model=None) -> coordination.MultiAgentCoordinationReport:
        return coordination.analyze_multi_agent_coordination(
            source_content=encoded(self.model if model is None else model),
            source_id=self.source_id,
        )

    def test_fixture_candidate_is_only_a_declared_relay(self) -> None:
        content = encoded(self.model)
        report = self.analyze().to_dict()
        self.assertEqual(report["profile_id"], "AOE-GD-D20-S20")
        self.assertEqual(report["component_id"], "multi_agent_supplied_coordination_trust")
        self.assertEqual(
            report["source"]["sha256"], "sha256:" + hashlib.sha256(content).hexdigest()
        )
        rows = {p["message_id"]: p for p in report["projections"]}
        self.assertEqual(rows["m1"]["assessment"], "declared_nonprivileged_relay")
        self.assertEqual(rows["m2"]["assessment"], "candidate_unapproved_privileged_relay")
        self.assertEqual(rows["m2"]["relay_message_ids"], ["m1", "m2"])
        self.assertEqual(rows["m2"]["unapproved_untrusted_agent_ids"], ["rogue"])
        self.assertFalse(report["agent_action_executed"])
        self.assertFalse(report["messages_observed_live"])
        self.assertFalse(report["finding_claimed"])
        self.assertTrue(all(value == "none" for value in report["effects"].values()))

    def test_approval_is_scoped_to_exact_sink_action_and_participant(self) -> None:
        model = copy.deepcopy(self.model)
        model["approvals"].append(
            {
                "receiver_agent_id": "executor",
                "action_id": "publish",
                "participant_agent_id": "rogue",
            }
        )
        self.assertEqual(
            self.analyze(model).to_dict()["projections"][-1]["assessment"],
            "declared_approved_or_trusted",
        )
        model["approvals"][0]["action_id"] = "read"
        self.assertEqual(
            self.analyze(model).to_dict()["projections"][-1]["assessment"],
            "candidate_unapproved_privileged_relay",
        )

    def test_unknown_trust_or_disposition_prevents_candidate(self) -> None:
        for section, index, field, value, basis in (
            ("agents", 0, "trust_state", "unknown", "unknown_agent_trust"),
            ("messages", 0, "disposition", "unknown", "unknown_message_disposition"),
            ("messages", 1, "disposition", "unknown", "unknown_message_disposition"),
        ):
            model = copy.deepcopy(self.model)
            model[section][index][field] = value
            with self.subTest(basis=basis):
                row = self.analyze(model).to_dict()["projections"][-1]
                self.assertEqual((row["assessment"], row["basis"]), ("unknown", basis))

    def test_incomplete_premises_prevent_candidate(self) -> None:
        for field, basis in (
            ("facts_complete", "incomplete_facts"),
            ("approvals_complete", "incomplete_approvals"),
        ):
            model = copy.deepcopy(self.model)
            model[field] = False
            with self.subTest(field=field):
                row = self.analyze(model).to_dict()["projections"][-1]
                self.assertEqual((row["assessment"], row["basis"]), ("unknown", basis))

    def test_rejection_blocks_relay_and_nonprivileged_sink_is_not_candidate(self) -> None:
        model = copy.deepcopy(self.model)
        model["messages"][0]["disposition"] = "rejected"
        row = self.analyze(model).to_dict()["projections"][-1]
        self.assertEqual(
            (row["assessment"], row["basis"]), ("unknown", "inconsistent_relay_dispositions")
        )
        model["messages"][1]["disposition"] = "rejected"
        row = self.analyze(model).to_dict()["projections"][-1]
        self.assertEqual(
            (row["assessment"], row["basis"]), ("declared_blocked", "rejected_message")
        )
        model = copy.deepcopy(self.model)
        model["agents"][2]["privileged_actions"] = []
        row = self.analyze(model).to_dict()["projections"][-1]
        self.assertEqual(row["assessment"], "declared_nonprivileged_relay")

    def test_unknown_receiver_trust_prevents_candidate(self) -> None:
        model = copy.deepcopy(self.model)
        model["agents"][2]["trust_state"] = "unknown"
        row = self.analyze(model).to_dict()["projections"][-1]
        self.assertEqual((row["assessment"], row["basis"]), ("unknown", "unknown_agent_trust"))

    def test_untrusted_privileged_receiver_cannot_be_treated_as_approved_chain(self) -> None:
        model = copy.deepcopy(self.model)
        model["agents"][2]["trust_state"] = "untrusted"
        model["approvals"].append(
            {
                "receiver_agent_id": "executor",
                "action_id": "publish",
                "participant_agent_id": "rogue",
            }
        )
        row = self.analyze(model).to_dict()["projections"][-1]
        self.assertEqual(
            (row["assessment"], row["basis"]), ("unknown", "untrusted_privileged_receiver")
        )

    def test_parent_relation_cycle_and_missing_parent_rejected(self) -> None:
        invalid = []
        missing = copy.deepcopy(self.model)
        missing["messages"][1]["parent_message_id"] = "absent"
        invalid.append(missing)
        wrong_action = copy.deepcopy(self.model)
        wrong_action["messages"][1]["action_id"] = "other"
        invalid.append(wrong_action)
        wrong_sender = copy.deepcopy(self.model)
        wrong_sender["messages"][1]["sender_agent_id"] = "rogue"
        invalid.append(wrong_sender)
        cycle = copy.deepcopy(self.model)
        cycle["messages"][0]["parent_message_id"] = "m2"
        cycle["messages"][0]["sender_agent_id"] = "executor"
        invalid.append(cycle)
        grandparent_missing = copy.deepcopy(self.model)
        grandparent_missing["messages"][0]["parent_message_id"] = "absent"
        invalid.append(grandparent_missing)
        for model in invalid:
            with (
                self.subTest(model=model),
                self.assertRaises(coordination.MultiAgentCoordinationError),
            ):
                self.analyze(model)

    def test_exact_source_replay_rejects_readdressed_forgery(self) -> None:
        report = self.analyze()
        self.assertEqual(
            coordination.verify_multi_agent_coordination(
                report,
                source_content=encoded(self.model),
                source_id=self.source_id,
            ),
            report,
        )
        changed = copy.deepcopy(self.model)
        changed["agents"][0]["trust_state"] = "trusted"
        with self.assertRaises(coordination.MultiAgentCoordinationError):
            coordination.verify_multi_agent_coordination(
                report,
                source_content=encoded(changed),
                source_id=self.source_id,
            )
        forged = report.to_dict()
        forged["projections"][1]["assessment"] = "declared_approved_or_trusted"
        forged["summary"]["candidate_unapproved_privileged_relay"] = 0
        forged["summary"]["declared_approved_or_trusted"] = 1
        parsed = coordination.MultiAgentCoordinationReport.from_json(
            encoded(readdress(forged)).decode("ascii")
        )
        with self.assertRaises(coordination.MultiAgentCoordinationError):
            coordination.verify_multi_agent_coordination(
                parsed,
                source_content=encoded(self.model),
                source_id=self.source_id,
            )

    def test_direct_construction_rejects_effect_claims(self) -> None:
        report = self.analyze()
        self.assertEqual(coordination.MultiAgentCoordinationReport(report.to_json()), report)
        with self.assertRaises(coordination.MultiAgentCoordinationError):
            coordination.MultiAgentCoordinationReport(" " + report.to_json())
        for section, key, value in (
            (None, "finding_claimed", True),
            (None, "agent_action_executed", True),
            ("effects", "agent_messaging", "used"),
        ):
            forged = report.to_dict()
            if section is None:
                forged[key] = value
            else:
                forged[section][key] = value
            changed = encoded(readdress(forged)).decode("ascii")
            with self.assertRaises(coordination.MultiAgentCoordinationError):
                coordination.MultiAgentCoordinationReport.from_json(changed)
            damaged = coordination.MultiAgentCoordinationReport(report.to_json())
            object.__setattr__(damaged, "_json", changed)
            with self.assertRaises(coordination.MultiAgentCoordinationError):
                damaged.to_json()

    def test_closed_model_duplicates_and_native_types(self) -> None:
        invalid = []
        extra = copy.deepcopy(self.model)
        extra["target_url"] = "https://example.invalid"
        invalid.append(extra)
        for section in ("agents", "messages"):
            model = copy.deepcopy(self.model)
            model[section].append(copy.deepcopy(model[section][0]))
            invalid.append(model)
        invalid_approval = copy.deepcopy(self.model)
        invalid_approval["approvals"] = [
            {
                "receiver_agent_id": "missing",
                "action_id": "publish",
                "participant_agent_id": "rogue",
            }
        ]
        invalid.append(invalid_approval)
        for section, field, value in (
            ("agents", "trust_state", "maybe"),
            ("agents", "privileged_actions", ["publish", "publish"]),
            ("messages", "disposition", "executed"),
            ("messages", "receiver_agent_id", "missing"),
        ):
            model = copy.deepcopy(self.model)
            model[section][0][field] = value
            invalid.append(model)
        for field, value in (
            ("facts_complete", 1),
            ("approvals_complete", "true"),
            ("schema_version", "v2"),
        ):
            model = copy.deepcopy(self.model)
            model[field] = value
            invalid.append(model)
        for model in invalid:
            with (
                self.subTest(model=model),
                self.assertRaises(coordination.MultiAgentCoordinationError),
            ):
                self.analyze(model)

    def test_duplicate_keys_bounds_and_no_side_effects(self) -> None:
        bad = [
            b'{"schema_version":"v1","schema_version":"v1"}',
            b'{"agents":[{"agent_id":"a","agent_id":"b"}]}',
            b'{"x":NaN}',
            b'{"x":1.3}',
            b'{"x":9223372036854775808}',
            b"\xff",
            b"[" * (coordination.MAX_DEPTH + 1) + b"0" + b"]" * (coordination.MAX_DEPTH + 1),
            b" " * (coordination.MAX_SOURCE_BYTES + 1),
        ]
        for source in bad:
            with (
                self.subTest(source=source[:32]),
                self.assertRaises(coordination.MultiAgentCoordinationError),
            ):
                coordination.analyze_multi_agent_coordination(
                    source_content=source, source_id=self.source_id
                )
        for source, identity in (
            (BytesAlias(encoded(self.model)), self.source_id),
            (encoded(self.model), StringAlias(self.source_id)),
            (encoded(self.model), "https://not-a-source"),
        ):
            with self.assertRaises(coordination.MultiAgentCoordinationError):
                coordination.analyze_multi_agent_coordination(
                    source_content=source, source_id=identity
                )
        report = self.analyze()
        with patch("socket.create_connection", side_effect=AssertionError("network attempt")):
            with patch("subprocess.run", side_effect=AssertionError("process attempt")):
                self.assertEqual(
                    coordination.verify_multi_agent_coordination(
                        report,
                        source_content=encoded(self.model),
                        source_id=self.source_id,
                    ),
                    report,
                )

    def test_adapter_determinism_and_detachment(self) -> None:
        native = {"source_id": self.source_id, "source": copy.deepcopy(self.model)}
        report = coordination.analyze_supplied_multi_agent_coordination(native)
        self.assertEqual(report, self.analyze())
        native["source"]["agents"][0]["trust_state"] = "trusted"
        self.assertNotEqual(report, coordination.analyze_supplied_multi_agent_coordination(native))
        for invalid in (
            {"source": self.model},
            {"source_id": self.source_id, "source": self.model, "extra": False},
            {"source_id": StringAlias(self.source_id), "source": self.model},
            {"source_id": self.source_id, "source": []},
            DictAlias({"source_id": self.source_id, "source": self.model}),
        ):
            with (
                self.subTest(invalid=invalid),
                self.assertRaises(coordination.MultiAgentCoordinationError),
            ):
                coordination.analyze_supplied_multi_agent_coordination(invalid)
        self.assertEqual(report.to_json(), self.analyze().to_json())
        self.assertEqual(
            coordination.MultiAgentCoordinationReport.from_json("\n" + report.to_json() + "\n"),
            report,
        )
        fixture = coordination.component_fixture()
        fixture["agents"][0]["trust_state"] = "trusted"
        self.assertEqual(coordination.component_fixture()["agents"][0]["trust_state"], "untrusted")
        with self.assertRaises(coordination.MultiAgentCoordinationError):
            coordination.verify_multi_agent_coordination(
                ReportAlias(report.to_json()),
                source_content=encoded(self.model),
                source_id=self.source_id,
            )


if __name__ == "__main__":
    unittest.main()
