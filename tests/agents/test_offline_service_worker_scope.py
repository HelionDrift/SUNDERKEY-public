"""Synthetic source-bound tests for supplied service-worker scope projections."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_service_worker_scope as worker


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def readdress(document: dict) -> dict:
    changed = copy.deepcopy(document)
    body = {
        key: value for key, value in changed.items() if key not in {"report_id", "report_sha256"}
    }
    digest = hashlib.sha256(encoded({"domain": worker.DOMAIN, "analysis": body})).hexdigest()
    changed["report_id"] = "SWS-" + digest[:32].upper()
    changed["report_sha256"] = "sha256:" + digest
    return changed


class BytesAlias(bytes):
    pass


class StringAlias(str):
    pass


class DictAlias(dict):
    pass


class ReportAlias(worker.ServiceWorkerScopeReport):
    pass


class OfflineServiceWorkerScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = worker.component_fixture()
        self.source_id = "synthetic:worker-scope"

    def analyze(self, model=None) -> worker.ServiceWorkerScopeReport:
        return worker.analyze_service_worker_scope(
            source_content=encoded(self.model if model is None else model),
            source_id=self.source_id,
        )

    def test_fixture_projection_no_effects_and_source_digest(self) -> None:
        content = encoded(self.model)
        report = self.analyze().to_dict()
        self.assertEqual(report["profile_id"], "AOE-GB-D05-S16")
        self.assertEqual(report["capability_id"], "army.gb.d05.s16")
        self.assertEqual(
            report["source"]["sha256"], "sha256:" + hashlib.sha256(content).hexdigest()
        )
        projections = {p["observation_id"]: p for p in report["projections"]}
        self.assertEqual(projections["obs-admin"]["expected_controller_id"], "app-admin")
        self.assertEqual(projections["obs-admin"]["assessment"], "declared_consistent")
        self.assertEqual(projections["obs-mismatch"]["expected_controller_id"], "app-root")
        self.assertEqual(
            projections["obs-mismatch"]["assessment"], "candidate_control_contradiction"
        )
        self.assertEqual(projections["obs-outside"]["expected_control"], "uncontrolled")
        self.assertEqual(report["summary"]["observation_count"], 3)
        self.assertFalse(report["browser_semantics_verified"])
        self.assertFalse(report["service_worker_executed"])
        self.assertFalse(report["finding_claimed"])
        self.assertTrue(all(value == "none" for value in report["effects"].values()))

    def test_origin_binding_and_path_prefix_are_exact_declared_labels(self) -> None:
        model = copy.deepcopy(self.model)
        model["observations"] = [model["observations"][0]]
        model["observations"][0]["page_origin_id"] = "different-origin"
        p = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual(
            (p["expected_control"], p["basis"]), ("uncontrolled", "no_matching_active_scope")
        )
        model["observations"][0]["page_origin_id"] = "app-origin"
        model["observations"][0]["page_path"] = "/application"
        p = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual(p["expected_control"], "uncontrolled")
        model["observations"][0]["page_path"] = "/app/admin/settings"
        p = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual(p["expected_controller_id"], "app-admin")
        self.assertEqual(p["matching_registration_ids"], ["app-admin", "app-root"])

    def test_unknown_state_competition_is_conservative(self) -> None:
        model = copy.deepcopy(self.model)
        model["registrations"][1]["state"] = "unknown"
        p = {p["observation_id"]: p for p in self.analyze(model).to_dict()["projections"]}
        self.assertEqual(
            (p["obs-admin"]["expected_control"], p["obs-admin"]["basis"]),
            ("unknown", "unknown_registration_state"),
        )
        self.assertEqual(p["obs-admin"]["assessment"], "unknown")
        self.assertEqual(p["obs-mismatch"]["expected_controller_id"], "app-root")
        model = copy.deepcopy(self.model)
        model["registrations"][0]["state"] = "unknown"
        p = {p["observation_id"]: p for p in self.analyze(model).to_dict()["projections"]}
        self.assertEqual(p["obs-admin"]["expected_controller_id"], "app-admin")
        self.assertEqual(p["obs-mismatch"]["expected_control"], "unknown")

    def test_inactive_registration_is_not_expected_controller(self) -> None:
        model = copy.deepcopy(self.model)
        model["registrations"][1]["state"] = "inactive"
        p = {p["observation_id"]: p for p in self.analyze(model).to_dict()["projections"]}
        self.assertEqual(p["obs-admin"]["expected_controller_id"], "app-root")
        self.assertEqual(p["obs-admin"]["assessment"], "candidate_control_contradiction")
        model["registrations"][0]["state"] = "inactive"
        p = {p["observation_id"]: p for p in self.analyze(model).to_dict()["projections"]}
        self.assertEqual(p["obs-admin"]["expected_control"], "uncontrolled")

    def test_incomplete_premises_and_unknown_observation(self) -> None:
        for flag in ("facts_complete", "registration_set_complete"):
            model = copy.deepcopy(self.model)
            model[flag] = False
            with self.subTest(flag=flag):
                projections = self.analyze(model).to_dict()["projections"]
                self.assertTrue(all(p["expected_control"] == "unknown" for p in projections))
                self.assertTrue(all(p["assessment"] == "unknown" for p in projections))
        model = copy.deepcopy(self.model)
        model["observations"] = [model["observations"][0]]
        model["observations"][0]["control_outcome"] = "unknown"
        model["observations"][0]["observed_controller_id"] = None
        p = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual((p["expected_control"], p["assessment"]), ("controlled", "unknown"))

    def test_controlled_wrong_controller_is_not_consistent(self) -> None:
        model = copy.deepcopy(self.model)
        model["observations"] = [model["observations"][0]]
        model["observations"][0]["observed_controller_id"] = "app-root"
        p = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual(p["control_outcome"], "controlled")
        self.assertEqual(p["assessment"], "candidate_control_contradiction")

    def test_persisted_controller_without_applicable_snapshot_is_unknown(self) -> None:
        model = copy.deepcopy(self.model)
        model["observations"][0]["registration_snapshot_applies"] = False
        model["observations"][0]["page_origin_id"] = "different-origin"
        p = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual(p["expected_control"], "unknown")
        self.assertEqual(p["basis"], "registration_snapshot_not_applicable")
        self.assertEqual(p["assessment"], "unknown")
        model["observations"][0]["page_origin_id"] = "app-origin"
        p = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual(p["expected_control"], "unknown")
        self.assertEqual(p["assessment"], "unknown")
        model["observations"][0]["page_origin_id"] = "different-origin"
        model["observations"][0]["registration_snapshot_applies"] = True
        p = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual(p["expected_control"], "uncontrolled")
        self.assertEqual(p["assessment"], "candidate_control_contradiction")

    def test_exact_source_replay_rejects_readdressed_forgery(self) -> None:
        report = self.analyze()
        self.assertEqual(
            worker.verify_service_worker_scope(
                report,
                source_content=encoded(self.model),
                source_id=self.source_id,
            ),
            report,
        )
        changed = copy.deepcopy(self.model)
        changed["registrations"][0]["state"] = "inactive"
        with self.assertRaises(worker.ServiceWorkerScopeError):
            worker.verify_service_worker_scope(
                report,
                source_content=encoded(changed),
                source_id=self.source_id,
            )
        forged = report.to_dict()
        forged["projections"][0]["expected_controller_id"] = "app-root"
        parsed = worker.ServiceWorkerScopeReport.from_json(
            encoded(readdress(forged)).decode("ascii")
        )
        with self.assertRaises(worker.ServiceWorkerScopeError):
            worker.verify_service_worker_scope(
                parsed,
                source_content=encoded(self.model),
                source_id=self.source_id,
            )

    def test_direct_report_construction_rejects_effect_claims(self) -> None:
        report = self.analyze()
        self.assertEqual(worker.ServiceWorkerScopeReport(report.to_json()), report)
        with self.assertRaises(worker.ServiceWorkerScopeError):
            worker.ServiceWorkerScopeReport(" " + report.to_json())
        for section, key, value in (
            (None, "finding_claimed", True),
            (None, "service_worker_executed", True),
            ("effects", "network", "used"),
        ):
            forged = report.to_dict()
            if section is None:
                forged[key] = value
            else:
                forged[section][key] = value
            changed = encoded(readdress(forged)).decode("ascii")
            with self.assertRaises(worker.ServiceWorkerScopeError):
                worker.ServiceWorkerScopeReport.from_json(changed)
            damaged = worker.ServiceWorkerScopeReport(report.to_json())
            object.__setattr__(damaged, "_json", changed)
            with self.assertRaises(worker.ServiceWorkerScopeError):
                damaged.to_json()

    def test_native_adapter_detachment_and_family_check(self) -> None:
        native = {"source_id": self.source_id, "source": copy.deepcopy(self.model)}
        report = worker.analyze_supplied_service_worker_scope(native)
        self.assertEqual(report, self.analyze())
        native["source"]["registrations"][0]["state"] = "inactive"
        self.assertNotEqual(report, worker.analyze_supplied_service_worker_scope(native))
        for invalid in (
            {"source": self.model},
            {"source_id": self.source_id, "source": self.model, "extra": False},
            {"source_id": StringAlias(self.source_id), "source": self.model},
            {"source_id": self.source_id, "source": []},
            DictAlias({"source_id": self.source_id, "source": self.model}),
        ):
            with self.subTest(invalid=invalid), self.assertRaises(worker.ServiceWorkerScopeError):
                worker.analyze_supplied_service_worker_scope(invalid)
        fixture = worker.component_fixture()
        fixture["registrations"][0]["scope_path"] = "/changed/"
        self.assertEqual(worker.component_fixture()["registrations"][0]["scope_path"], "/app/")
        with self.assertRaises(worker.ServiceWorkerScopeError):
            worker.verify_service_worker_scope(
                ReportAlias(report.to_json()),
                source_content=encoded(self.model),
                source_id=self.source_id,
            )

    def test_closed_model_duplicate_scope_and_path_rejection(self) -> None:
        invalid = []
        extra = copy.deepcopy(self.model)
        extra["target_url"] = "https://example.invalid"
        invalid.append(extra)
        for section in ("registrations", "observations"):
            model = copy.deepcopy(self.model)
            model[section].append(copy.deepcopy(model[section][0]))
            invalid.append(model)
        same_scope = copy.deepcopy(self.model)
        same_scope["registrations"][1]["scope_path"] = "/app/"
        invalid.append(same_scope)
        for section, field, value in (
            ("registrations", "script_path", "https://example.invalid/sw.js"),
            ("registrations", "scope_path", "/app/../admin"),
            ("registrations", "scope_path", "/app%2Fadmin"),
            ("registrations", "scope_path", "//"),
            ("registrations", "state", "installed"),
            ("observations", "page_path", "/a//b"),
            ("observations", "control_outcome", "maybe"),
            ("observations", "observed_controller_id", None),
        ):
            model = copy.deepcopy(self.model)
            model[section][0][field] = value
            invalid.append(model)
        for field, value in (
            ("facts_complete", 1),
            ("registration_set_complete", "true"),
            ("schema_version", "v2"),
        ):
            model = copy.deepcopy(self.model)
            model[field] = value
            invalid.append(model)
        for model in invalid:
            with self.subTest(model=model), self.assertRaises(worker.ServiceWorkerScopeError):
                self.analyze(model)

    def test_duplicate_keys_bounds_and_side_effect_absence(self) -> None:
        bad = [
            b'{"schema_version":"v1","schema_version":"v1"}',
            b'{"registrations":[{"registration_id":"a","registration_id":"b"}]}',
            b'{"x":NaN}',
            b'{"x":1.3}',
            b'{"x":9223372036854775808}',
            b"\xff",
            b"[" * (worker.MAX_DEPTH + 1) + b"0" + b"]" * (worker.MAX_DEPTH + 1),
            b" " * (worker.MAX_SOURCE_BYTES + 1),
        ]
        for source in bad:
            with (
                self.subTest(source=source[:32]),
                self.assertRaises(worker.ServiceWorkerScopeError),
            ):
                worker.analyze_service_worker_scope(source_content=source, source_id=self.source_id)
        for source, identity in (
            (BytesAlias(encoded(self.model)), self.source_id),
            (encoded(self.model), StringAlias(self.source_id)),
            (encoded(self.model), "https://not-a-source"),
        ):
            with self.assertRaises(worker.ServiceWorkerScopeError):
                worker.analyze_service_worker_scope(source_content=source, source_id=identity)
        report = self.analyze()
        with patch("socket.create_connection", side_effect=AssertionError("network attempt")):
            with patch("subprocess.run", side_effect=AssertionError("process attempt")):
                self.assertEqual(
                    worker.verify_service_worker_scope(
                        report,
                        source_content=encoded(self.model),
                        source_id=self.source_id,
                    ),
                    report,
                )

    def test_determinism_and_empty_registration_set(self) -> None:
        report = self.analyze()
        self.assertEqual(report.to_json(), self.analyze().to_json())
        self.assertEqual(
            worker.ServiceWorkerScopeReport.from_json("\n" + report.to_json() + "\n"), report
        )
        model = copy.deepcopy(self.model)
        model["observations"].reverse()
        self.assertEqual(
            self.analyze(model).to_dict()["projections"], report.to_dict()["projections"]
        )
        self.assertNotEqual(self.analyze(model).to_json(), report.to_json())
        model = copy.deepcopy(self.model)
        model["registrations"] = []
        self.assertTrue(
            all(
                p["expected_control"] == "uncontrolled"
                for p in self.analyze(model).to_dict()["projections"]
            )
        )
        model = copy.deepcopy(self.model)
        model["registrations"] = [
            {
                **model["registrations"][0],
                "registration_id": f"r-{index}",
                "scope_path": f"/r-{index}/",
            }
            for index in range(worker.MAX_REGISTRATIONS + 1)
        ]
        with self.assertRaises(worker.ServiceWorkerScopeError):
            self.analyze(model)


if __name__ == "__main__":
    unittest.main()
