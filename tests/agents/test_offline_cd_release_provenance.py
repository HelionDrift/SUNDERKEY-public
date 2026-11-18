"""Synthetic source-bound tests for supplied CD and GitOps lineage."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_cd_release_provenance as release


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def readdress(document: dict) -> dict:
    changed = copy.deepcopy(document)
    body = {k: v for k, v in changed.items() if k not in {"report_id", "report_sha256"}}
    digest = hashlib.sha256(encoded({"domain": release.DOMAIN, "analysis": body})).hexdigest()
    changed["report_id"] = "CDP-" + digest[:32].upper()
    changed["report_sha256"] = "sha256:" + digest
    return changed


class BytesAlias(bytes):
    pass


class StringAlias(str):
    pass


class DictAlias(dict):
    pass


class ReportAlias(release.CdReleaseProvenanceReport):
    pass


class OfflineCdReleaseProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = release.component_fixture()
        self.source_id = "synthetic:release"

    def analyze(self, model=None) -> release.CdReleaseProvenanceReport:
        return release.analyze_cd_release_provenance(
            source_content=encoded(self.model if model is None else model),
            source_id=self.source_id,
        )

    def test_fixture_lineage_and_no_effect_claims(self) -> None:
        content = encoded(self.model)
        report = self.analyze().to_dict()
        self.assertEqual(report["profile_id"], "AOE-GC-D17-S03")
        self.assertEqual(report["component_id"], "cd_supplied_release_provenance")
        self.assertEqual(
            report["source"]["sha256"], "sha256:" + hashlib.sha256(content).hexdigest()
        )
        rows = {p["declaration_id"]: p for p in report["projections"]}
        self.assertEqual(rows["env-consistent"]["assessment"], "declared_consistent")
        self.assertEqual(rows["env-mismatch"]["assessment"], "candidate_observed_artifact_mismatch")
        self.assertEqual(rows["env-mismatch"]["basis"], "observed_desired_digest_mismatch")
        self.assertFalse(report["provenance_verified_cryptographically"])
        self.assertFalse(report["gitops_state_observed_live"])
        self.assertFalse(report["finding_claimed"])
        self.assertTrue(all(value == "none" for value in report["effects"].values()))

    def test_each_declared_digest_link_is_checked(self) -> None:
        for section, field, basis in (
            ("builds", "input_sha256", "build_source_digest_mismatch"),
            ("releases", "artifact_sha256", "release_build_digest_mismatch"),
            ("gitops_declarations", "desired_artifact_sha256", "desired_release_digest_mismatch"),
        ):
            model = copy.deepcopy(self.model)
            model[section][0][field] = "sha256:" + "a" * 64
            with self.subTest(section=section):
                row = self.analyze(model).to_dict()["projections"][0]
                self.assertEqual(
                    (row["assessment"], row["basis"]),
                    ("candidate_declared_lineage_conflict", basis),
                )

    def test_missing_records_and_incomplete_inventory_remain_unknown(self) -> None:
        for section, basis in (
            ("releases", "missing_release"),
            ("builds", "missing_build"),
            ("source_revisions", "missing_revision"),
        ):
            model = copy.deepcopy(self.model)
            model[section] = []
            with self.subTest(section=section):
                row = self.analyze(model).to_dict()["projections"][0]
                self.assertEqual((row["assessment"], row["basis"]), ("unknown", basis))
        for flag, basis in (
            ("facts_complete", "incomplete_facts"),
            ("lineage_complete", "incomplete_lineage"),
        ):
            model = copy.deepcopy(self.model)
            model[flag] = False
            with self.subTest(flag=flag):
                rows = self.analyze(model).to_dict()["projections"]
                self.assertTrue(
                    all(p["assessment"] == "unknown" and p["basis"] == basis for p in rows)
                )

    def test_provenance_approval_and_observed_state_uncertainty(self) -> None:
        for provenance, approval, expected, basis in (
            (
                "failed",
                "approved",
                "candidate_release_gate_conflict",
                "approved_without_provenance",
            ),
            ("unknown", "approved", "unknown", "provenance_or_approval_unknown"),
            ("verified", "unknown", "unknown", "provenance_or_approval_unknown"),
            ("failed", "denied", "declared_blocked", "provenance_or_approval_blocked"),
            ("verified", "denied", "declared_blocked", "provenance_or_approval_blocked"),
        ):
            model = copy.deepcopy(self.model)
            model["builds"][0]["provenance_disposition"] = provenance
            model["releases"][0]["approval_disposition"] = approval
            with self.subTest(provenance=provenance, approval=approval):
                row = self.analyze(model).to_dict()["projections"][0]
                self.assertEqual((row["assessment"], row["basis"]), (expected, basis))
        model = copy.deepcopy(self.model)
        model["gitops_declarations"][0].update(
            observed_status="unknown", observed_artifact_sha256=None
        )
        row = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual((row["assessment"], row["basis"]), ("unknown", "observed_state_unknown"))
        model["gitops_declarations"][0]["observed_status"] = "absent"
        row = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual(
            (row["assessment"], row["basis"]), ("declared_not_observed", "not_observed")
        )

    def test_exact_source_replay_rejects_readdressed_forgery(self) -> None:
        report = self.analyze()
        self.assertEqual(
            release.verify_cd_release_provenance(
                report,
                source_content=encoded(self.model),
                source_id=self.source_id,
            ),
            report,
        )
        changed = copy.deepcopy(self.model)
        changed["releases"][0]["approval_disposition"] = "denied"
        with self.assertRaises(release.CdReleaseProvenanceError):
            release.verify_cd_release_provenance(
                report,
                source_content=encoded(changed),
                source_id=self.source_id,
            )
        forged = report.to_dict()
        forged["projections"][1]["assessment"] = "declared_consistent"
        forged["summary"]["candidate_observed_artifact_mismatch"] = 0
        forged["summary"]["declared_consistent"] = 2
        parsed = release.CdReleaseProvenanceReport.from_json(
            encoded(readdress(forged)).decode("ascii")
        )
        with self.assertRaises(release.CdReleaseProvenanceError):
            release.verify_cd_release_provenance(
                parsed,
                source_content=encoded(self.model),
                source_id=self.source_id,
            )

    def test_direct_construction_rejects_effect_claims(self) -> None:
        report = self.analyze()
        self.assertEqual(release.CdReleaseProvenanceReport(report.to_json()), report)
        with self.assertRaises(release.CdReleaseProvenanceError):
            release.CdReleaseProvenanceReport(" " + report.to_json())
        for section, key, value in (
            (None, "finding_claimed", True),
            (None, "provenance_verified_cryptographically", True),
            ("effects", "git_write", "used"),
        ):
            forged = report.to_dict()
            if section is None:
                forged[key] = value
            else:
                forged[section][key] = value
            changed = encoded(readdress(forged)).decode("ascii")
            with self.assertRaises(release.CdReleaseProvenanceError):
                release.CdReleaseProvenanceReport.from_json(changed)
            damaged = release.CdReleaseProvenanceReport(report.to_json())
            object.__setattr__(damaged, "_json", changed)
            with self.assertRaises(release.CdReleaseProvenanceError):
                damaged.to_json()

    def test_closed_model_and_duplicate_references(self) -> None:
        invalid = []
        extra = copy.deepcopy(self.model)
        extra["repository_url"] = "https://example.invalid"
        invalid.append(extra)
        for section in ("source_revisions", "builds", "releases", "gitops_declarations"):
            model = copy.deepcopy(self.model)
            model[section].append(copy.deepcopy(model[section][0]))
            invalid.append(model)
        for section, field, value in (
            ("source_revisions", "commit_sha256", "ABC"),
            ("builds", "provenance_disposition", "signed"),
            ("releases", "approval_disposition", "maybe"),
            ("gitops_declarations", "observed_status", "deployed"),
            ("gitops_declarations", "observed_artifact_sha256", None),
        ):
            model = copy.deepcopy(self.model)
            model[section][0][field] = value
            invalid.append(model)
        for flag, value in (
            ("facts_complete", 1),
            ("lineage_complete", "true"),
            ("schema_version", "v2"),
        ):
            model = copy.deepcopy(self.model)
            model[flag] = value
            invalid.append(model)
        for model in invalid:
            with self.subTest(model=model), self.assertRaises(release.CdReleaseProvenanceError):
                self.analyze(model)

    def test_raw_source_bounds_and_no_side_effects(self) -> None:
        bad = [
            b'{"schema_version":"v1","schema_version":"v1"}',
            b'{"builds":[{"build_id":"a","build_id":"b"}]}',
            b'{"x":NaN}',
            b'{"x":1.3}',
            b'{"x":9223372036854775808}',
            b"\xff",
            b"[" * (release.MAX_DEPTH + 1) + b"0" + b"]" * (release.MAX_DEPTH + 1),
            b" " * (release.MAX_SOURCE_BYTES + 1),
        ]
        for source in bad:
            with (
                self.subTest(source=source[:32]),
                self.assertRaises(release.CdReleaseProvenanceError),
            ):
                release.analyze_cd_release_provenance(
                    source_content=source, source_id=self.source_id
                )
        for source, identity in (
            (BytesAlias(encoded(self.model)), self.source_id),
            (encoded(self.model), StringAlias(self.source_id)),
            (encoded(self.model), "https://not-a-source"),
        ):
            with self.assertRaises(release.CdReleaseProvenanceError):
                release.analyze_cd_release_provenance(source_content=source, source_id=identity)
        report = self.analyze()
        with patch("socket.create_connection", side_effect=AssertionError("network attempt")):
            with patch("subprocess.run", side_effect=AssertionError("process attempt")):
                self.assertEqual(
                    release.verify_cd_release_provenance(
                        report,
                        source_content=encoded(self.model),
                        source_id=self.source_id,
                    ),
                    report,
                )

    def test_native_adapter_detached_and_deterministic(self) -> None:
        native = {"source_id": self.source_id, "source": copy.deepcopy(self.model)}
        report = release.analyze_supplied_cd_release_provenance(native)
        self.assertEqual(report, self.analyze())
        native["source"]["releases"][0]["approval_disposition"] = "denied"
        self.assertNotEqual(report, release.analyze_supplied_cd_release_provenance(native))
        for invalid in (
            {"source": self.model},
            {"source_id": self.source_id, "source": self.model, "extra": False},
            {"source_id": StringAlias(self.source_id), "source": self.model},
            {"source_id": self.source_id, "source": []},
            DictAlias({"source_id": self.source_id, "source": self.model}),
        ):
            with self.subTest(invalid=invalid), self.assertRaises(release.CdReleaseProvenanceError):
                release.analyze_supplied_cd_release_provenance(invalid)
        self.assertEqual(report.to_json(), self.analyze().to_json())
        self.assertEqual(
            release.CdReleaseProvenanceReport.from_json("\n" + report.to_json() + "\n"), report
        )
        fixture = release.component_fixture()
        fixture["releases"][0]["approval_disposition"] = "denied"
        self.assertEqual(
            release.component_fixture()["releases"][0]["approval_disposition"], "approved"
        )
        with self.assertRaises(release.CdReleaseProvenanceError):
            release.verify_cd_release_provenance(
                ReportAlias(report.to_json()),
                source_content=encoded(self.model),
                source_id=self.source_id,
            )

    def test_empty_declarations_and_array_bound(self) -> None:
        model = copy.deepcopy(self.model)
        model["gitops_declarations"] = []
        self.assertEqual(self.analyze(model).to_dict()["projections"], [])
        model = copy.deepcopy(self.model)
        model["source_revisions"] = [
            {"revision_id": f"rev-{index}", "commit_sha256": "sha256:" + "1" * 64}
            for index in range(release.MAX_REVISIONS + 1)
        ]
        with self.assertRaises(release.CdReleaseProvenanceError):
            self.analyze(model)


if __name__ == "__main__":
    unittest.main()
