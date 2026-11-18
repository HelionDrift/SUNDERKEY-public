"""Synthetic source-bound tests for declared workload identity trust paths."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_workload_identity_trust as workload_trust


def encoded(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def readdress(document: dict) -> dict:
    changed = copy.deepcopy(document)
    body = {k: v for k, v in changed.items() if k not in {"report_id", "report_sha256"}}
    digest = hashlib.sha256(
        encoded({"domain": workload_trust.DOMAIN, "analysis": body})
    ).hexdigest()
    changed["report_id"] = "WIT-" + digest[:32].upper()
    changed["report_sha256"] = "sha256:" + digest
    return changed


class BytesAlias(bytes):
    pass


class StringAlias(str):
    pass


class ReportAlias(workload_trust.WorkloadIdentityTrustReport):
    pass


class OfflineWorkloadIdentityTrustTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = workload_trust.component_fixture()
        self.source_id = "synthetic:workload-trust"

    def analyze(self, model=None) -> workload_trust.WorkloadIdentityTrustReport:
        return workload_trust.analyze_workload_identity_trust(
            source_content=encoded(self.model if model is None else model),
            source_id=self.source_id,
        )

    def test_exact_match_is_declaration_not_token_or_privilege_proof(self) -> None:
        content = encoded(self.model)
        report = workload_trust.analyze_workload_identity_trust(
            source_content=content,
            source_id=self.source_id,
        )
        document = report.to_dict()
        self.assertEqual(document["profile_id"], "AOE-GC-D14-S10")
        self.assertEqual(document["capability_id"], "cloud.workload-identity-metadata")
        self.assertEqual(document["wave_id"], "IW2-013")
        self.assertEqual(
            document["source"],
            {
                "source_id": self.source_id,
                "sha256": "sha256:" + hashlib.sha256(content).hexdigest(),
                "byte_count": len(content),
            },
        )
        self.assertEqual(
            document["projections"],
            [
                {
                    "claim_id": "claim-1",
                    "requested_role_ref": "role:readonly",
                    "assessment": "declared_exact_match",
                    "basis": "matching_allow_binding",
                    "matching_allow_rule_ids": ["rule-1"],
                    "matching_deny_rule_ids": [],
                    "matching_binding_ids": ["binding-1"],
                }
            ],
        )
        self.assertEqual(
            document["summary"],
            {
                "claim_count": 1,
                "declared_exact_match": 1,
                "declared_denied": 0,
                "unknown": 0,
            },
        )
        self.assertTrue(document["offline_only"])
        for flag in (
            "claim_authenticity_verified",
            "token_signature_verified",
            "trust_source_authenticated",
            "effective_privilege_proven",
            "finding_claimed",
            "positive_use_approved",
            "qualification_claimed",
        ):
            self.assertFalse(document[flag])
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertNotIn("system:serviceaccount", report.to_json())
        self.assertNotIn("https://issuer", report.to_json())
        self.assertEqual(
            workload_trust.verify_workload_identity_trust(
                report,
                source_content=content,
                source_id=self.source_id,
            ),
            report,
        )

    def test_exact_issuer_subject_audience_and_role_boundaries(self) -> None:
        for field, value in (
            ("issuer", "https://ISSUER.example.invalid"),
            ("subject", "system:serviceaccount:demo:other"),
            ("audience", "sts.other.invalid"),
        ):
            model = copy.deepcopy(self.model)
            model["claims"][0][field] = value
            projection = self.analyze(model).to_dict()["projections"][0]
            self.assertEqual(projection["assessment"], "declared_denied")
            self.assertEqual(projection["basis"], "complete_no_trust_rule")
        model = copy.deepcopy(self.model)
        model["claims"][0]["requested_role_ref"] = "role:writer"
        projection = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual(projection["assessment"], "declared_denied")
        self.assertEqual(projection["basis"], "complete_no_binding")
        self.assertEqual(projection["matching_allow_rule_ids"], ["rule-1"])

    def test_explicit_deny_and_rule_conflict(self) -> None:
        model = copy.deepcopy(self.model)
        model["trust_rules"][0]["effect"] = "deny"
        model["role_bindings"] = []
        projection = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual(projection["assessment"], "declared_denied")
        self.assertEqual(projection["basis"], "matching_deny_rule")
        model = copy.deepcopy(self.model)
        other = copy.deepcopy(model["trust_rules"][0])
        other["rule_id"] = "rule-2"
        other["effect"] = "deny"
        model["trust_rules"].append(other)
        projection = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual(projection["assessment"], "unknown")
        self.assertEqual(projection["basis"], "conflicting_trust_rules")
        self.assertEqual(projection["matching_deny_rule_ids"], ["rule-2"])

    def test_incomplete_trust_and_bindings_remain_unknown(self) -> None:
        model = copy.deepcopy(self.model)
        model["trust_rules_complete"] = False
        projection = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual(projection["assessment"], "unknown")
        self.assertEqual(projection["basis"], "incomplete_trust_rules")
        model = copy.deepcopy(self.model)
        model["role_bindings_complete"] = False
        projection = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual(projection["assessment"], "declared_exact_match")
        model = copy.deepcopy(self.model)
        model["role_bindings_complete"] = False
        model["role_bindings"] = []
        projection = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual(projection["assessment"], "unknown")
        self.assertEqual(projection["basis"], "incomplete_role_bindings")
        model["trust_rules_complete"] = False
        model["trust_rules"] = []
        projection = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual(projection["basis"], "incomplete_trust_rules")
        model = copy.deepcopy(self.model)
        model["trust_rules_complete"] = False
        model["trust_rules"][0]["effect"] = "deny"
        model["role_bindings"] = []
        projection = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual(projection["assessment"], "unknown")

    def test_multiple_bindings_and_deterministic_claim_order(self) -> None:
        model = copy.deepcopy(self.model)
        second = copy.deepcopy(model["claims"][0])
        second["claim_id"] = "claim-0"
        second["requested_role_ref"] = "role:writer"
        model["claims"].append(second)
        model["role_bindings"].append(
            {
                "binding_id": "binding-2",
                "rule_id": "rule-1",
                "role_ref": "role:writer",
            }
        )
        report = self.analyze(model).to_dict()
        self.assertEqual([p["claim_id"] for p in report["projections"]], ["claim-0", "claim-1"])
        self.assertEqual(
            [p["assessment"] for p in report["projections"]],
            ["declared_exact_match", "declared_exact_match"],
        )
        self.assertEqual(report["projections"][0]["matching_binding_ids"], ["binding-2"])

    def test_fixture_detached_deterministic_and_replay_bound(self) -> None:
        fixture = workload_trust.component_fixture()
        fixture["claims"][0]["subject"] = "changed"
        self.assertEqual(
            workload_trust.component_fixture()["claims"][0]["subject"],
            "system:serviceaccount:demo:reader",
        )
        first = self.analyze()
        self.assertEqual(first.to_json(), self.analyze().to_json())
        detached = first.to_dict()
        detached["projections"][0]["assessment"] = "declared_denied"
        self.assertNotEqual(detached, first.to_dict())
        parsed = workload_trust.WorkloadIdentityTrustReport.from_json("\n" + first.to_json() + "\n")
        self.assertEqual(parsed, first)
        self.assertIsNot(
            workload_trust.verify_workload_identity_trust(
                first,
                source_content=encoded(self.model),
                source_id=self.source_id,
            ),
            first,
        )

    def test_native_component_adapter_matches_byte_analyzer(self) -> None:
        native = {"source_id": self.source_id, "source": copy.deepcopy(self.model)}
        report = workload_trust.analyze_supplied_workload_identity_trust(native)
        self.assertEqual(report, self.analyze())
        native["source"]["claims"][0]["subject"] = "changed"
        self.assertNotEqual(report, workload_trust.analyze_supplied_workload_identity_trust(native))
        for invalid in (
            {"source": copy.deepcopy(self.model)},
            {"source_id": self.source_id, "source": copy.deepcopy(self.model), "extra": False},
            {"source_id": StringAlias(self.source_id), "source": copy.deepcopy(self.model)},
            {"source_id": self.source_id, "source": []},
        ):
            with (
                self.subTest(invalid=invalid),
                self.assertRaises(workload_trust.WorkloadIdentityTrustError),
            ):
                workload_trust.analyze_supplied_workload_identity_trust(invalid)

    def test_replay_rejects_changed_source_and_readdressed_forgery(self) -> None:
        report = self.analyze()
        changed = copy.deepcopy(self.model)
        changed["claims"][0]["audience"] = "elsewhere"
        with self.assertRaises(workload_trust.WorkloadIdentityTrustError):
            workload_trust.verify_workload_identity_trust(
                report,
                source_content=encoded(changed),
                source_id=self.source_id,
            )
        forged = report.to_dict()
        forged["projections"][0]["matching_binding_ids"] = ["wrong-binding"]
        parsed = workload_trust.WorkloadIdentityTrustReport.from_json(
            encoded(readdress(forged)).decode("ascii")
        )
        with self.assertRaises(workload_trust.WorkloadIdentityTrustError):
            workload_trust.verify_workload_identity_trust(
                parsed,
                source_content=encoded(self.model),
                source_id=self.source_id,
            )
        with self.assertRaises(workload_trust.WorkloadIdentityTrustError):
            workload_trust.WorkloadIdentityTrustReport.from_json(
                report.to_json().replace(
                    '"effective_privilege_proven":false', '"effective_privilege_proven":true'
                )
            )

    def test_closed_model_rejects_duplicate_and_dangling_bindings(self) -> None:
        invalid = []
        extra = copy.deepcopy(self.model)
        extra["token"] = "in-scope?"
        invalid.append(extra)
        duplicate_claim = copy.deepcopy(self.model)
        duplicate_claim["claims"].append(copy.deepcopy(duplicate_claim["claims"][0]))
        invalid.append(duplicate_claim)
        duplicate_rule = copy.deepcopy(self.model)
        duplicate_rule["trust_rules"].append(copy.deepcopy(duplicate_rule["trust_rules"][0]))
        invalid.append(duplicate_rule)
        duplicate_binding = copy.deepcopy(self.model)
        duplicate_binding["role_bindings"].append(
            copy.deepcopy(duplicate_binding["role_bindings"][0])
        )
        invalid.append(duplicate_binding)
        dangling = copy.deepcopy(self.model)
        dangling["role_bindings"][0]["rule_id"] = "missing"
        invalid.append(dangling)
        denial_binding = copy.deepcopy(self.model)
        denial_binding["trust_rules"][0]["effect"] = "deny"
        invalid.append(denial_binding)
        for field, value in (
            ("trust_rules_complete", 1),
            ("role_bindings_complete", "true"),
            ("claims", {}),
            ("schema_version", "v2"),
        ):
            candidate = copy.deepcopy(self.model)
            candidate[field] = value
            invalid.append(candidate)
        for candidate in invalid:
            with (
                self.subTest(candidate=candidate),
                self.assertRaises(workload_trust.WorkloadIdentityTrustError),
            ):
                self.analyze(candidate)

    def test_claim_input_adversaries(self) -> None:
        for field, value in (
            ("issuer", ""),
            ("issuer", "x\ny"),
            ("subject", "x" * (workload_trust.MAX_TEXT_BYTES + 1)),
            ("audience", None),
            ("claim_id", "../claim"),
            ("requested_role_ref", "\ud800"),
        ):
            candidate = copy.deepcopy(self.model)
            candidate["claims"][0][field] = value
            with (
                self.subTest(field=field, value=str(value)[:16]),
                self.assertRaises(workload_trust.WorkloadIdentityTrustError),
            ):
                self.analyze(candidate)
        for field, value in (("issuer", False), ("subject", "x\ty"), ("effect", "permit")):
            candidate = copy.deepcopy(self.model)
            candidate["trust_rules"][0][field] = value
            with self.assertRaises(workload_trust.WorkloadIdentityTrustError):
                self.analyze(candidate)

    def test_duplicate_key_raw_json_and_resource_bounds(self) -> None:
        bad = [
            b'{"schema_version":"v1","schema_version":"v1"}',
            b'{"claims":[{"issuer":"a","issuer":"b"}]}',
            b'{"x":NaN}',
            b'{"x":1.2}',
            b'{"x":9223372036854775808}',
            b"\xff",
            b"[" * (workload_trust.MAX_DEPTH + 1) + b"0" + b"]" * (workload_trust.MAX_DEPTH + 1),
            b" " * (workload_trust.MAX_SOURCE_BYTES + 1),
        ]
        for source in bad:
            with (
                self.subTest(source=source[:32]),
                self.assertRaises(workload_trust.WorkloadIdentityTrustError),
            ):
                workload_trust.analyze_workload_identity_trust(
                    source_content=source,
                    source_id=self.source_id,
                )
        for source, identity in (
            (BytesAlias(encoded(self.model)), self.source_id),
            (encoded(self.model), StringAlias(self.source_id)),
            (encoded(self.model), "../source"),
        ):
            with self.assertRaises(workload_trust.WorkloadIdentityTrustError):
                workload_trust.analyze_workload_identity_trust(
                    source_content=source,
                    source_id=identity,
                )

    def test_empty_claims_and_declared_array_limits(self) -> None:
        model = copy.deepcopy(self.model)
        model["claims"] = []
        self.assertEqual(self.analyze(model).to_dict()["projections"], [])
        model = copy.deepcopy(self.model)
        model["claims"] = [
            {**model["claims"][0], "claim_id": f"claim-{index}"}
            for index in range(workload_trust.MAX_CLAIMS + 1)
        ]
        with self.assertRaises(workload_trust.WorkloadIdentityTrustError):
            self.analyze(model)
        model = copy.deepcopy(self.model)
        model["trust_rules"] = [
            {**model["trust_rules"][0], "rule_id": f"rule-{index}"}
            for index in range(workload_trust.MAX_RULES + 1)
        ]
        with self.assertRaises(workload_trust.WorkloadIdentityTrustError):
            self.analyze(model)

    def test_report_family_and_no_network_or_process_effect(self) -> None:
        report = self.analyze()
        with self.assertRaises(workload_trust.WorkloadIdentityTrustError):
            workload_trust.verify_workload_identity_trust(
                ReportAlias(report.to_json()),
                source_content=encoded(self.model),
                source_id=self.source_id,
            )
        with self.assertRaises(workload_trust.WorkloadIdentityTrustError):
            workload_trust.WorkloadIdentityTrustReport.from_json(StringAlias(report.to_json()))
        with (
            patch("socket.create_connection", side_effect=AssertionError("network attempt")),
            patch("subprocess.run", side_effect=AssertionError("process attempt")),
        ):
            self.assertEqual(
                workload_trust.verify_workload_identity_trust(
                    report,
                    source_content=encoded(self.model),
                    source_id=self.source_id,
                ),
                report,
            )

    def test_direct_constructor_rejects_forged_effects_and_claims(self) -> None:
        valid = self.analyze()
        self.assertEqual(
            workload_trust.WorkloadIdentityTrustReport(valid.to_json()).to_dict(),
            valid.to_dict(),
        )
        for section, field, value in (
            (None, "finding_claimed", True),
            ("effects", "network", "invoked"),
        ):
            forged = valid.to_dict()
            if section is None:
                forged[field] = value
            else:
                forged[section][field] = value
            with (
                self.subTest(field=field),
                self.assertRaises(workload_trust.WorkloadIdentityTrustError),
            ):
                workload_trust.WorkloadIdentityTrustReport(
                    encoded(readdress(forged)).decode("ascii")
                )
        with self.assertRaises(workload_trust.WorkloadIdentityTrustError):
            workload_trust.WorkloadIdentityTrustReport("\n" + valid.to_json() + "\n")
        with self.assertRaises(workload_trust.WorkloadIdentityTrustError):
            workload_trust.WorkloadIdentityTrustReport(StringAlias(valid.to_json()))
        with self.assertRaises(workload_trust.WorkloadIdentityTrustError):
            workload_trust.WorkloadIdentityTrustReport(" " * (workload_trust.MAX_REPORT_BYTES + 1))

    def test_object_setattr_tamper_cannot_export_forged_report(self) -> None:
        report = self.analyze()
        forged = report.to_dict()
        forged["effects"]["network"] = "invoked"
        object.__setattr__(report, "_json", encoded(readdress(forged)).decode("ascii"))
        for export in (report.to_dict, report.to_json):
            with (
                self.subTest(export=export.__name__),
                self.assertRaises(workload_trust.WorkloadIdentityTrustError),
            ):
                export()
        incomplete = object.__new__(workload_trust.WorkloadIdentityTrustReport)
        for export in (incomplete.to_dict, incomplete.to_json):
            with (
                self.subTest(incomplete_export=export.__name__),
                self.assertRaises(workload_trust.WorkloadIdentityTrustError),
            ):
                export()


if __name__ == "__main__":
    unittest.main()
