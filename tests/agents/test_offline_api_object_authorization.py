"""Synthetic source-bound tests for supplied object-level access comparisons."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_api_object_authorization as object_auth


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
    digest = hashlib.sha256(encoded({"domain": object_auth.DOMAIN, "analysis": body})).hexdigest()
    changed["report_id"] = "OAA-" + digest[:32].upper()
    changed["report_sha256"] = "sha256:" + digest
    return changed


class BytesAlias(bytes):
    pass


class StringAlias(str):
    pass


class DictAlias(dict):
    pass


class ReportAlias(object_auth.ApiObjectAuthorizationReport):
    pass


class OfflineApiObjectAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = object_auth.component_fixture()
        self.source_id = "synthetic:object-auth"

    def analyze(self, model=None) -> object_auth.ApiObjectAuthorizationReport:
        return object_auth.analyze_api_object_authorization(
            source_content=encoded(self.model if model is None else model),
            source_id=self.source_id,
        )

    def test_candidate_and_consistent_result_are_only_supplied_projections(self) -> None:
        content = encoded(self.model)
        report = object_auth.analyze_api_object_authorization(
            source_content=content,
            source_id=self.source_id,
        )
        document = report.to_dict()
        self.assertEqual(document["profile_id"], "AOE-GB-D06-S09")
        self.assertEqual(document["capability_id"], "api.authorization.object-level")
        self.assertEqual(document["wave_id"], "IW2-001")
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
                    "observation_id": "obs-outsider",
                    "subject_id": "bob",
                    "object_id": "invoice-1",
                    "action": "read",
                    "supplied_outcome": "allowed",
                    "owner_relation": "non_owner",
                    "tenant_relation": "different_tenant",
                    "expected_decision": "deny",
                    "assessment": "candidate_policy_contradiction",
                    "basis": "matched_rule",
                    "matching_rule_ids": ["cross-tenant-read"],
                },
                {
                    "observation_id": "obs-owner",
                    "subject_id": "alice",
                    "object_id": "invoice-1",
                    "action": "read",
                    "supplied_outcome": "allowed",
                    "owner_relation": "owner",
                    "tenant_relation": "same_tenant",
                    "expected_decision": "allow",
                    "assessment": "declared_consistent",
                    "basis": "matched_rule",
                    "matching_rule_ids": ["owner-read"],
                },
            ],
        )
        self.assertEqual(
            document["summary"],
            {
                "observation_count": 2,
                "candidate_policy_contradiction": 1,
                "declared_consistent": 1,
                "unknown": 0,
            },
        )
        self.assertTrue(document["offline_only"])
        for flag in (
            "facts_authenticated",
            "policy_authenticated",
            "access_outcomes_authenticated",
            "server_enforcement_observed",
            "finding_claimed",
            "positive_use_approved",
            "qualification_claimed",
        ):
            self.assertFalse(document[flag])
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertEqual(
            object_auth.verify_api_object_authorization(
                report,
                source_content=content,
                source_id=self.source_id,
            ),
            report,
        )

    def test_complete_default_deny_and_opposite_mismatch(self) -> None:
        model = copy.deepcopy(self.model)
        model["policy_rules"] = []
        model["access_outcomes"] = [model["access_outcomes"][1]]
        projection = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual(projection["expected_decision"], "deny")
        self.assertEqual(projection["basis"], "complete_default_deny")
        self.assertEqual(projection["assessment"], "candidate_policy_contradiction")
        model = copy.deepcopy(self.model)
        model["access_outcomes"][0]["outcome"] = "denied"
        model["access_outcomes"] = [model["access_outcomes"][0]]
        projection = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual(projection["expected_decision"], "allow")
        self.assertEqual(projection["assessment"], "candidate_policy_contradiction")

    def test_declared_denial_outcome_is_not_a_candidate(self) -> None:
        model = copy.deepcopy(self.model)
        model["access_outcomes"][1]["outcome"] = "denied"
        projection = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual(projection["expected_decision"], "deny")
        self.assertEqual(projection["assessment"], "declared_consistent")
        self.assertEqual(projection["basis"], "matched_rule")

    def test_same_tenant_non_owner_is_not_owner(self) -> None:
        model = copy.deepcopy(self.model)
        model["subjects"][1]["tenant_id"] = "tenant-a"
        model["access_outcomes"] = [model["access_outcomes"][1]]
        projection = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual(projection["owner_relation"], "non_owner")
        self.assertEqual(projection["tenant_relation"], "same_tenant")
        self.assertEqual(projection["basis"], "complete_default_deny")

    def test_incomplete_premises_never_make_consistency_or_candidate(self) -> None:
        for flag in ("facts_complete", "policy_complete"):
            model = copy.deepcopy(self.model)
            model[flag] = False
            projections = self.analyze(model).to_dict()["projections"]
            self.assertTrue(all(p["assessment"] == "unknown" for p in projections))
            self.assertTrue(all(p["expected_decision"] == "unknown" for p in projections))
            self.assertTrue(
                all(
                    p["basis"]
                    == ("incomplete_facts" if flag == "facts_complete" else "incomplete_policy")
                    for p in projections
                )
            )

    def test_missing_or_unknown_subject_object_relations_are_unknown(self) -> None:
        cases = []
        missing_subject = copy.deepcopy(self.model)
        missing_subject["subjects"] = [missing_subject["subjects"][0]]
        cases.append((missing_subject, "missing_subject"))
        missing_object = copy.deepcopy(self.model)
        missing_object["objects"] = []
        cases.append((missing_object, "missing_object"))
        for section, index, field in (
            ("subjects", 1, "tenant_id"),
            ("objects", 0, "owner_subject_id"),
            ("objects", 0, "tenant_id"),
        ):
            model = copy.deepcopy(self.model)
            model[section][index][field] = None
            cases.append((model, "unknown_relation"))
        for model, basis in cases:
            with self.subTest(basis=basis):
                projection = next(
                    p
                    for p in self.analyze(model).to_dict()["projections"]
                    if p["observation_id"] == "obs-outsider"
                )
                self.assertEqual(projection["assessment"], "unknown")
                self.assertEqual(projection["basis"], basis)

    def test_unknown_outcome_and_conflicting_rules(self) -> None:
        model = copy.deepcopy(self.model)
        model["access_outcomes"][1]["outcome"] = "unknown"
        projection = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual(projection["assessment"], "unknown")
        self.assertEqual(projection["basis"], "unknown_outcome")
        model = copy.deepcopy(self.model)
        extra = copy.deepcopy(model["policy_rules"][1])
        extra["rule_id"] = "conflict"
        extra["decision"] = "allow"
        model["policy_rules"].append(extra)
        projection = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual(projection["assessment"], "unknown")
        self.assertEqual(projection["expected_decision"], "unknown")
        self.assertEqual(projection["basis"], "conflicting_rules")
        self.assertEqual(projection["matching_rule_ids"], ["conflict", "cross-tenant-read"])

    def test_fixture_detached_and_deterministic_replay(self) -> None:
        fixture = object_auth.component_fixture()
        fixture["objects"][0]["tenant_id"] = "changed"
        self.assertEqual(object_auth.component_fixture()["objects"][0]["tenant_id"], "tenant-a")
        first = self.analyze()
        self.assertEqual(first.to_json(), self.analyze().to_json())
        detached = first.to_dict()
        detached["projections"][0]["assessment"] = "declared_consistent"
        self.assertNotEqual(detached, first.to_dict())
        parsed = object_auth.ApiObjectAuthorizationReport.from_json("\n" + first.to_json() + "\n")
        self.assertEqual(parsed, first)
        self.assertIsNot(
            object_auth.verify_api_object_authorization(
                first,
                source_content=encoded(self.model),
                source_id=self.source_id,
            ),
            first,
        )
        permuted = copy.deepcopy(self.model)
        permuted["access_outcomes"] = list(reversed(permuted["access_outcomes"]))
        self.assertEqual(
            self.analyze(permuted).to_dict()["projections"], first.to_dict()["projections"]
        )
        self.assertNotEqual(self.analyze(permuted).to_json(), first.to_json())

    def test_native_adapter_exact_source_wrapper(self) -> None:
        native = {"source_id": self.source_id, "source": copy.deepcopy(self.model)}
        report = object_auth.analyze_supplied_api_object_authorization(native)
        self.assertEqual(report, self.analyze())
        native["source"]["objects"][0]["tenant_id"] = "changed"
        self.assertNotEqual(report, object_auth.analyze_supplied_api_object_authorization(native))
        for invalid in (
            {"source": copy.deepcopy(self.model)},
            {"source_id": self.source_id, "source": copy.deepcopy(self.model), "extra": False},
            {"source_id": StringAlias(self.source_id), "source": copy.deepcopy(self.model)},
            {"source_id": self.source_id, "source": []},
            DictAlias({"source_id": self.source_id, "source": copy.deepcopy(self.model)}),
        ):
            with (
                self.subTest(invalid=invalid),
                self.assertRaises(object_auth.ApiObjectAuthorizationError),
            ):
                object_auth.analyze_supplied_api_object_authorization(invalid)

    def test_source_replay_rejects_tamper_even_if_readdressed(self) -> None:
        report = self.analyze()
        modified = copy.deepcopy(self.model)
        modified["access_outcomes"][1]["outcome"] = "denied"
        with self.assertRaises(object_auth.ApiObjectAuthorizationError):
            object_auth.verify_api_object_authorization(
                report,
                source_content=encoded(modified),
                source_id=self.source_id,
            )
        forged = report.to_dict()
        forged["projections"][0]["expected_decision"] = "allow"
        parsed = object_auth.ApiObjectAuthorizationReport.from_json(
            encoded(readdress(forged)).decode("ascii")
        )
        with self.assertRaises(object_auth.ApiObjectAuthorizationError):
            object_auth.verify_api_object_authorization(
                parsed,
                source_content=encoded(self.model),
                source_id=self.source_id,
            )
        with self.assertRaises(object_auth.ApiObjectAuthorizationError):
            object_auth.ApiObjectAuthorizationReport.from_json(
                report.to_json().replace('"finding_claimed":false', '"finding_claimed":true')
            )

    def test_direct_report_construction_and_export_validate_invariants(self) -> None:
        report = self.analyze()
        self.assertEqual(
            object_auth.ApiObjectAuthorizationReport(report.to_json()),
            report,
        )
        with self.assertRaises(object_auth.ApiObjectAuthorizationError):
            object_auth.ApiObjectAuthorizationReport(" " + report.to_json())
        for section, key, value in (
            ("effects", "network", "used"),
            (None, "finding_claimed", True),
        ):
            forged = report.to_dict()
            if section is None:
                forged[key] = value
            else:
                forged[section][key] = value
            forged_json = encoded(readdress(forged)).decode("ascii")
            with self.subTest(key=key), self.assertRaises(object_auth.ApiObjectAuthorizationError):
                object_auth.ApiObjectAuthorizationReport(forged_json)
            damaged = object_auth.ApiObjectAuthorizationReport(report.to_json())
            object.__setattr__(damaged, "_json", forged_json)
            with self.assertRaises(object_auth.ApiObjectAuthorizationError):
                damaged.to_dict()
            with self.assertRaises(object_auth.ApiObjectAuthorizationError):
                damaged.to_json()

    def test_duplicate_keys_and_unbounded_raw_input(self) -> None:
        bad = [
            b'{"schema_version":"v1","schema_version":"v1"}',
            b'{"subjects":[{"subject_id":"a","subject_id":"b"}]}',
            b'{"x":NaN}',
            b'{"x":1.3}',
            b'{"x":9223372036854775808}',
            b"\xff",
            b"[" * (object_auth.MAX_DEPTH + 1) + b"0" + b"]" * (object_auth.MAX_DEPTH + 1),
            b" " * (object_auth.MAX_SOURCE_BYTES + 1),
        ]
        for source in bad:
            with (
                self.subTest(source=source[:32]),
                self.assertRaises(object_auth.ApiObjectAuthorizationError),
            ):
                object_auth.analyze_api_object_authorization(
                    source_content=source,
                    source_id=self.source_id,
                )
        for source, identity in (
            (BytesAlias(encoded(self.model)), self.source_id),
            (encoded(self.model), StringAlias(self.source_id)),
            (encoded(self.model), "https://not-a-source"),
        ):
            with self.assertRaises(object_auth.ApiObjectAuthorizationError):
                object_auth.analyze_api_object_authorization(
                    source_content=source,
                    source_id=identity,
                )

    def test_closed_model_and_duplicate_facts(self) -> None:
        invalid = []
        extra = copy.deepcopy(self.model)
        extra["target_url"] = "https://example.invalid"
        invalid.append(extra)
        for section, field in (
            ("subjects", "subject_id"),
            ("objects", "object_id"),
            ("policy_rules", "rule_id"),
            ("access_outcomes", "observation_id"),
        ):
            candidate = copy.deepcopy(self.model)
            candidate[section].append(copy.deepcopy(candidate[section][0]))
            invalid.append(candidate)
        for field, value in (
            ("facts_complete", 1),
            ("policy_complete", "true"),
            ("subjects", {}),
            ("schema_version", "v2"),
        ):
            candidate = copy.deepcopy(self.model)
            candidate[field] = value
            invalid.append(candidate)
        for section, field, value in (
            ("subjects", "tenant_id", "tenant/x"),
            ("objects", "owner_subject_id", 3),
            ("policy_rules", "owner_relation", "any"),
            ("policy_rules", "tenant_relation", "any"),
            ("policy_rules", "decision", "permit"),
            ("access_outcomes", "outcome", "accepted"),
        ):
            candidate = copy.deepcopy(self.model)
            candidate[section][0][field] = value
            invalid.append(candidate)
        for candidate in invalid:
            with (
                self.subTest(candidate=candidate),
                self.assertRaises(object_auth.ApiObjectAuthorizationError),
            ):
                self.analyze(candidate)

    def test_array_bounds_and_empty_outcomes(self) -> None:
        model = copy.deepcopy(self.model)
        model["access_outcomes"] = []
        self.assertEqual(self.analyze(model).to_dict()["projections"], [])
        model = copy.deepcopy(self.model)
        model["subjects"] = [
            {"subject_id": f"subject-{index}", "tenant_id": "t"}
            for index in range(object_auth.MAX_SUBJECTS + 1)
        ]
        with self.assertRaises(object_auth.ApiObjectAuthorizationError):
            self.analyze(model)
        model = copy.deepcopy(self.model)
        model["policy_rules"] = [
            {**model["policy_rules"][0], "rule_id": f"rule-{index}"}
            for index in range(object_auth.MAX_RULES + 1)
        ]
        with self.assertRaises(object_auth.ApiObjectAuthorizationError):
            self.analyze(model)

    def test_report_family_and_no_network_or_process_effect(self) -> None:
        report = self.analyze()
        with self.assertRaises(object_auth.ApiObjectAuthorizationError):
            object_auth.verify_api_object_authorization(
                ReportAlias(report.to_json()),
                source_content=encoded(self.model),
                source_id=self.source_id,
            )
        with self.assertRaises(object_auth.ApiObjectAuthorizationError):
            object_auth.ApiObjectAuthorizationReport.from_json(StringAlias(report.to_json()))
        with patch("socket.create_connection", side_effect=AssertionError("network attempt")):
            with patch("subprocess.run", side_effect=AssertionError("process attempt")):
                self.assertEqual(
                    object_auth.verify_api_object_authorization(
                        report,
                        source_content=encoded(self.model),
                        source_id=self.source_id,
                    ),
                    report,
                )


if __name__ == "__main__":
    unittest.main()
