"""Synthetic local checks for supplied property write declarations."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_property_authorization as property_auth


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
    data = encoded({"domain": property_auth.DOMAIN, "analysis": body})
    digest = hashlib.sha256(data).hexdigest()
    changed["report_id"] = "PA-" + digest[:32].upper()
    changed["report_sha256"] = "sha256:" + digest
    return changed


class BytesAlias(bytes):
    pass


class StringAlias(str):
    pass


class ReportAlias(property_auth.PropertyAuthorizationReport):
    pass


class OfflinePropertyAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = property_auth.component_fixture()

    def inputs(self, *, before=None, after=None, policy=None, **changes) -> dict:
        return {
            "before_content": encoded(self.fixture["before"] if before is None else before),
            "after_content": encoded(self.fixture["after"] if after is None else after),
            "policy_content": encoded(self.fixture["policy"] if policy is None else policy),
            "before_source_id": self.fixture["before_source_id"],
            "after_source_id": self.fixture["after_source_id"],
            "policy_source_id": self.fixture["policy_source_id"],
            **changes,
        }

    def analyze(self, **changes) -> property_auth.PropertyAuthorizationReport:
        return property_auth.analyze_property_authorization(**self.inputs(**changes))

    def test_explicit_permitted_and_prohibited_nested_property_changes(self) -> None:
        arguments = self.inputs()
        report = property_auth.analyze_property_authorization(**arguments)
        document = report.to_dict()
        self.assertEqual(document["profile_id"], "AOE-GB-D06-S11")
        self.assertEqual(
            document["changes"],
            [
                {
                    "path": "/profile/display_name",
                    "change": "replaced",
                    "assessment": "declared_permitted",
                    "policy_basis": "explicit_rule",
                },
                {
                    "path": "/profile/role",
                    "change": "replaced",
                    "assessment": "declared_prohibited",
                    "policy_basis": "explicit_rule",
                },
            ],
        )
        self.assertEqual(
            document["summary"],
            {
                "changed_path_count": 2,
                "declared_permitted": 1,
                "declared_prohibited": 1,
                "uncertain": 0,
            },
        )
        for field, content in (
            ("before_source", arguments["before_content"]),
            ("after_source", arguments["after_content"]),
            ("policy_source", arguments["policy_content"]),
        ):
            self.assertEqual(
                document[field]["sha256"],
                "sha256:" + hashlib.sha256(content).hexdigest(),
            )
            self.assertEqual(document[field]["byte_count"], len(content))
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertTrue(document["offline_only"])
        for flag in (
            "body_provenance_authenticated",
            "policy_authenticated",
            "server_enforcement_observed",
            "finding_claimed",
            "positive_use_approved",
            "qualification_claimed",
        ):
            self.assertFalse(document[flag])
        self.assertNotIn("Ada", report.to_json())
        self.assertNotIn('admin"}', report.to_json())
        self.assertEqual(property_auth.verify_property_authorization(report, **arguments), report)

    def test_absent_null_and_no_change_are_distinct(self) -> None:
        policy = {
            "schema_version": "v1",
            "role": "member",
            "complete": True,
            "properties": [{"path": "/x", "write_roles": []}],
        }
        added = self.analyze(before={}, after={"x": None}, policy=policy).to_dict()
        self.assertEqual(added["changes"][0]["change"], "added")
        removed = self.analyze(before={"x": None}, after={}, policy=policy).to_dict()
        self.assertEqual(removed["changes"][0]["change"], "removed")
        self.assertEqual(
            self.analyze(before={"x": None}, after={"x": None}, policy=policy).to_dict()["changes"],
            [],
        )
        self.assertEqual(
            self.analyze(before={"x": False}, after={"x": 0}, policy=policy).to_dict()["changes"][
                0
            ]["change"],
            "replaced",
        )
        self.assertEqual(
            self.analyze(before={"x": [False]}, after={"x": [0]}, policy=policy).to_dict()[
                "changes"
            ][0]["change"],
            "replaced",
        )

    def test_nested_pointer_escaping_and_atomic_array(self) -> None:
        policy = {
            "schema_version": "v1",
            "role": "reader",
            "complete": True,
            "properties": [
                {"path": "/a~1b/c~0d", "write_roles": ["reader"]},
                {"path": "/items", "write_roles": []},
            ],
        }
        report = self.analyze(
            before={"a/b": {"c~d": 1}, "items": [1, 2]},
            after={"a/b": {"c~d": 2}, "items": [1, 3]},
            policy=policy,
        ).to_dict()
        self.assertEqual([entry["path"] for entry in report["changes"]], ["/a~1b/c~0d", "/items"])
        self.assertEqual(
            [entry["assessment"] for entry in report["changes"]],
            ["declared_permitted", "declared_prohibited"],
        )

    def test_parent_replacement_does_not_hide_protected_descendant(self) -> None:
        policy = {
            "schema_version": "v1",
            "role": "member",
            "complete": False,
            "properties": [{"path": "/profile/role", "write_roles": []}],
        }
        report = self.analyze(
            before={"profile": {"role": "member"}}, after={"profile": None}, policy=policy
        ).to_dict()
        self.assertEqual(
            report["changes"],
            [
                {
                    "path": "/profile",
                    "change": "replaced",
                    "assessment": "uncertain",
                    "policy_basis": "incomplete_unlisted",
                },
                {
                    "path": "/profile/role",
                    "change": "removed",
                    "assessment": "declared_prohibited",
                    "policy_basis": "explicit_rule",
                },
            ],
        )

    def test_empty_json_member_names_have_valid_pointer_paths(self) -> None:
        policy = {
            "schema_version": "v1",
            "role": "member",
            "complete": True,
            "properties": [{"path": "//", "write_roles": ["member"]}],
        }
        report = self.analyze(before={"": {"": 1}}, after={"": {"": 2}}, policy=policy).to_dict()
        self.assertEqual(report["changes"][0]["path"], "//")
        self.assertEqual(report["changes"][0]["assessment"], "declared_permitted")

    def test_incomplete_policy_preserves_uncertainty(self) -> None:
        policy = {"schema_version": "v1", "role": "member", "complete": False, "properties": []}
        report = self.analyze(before={}, after={"secret": "not reported"}, policy=policy)
        self.assertEqual(
            report.to_dict()["changes"],
            [
                {
                    "path": "/secret",
                    "change": "added",
                    "assessment": "uncertain",
                    "policy_basis": "incomplete_unlisted",
                },
            ],
        )
        self.assertNotIn("not reported", report.to_json())
        policy["complete"] = True
        report = self.analyze(before={}, after={"secret": "not reported"}, policy=policy)
        self.assertEqual(report.to_dict()["changes"][0]["assessment"], "declared_prohibited")
        self.assertEqual(report.to_dict()["changes"][0]["policy_basis"], "complete_default_deny")

    def test_fixture_detached_and_deterministic_source_binding(self) -> None:
        fresh = property_auth.component_fixture()
        fresh["before"]["profile"]["role"] = "changed"
        self.assertEqual(property_auth.component_fixture()["before"]["profile"]["role"], "member")
        inputs = self.inputs()
        first = property_auth.analyze_property_authorization(**inputs)
        second = property_auth.analyze_property_authorization(**inputs)
        self.assertEqual(first.to_json(), second.to_json())
        detached = first.to_dict()
        detached["changes"][0]["assessment"] = "uncertain"
        self.assertNotEqual(detached, first.to_dict())
        restored = property_auth.PropertyAuthorizationReport.from_json(
            "\n" + first.to_json() + "\n"
        )
        self.assertEqual(restored, first)
        self.assertIsNot(property_auth.verify_property_authorization(first, **inputs), first)
        changed = self.analyze(after={"profile": {"display_name": "Ada L", "role": "owner"}})
        self.assertNotEqual(first.to_json(), changed.to_json())

    def test_replay_rejects_modified_source_and_readdressed_forgery(self) -> None:
        inputs = self.inputs()
        report = property_auth.analyze_property_authorization(**inputs)
        modified = {
            **inputs,
            "after_content": encoded({"profile": {"display_name": "Ada L", "role": "owner"}}),
        }
        with self.assertRaises(property_auth.PropertyAuthorizationError):
            property_auth.verify_property_authorization(report, **modified)
        forged = report.to_dict()
        forged["changes"][1]["assessment"] = "declared_permitted"
        forged["summary"]["declared_permitted"] = 2
        forged["summary"]["declared_prohibited"] = 0
        forged = readdress(forged)
        parsed = property_auth.PropertyAuthorizationReport.from_json(
            encoded(forged).decode("ascii")
        )
        with self.assertRaises(property_auth.PropertyAuthorizationError):
            property_auth.verify_property_authorization(parsed, **inputs)
        with self.assertRaises(property_auth.PropertyAuthorizationError):
            property_auth.PropertyAuthorizationReport.from_json(
                report.to_json().replace('"finding_claimed":false', '"finding_claimed":true')
            )

    def test_direct_report_construction_and_export_validate_invariants(self) -> None:
        report = self.analyze()
        self.assertEqual(property_auth.PropertyAuthorizationReport(report.to_json()), report)
        with self.assertRaises(property_auth.PropertyAuthorizationError):
            property_auth.PropertyAuthorizationReport(" " + report.to_json())
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
            with self.subTest(key=key), self.assertRaises(property_auth.PropertyAuthorizationError):
                property_auth.PropertyAuthorizationReport(forged_json)
            damaged = property_auth.PropertyAuthorizationReport(report.to_json())
            object.__setattr__(damaged, "_json", forged_json)
            with self.assertRaises(property_auth.PropertyAuthorizationError):
                damaged.to_dict()
            with self.assertRaises(property_auth.PropertyAuthorizationError):
                damaged.to_json()

    def test_closed_policy_and_path_validation(self) -> None:
        baseline = copy.deepcopy(self.fixture["policy"])
        invalid = []
        duplicate = copy.deepcopy(baseline)
        duplicate["properties"].append(copy.deepcopy(duplicate["properties"][0]))
        invalid.append(duplicate)
        for path in ("", "role", "/x~2", "/x~"):
            candidate = copy.deepcopy(baseline)
            candidate["properties"][0]["path"] = path
            invalid.append(candidate)
        extra = copy.deepcopy(baseline)
        extra["unexpected"] = True
        invalid.append(extra)
        wrong_role = copy.deepcopy(baseline)
        wrong_role["role"] = True
        invalid.append(wrong_role)
        duplicate_role = copy.deepcopy(baseline)
        duplicate_role["properties"][0]["write_roles"] = ["member", "member"]
        invalid.append(duplicate_role)
        for policy in invalid:
            with (
                self.subTest(policy=policy),
                self.assertRaises(property_auth.PropertyAuthorizationError),
            ):
                self.analyze(policy=policy)

    def test_raw_json_and_resource_adversaries(self) -> None:
        base = self.inputs()
        bad_sources = [
            b'{"x":1,"x":2}',
            b'{"x":{"a":1,"a":2}}',
            b'{"x":NaN}',
            b'{"x":1.5}',
            b'{"x":9223372036854775808}',
            b'{"x":true,}',
            b"\xff",
            b"[" * (property_auth.MAX_DEPTH + 1) + b"0" + b"]" * (property_auth.MAX_DEPTH + 1),
            b"{" + b'"x":' + b'"a"' * property_auth.MAX_SOURCE_BYTES + b"}",
        ]
        for source in bad_sources:
            with (
                self.subTest(source=source[:32]),
                self.assertRaises(property_auth.PropertyAuthorizationError),
            ):
                property_auth.analyze_property_authorization(**{**base, "before_content": source})
        for name, value in (
            ("before_content", BytesAlias(base["before_content"])),
            ("before_source_id", StringAlias("synthetic:before")),
            ("before_source_id", "../not-a-source"),
            ("policy_source_id", base["before_source_id"]),
        ):
            with (
                self.subTest(name=name, value=value),
                self.assertRaises(property_auth.PropertyAuthorizationError),
            ):
                property_auth.analyze_property_authorization(**{**base, name: value})
        with self.assertRaises(property_auth.PropertyAuthorizationError):
            property_auth.analyze_property_authorization(
                **{
                    **base,
                    "after_content": encoded(
                        {str(i): i for i in range(property_auth.MAX_CHANGES + 1)}
                    ),
                    "before_content": b"{}",
                    "policy_content": encoded(
                        {
                            "schema_version": "v1",
                            "role": "member",
                            "complete": False,
                            "properties": [],
                        }
                    ),
                }
            )

    def test_report_family_and_replay_boundary(self) -> None:
        inputs = self.inputs()
        report = property_auth.analyze_property_authorization(**inputs)
        with self.assertRaises(property_auth.PropertyAuthorizationError):
            property_auth.verify_property_authorization(ReportAlias(report.to_json()), **inputs)
        with self.assertRaises(property_auth.PropertyAuthorizationError):
            property_auth.PropertyAuthorizationReport.from_json(StringAlias(report.to_json()))
        with self.assertRaises(property_auth.PropertyAuthorizationError):
            property_auth.PropertyAuthorizationReport.from_json(report.to_json() + report.to_json())
        with patch("socket.create_connection", side_effect=AssertionError("network attempt")):
            with patch("subprocess.run", side_effect=AssertionError("process attempt")):
                self.assertEqual(
                    property_auth.verify_property_authorization(report, **inputs),
                    report,
                )


if __name__ == "__main__":
    unittest.main()
