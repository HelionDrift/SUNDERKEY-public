"""Synthetic tests for source-bound web-route and UI policy projection."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_web_route_authorization as route_auth


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def readdress(document: dict) -> dict:
    changed = copy.deepcopy(document)
    body = {k: v for k, v in changed.items() if k not in {"report_id", "report_sha256"}}
    digest = hashlib.sha256(encoded({"domain": route_auth.DOMAIN, "analysis": body})).hexdigest()
    changed["report_id"] = "WRA-" + digest[:32].upper()
    changed["report_sha256"] = "sha256:" + digest
    return changed


class BytesAlias(bytes):
    pass


class StringAlias(str):
    pass


class DictAlias(dict):
    pass


class ReportAlias(route_auth.WebRouteAuthorizationReport):
    pass


class OfflineWebRouteAuthorizationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = route_auth.component_fixture()
        self.source_id = "synthetic:web-route"

    def analyze(self, model=None) -> route_auth.WebRouteAuthorizationReport:
        return route_auth.analyze_web_route_authorization(
            source_content=encoded(self.model if model is None else model),
            source_id=self.source_id,
        )

    def test_fixture_projections_and_no_effect_claims(self) -> None:
        report = self.analyze().to_dict()
        self.assertEqual(report["profile_id"], "AOE-GB-D05-S12")
        self.assertEqual(report["capability_id"], "web.access-control.multitenancy")
        projections = {p["observation_id"]: p for p in report["projections"]}
        self.assertEqual(projections["obs-owner"]["expected_decision"], "allow")
        self.assertEqual(projections["obs-owner"]["server_assessment"], "declared_consistent")
        self.assertEqual(
            projections["obs-owner"]["ui_assessment"], "declared_ui_access_decision_same"
        )
        self.assertEqual(projections["obs-cross-tenant"]["basis"], "different_tenant")
        self.assertEqual(
            projections["obs-cross-tenant"]["server_assessment"],
            "candidate_policy_contradiction",
        )
        self.assertEqual(
            projections["obs-cross-tenant"]["ui_assessment"],
            "declared_ui_access_decision_differs",
        )
        self.assertEqual(projections["obs-anonymous"]["basis"], "anonymous_deny")
        self.assertEqual(report["summary"]["observation_count"], 3)
        self.assertEqual(report["summary"]["server"]["candidate_policy_contradiction"], 1)
        self.assertTrue(all(value == "none" for value in report["effects"].values()))
        self.assertFalse(report["finding_claimed"])

    def test_ui_visibility_never_substitutes_for_server_outcome(self) -> None:
        model = copy.deepcopy(self.model)
        outsider = next(
            o for o in model["observations"] if o["observation_id"] == "obs-cross-tenant"
        )
        outsider["ui_visibility"] = "hidden"
        outsider["server_outcome"] = "allowed"
        p = {p["observation_id"]: p for p in self.analyze(model).to_dict()["projections"]}
        self.assertEqual(p["obs-cross-tenant"]["ui_assessment"], "declared_ui_access_decision_same")
        self.assertEqual(
            p["obs-cross-tenant"]["server_assessment"], "candidate_policy_contradiction"
        )
        outsider["ui_visibility"] = "visible"
        outsider["server_outcome"] = "denied"
        p = {p["observation_id"]: p for p in self.analyze(model).to_dict()["projections"]}
        self.assertEqual(
            p["obs-cross-tenant"]["ui_assessment"], "declared_ui_access_decision_differs"
        )
        self.assertEqual(p["obs-cross-tenant"]["server_assessment"], "declared_consistent")
        outsider["server_outcome"] = "unknown"
        p = {p["observation_id"]: p for p in self.analyze(model).to_dict()["projections"]}
        self.assertEqual(p["obs-cross-tenant"]["server_assessment"], "unknown")
        self.assertEqual(
            p["obs-cross-tenant"]["ui_assessment"], "declared_ui_access_decision_differs"
        )

    def test_public_api_route_hidden_in_ui_is_not_policy_finding(self) -> None:
        model = copy.deepcopy(self.model)
        model["routes"][0].update(access="public", required_role=None, tenant_scope="none")
        owner = next(o for o in model["observations"] if o["observation_id"] == "obs-owner")
        owner["ui_visibility"] = "hidden"
        report = self.analyze(model).to_dict()
        projection = next(p for p in report["projections"] if p["observation_id"] == "obs-owner")
        self.assertEqual(projection["expected_decision"], "allow")
        self.assertEqual(projection["server_assessment"], "declared_consistent")
        self.assertEqual(projection["ui_assessment"], "declared_ui_access_decision_differs")
        self.assertNotIn("candidate_ui_policy_mismatch", report["summary"]["ui"])

    def test_public_authenticated_and_role_decisions(self) -> None:
        model = copy.deepcopy(self.model)
        model["routes"] = [
            {
                "route_id": "public",
                "route_path": "/",
                "access": "public",
                "required_role": None,
                "tenant_scope": "none",
            },
            {
                "route_id": "account",
                "route_path": "/account",
                "access": "authenticated",
                "required_role": None,
                "tenant_scope": "none",
            },
            {
                "route_id": "admin",
                "route_path": "/admin",
                "access": "role",
                "required_role": "admin",
                "tenant_scope": "none",
            },
        ]
        model["observations"] = [
            {
                "observation_id": "a",
                "principal_id": None,
                "route_id": "public",
                "resource_tenant_id": None,
                "ui_visibility": "visible",
                "server_outcome": "allowed",
            },
            {
                "observation_id": "b",
                "principal_id": None,
                "route_id": "account",
                "resource_tenant_id": None,
                "ui_visibility": "hidden",
                "server_outcome": "denied",
            },
            {
                "observation_id": "c",
                "principal_id": "alice",
                "route_id": "account",
                "resource_tenant_id": None,
                "ui_visibility": "visible",
                "server_outcome": "allowed",
            },
            {
                "observation_id": "d",
                "principal_id": "alice",
                "route_id": "admin",
                "resource_tenant_id": None,
                "ui_visibility": "visible",
                "server_outcome": "allowed",
            },
        ]
        projections = self.analyze(model).to_dict()["projections"]
        self.assertEqual(
            [p["basis"] for p in projections],
            ["public_route", "anonymous_deny", "authenticated_route", "matched_role"],
        )
        self.assertTrue(all(p["server_assessment"] == "declared_consistent" for p in projections))
        model["principals"][0]["roles"] = []
        projection = self.analyze(model).to_dict()["projections"][-1]
        self.assertEqual(
            (projection["basis"], projection["expected_decision"]), ("missing_role", "deny")
        )

    def test_missing_role_deny_precedes_unknown_tenant(self) -> None:
        model = copy.deepcopy(self.model)
        model["principals"][0]["roles"] = []
        model["principals"][0]["tenant_id"] = None
        model["observations"] = [model["observations"][0]]
        model["observations"][0]["resource_tenant_id"] = None
        p = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual((p["expected_decision"], p["basis"]), ("deny", "missing_role"))

    def test_unknown_and_incomplete_premises_do_not_claim_alignment(self) -> None:
        cases = []
        for flag in ("facts_complete", "policy_complete"):
            model = copy.deepcopy(self.model)
            model[flag] = False
            cases.append(model)
        missing_route = copy.deepcopy(self.model)
        missing_route["routes"] = []
        cases.append(missing_route)
        missing_principal = copy.deepcopy(self.model)
        missing_principal["principals"] = []
        missing_principal["observations"] = [missing_principal["observations"][0]]
        cases.append(missing_principal)
        for section, field in (("principals", "tenant_id"), ("observations", "resource_tenant_id")):
            model = copy.deepcopy(self.model)
            model[section][0][field] = None
            model["observations"] = [model["observations"][0]]
            cases.append(model)
        for model in cases:
            with self.subTest(model=model):
                projections = self.analyze(model).to_dict()["projections"]
                self.assertTrue(
                    all(
                        p["server_assessment"] == "unknown"
                        for p in projections
                        if p["expected_decision"] == "unknown"
                    )
                )
                self.assertTrue(
                    all(
                        p["ui_assessment"] == "unknown"
                        for p in projections
                        if p["expected_decision"] == "unknown"
                    )
                )

    def test_missing_declared_principal_is_not_anonymous(self) -> None:
        model = copy.deepcopy(self.model)
        model["principals"] = []
        model["observations"] = [model["observations"][0]]
        p = self.analyze(model).to_dict()["projections"][0]
        self.assertEqual((p["basis"], p["expected_decision"]), ("missing_principal", "unknown"))

    def test_exact_source_replay_rejects_readdressed_forgery(self) -> None:
        report = self.analyze()
        self.assertEqual(
            route_auth.verify_web_route_authorization(
                report,
                source_content=encoded(self.model),
                source_id=self.source_id,
            ),
            report,
        )
        modified = copy.deepcopy(self.model)
        modified["observations"][0]["server_outcome"] = "denied"
        with self.assertRaises(route_auth.WebRouteAuthorizationError):
            route_auth.verify_web_route_authorization(
                report,
                source_content=encoded(modified),
                source_id=self.source_id,
            )
        forged = report.to_dict()
        forged["projections"][0]["expected_decision"] = "allow"
        parsed = route_auth.WebRouteAuthorizationReport.from_json(
            encoded(readdress(forged)).decode("ascii")
        )
        with self.assertRaises(route_auth.WebRouteAuthorizationError):
            route_auth.verify_web_route_authorization(
                parsed,
                source_content=encoded(self.model),
                source_id=self.source_id,
            )

    def test_report_construction_and_export_reject_claim_forgery(self) -> None:
        report = self.analyze()
        self.assertEqual(route_auth.WebRouteAuthorizationReport(report.to_json()), report)
        with self.assertRaises(route_auth.WebRouteAuthorizationError):
            route_auth.WebRouteAuthorizationReport(" " + report.to_json())
        for section, key, value in (
            (None, "finding_claimed", True),
            ("effects", "network", "used"),
        ):
            forged = report.to_dict()
            if section is None:
                forged[key] = value
            else:
                forged[section][key] = value
            changed = encoded(readdress(forged)).decode("ascii")
            with self.assertRaises(route_auth.WebRouteAuthorizationError):
                route_auth.WebRouteAuthorizationReport.from_json(changed)
            damaged = route_auth.WebRouteAuthorizationReport(report.to_json())
            object.__setattr__(damaged, "_json", changed)
            with self.assertRaises(route_auth.WebRouteAuthorizationError):
                damaged.to_json()

    def test_native_adapter_is_detached_and_exact(self) -> None:
        model = {"source_id": self.source_id, "source": copy.deepcopy(self.model)}
        report = route_auth.analyze_supplied_web_route_authorization(model)
        self.assertEqual(report, self.analyze())
        model["source"]["routes"][0]["tenant_scope"] = "none"
        self.assertNotEqual(report, route_auth.analyze_supplied_web_route_authorization(model))
        for invalid in (
            {"source": self.model},
            {"source_id": self.source_id, "source": self.model, "extra": False},
            {"source_id": StringAlias(self.source_id), "source": self.model},
            {"source_id": self.source_id, "source": []},
            DictAlias({"source_id": self.source_id, "source": self.model}),
        ):
            with (
                self.subTest(invalid=invalid),
                self.assertRaises(route_auth.WebRouteAuthorizationError),
            ):
                route_auth.analyze_supplied_web_route_authorization(invalid)
        fixture = route_auth.component_fixture()
        fixture["routes"][0]["route_path"] = "/changed"
        self.assertEqual(
            route_auth.component_fixture()["routes"][0]["route_path"], "/workspace/settings"
        )

    def test_closed_model_and_ambiguous_path_rejection(self) -> None:
        invalid = []
        extra = copy.deepcopy(self.model)
        extra["target_url"] = "https://example.invalid"
        invalid.append(extra)
        for section, key in (
            ("principals", "principal_id"),
            ("routes", "route_id"),
            ("observations", "observation_id"),
        ):
            candidate = copy.deepcopy(self.model)
            candidate[section].append(copy.deepcopy(candidate[section][0]))
            invalid.append(candidate)
        for section, field, value in (
            ("routes", "route_path", "https://example.invalid/a"),
            ("routes", "route_path", "/a/../b"),
            ("routes", "route_path", "/a%2Fb"),
            ("routes", "tenant_scope", "tenant/*"),
            ("routes", "access", "guest"),
            ("routes", "required_role", 1),
            ("principals", "roles", ["admin", "admin"]),
            ("observations", "ui_visibility", "rendered"),
            ("observations", "server_outcome", "accepted"),
        ):
            candidate = copy.deepcopy(self.model)
            candidate[section][0][field] = value
            invalid.append(candidate)
        for field, value in (
            ("facts_complete", 1),
            ("policy_complete", "true"),
            ("schema_version", "v2"),
        ):
            candidate = copy.deepcopy(self.model)
            candidate[field] = value
            invalid.append(candidate)
        public_tenant = copy.deepcopy(self.model)
        public_tenant["routes"][0].update(access="public", required_role=None)
        invalid.append(public_tenant)
        for candidate in invalid:
            with (
                self.subTest(candidate=candidate),
                self.assertRaises(route_auth.WebRouteAuthorizationError),
            ):
                self.analyze(candidate)

    def test_duplicate_keys_and_bounded_raw_source(self) -> None:
        bad = [
            b'{"schema_version":"v1","schema_version":"v1"}',
            b'{"principals":[{"principal_id":"a","principal_id":"b"}]}',
            b'{"x":NaN}',
            b'{"x":1.3}',
            b'{"x":9223372036854775808}',
            b"\xff",
            b"[" * (route_auth.MAX_DEPTH + 1) + b"0" + b"]" * (route_auth.MAX_DEPTH + 1),
            b" " * (route_auth.MAX_SOURCE_BYTES + 1),
        ]
        for source in bad:
            with (
                self.subTest(source=source[:32]),
                self.assertRaises(route_auth.WebRouteAuthorizationError),
            ):
                route_auth.analyze_web_route_authorization(
                    source_content=source, source_id=self.source_id
                )
        for source, identity in (
            (BytesAlias(encoded(self.model)), self.source_id),
            (encoded(self.model), StringAlias(self.source_id)),
            (encoded(self.model), "https://not-a-source"),
        ):
            with self.assertRaises(route_auth.WebRouteAuthorizationError):
                route_auth.analyze_web_route_authorization(
                    source_content=source, source_id=identity
                )

    def test_array_bounds_and_empty_observations(self) -> None:
        model = copy.deepcopy(self.model)
        model["observations"] = []
        self.assertEqual(self.analyze(model).to_dict()["projections"], [])
        model = copy.deepcopy(self.model)
        model["principals"] = [
            {"principal_id": f"p-{index}", "tenant_id": "t", "roles": []}
            for index in range(route_auth.MAX_PRINCIPALS + 1)
        ]
        with self.assertRaises(route_auth.WebRouteAuthorizationError):
            self.analyze(model)

    def test_determinism_and_family_checks_without_side_effects(self) -> None:
        report = self.analyze()
        self.assertEqual(report.to_json(), self.analyze().to_json())
        self.assertEqual(
            route_auth.WebRouteAuthorizationReport.from_json("\n" + report.to_json() + "\n"), report
        )
        reversed_model = copy.deepcopy(self.model)
        reversed_model["observations"].reverse()
        self.assertEqual(
            self.analyze(reversed_model).to_dict()["projections"], report.to_dict()["projections"]
        )
        self.assertNotEqual(self.analyze(reversed_model).to_json(), report.to_json())
        with self.assertRaises(route_auth.WebRouteAuthorizationError):
            route_auth.verify_web_route_authorization(
                ReportAlias(report.to_json()),
                source_content=encoded(self.model),
                source_id=self.source_id,
            )
        with self.assertRaises(route_auth.WebRouteAuthorizationError):
            route_auth.WebRouteAuthorizationReport.from_json(StringAlias(report.to_json()))
        with patch("socket.create_connection", side_effect=AssertionError("network attempt")):
            with patch("subprocess.run", side_effect=AssertionError("process attempt")):
                self.assertEqual(
                    route_auth.verify_web_route_authorization(
                        report,
                        source_content=encoded(self.model),
                        source_id=self.source_id,
                    ),
                    report,
                )


if __name__ == "__main__":
    unittest.main()
