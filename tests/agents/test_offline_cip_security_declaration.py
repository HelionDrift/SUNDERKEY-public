"""Supplied CIP Security property requirement and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_cip_security_declaration import (
    CipSecurityDeclarationError,
    analyze_supplied_cip_security,
    component_fixture,
    verify_supplied_cip_security,
    verify_supplied_cip_security_bytes,
)


class CipSecurityDeclarationTests(unittest.TestCase):
    def test_unmet_required_property_is_inert_candidate(self) -> None:
        model = component_fixture()
        report = analyze_supplied_cip_security(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(
            body["connection_projections"][0]["unmet_property_labels"],
            ["message_confidentiality"],
        )
        self.assertFalse(body["industrial_network_contacted"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_cip_security(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_cip_security_bytes(report.to_json().encode(), model=model).to_json(),
            report.to_json(),
        )

    def test_optional_confidentiality_and_incomplete_context(self) -> None:
        model = component_fixture()
        model["connections"][0]["confidentiality_required"] = False
        self.assertEqual(analyze_supplied_cip_security(model).to_dict()["candidate_count"], 0)
        model["connections"][0]["context_complete"] = False
        self.assertEqual(analyze_supplied_cip_security(model).to_dict()["unknown_count"], 1)

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_cip_security(model)
        changed = copy.deepcopy(model)
        changed["connections"][0]["encryption_declared"] = True
        with self.assertRaises(CipSecurityDeclarationError):
            verify_supplied_cip_security(report, model=changed)
        with self.assertRaises(CipSecurityDeclarationError):
            verify_supplied_cip_security(report.to_dict(), model=model)
        with self.assertRaises(CipSecurityDeclarationError):
            verify_supplied_cip_security_bytes(b"{}", model=model)

    def test_rejects_duplicate_connection_and_non_boolean_control(self) -> None:
        model = component_fixture()
        model["connections"].append(copy.deepcopy(model["connections"][0]))
        with self.assertRaises(CipSecurityDeclarationError):
            analyze_supplied_cip_security(model)
        model = component_fixture()
        model["connections"][0]["integrity_required"] = 1
        with self.assertRaises(ValueError):
            analyze_supplied_cip_security(model)


if __name__ == "__main__":
    unittest.main()
