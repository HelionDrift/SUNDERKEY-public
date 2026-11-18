"""Supplied SaaS signals are only exact-domain correlation hypotheses."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_saas_signal_correlation import (
    SaasSignalAnalysis,
    SaasSignalCorrelationError,
    analyze_supplied_saas_signals,
    verify_supplied_saas_signals,
)


def _model() -> dict:
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-saas-signal-correlation-v1",
        "catalog_domains": ["managed.example"],
        "signals": [
            {
                "signal_id": "idp-one",
                "kind": "idp_app",
                "domain": "unlisted.example",
                "source_id": "fixture-idp",
            },
            {
                "signal_id": "dns-one",
                "kind": "dns_alias",
                "domain": "unlisted.example",
                "source_id": "fixture-dns",
            },
            {
                "signal_id": "catalog-one",
                "kind": "managed_catalog",
                "domain": "managed.example",
                "source_id": "fixture-catalog",
            },
            {
                "signal_id": "subdomain-one",
                "kind": "egress_domain",
                "domain": "sub.managed.example",
                "source_id": "fixture-egress",
            },
        ],
    }


class SaasSignalCorrelationTests(unittest.TestCase):
    def test_exact_domain_join_and_unverified_catalog_status(self):
        model = _model()
        original = copy.deepcopy(model)
        analysis = analyze_supplied_saas_signals(model)
        report = analysis.to_dict()
        rows = {row["domain"]: row for row in report["observations"]}
        self.assertEqual(
            rows["unlisted.example"]["corroboration_status"], "multiple_supplied_signal_kinds"
        )
        self.assertEqual(rows["unlisted.example"]["source_ids"], ["fixture-dns", "fixture-idp"])
        self.assertEqual(
            rows["unlisted.example"]["catalog_status"], "not_listed_in_supplied_catalog"
        )
        self.assertEqual(rows["managed.example"]["catalog_status"], "listed_in_supplied_catalog")
        self.assertEqual(
            rows["sub.managed.example"]["catalog_status"], "not_listed_in_supplied_catalog"
        )
        self.assertFalse(report["flags"]["unauthorized_use_proven"])
        self.assertEqual(set(report["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        self.assertEqual(verify_supplied_saas_signals(analysis, model=model).to_dict(), report)

    def test_noncanonical_domains_and_duplicate_signals_are_refused(self):
        for invalid in ("Managed.example", "*.managed.example", "managed.example.", "127.0.0.1"):
            with self.subTest(invalid=invalid):
                model = _model()
                model["signals"][0]["domain"] = invalid
                with self.assertRaises(SaasSignalCorrelationError):
                    analyze_supplied_saas_signals(model)
        model = _model()
        model["signals"].append({**model["signals"][0], "signal_id": "new-id"})
        with self.assertRaises(SaasSignalCorrelationError):
            analyze_supplied_saas_signals(model)
        model = _model()
        model["catalog_domains"].append("managed.example")
        with self.assertRaises(SaasSignalCorrelationError):
            analyze_supplied_saas_signals(model)

    def test_tampered_or_changed_source_models_are_refused(self):
        report = analyze_supplied_saas_signals(_model()).to_dict()
        report["flags"]["saas_use_proven"] = True
        with self.assertRaises(SaasSignalCorrelationError):
            SaasSignalAnalysis(report)
        analysis = analyze_supplied_saas_signals(_model())
        model = _model()
        model["catalog_domains"].append("unlisted.example")
        with self.assertRaises(SaasSignalCorrelationError):
            verify_supplied_saas_signals(analysis, model=model)


if __name__ == "__main__":
    unittest.main()
