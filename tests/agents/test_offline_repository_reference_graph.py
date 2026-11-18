"""Supplied repository links do not prove visibility, ownership or live refs."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_repository_reference_graph import (
    RepositoryReferenceGraph,
    RepositoryReferenceGraphError,
    analyze_supplied_repository_references,
    verify_supplied_repository_references,
)


def _model() -> dict:
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-repository-reference-graph-v1",
        "repositories": [
            {
                "repo_id": "app",
                "owner_id": "org-a",
                "visibility": "private",
                "source_id": "fixture-inventory",
            },
            {
                "repo_id": "lib",
                "owner_id": "org-b",
                "visibility": "public",
                "source_id": "fixture-inventory",
            },
        ],
        "references": [
            {
                "reference_id": "external-branch",
                "from_repo_id": "app",
                "to_repo_id": "lib",
                "selector_kind": "branch",
                "selector": "main",
                "source_id": "fixture-manifest",
            },
            {
                "reference_id": "internal-commit",
                "from_repo_id": "app",
                "to_repo_id": "app",
                "selector_kind": "commit",
                "selector": "a" * 40,
                "source_id": "fixture-manifest",
            },
            {
                "reference_id": "unknown-tag",
                "from_repo_id": "app",
                "to_repo_id": "absent-repo",
                "selector_kind": "tag",
                "selector": "v1",
                "source_id": "fixture-manifest",
            },
        ],
    }


class RepositoryReferenceGraphTests(unittest.TestCase):
    def test_declared_owner_visibility_and_selector_classes_remain_distinct(self):
        model = _model()
        original = copy.deepcopy(model)
        report = analyze_supplied_repository_references(model)
        body = report.to_dict()
        rows = {row["reference_id"]: row for row in body["observations"]}
        self.assertEqual(rows["external-branch"]["owner_relation"], "different_declared_owner")
        self.assertEqual(rows["external-branch"]["target_visibility"], "public")
        self.assertEqual(rows["external-branch"]["selector_class"], "named_ref")
        self.assertEqual(rows["internal-commit"]["owner_relation"], "same_declared_owner")
        self.assertEqual(rows["internal-commit"]["selector_class"], "syntactic_commit_digest")
        self.assertEqual(rows["unknown-tag"]["owner_relation"], "unresolved_supplied_target")
        self.assertEqual(rows["unknown-tag"]["target_visibility"], "not_supplied")
        self.assertFalse(body["flags"]["commit_existence_proven"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        self.assertEqual(verify_supplied_repository_references(report, model=model).to_dict(), body)

    def test_invalid_source_ref_and_duplicate_signatures_are_refused(self):
        model = _model()
        model["references"][0]["from_repo_id"] = "missing"
        with self.assertRaises(RepositoryReferenceGraphError):
            analyze_supplied_repository_references(model)
        model = _model()
        model["references"][1]["selector"] = "a" * 39
        with self.assertRaises(RepositoryReferenceGraphError):
            analyze_supplied_repository_references(model)
        model = _model()
        model["references"].append({**model["references"][0], "reference_id": "duplicate"})
        with self.assertRaises(RepositoryReferenceGraphError):
            analyze_supplied_repository_references(model)

    def test_tampered_output_and_changed_model_are_refused(self):
        body = analyze_supplied_repository_references(_model()).to_dict()
        body["flags"]["repository_visibility_proven"] = True
        with self.assertRaises(RepositoryReferenceGraphError):
            RepositoryReferenceGraph(body)
        report = analyze_supplied_repository_references(_model())
        model = _model()
        model["repositories"][1]["visibility"] = "private"
        with self.assertRaises(RepositoryReferenceGraphError):
            verify_supplied_repository_references(report, model=model)


if __name__ == "__main__":
    unittest.main()
