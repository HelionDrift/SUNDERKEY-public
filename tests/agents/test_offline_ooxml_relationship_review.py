"""Synthetic OOXML relationship tests preserve delivery uncertainty."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_ooxml_relationship_review import (
    OoxmlRelationshipReviewError,
    OoxmlRelationshipReviewReport,
    analyze_supplied_ooxml_relationships,
    component_fixture,
    verify_supplied_ooxml_relationships,
)


class OoxmlRelationshipReviewTests(unittest.TestCase):
    def test_external_declaration_does_not_claim_fetch_or_delivery(self) -> None:
        report = analyze_supplied_ooxml_relationships(component_fixture())
        body = report.to_dict()
        self.assertEqual(body["relationship_count"], 2)
        self.assertEqual(body["external_relationship_count"], 1)
        self.assertEqual(body["internal_relationship_count"], 1)
        self.assertFalse(body["external_target_reachable"])
        self.assertFalse(body["document_delivered"])
        self.assertEqual(body["candidate_count"], 0)
        self.assertNotIn("resource.synthetic.example", report.to_json())

    def test_relative_external_target_remains_unresolved(self) -> None:
        model = component_fixture()
        model["relationships_xml"] = model["relationships_xml"].replace(
            "https://resource.synthetic.example/info", "linked/resource.xml"
        )
        body = analyze_supplied_ooxml_relationships(model).to_dict()
        self.assertTrue(body["external_relationships"][0]["target_is_relative"])
        self.assertFalse(body["external_target_reachable"])

    def test_dtd_duplicate_id_and_nested_relationship_rejected(self) -> None:
        model = component_fixture()
        model["relationships_xml"] = '<!DOCTYPE a [<!ENTITY x "y">]>' + model[
            "relationships_xml"
        ]
        with self.assertRaises(OoxmlRelationshipReviewError):
            analyze_supplied_ooxml_relationships(model)
        model = component_fixture()
        model["relationships_xml"] = model["relationships_xml"].replace('Id="rId2"', 'Id="rId1"')
        with self.assertRaises(OoxmlRelationshipReviewError):
            analyze_supplied_ooxml_relationships(model)
        model = component_fixture()
        model["relationships_xml"] = model["relationships_xml"].replace(
            'Target="word/document.xml"/>', 'Target="word/document.xml"><Nested/></Relationship>'
        )
        with self.assertRaises(OoxmlRelationshipReviewError):
            analyze_supplied_ooxml_relationships(model)

    def test_bad_mode_or_target_and_nonsynthetic_source_rejected(self) -> None:
        model = component_fixture()
        model["relationships_xml"] = model["relationships_xml"].replace(
            'TargetMode="External"', 'TargetMode="Unknown"'
        )
        with self.assertRaises(OoxmlRelationshipReviewError):
            analyze_supplied_ooxml_relationships(model)
        model = component_fixture()
        model["relationships_xml"] = model["relationships_xml"].replace(
            "https://resource.synthetic.example/info", "file:///tmp/local"
        )
        with self.assertRaises(OoxmlRelationshipReviewError):
            analyze_supplied_ooxml_relationships(model)
        model = component_fixture()
        model["relationships_xml"] = model["relationships_xml"].replace(
            "https://resource.synthetic.example/info", "https:resource"
        )
        with self.assertRaises(OoxmlRelationshipReviewError):
            analyze_supplied_ooxml_relationships(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(OoxmlRelationshipReviewError):
            analyze_supplied_ooxml_relationships(model)

    def test_replay_requires_separate_original_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_ooxml_relationships(model)
        self.assertEqual(
            verify_supplied_ooxml_relationships(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["relationships_xml"] = changed["relationships_xml"].replace(
            "resource.synthetic.example", "other.synthetic.example"
        )
        with self.assertRaises(OoxmlRelationshipReviewError):
            verify_supplied_ooxml_relationships(report, model=changed)
        with self.assertRaises(OoxmlRelationshipReviewError):
            OoxmlRelationshipReviewReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
