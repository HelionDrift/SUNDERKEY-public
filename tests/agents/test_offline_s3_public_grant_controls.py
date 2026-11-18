"""Offline supplied S3 public-grant control regressions."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_s3_public_grant_controls import (
    S3PublicGrantControlsError,
    analyze_supplied_s3_public_grants,
    component_fixture,
    verify_supplied_s3_public_grants,
    verify_supplied_s3_public_grants_bytes,
)


class S3PublicGrantControlsTests(unittest.TestCase):
    def test_future_write_blocks_do_not_suppress_existing_grants(self) -> None:
        model = component_fixture()
        report = analyze_supplied_s3_public_grants(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 2)
        self.assertEqual(body["effective_controls"]["block_public_acls"], True)
        self.assertEqual(body["effective_controls"]["block_public_policy"], True)
        self.assertFalse(body["public_reachability_claimed"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(
            verify_supplied_s3_public_grants(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_s3_public_grants_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_effective_suppression_and_missing_root_stay_distinct(self) -> None:
        model = component_fixture()
        model["organization_controls"]["ignore_public_acls"] = True
        model["account_controls"]["restrict_public_buckets"] = True
        body = analyze_supplied_s3_public_grants(model).to_dict()
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(
            [row["disposition"] for row in body["grant_path_projections"]],
            ["public_acl_ignored", "public_policy_restricted"],
        )
        model = component_fixture()
        model["organization_controls"]["ignore_public_acls"] = None
        self.assertEqual(analyze_supplied_s3_public_grants(model).to_dict()["unknown_count"], 1)
        model["bucket_owner_enforced"] = True
        body = analyze_supplied_s3_public_grants(model).to_dict()
        self.assertEqual(
            body["grant_path_projections"][0]["disposition"], "acl_disabled_by_object_ownership"
        )

    def test_replay_rejects_changed_source_and_forged_report(self) -> None:
        model = component_fixture()
        report = analyze_supplied_s3_public_grants(model)
        changed = copy.deepcopy(model)
        changed["bucket_controls"]["restrict_public_buckets"] = True
        with self.assertRaises(S3PublicGrantControlsError):
            verify_supplied_s3_public_grants(report, model=changed)
        with self.assertRaises(S3PublicGrantControlsError):
            verify_supplied_s3_public_grants(report.to_dict(), model=model)
        with self.assertRaises(S3PublicGrantControlsError):
            verify_supplied_s3_public_grants_bytes(b"{}", model=model)

    def test_rejects_unknown_setting_name_and_nonboolean(self) -> None:
        model = component_fixture()
        model["bucket_controls"]["invented"] = True
        with self.assertRaises(ValueError):
            analyze_supplied_s3_public_grants(model)
        model = component_fixture()
        model["public_read_acl"] = 1
        with self.assertRaises(S3PublicGrantControlsError):
            analyze_supplied_s3_public_grants(model)


if __name__ == "__main__":
    unittest.main()
