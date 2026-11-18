"""Synthetic mailbox-forwarding projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_mailbox_forwarding_policy import (
    MailboxForwardingPolicyError,
    MailboxForwardingPolicyReport,
    analyze_supplied_mailbox_forwarding,
    component_fixture,
    verify_supplied_mailbox_forwarding,
)


class MailboxForwardingPolicyTests(unittest.TestCase):
    def test_declared_gap_is_not_delivered_mail_finding(self) -> None:
        report = analyze_supplied_mailbox_forwarding(component_fixture()).to_dict()
        self.assertEqual(report["declared_policy_deviation_mailbox_ids"], ["mailbox-a"])
        self.assertEqual(len(report["mailbox_projections"][0]["declared_policy_flags"]), 2)
        self.assertFalse(report["tenant_connected"])
        self.assertFalse(report["mailbox_content_read"])
        self.assertFalse(report["forwarding_setting_verified"])
        self.assertFalse(report["message_sent"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_inactive_forward_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["mailboxes"][0]["external_forward_declared"] = False
        model["mailboxes"][0]["destination_domain_id"] = None
        report = analyze_supplied_mailbox_forwarding(model).to_dict()
        self.assertEqual(report["declared_policy_deviation_mailbox_ids"], [])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_unknown_policy_missing_destination_and_nonfixture(self) -> None:
        model = component_fixture()
        model["mailboxes"][0]["policy_id"] = "unknown"
        with self.assertRaises(MailboxForwardingPolicyError):
            analyze_supplied_mailbox_forwarding(model)
        model = component_fixture()
        model["mailboxes"][0]["destination_domain_id"] = None
        with self.assertRaises(MailboxForwardingPolicyError):
            analyze_supplied_mailbox_forwarding(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(MailboxForwardingPolicyError):
            analyze_supplied_mailbox_forwarding(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_mailbox_forwarding(model)
        self.assertEqual(
            verify_supplied_mailbox_forwarding(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["mailboxes"][0]["destination_domain_id"] = "another-example"
        with self.assertRaises(MailboxForwardingPolicyError):
            verify_supplied_mailbox_forwarding(report, model=changed)
        with self.assertRaises(MailboxForwardingPolicyError):
            MailboxForwardingPolicyReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()
