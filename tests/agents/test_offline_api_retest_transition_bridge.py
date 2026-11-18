"""API retest transitions cannot detach from child source and world history."""

from __future__ import annotations

import copy
import unittest

import tests.agents.test_offline_api_retest_lineage as lineage_fixture
from sunderkey.offline_api_retest_lineage import build_initial_offline_api_retest_lineage
from sunderkey.offline_api_retest_transition_bridge import (
    OfflineApiRetestTransitionError,
    build_offline_api_retest_transition,
    verify_offline_api_retest_transition,
)


class OfflineApiRetestTransitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        lineage_fixture.OfflineApiRetestLineageTests.setUpClass()

    def setUp(self) -> None:
        fixture = lineage_fixture.OfflineApiRetestLineageTests(
            "test_positive_to_negative_retest_is_one_custody_bound_child"
        )
        self.fixture = fixture
        self.first = build_initial_offline_api_retest_lineage(**fixture.options(0))
        second = fixture.options(1)
        self.options = {
            "prior_lineage": self.first,
            "prior_source": fixture.values[0][0],
            "second_source": fixture.values[1][0],
            "second_batch": second["batch"],
            "second_projection": second["projection"],
            "adapter": fixture.adapter,
            "observed_at": second["observed_at"],
            "expires_at": second["expires_at"],
        }

    def test_negative_retest_transition_binds_child_without_fix_claim(self) -> None:
        transition = build_offline_api_retest_transition(**self.options)
        self.assertEqual(
            verify_offline_api_retest_transition(document=transition, **self.options),
            transition,
        )
        self.assertEqual(
            transition["observation_change"],
            "prior_signal_not_observed_in_second_synthetic_case",
        )
        self.assertEqual(transition["review_status"], "not_reviewed")
        self.assertEqual(transition["remediation_status"], "not_claimed")
        self.assertEqual(transition["effects"]["finding_publication"], "none")
        self.assertEqual(len(transition["child_lineage"]["world_snapshot"]["conflicts"]), 1)

    def test_unrelated_prior_replay_and_tamper_fail(self) -> None:
        with self.assertRaisesRegex(OfflineApiRetestTransitionError, "absent"):
            build_offline_api_retest_transition(
                **{**self.options, "prior_source": self.fixture.values[1][0]}
            )
        with self.assertRaisesRegex(OfflineApiRetestTransitionError, "sources"):
            build_offline_api_retest_transition(
                **{**self.options, "second_source": self.fixture.values[0][0]}
            )
        transition = build_offline_api_retest_transition(**self.options)
        changed = copy.deepcopy(transition)
        changed["review_status"] = "accepted"
        with self.assertRaisesRegex(OfflineApiRetestTransitionError, "does not match"):
            verify_offline_api_retest_transition(document=changed, **self.options)


if __name__ == "__main__":
    unittest.main()
