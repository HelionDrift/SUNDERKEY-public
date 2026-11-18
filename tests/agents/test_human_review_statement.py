"""Non-authorizing, signed historical review opinion tests."""

from __future__ import annotations

import base64
import copy
import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from jsonschema import Draft202012Validator

from sunderkey.expert_review import ReviewerRole
from sunderkey.human_review_statement import (
    HumanReviewStatementError,
    build_human_review_statement,
    human_review_statement_signing_bytes,
    verify_human_review_statement,
)

from .test_human_escalation_routing import AT, case, plan, reviewer

SCHEMA = (
    Path(__file__).resolve().parents[2]
    / "registry/schemas/human-review-statement-v1.schema.json"
)
RATIONALE = "sha256:" + "c" * 64


class HumanReviewStatementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = plan(
            (case(),),
            (
                reviewer("principal:technical", team="team:origin"),
                reviewer("principal:control"),
                reviewer("principal:assurance"),
            ),
        )
        self.slot = next(
            item for item in self.plan.slots
            if item.role is ReviewerRole.INDEPENDENT_CONTROL
        )
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def _unsigned(self, **changes):
        values = {
            "case_id": self.slot.case_id,
            "role": self.slot.role,
            "reviewer_id": self.slot.reviewer_id,
            "disposition": "challenges",
            "rationale_sha256": RATIONALE,
            "reviewed_at": AT,
            "pinned_public_key": self.public,
        }
        values.update(changes)
        return build_human_review_statement(self.plan, **values)

    def _signed(self, **changes):
        unsigned = self._unsigned(**changes)
        signature = self.private.sign(human_review_statement_signing_bytes(unsigned))
        return {
            **unsigned,
            "signature_b64url": base64.urlsafe_b64encode(signature).decode().rstrip("="),
        }

    def test_exact_selected_slot_and_signature_verify_without_approval(self) -> None:
        record = self._signed()
        self.assertEqual(
            verify_human_review_statement(
                json.dumps(record), self.plan, pinned_public_key=self.public
            ),
            record,
        )
        self.assertEqual(record["routing_plan_sha256"], self.plan.plan_sha256)
        self.assertEqual(record["role"], ReviewerRole.INDEPENDENT_CONTROL.value)
        self.assertEqual(record["effects"]["review_approval"], "none")
        self.assertEqual(record["effects"]["authority"], "none")
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(record)

    def test_wrong_slot_unfilled_slot_and_out_of_window_time_fail(self) -> None:
        with self.assertRaises(HumanReviewStatementError):
            self._unsigned(reviewer_id="principal:technical")
        with self.assertRaises(HumanReviewStatementError):
            self._unsigned(reviewed_at="2026-09-23T14:00:00Z")
        with self.assertRaises(HumanReviewStatementError):
            self._unsigned(reviewed_at="2026-09-23T12:59:59Z")
        unfilled = plan((case(),), ())
        with self.assertRaises(HumanReviewStatementError):
            build_human_review_statement(
                unfilled, case_id="case:one", role=ReviewerRole.INDEPENDENT_CONTROL,
                reviewer_id="principal:control", disposition="supports",
                rationale_sha256=RATIONALE, reviewed_at=AT,
                pinned_public_key=self.public,
            )

    def test_substituted_signature_source_and_effects_fail(self) -> None:
        record = self._signed()
        other_key = Ed25519PrivateKey.generate().public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        with self.assertRaises(HumanReviewStatementError):
            verify_human_review_statement(
                record, self.plan, pinned_public_key=other_key
            )
        changed = copy.deepcopy(record)
        changed["disposition"] = "supports"
        with self.assertRaises(HumanReviewStatementError):
            verify_human_review_statement(
                changed, self.plan, pinned_public_key=self.public
            )
        changed = copy.deepcopy(record)
        changed["effects"]["review_approval"] = "accepted"
        with self.assertRaises(HumanReviewStatementError):
            human_review_statement_signing_bytes({
                key: value for key, value in changed.items()
                if key != "signature_b64url"
            })
        with self.assertRaises(HumanReviewStatementError):
            verify_human_review_statement(
                changed, self.plan, pinned_public_key=self.public
            )
        with self.assertRaises(HumanReviewStatementError):
            verify_human_review_statement(
                '{"schema_version":1,"schema_version":1}', self.plan,
                pinned_public_key=self.public,
            )

    def test_tampered_plan_cannot_be_used_as_source(self) -> None:
        record = self._signed()
        object.__setattr__(self.plan, "plan_sha256", "sha256:" + "0" * 64)
        with self.assertRaises(HumanReviewStatementError):
            verify_human_review_statement(
                record, self.plan, pinned_public_key=self.public
            )


if __name__ == "__main__":
    unittest.main()
