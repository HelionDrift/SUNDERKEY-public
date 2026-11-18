"""Historical signed opinions never become threat-test authorization."""

from __future__ import annotations

import base64
import copy
import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

from sunderkey.emerging_threat_review import build_emerging_threat_review
from sunderkey.emerging_threat_review_statement import (
    EmergingThreatReviewStatementError,
    build_emerging_threat_review_statement,
    emerging_threat_review_statement_signing_bytes,
    verify_emerging_threat_review_statement,
)

from .test_emerging_threat_review import NOW, sources

SIGNED_AT = "2026-10-03T23:00:00Z"
RATIONALE = "sha256:" + "d" * 64


def signed_fixture() -> tuple[dict, dict, dict, dict, bytes]:
    advisory, inventory = sources()
    review = build_emerging_threat_review(advisory, inventory, NOW)
    signer = Ed25519PrivateKey.generate()
    public_key = signer.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    unsigned = build_emerging_threat_review_statement(
        advisory, inventory, NOW, review,
        reviewer_id="reviewer-synthetic-01",
        claimed_role="independent_control",
        disposition="insufficient_evidence",
        rationale_sha256=RATIONALE,
        signed_at=SIGNED_AT,
        pinned_public_key=public_key,
    )
    signature = signer.sign(emerging_threat_review_statement_signing_bytes(unsigned))
    signed = {
        **unsigned,
        "signature_b64url": base64.urlsafe_b64encode(signature).rstrip(b"=").decode(),
    }
    return advisory, inventory, review, signed, public_key


class EmergingThreatReviewStatementTests(unittest.TestCase):
    def test_externally_signed_opinion_replays_without_authority(self) -> None:
        advisory, inventory, review, signed, public_key = signed_fixture()
        result = verify_emerging_threat_review_statement(
            signed, advisory, inventory, NOW, review, pinned_public_key=public_key
        )
        self.assertEqual(result["status"], "valid_historical_opinion_only")
        self.assertEqual(result["qualification_effect"], "none")
        self.assertEqual(signed["effects"]["test_execution"], "none")
        self.assertEqual(signed["effects"]["review_approval"], "none")

    def test_changed_source_signature_key_and_claim_fail(self) -> None:
        advisory, inventory, review, signed, public_key = signed_fixture()
        substitutions = []
        changed = copy.deepcopy(signed)
        changed["disposition"] = "supports"
        substitutions.append((changed, advisory, inventory, review, public_key))
        changed = copy.deepcopy(signed)
        changed["signature_b64url"] = "A" * 86
        substitutions.append((changed, advisory, inventory, review, public_key))
        changed = copy.deepcopy(signed)
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        final_index = alphabet.index(changed["signature_b64url"][-1])
        changed["signature_b64url"] = (
            changed["signature_b64url"][:-1] + alphabet[final_index ^ 1]
        )
        substitutions.append((changed, advisory, inventory, review, public_key))
        changed = copy.deepcopy(advisory)
        changed["source_sha256"] = "sha256:" + "e" * 64
        substitutions.append((signed, changed, inventory, review, public_key))
        changed = copy.deepcopy(review)
        changed["candidate_count"] = 0
        substitutions.append((signed, advisory, inventory, changed, public_key))
        substitutions.append((signed, advisory, inventory, review, b"x" * 32))
        for payload, source, assets, packet, key in substitutions:
            with self.subTest(payload=payload, key=key):
                with self.assertRaises(EmergingThreatReviewStatementError):
                    verify_emerging_threat_review_statement(
                        payload, source, assets, NOW, packet, pinned_public_key=key
                    )

    def test_review_window_and_roles_are_bounded(self) -> None:
        advisory, inventory, review, _, public_key = signed_fixture()
        for override in (
            {"claimed_role": "model"},
            {"reviewer_id": ""},
            {"disposition": "approved"},
            {"rationale_sha256": "bad"},
            {"signed_at": "2026-10-11T22:00:01Z"},
            {"signed_at": "2026-10-03T21:59:59Z"},
        ):
            values = {
                "reviewer_id": "reviewer-synthetic-01",
                "claimed_role": "independent_control",
                "disposition": "supports",
                "rationale_sha256": RATIONALE,
                "signed_at": SIGNED_AT,
                "pinned_public_key": public_key,
                **override,
            }
            with self.subTest(override=override):
                with self.assertRaises(EmergingThreatReviewStatementError):
                    build_emerging_threat_review_statement(
                        advisory, inventory, NOW, review, **values
                    )

    def test_nondefault_inventory_age_is_part_of_review_replay(self) -> None:
        advisory, inventory = sources()
        review = build_emerging_threat_review(
            advisory, inventory, NOW, maximum_inventory_age_seconds=3600
        )
        signer = Ed25519PrivateKey.generate()
        public_key = signer.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        arguments = {
            "reviewer_id": "reviewer-synthetic-01",
            "claimed_role": "independent_control",
            "disposition": "insufficient_evidence",
            "rationale_sha256": RATIONALE,
            "signed_at": SIGNED_AT,
            "pinned_public_key": public_key,
        }
        with self.assertRaises(EmergingThreatReviewStatementError):
            build_emerging_threat_review_statement(
                advisory, inventory, NOW, review, **arguments
            )
        unsigned = build_emerging_threat_review_statement(
            advisory, inventory, NOW, review,
            maximum_inventory_age_seconds=3600, **arguments
        )
        signature = signer.sign(emerging_threat_review_statement_signing_bytes(unsigned))
        signed = {
            **unsigned,
            "signature_b64url": base64.urlsafe_b64encode(signature).rstrip(b"=").decode(),
        }
        self.assertEqual(
            verify_emerging_threat_review_statement(
                signed, advisory, inventory, NOW, review,
                pinned_public_key=public_key, maximum_inventory_age_seconds=3600,
            )["status"],
            "valid_historical_opinion_only",
        )

    def test_unsigned_and_signed_shapes_match_schema(self) -> None:
        _, _, _, signed, _ = signed_fixture()
        path = (
            Path(__file__).resolve().parents[2]
            / "registry/schemas/emerging-threat-review-statement-v1.schema.json"
        )
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(signed)


if __name__ == "__main__":
    unittest.main()
