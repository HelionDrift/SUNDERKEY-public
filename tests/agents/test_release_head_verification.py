"""Offline D012 release-head verification against explicit caller trust anchors."""

from __future__ import annotations

import hashlib
import unittest
from dataclasses import replace
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sunderkey import release_head_verification as verification
from sunderkey.candidate_enrollment_production_custody_contract import (
    LedgerHeadDescriptor,
    SignedReleaseHeadDescriptor,
    provider_subject_sha256,
)
from sunderkey.release_head_signing_profile import signed_release_head_signing_bytes

ROOT = "sha256:" + "b" * 64
SIGNER = "key.release.offline"
DEPLOYMENT = "deployment.offline"
PRIVATE = Ed25519PrivateKey.from_private_bytes(b"\x42" * 32)
PUBLIC = PRIVATE.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)
PUBLIC_DIGEST = "sha256:" + hashlib.sha256(PUBLIC).hexdigest()


def _head(previous: LedgerHeadDescriptor | None = None) -> LedgerHeadDescriptor:
    return LedgerHeadDescriptor(
        DEPLOYMENT,
        1 if previous is None else previous.ledger_sequence + 1,
        "entry.genesis" if previous is None else "entry.successor",
        "sha256:" + ("a" if previous is None else "c") * 64,
        None if previous is None else provider_subject_sha256(previous),
    )


def _signed(head: LedgerHeadDescriptor) -> SignedReleaseHeadDescriptor:
    unsigned = SignedReleaseHeadDescriptor(
        head, SIGNER, ROOT, "Ed25519", bytes(64), "2026-09-28T12:34:56Z"
    )
    return replace(unsigned, signature=PRIVATE.sign(signed_release_head_signing_bytes(unsigned)))


def _anchor(previous: LedgerHeadDescriptor | None = None) -> verification.ReleaseHeadTrustAnchor:
    return verification.ReleaseHeadTrustAnchor(DEPLOYMENT, SIGNER, PUBLIC_DIGEST, ROOT, previous)


class OfflineReleaseHeadVerificationTests(unittest.TestCase):
    def test_genesis_and_successor_are_verified_without_authority(self):
        genesis = _head()
        for head, previous in ((genesis, None), (_head(genesis), genesis)):
            with self.subTest(sequence=head.ledger_sequence):
                signed = _signed(head)
                result = verification.verify_release_head_offline(signed, PUBLIC, _anchor(previous))
                self.assertIs(type(result), verification.OfflineReleaseHeadVerificationPreview)
                self.assertEqual(result.head_sha256, provider_subject_sha256(head))
                self.assertEqual(
                    result.signing_input_sha256,
                    "sha256:"
                    + hashlib.sha256(signed_release_head_signing_bytes(signed)).hexdigest(),
                )
                self.assertTrue(result.signature_verified)
                self.assertTrue(result.predecessor_verified)
                self.assertTrue(result.rollback_checked)
                self.assertEqual(result.qualification_effect, "none")
                self.assertEqual(result.authority_effect, "none")
                self.assertFalse(result.network_call_performed)
                self.assertFalse(result.provider_call_performed)

    def test_signature_tampering_and_wrong_key_reject(self):
        signed = _signed(_head())
        other_private = Ed25519PrivateKey.from_private_bytes(b"\x43" * 32)
        other_public = other_private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        other_digest = "sha256:" + hashlib.sha256(other_public).hexdigest()
        for altered, public, anchor in (
            (replace(signed, signature=b"\x00" * 64), PUBLIC, _anchor()),
            (signed, other_public, _anchor()),
            (signed, other_public, replace(_anchor(), public_key_sha256=other_digest)),
        ):
            with (
                self.subTest(public=public, signature=altered.signature[:2]),
                self.assertRaises(verification.ReleaseHeadVerificationError),
            ):
                verification.verify_release_head_offline(altered, public, anchor)

    def test_key_root_signer_and_deployment_trust_changes_reject(self):
        signed = _signed(_head())
        changes = (
            {"public_key_sha256": "sha256:" + "f" * 64},
            {"signer_key_id": "key.other"},
            {"offline_root_authorization_sha256": "sha256:" + "e" * 64},
            {"deployment_id": "deployment.other"},
        )
        for change in changes:
            with (
                self.subTest(change=change),
                self.assertRaises(verification.ReleaseHeadVerificationError),
            ):
                verification.verify_release_head_offline(
                    signed, PUBLIC, replace(_anchor(), **change)
                )

    def test_fork_rollback_and_missing_predecessor_reject(self):
        genesis = _head()
        successor = _signed(_head(genesis))
        alternate = replace(genesis, entry_id="entry.alternate")
        for signed, anchor in (
            (successor, _anchor()),
            (successor, _anchor(alternate)),
            (_signed(genesis), _anchor(genesis)),
        ):
            with (
                self.subTest(sequence=signed.head.ledger_sequence),
                self.assertRaises(verification.ReleaseHeadVerificationError),
            ):
                verification.verify_release_head_offline(signed, PUBLIC, anchor)

    def test_native_bounded_public_inputs_reject(self):
        signed = _signed(_head())
        for key in (b"", b"x" * 31, bytearray(PUBLIC)):
            with (
                self.subTest(key_type=type(key).__name__),
                self.assertRaises(verification.ReleaseHeadVerificationError),
            ):
                verification.verify_release_head_offline(signed, key, _anchor())
        with self.assertRaises(verification.ReleaseHeadVerificationError):
            verification.ReleaseHeadTrustAnchor(
                DEPLOYMENT,
                SIGNER,
                PUBLIC_DIGEST,
                ROOT,
                replace(_head(), deployment_id="other"),
            )

    def test_preview_cannot_claim_authority_or_qualification(self):
        preview = verification.verify_release_head_offline(_signed(_head()), PUBLIC, _anchor())
        for change in (
            {"qualification_effect": "qualified"},
            {"authority_effect": "release_admitted"},
            {"signature_verified": False},
            {"provider_call_performed": True},
        ):
            with (
                self.subTest(change=change),
                self.assertRaises(verification.ReleaseHeadVerificationError),
            ):
                replace(preview, **change)

    def test_late_signed_head_and_anchor_mutations_fail_closed(self):
        for mutation in (
            lambda signed, anchor: object.__setattr__(signed.head, "entry_id", "entry.late"),
            lambda signed, anchor: object.__setattr__(signed, "signature", b"x" * 64),
            lambda signed, anchor: object.__setattr__(anchor, "signer_key_id", "key.late"),
        ):
            signed = _signed(_head())
            anchor = _anchor()

            def changed_verification(
                public_key_bytes,
                signature,
                signing_bytes,
                mutation=mutation,
                signed=signed,
                anchor=anchor,
            ):
                mutation(signed, anchor)

            with (
                self.subTest(mutation=mutation),
                patch.object(verification, "_verify_signature", side_effect=changed_verification),
                self.assertRaisesRegex(verification.ReleaseHeadVerificationError, "changed"),
            ):
                verification.verify_release_head_offline(signed, PUBLIC, anchor)

    def test_late_predecessor_mutation_fails_closed(self):
        predecessor = _head()
        signed = _signed(_head(predecessor))
        anchor = _anchor(predecessor)

        def changed_verification(public_key_bytes, signature, signing_bytes):
            object.__setattr__(predecessor, "entry_id", "entry.late")

        with (
            patch.object(verification, "_verify_signature", side_effect=changed_verification),
            self.assertRaisesRegex(verification.ReleaseHeadVerificationError, "changed"),
        ):
            verification.verify_release_head_offline(signed, PUBLIC, anchor)

    def test_digest_step_cannot_change_returned_signer(self):
        signed = _signed(_head())
        anchor = _anchor()
        original_digest = verification.provider_subject_sha256

        def mutate_anchor(head):
            object.__setattr__(anchor, "signer_key_id", "key.attacker")
            return original_digest(head)

        with (
            patch.object(
                verification, "provider_subject_sha256", side_effect=mutate_anchor
            ),
            self.assertRaisesRegex(verification.ReleaseHeadVerificationError, "changed"),
        ):
            verification.verify_release_head_offline(signed, PUBLIC, anchor)


if __name__ == "__main__":
    unittest.main()
