"""Command line coverage for Phase 4 trust bootstrap operations."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sunderkey.cli import main
from sunderkey.identity import (
    PrincipalOperation,
    PrincipalTrustPolicy,
    TrustKeyState,
    TrustKeyUse,
)
from sunderkey.store import format_timestamp

ZERO_SIGNATURE = (
    base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode("ascii")
)


def run_cli(*arguments: str) -> dict[str, object]:
    output = io.StringIO()
    with patch("sys.argv", ["sunderkey", *arguments]), redirect_stdout(output):
        main()
    return json.loads(output.getvalue())


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def public_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def signed_policy(
    root_private: Ed25519PrivateKey,
    assertion_private: Ed25519PrivateKey,
    store_id: str,
) -> PrincipalTrustPolicy:
    now = datetime.now(UTC).replace(microsecond=0)
    operation = PrincipalOperation.MISSION_STOP.value
    raw = {
        "schema_version": 1,
        "policy_id": "POLICY-CLI-PHASE4",
        "policy_version": 1,
        "issuer": "sunderkey-security",
        "audience": "sunderkey-runtime",
        "store_id": store_id,
        "issued_at": format_timestamp(now - timedelta(minutes=1)),
        "not_before": format_timestamp(now - timedelta(minutes=1)),
        "expires_at": format_timestamp(now + timedelta(hours=1)),
        "max_scope_lifetime_seconds": 1800,
        "max_assertion_lifetime_seconds": 300,
        "allowed_profiles": ["AOE-HQ-12"],
        "allowed_subjects": ["operator:alice"],
        "allowed_operations": [operation],
        "keys": [
            {
                "key_id": "ASSERTION-CLI-2026",
                "issuer": "identity-provider",
                "public_key": b64url(public_bytes(assertion_private)),
                "key_use": TrustKeyUse.PRINCIPAL_ASSERTION.value,
                "state": TrustKeyState.ACTIVE.value,
                "not_before": format_timestamp(now - timedelta(minutes=1)),
                "not_after": format_timestamp(now + timedelta(hours=1)),
                "retire_at": None,
                "allowed_profiles": ["AOE-HQ-12"],
                "allowed_subjects": ["operator:alice"],
                "allowed_operations": [operation],
            }
        ],
        "root_key_id": "ROOT-CLI-2026",
        "signature": ZERO_SIGNATURE,
    }
    unsigned = PrincipalTrustPolicy.from_dict(raw)
    return replace(
        unsigned,
        signature=b64url(root_private.sign(unsigned.signing_bytes())),
    )


class Phase4CliTests(unittest.TestCase):
    def test_trust_bootstrap_commands_form_a_public_key_only_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            store_path = directory / "missions.sqlite3"
            policy_path = directory / "policy.json"
            root_private = Ed25519PrivateKey.generate()
            assertion_private = Ed25519PrivateKey.generate()
            raw_root = public_bytes(root_private)
            root_text = b64url(raw_root)
            root_hash = "sha256:" + hashlib.sha256(raw_root).hexdigest()

            initialized = run_cli(
                "init-store",
                "--store",
                str(store_path),
            )
            store_id = str(initialized["store_id"])
            self.assertRegex(store_id, r"\ASTR-[0-9A-F]{32}\Z")

            initial = run_cli(
                "trust-status",
                "--store",
                str(store_path),
            )
            self.assertFalse(initial["root_pinned"])
            self.assertFalse(initial["policy_applied"])

            pinned = run_cli(
                "trust-pin-root",
                "--store",
                str(store_path),
                "--root-key-id",
                "ROOT-CLI-2026",
                "--audience",
                "sunderkey-runtime",
                "--root-public-key",
                root_text,
                "--expected-key-hash",
                root_hash,
            )
            self.assertTrue(pinned["root_pinned"])
            self.assertFalse(pinned["policy_applied"])

            policy = signed_policy(
                root_private,
                assertion_private,
                store_id,
            )
            policy_path.write_text(
                json.dumps(
                    policy.to_dict(),
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                encoding="utf-8",
                newline="\n",
            )
            applied = run_cli(
                "trust-apply-policy",
                "--store",
                str(store_path),
                "--policy",
                str(policy_path),
            )
            self.assertTrue(applied["root_pinned"])
            self.assertTrue(applied["policy_applied"])
            self.assertEqual(applied["policy_version"], 1)
            self.assertEqual(
                run_cli(
                    "trust-status",
                    "--store",
                    str(store_path),
                ),
                applied,
            )

    def test_trust_cli_never_accepts_private_key_material(self) -> None:
        help_text = main.__module__
        parser_help = __import__(
            "sunderkey.cli",
            fromlist=["build_parser"],
        ).build_parser().format_help()

        self.assertEqual(help_text, "sunderkey.cli")
        self.assertNotIn("private-key", parser_help)


if __name__ == "__main__":
    unittest.main()
