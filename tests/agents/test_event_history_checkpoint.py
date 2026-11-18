from __future__ import annotations

import base64
import copy
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from jsonschema import Draft202012Validator

from sunderkey.event_assessment_history import OfflineEventAssessmentHistoryStore
from sunderkey.event_history_checkpoint import (
    EventHistoryCheckpointError,
    build_event_history_checkpoint,
    event_history_checkpoint_signing_bytes,
    verify_event_history_checkpoint,
)

from .test_event_assessment_planning import AT, SCOPE, event

DOMAIN = "custody:event-assessment:test"
SCHEMA = (
    Path(__file__).resolve().parents[2]
    / "registry/schemas/event-history-checkpoint-v1.schema.json"
)


def _signed(store, private, public, at="2026-09-23T14:00:00Z"):
    unsigned = build_event_history_checkpoint(
        store, pinned_public_key=public, custody_domain=DOMAIN, observed_at=at
    )
    signature = private.sign(event_history_checkpoint_signing_bytes(unsigned))
    return {
        **unsigned,
        "signature_b64url": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
    }


class EventHistoryCheckpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = OfflineEventAssessmentHistoryStore(
            Path(self.temporary.name) / "history.sqlite3", SCOPE
        )
        self.store.initialize()
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def test_signed_exact_head_verifies_without_scheduling_or_authority(self) -> None:
        self.store.append(request_id="eventreq:first", events=(event(),), as_of=AT)
        record = _signed(self.store, self.private, self.public)
        verified = verify_event_history_checkpoint(
            json.dumps(record), self.store,
            pinned_public_key=self.public, expected_custody_domain=DOMAIN,
        )
        self.assertEqual(verified, record)
        self.assertEqual(record["head_sequence"], 1)
        self.assertEqual(record["effects"]["scheduling"], "none")
        self.assertEqual(record["effects"]["authority"], "none")
        self.assertEqual(record["head_sha256"], self.store.verify().head_sha256)
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(record)

    def test_genesis_head_can_be_checkpointed_without_scheduling(self) -> None:
        record = _signed(self.store, self.private, self.public)
        self.assertEqual(record["head_sequence"], 0)
        self.assertEqual(
            verify_event_history_checkpoint(
                record, self.store,
                pinned_public_key=self.public, expected_custody_domain=DOMAIN,
            ),
            record,
        )

    def test_changed_head_rejects_old_signature_even_when_chain_is_valid(self) -> None:
        self.store.append(request_id="eventreq:first", events=(event(),), as_of=AT)
        record = _signed(self.store, self.private, self.public)
        self.store.append(
            request_id="eventreq:second", events=(event(),),
            as_of="2026-09-23T14:30:00Z",
        )
        self.assertEqual(self.store.verify().head_sequence, 2)
        with self.assertRaises(EventHistoryCheckpointError):
            verify_event_history_checkpoint(
                record, self.store,
                pinned_public_key=self.public, expected_custody_domain=DOMAIN,
            )

    def test_key_domain_signature_and_effect_substitution_fail(self) -> None:
        self.store.append(request_id="eventreq:first", events=(event(),), as_of=AT)
        record = _signed(self.store, self.private, self.public)
        other_key = Ed25519PrivateKey.generate().public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        for public, domain, changed in (
            (other_key, DOMAIN, record),
            (self.public, "custody:other", record),
        ):
            with self.assertRaises(EventHistoryCheckpointError):
                verify_event_history_checkpoint(
                    changed, self.store,
                    pinned_public_key=public, expected_custody_domain=domain,
                )
        changed = copy.deepcopy(record)
        changed["effects"]["scheduling"] = "allowed"
        with self.assertRaises(EventHistoryCheckpointError):
            event_history_checkpoint_signing_bytes(
                {key: value for key, value in changed.items() if key != "signature_b64url"}
            )
        with self.assertRaises(EventHistoryCheckpointError):
            verify_event_history_checkpoint(
                changed, self.store,
                pinned_public_key=self.public, expected_custody_domain=DOMAIN,
            )
        changed = copy.deepcopy(record)
        changed["signature_b64url"] = "A" * 86
        with self.assertRaises(EventHistoryCheckpointError):
            verify_event_history_checkpoint(
                changed, self.store,
                pinned_public_key=self.public, expected_custody_domain=DOMAIN,
            )

    def test_missing_history_and_malformed_records_fail_before_acceptance(self) -> None:
        missing = OfflineEventAssessmentHistoryStore(
            Path(self.temporary.name) / "missing.sqlite3", SCOPE
        )
        with self.assertRaises(EventHistoryCheckpointError):
            build_event_history_checkpoint(
                missing, pinned_public_key=self.public,
                custody_domain=DOMAIN, observed_at="2026-09-23T14:00:00Z",
            )
        with self.assertRaises(EventHistoryCheckpointError):
            build_event_history_checkpoint(
                self.store, pinned_public_key=self.public,
                custody_domain=DOMAIN, observed_at="2026-09-23T14:00:00+00:00",
            )
        with self.assertRaises(EventHistoryCheckpointError):
            verify_event_history_checkpoint(
                '{"schema_version":1,"schema_version":1}', self.store,
                pinned_public_key=self.public, expected_custody_domain=DOMAIN,
            )


if __name__ == "__main__":
    unittest.main()
