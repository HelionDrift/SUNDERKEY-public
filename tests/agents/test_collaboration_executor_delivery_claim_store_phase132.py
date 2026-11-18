"""Phase 132 atomic executor delivery claim writer coverage."""

from __future__ import annotations

import ast
import json
import sqlite3
import unittest
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.collaboration_executor_delivery_claim_store import (
    CollaborationExecutorDeliveryClaimService,
)
from sunderkey.errors import CollaborationPlanError, StoreConflictError

from . import test_collaboration_executor_delivery_claim_phase130 as phase130

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "registry/schemas"


class CollaborationExecutorDeliveryClaimStorePhase132Tests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = phase130.CollaborationExecutorDeliveryClaimPhase130Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.root = fixture.fixture.root
        self.service = CollaborationExecutorDeliveryClaimService(
            self.root.store,
            self.root.registry,
            clock=lambda: self.root.now,
        )

    def _claim(
        self,
        claimant: str = "executor-instance-a",
        lease_seconds: int = 10,
    ):
        return self.service.claim(
            self.fixture.reservation.authentication_id,
            claimant_instance_id=claimant,
            lease_seconds=lease_seconds,
        )

    def test_initial_claim_is_durable_and_inert(self) -> None:
        receipt = self._claim()
        document = receipt.to_dict()
        self.assertEqual(document["custody_status"], "durable_delivery_claim")
        self.assertEqual(document["external_effect_status"], "not_started")
        self.assertEqual(document["runtime_effect"], "none")
        self.assertEqual(
            self.service.get_latest(self.fixture.reservation.authentication_id),
            receipt,
        )
        with closing(sqlite3.connect(self.root.store.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM executor_dispatch_delivery_claims"
                ).fetchone()[0],
                1,
            )
        self.assertEqual(
            self.root.store.verify_store(self.root.registry).status,
            "valid",
        )

    def test_same_claimant_replays_and_competitor_fails_while_active(self) -> None:
        first = self._claim()
        self.root.now = datetime(2026, 7, 30, 10, 8, 35, tzinfo=UTC)
        self.assertEqual(self._claim(lease_seconds=20), first)
        with self.assertRaisesRegex(StoreConflictError, "active claimant"):
            self._claim("executor-instance-b")
        with closing(sqlite3.connect(self.root.store.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM executor_dispatch_delivery_claims"
                ).fetchone()[0],
                1,
            )

    def test_expired_claim_allows_one_generation_takeover(self) -> None:
        first = self._claim()
        self.root.now = datetime(2026, 7, 30, 10, 8, 40, tzinfo=UTC)
        second = self._claim("executor-instance-b")
        document = second.to_dict()["delivery_claim"]
        self.assertEqual(document["claim_generation"], 2)
        self.assertEqual(document["predecessor"]["claim_id"], first.claim_id)
        self.assertEqual(
            document["claimant"]["instance_id"],
            "executor-instance-b",
        )

    def test_dispatch_deadline_and_late_insert_fail_closed(self) -> None:
        with self.assertRaisesRegex(CollaborationPlanError, "window"):
            self._claim(lease_seconds=60)
        with patch.object(
            self.service,
            "_insert",
            side_effect=sqlite3.IntegrityError("injected claim failure"),
        ), self.assertRaisesRegex(StoreConflictError, "Could not commit"):
            self._claim()
        self.assertIsNone(
            self.service.get_latest(self.fixture.reservation.authentication_id)
        )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_commit_receipt_matches_strict_schema(self) -> None:
        schema = json.loads(
            (
                SCHEMAS
                / "collaboration-executor-delivery-claim-commit-receipt-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        schema["properties"]["delivery_claim"] = json.loads(
            (
                SCHEMAS / "collaboration-executor-delivery-claim-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(self._claim().to_dict())

    def test_writer_has_no_network_process_or_adapter_invocation(self) -> None:
        source_path = (
            ROOT / "src/sunderkey/collaboration_executor_delivery_claim_store.py"
        )
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertFalse(
            imports
            & {
                "asyncio",
                "httpx",
                "requests",
                "socket",
                "subprocess",
                "urllib",
            }
        )
        self.assertNotIn("CollaborationExecutorAdapter", source)


if __name__ == "__main__":
    unittest.main()
