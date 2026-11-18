"""Phase 130 provider-neutral executor delivery claim coverage."""

from __future__ import annotations

import ast
import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.collaboration_executor_delivery_claim import (
    CollaborationExecutorDeliveryClaim,
    build_collaboration_executor_delivery_claim,
)
from sunderkey.errors import CollaborationPlanError, QualificationError

from . import test_authenticated_collaboration_executor_dispatch_phase129 as phase129

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "registry/schemas"


class CollaborationExecutorDeliveryClaimPhase130Tests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = phase129.AuthenticatedCollaborationExecutorDispatchPhase129Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.reservation = fixture._reserve()

    def _claim(
        self,
        *,
        claimed_at: str = "2026-07-30T10:08:30Z",
        lease_expires_at: str = "2026-07-30T10:08:40Z",
        previous_claim=None,
        claimant: str = "executor-instance-a",
    ) -> CollaborationExecutorDeliveryClaim:
        return build_collaboration_executor_delivery_claim(
            self.reservation,
            claimant_instance_id=claimant,
            claimed_at=claimed_at,
            lease_expires_at=lease_expires_at,
            previous_claim=previous_claim,
        )

    def test_initial_claim_binds_reserved_dispatch_without_effect(self) -> None:
        claim = self._claim()
        document = claim.to_dict()
        authentication = self.reservation.to_dict()["dispatch_authentication"]
        self.assertEqual(document["claim_generation"], 1)
        self.assertIsNone(document["predecessor"])
        self.assertEqual(
            document["reservation"]["authentication_id"],
            authentication["authentication_id"],
        )
        self.assertEqual(document["claim_status"], "claimed_pending_invocation")
        self.assertEqual(
            document["claimant_identity_status"],
            "deployment_instance_unverified",
        )
        self.assertEqual(document["external_effect_status"], "not_started")
        self.assertEqual(document["runtime_effect"], "none")

    def test_takeover_requires_exact_predecessor_expiry(self) -> None:
        first = self._claim()
        with self.assertRaisesRegex(CollaborationPlanError, "window"):
            self._claim(
                claimed_at="2026-07-30T10:08:39Z",
                lease_expires_at="2026-07-30T10:08:49Z",
                previous_claim=first,
                claimant="executor-instance-b",
            )
        second = self._claim(
            claimed_at="2026-07-30T10:08:40Z",
            lease_expires_at="2026-07-30T10:08:50Z",
            previous_claim=first,
            claimant="executor-instance-b",
        )
        document = second.to_dict()
        self.assertEqual(document["claim_generation"], 2)
        self.assertEqual(document["predecessor"]["claim_id"], first.claim_id)
        self.assertEqual(
            document["predecessor"]["lease_expires_at"],
            first.to_dict()["lease_expires_at"],
        )

    def test_claim_lease_and_dispatch_deadline_are_bounded(self) -> None:
        with self.assertRaisesRegex(CollaborationPlanError, "window"):
            self._claim(lease_expires_at="2026-07-30T10:09:31Z")
        with self.assertRaisesRegex(CollaborationPlanError, "window"):
            self._claim(
                claimed_at="2026-07-30T10:09:50Z",
                lease_expires_at="2026-07-30T10:10:01Z",
            )

    def test_claim_is_content_addressed_and_strict(self) -> None:
        claim = self._claim()
        changed = claim.to_dict()
        changed["claimant"]["instance_id"] = "executor-instance-b"
        with self.assertRaisesRegex(CollaborationPlanError, "hash"):
            CollaborationExecutorDeliveryClaim.from_dict(changed)
        changed = claim.to_dict()
        changed["unexpected"] = True
        with self.assertRaises((CollaborationPlanError, QualificationError)):
            CollaborationExecutorDeliveryClaim.from_dict(changed)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_claim_matches_strict_schema(self) -> None:
        schema = json.loads(
            (SCHEMAS / "collaboration-executor-delivery-claim-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(self._claim().to_dict())

    def test_contract_has_no_network_process_or_adapter_invocation(self) -> None:
        source_path = ROOT / "src/sunderkey/collaboration_executor_delivery_claim.py"
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
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
        self.assertNotIn("CollaborationExecutorAdapter", source_path.read_text())


if __name__ == "__main__":
    unittest.main()
