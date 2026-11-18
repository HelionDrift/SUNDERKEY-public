from __future__ import annotations

import unittest

from sunderkey.errors import PrincipalAuthenticationError
from sunderkey.identity import (
    SAFETY_REDUCING_OPERATIONS,
    PrincipalOperation,
    validate_operation_intent,
)

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


class TargetHealthGateIdentityPhase199Tests(unittest.TestCase):
    def intent(self) -> dict[str, object]:
        return {
            "idempotency_key_sha256": DIGEST_A,
            "mission_id": "MISSION-PHASE199",
            "principal_profile_id": "AOE-HQ-12",
            "recovery_intent_sha256": DIGEST_B,
            "role": "independent_control",
        }

    def test_resume_operation_is_closed_and_control_only(self) -> None:
        operation = PrincipalOperation.TARGET_HEALTH_GATE_RESUME

        self.assertEqual(
            operation.value,
            "sunderkey.target-health-gate.resume.v1",
        )
        self.assertEqual(
            validate_operation_intent(operation, self.intent()),
            self.intent(),
        )
        self.assertNotIn(operation, SAFETY_REDUCING_OPERATIONS)

    def test_resume_intent_rejects_wrong_role(self) -> None:
        intent = self.intent()
        intent["role"] = "mission_owner"

        with self.assertRaises(PrincipalAuthenticationError):
            validate_operation_intent(
                PrincipalOperation.TARGET_HEALTH_GATE_RESUME,
                intent,
            )

    def test_resume_intent_rejects_open_or_malformed_values(self) -> None:
        cases = (
            {**self.intent(), "unexpected": True},
            {key: value for key, value in self.intent().items() if key != "role"},
            {**self.intent(), "recovery_intent_sha256": "sha256:" + "A" * 64},
            {**self.intent(), "idempotency_key_sha256": True},
        )
        for intent in cases:
            with self.subTest(intent=intent), self.assertRaises(
                PrincipalAuthenticationError
            ):
                validate_operation_intent(
                    PrincipalOperation.TARGET_HEALTH_GATE_RESUME,
                    intent,
                )


if __name__ == "__main__":
    unittest.main()
