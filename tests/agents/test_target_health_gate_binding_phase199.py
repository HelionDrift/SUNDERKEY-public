from __future__ import annotations

import inspect
import unittest
from dataclasses import FrozenInstanceError, replace
from typing import Any

from sunderkey.action_admission_contracts import (
    ArtifactBinding,
    ContextBinding,
    CredentialLease,
    TargetBinding,
    TargetEnvironment,
    WorkerSession,
    canonical_sha256,
)
from sunderkey.execution_control_runtime import ExecutionBinding
from sunderkey.target_health_gate_contracts import (
    TargetHealthGateContractError,
    build_target_health_execution_binding,
)


def digest(character: str) -> str:
    return "sha256:" + character * 64


def binding_inputs() -> tuple[ContextBinding, WorkerSession, CredentialLease, TargetBinding]:
    tenant_id = "tenant:phase199"
    mission_id = "mission:phase199"
    scope_sha256 = digest("1")
    worker = WorkerSession(
        worker_id="worker:phase199",
        worker_profile_id="profile:phase199",
        session_id="session:phase199",
        tenant_id=tenant_id,
        mission_id=mission_id,
        fence_token_sha256=digest("2"),
        leader_epoch=7,
        issued_at="2026-09-22T10:00:00Z",
        expires_at="2026-09-22T12:00:00Z",
    )
    return (
        ContextBinding(
            tenant_id=tenant_id,
            mission_id=mission_id,
            scope_id="scope:phase199",
            scope_sha256=scope_sha256,
            policy=ArtifactBinding(
                artifact_ref="artifact:phase199-policy",
                artifact_sha256=digest("3"),
                exact_version="1.0.0",
            ),
        ),
        worker,
        CredentialLease(
            lease_id="lease:phase199",
            credential_ref_sha256=digest("4"),
            tenant_id=tenant_id,
            mission_id=mission_id,
            scope_sha256=scope_sha256,
            worker_id=worker.worker_id,
            session_id=worker.session_id,
            fence_token_sha256=worker.fence_token_sha256,
            leader_epoch=worker.leader_epoch,
            permitted_action_sha256=digest("5"),
            revoked=False,
            issued_at="2026-09-22T10:00:00Z",
            expires_at="2026-09-22T12:00:00Z",
        ),
        TargetBinding(
            target_id="target:phase199",
            target_sha256=digest("6"),
            authority_sha256=digest("7"),
            tenant_id=tenant_id,
            mission_id=mission_id,
            scope_sha256=scope_sha256,
            environment=TargetEnvironment.LIVE,
        ),
    )


def build(
    inputs: tuple[ContextBinding, WorkerSession, CredentialLease, TargetBinding],
) -> ExecutionBinding:
    context, worker, credential, target = inputs
    return build_target_health_execution_binding(
        context=context,
        worker_session=worker,
        credential_lease=credential,
        target=target,
    )


class TargetHealthExecutionBindingTests(unittest.TestCase):
    def test_builder_has_the_minimal_keyword_only_surface(self) -> None:
        signature = inspect.signature(build_target_health_execution_binding)
        self.assertEqual(
            tuple(signature.parameters),
            ("context", "worker_session", "credential_lease", "target"),
        )
        self.assertTrue(
            all(
                parameter.kind is inspect.Parameter.KEYWORD_ONLY
                for parameter in signature.parameters.values()
            )
        )

        context, worker, credential, target = binding_inputs()
        with self.assertRaises(TypeError):
            build_target_health_execution_binding(
                context=context,
                worker_session=worker,
                credential_lease=credential,
                target=target,
                context_sha256=digest("8"),
            )

    def test_builder_maps_every_authoritative_field_exactly(self) -> None:
        context, worker, credential, target = binding_inputs()

        result = build((context, worker, credential, target))

        self.assertIs(type(result), ExecutionBinding)
        self.assertEqual(
            result.to_dict(),
            {
                "context_id": context.mission_id,
                "context_sha256": canonical_sha256(context.to_dict()),
                "fence_epoch": worker.leader_epoch,
                "lease_id": credential.lease_id,
                "scope_id": context.scope_id,
                "scope_sha256": context.scope_sha256,
                "session_id": worker.session_id,
                "target_id": target.target_id,
                "target_sha256": target.target_sha256,
                "tenant_id": context.tenant_id,
            },
        )

    def test_context_digest_binds_complete_context(self) -> None:
        context, worker, credential, target = binding_inputs()
        initial = build((context, worker, credential, target))
        changed_context = replace(
            context,
            policy=replace(context.policy, exact_version="1.0.1"),
        )

        changed = build((changed_context, worker, credential, target))

        self.assertEqual(initial.context_id, changed.context_id)
        self.assertEqual(initial.scope_sha256, changed.scope_sha256)
        self.assertNotEqual(initial.context_sha256, changed.context_sha256)
        self.assertEqual(changed.context_sha256, canonical_sha256(changed_context.to_dict()))

    def test_builder_rejects_every_cross_binding_mismatch(self) -> None:
        cases: tuple[tuple[str, dict[str, Any]], ...] = (
            ("worker", {"tenant_id": "tenant:other"}),
            ("credential", {"tenant_id": "tenant:other"}),
            ("target", {"tenant_id": "tenant:other"}),
            ("worker", {"mission_id": "mission:other"}),
            ("credential", {"mission_id": "mission:other"}),
            ("target", {"mission_id": "mission:other"}),
            ("credential", {"scope_sha256": digest("8")}),
            ("target", {"scope_sha256": digest("8")}),
            ("credential", {"worker_id": "worker:other"}),
            ("credential", {"session_id": "session:other"}),
            ("credential", {"fence_token_sha256": digest("8")}),
            ("credential", {"leader_epoch": 8}),
        )
        for member, replacement in cases:
            with self.subTest(member=member, replacement=replacement):
                context, worker, credential, target = binding_inputs()
                values: dict[str, Any] = {
                    "context": context,
                    "worker": worker,
                    "credential": credential,
                    "target": target,
                }
                values[member] = replace(values[member], **replacement)

                with self.assertRaises(TargetHealthGateContractError):
                    build(
                        (
                            values["context"],
                            values["worker"],
                            values["credential"],
                            values["target"],
                        )
                    )

    def test_builder_rejects_revoked_credential(self) -> None:
        context, worker, credential, target = binding_inputs()

        with self.assertRaises(TargetHealthGateContractError):
            build((context, worker, replace(credential, revoked=True), target))

    def test_builder_rejects_non_contract_inputs(self) -> None:
        cases: tuple[tuple[int, Any], ...] = (
            (0, {}),
            (1, {}),
            (2, {}),
            (3, {}),
            (0, None),
            (1, None),
            (2, None),
            (3, None),
        )
        for position, value in cases:
            with self.subTest(position=position, value=value):
                inputs = list(binding_inputs())
                inputs[position] = value

                with self.assertRaises(TargetHealthGateContractError):
                    build(tuple(inputs))  # type: ignore[arg-type]

    def test_builder_revalidates_forged_contract_values(self) -> None:
        cases: tuple[tuple[int, str, Any], ...] = (
            (0, "tenant_id", " tenant:phase199"),
            (0, "scope_sha256", "sha256:" + "A" * 64),
            (0, "scope_id", "scope:" + chr(0x2603)),
            (1, "leader_epoch", True),
            (1, "fence_token_sha256", "sha256:" + "A" * 64),
            (2, "revoked", 1),
            (2, "lease_id", "lease: phase199"),
            (3, "target_id", "target: phase199"),
            (3, "target_sha256", "sha256:" + "A" * 64),
        )
        for position, field, value in cases:
            with self.subTest(position=position, field=field, value=value):
                inputs = list(binding_inputs())
                object.__setattr__(inputs[position], field, value)

                with self.assertRaises(TargetHealthGateContractError):
                    build(tuple(inputs))  # type: ignore[arg-type]

    def test_builder_is_deterministic_and_does_not_mutate_sources(self) -> None:
        inputs = binding_inputs()
        source_documents = tuple(item.to_dict() for item in inputs)

        first = build(inputs)
        second = build(inputs)

        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(tuple(item.to_dict() for item in inputs), source_documents)

        with self.assertRaises(FrozenInstanceError):
            first.tenant_id = "tenant:other"  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
