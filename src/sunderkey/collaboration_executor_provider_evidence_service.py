"""Read-only evidence verification against durable report authentication."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .authenticated_collaboration_executor_provider_report import (
    AuthenticatedCollaborationExecutorProviderReportService,
)
from .collaboration_executor_provider_evidence import (
    validate_collaboration_executor_provider_evidence_digest_document,
    verify_collaboration_executor_provider_evidence_digest,
)
from .errors import CollaborationPlanError, StoreIntegrityError
from .registry import ExpertRegistry
from .store import MissionStore, canonical_json, format_timestamp


@dataclass(frozen=True)
class CollaborationExecutorProviderEvidenceVerificationReceipt:
    """Transient digest verification against durable authentication custody."""

    verification_json: str

    @property
    def verification_id(self) -> str:
        return str(self.to_dict()["evidence_verification"]["verification_id"])

    @property
    def report_authentication_id(self) -> str:
        return str(
            self.to_dict()["evidence_verification"][
                "report_authentication_id"
            ]
        )

    def to_dict(self) -> dict[str, Any]:
        try:
            verification = (
                validate_collaboration_executor_provider_evidence_digest_document(
                    json.loads(self.verification_json)
                )
            )
        except (
            json.JSONDecodeError,
            CollaborationPlanError,
            TypeError,
            ValueError,
        ) as exc:
            raise StoreIntegrityError(
                "Provider evidence verification receipt is invalid"
            ) from exc
        return {
            "schema_version": 1,
            "evidence_verification": verification,
            "base_custody_status": "durable_authenticated_provider_report",
            "verification_custody_status": "transient_not_retained",
            "evidence_retention_status": "not_retained",
            "semantic_verification_status": "not_performed",
            "external_effect_status": (
                "authenticated_report_evidence_digest_verified_"
                "effect_unverified"
            ),
            "runtime_effect": "none",
        }


class CollaborationExecutorProviderEvidenceVerificationService:
    """Verify evidence bytes against deeply checked durable report custody."""

    def __init__(
        self,
        store: MissionStore,
        registry: ExpertRegistry,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._authentications = (
            AuthenticatedCollaborationExecutorProviderReportService(
                store,
                registry,
                clock=clock,
            )
        )

    def verify(
        self,
        report_authentication_id: str,
        evidence: bytes,
        *,
        evidence_media_type: str,
    ) -> CollaborationExecutorProviderEvidenceVerificationReceipt:
        authentication_receipt = self._authentications.get(
            report_authentication_id
        )
        authentication = authentication_receipt.to_dict()[
            "provider_report_authentication"
        ]
        now = self._authentications._reports._attempts._clock_value()
        verified = verify_collaboration_executor_provider_evidence_digest(
            authentication,
            evidence,
            evidence_media_type=evidence_media_type,
            verified_at=format_timestamp(now),
        )
        return CollaborationExecutorProviderEvidenceVerificationReceipt(
            verification_json=canonical_json(verified.to_dict())
        )


__all__ = [
    "CollaborationExecutorProviderEvidenceVerificationReceipt",
    "CollaborationExecutorProviderEvidenceVerificationService",
]
