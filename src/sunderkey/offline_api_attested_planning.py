"""Replay receipt-sourced API planning with a local, nonauthoritative signature."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from .offline_api_planning_bundle import (
    OfflineApiPlanningError,
    verify_offline_api_planning_bundle,
)
from .offline_api_source_attestation import (
    OfflineApiSourceAttestationError,
    OfflineSourceKeyBinding,
    rehearse_offline_api_source_freshness,
)
from .offline_api_source_ledger import (
    OfflineApiSourceLedgerError,
    append_offline_api_source_batch,
    verify_offline_api_source_ledger,
)

DOMAIN = "sunderkey.offline-api-attested-planning.v1"
PLANNING_FIELDS = {
    "adapter",
    "sources",
    "batch",
    "scope",
    "observed_at",
    "expires_at",
    "capability_availability",
    "validator_availability",
    "limits",
    "specialist_capacity",
    "commander_capacity",
    "validator_capacity",
    "registry",
}
NO_EFFECTS = {
    "authority": "none",
    "deployment": "none",
    "execution": "none",
    "finding_publication": "none",
    "network": "none",
    "qualification": "none",
    "routing": "none",
    "target_execution": "none",
}


class OfflineApiAttestedPlanningError(ValueError):
    """Raised when the signed local source and planning replay differ."""


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def build_offline_api_attested_planning_rehearsal(
    *,
    bundle: Mapping[str, Any],
    planning_inputs: Mapping[str, Any],
    ledger: Mapping[str, Any],
    attestation: Mapping[str, Any],
    key_binding: OfflineSourceKeyBinding,
    as_of: str,
) -> dict[str, Any]:
    """Bind exact source replay to local signature freshness without use approval."""

    if not isinstance(planning_inputs, Mapping) or not (
        PLANNING_FIELDS <= set(planning_inputs) <= PLANNING_FIELDS | {"target_context"}
    ):
        raise OfflineApiAttestedPlanningError("planning replay input fields are invalid")
    try:
        checked_bundle = verify_offline_api_planning_bundle(
            bundle=bundle, **dict(planning_inputs)
        )
        expected_ledger = append_offline_api_source_batch(
            adapter=planning_inputs["adapter"],
            sources=planning_inputs["sources"],
            batch=planning_inputs["batch"],
        )
        checked_ledger = verify_offline_api_source_ledger(ledger)
        if _canonical(checked_ledger) != _canonical(expected_ledger):
            raise OfflineApiAttestedPlanningError("source ledger differs from planning replay")
        scope = planning_inputs["scope"]
        if (
            checked_bundle["batch_sha256"] != checked_ledger["batch_sha256s"][-1]
            or checked_bundle["scope_sha256"] != scope.content_sha256
            or checked_ledger["source_scope_sha256"] != scope.content_sha256
        ):
            raise OfflineApiAttestedPlanningError("planning source or scope binding differs")
        freshness = rehearse_offline_api_source_freshness(
            document=attestation,
            ledger=checked_ledger,
            key_binding=key_binding,
            as_of=as_of,
            expected_mission_id=checked_ledger["mission_id"],
            expected_scope_id=scope.scope_id,
            expected_scope_sha256=scope.content_sha256,
        )
        observed = datetime.strptime(
            planning_inputs["observed_at"], "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=UTC)
        current = datetime.strptime(as_of, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        if current < observed:
            raise OfflineApiAttestedPlanningError("local review precedes observation")
    except OfflineApiAttestedPlanningError:
        raise
    except (
        OfflineApiPlanningError,
        OfflineApiSourceLedgerError,
        OfflineApiSourceAttestationError,
        AttributeError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise OfflineApiAttestedPlanningError("attested planning sources are invalid") from exc
    body = {
        "schema_version": 1,
        "bundle_sha256": checked_bundle["bundle_sha256"],
        "ledger_sha256": checked_ledger["ledger_sha256"],
        "attestation_sha256": attestation["attestation_sha256"],
        "local_freshness_sha256": freshness["rehearsal_sha256"],
        "mission_id": checked_ledger["mission_id"],
        "scope_id": checked_ledger["scope_id"],
        "as_of": as_of,
        "source_replay_performed": True,
        "source_authentication": "caller_provided_key_only",
        "live_currentness_verified": False,
        "positive_use_approved": False,
        "effects": dict(NO_EFFECTS),
    }
    return {**body, "rehearsal_sha256": _digest({"domain": DOMAIN, "body": body})}


def verify_offline_api_attested_planning_rehearsal(
    *,
    document: Mapping[str, Any],
    bundle: Mapping[str, Any],
    planning_inputs: Mapping[str, Any],
    ledger: Mapping[str, Any],
    attestation: Mapping[str, Any],
    key_binding: OfflineSourceKeyBinding,
    as_of: str,
) -> dict[str, Any]:
    expected = build_offline_api_attested_planning_rehearsal(
        bundle=bundle,
        planning_inputs=planning_inputs,
        ledger=ledger,
        attestation=attestation,
        key_binding=key_binding,
        as_of=as_of,
    )
    try:
        same = isinstance(document, Mapping) and _canonical(document) == _canonical(expected)
    except (TypeError, ValueError):
        same = False
    if not same:
        raise OfflineApiAttestedPlanningError("attested planning rehearsal does not match")
    return expected


__all__ = [
    "OfflineApiAttestedPlanningError",
    "build_offline_api_attested_planning_rehearsal",
    "verify_offline_api_attested_planning_rehearsal",
]
