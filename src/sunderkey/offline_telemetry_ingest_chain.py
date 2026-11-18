"""Replay bounded telemetry batches as one gap-free historical source chain."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from .defender_telemetry_adapters import (
    DefenderTelemetryAdapterError,
    TelemetryIngestBatch,
)

DOMAIN = "sunderkey.offline-telemetry-ingest-chain.v1"
MAX_BATCHES = 64
MAX_EVENTS = 8192
NO_EFFECTS = {
    "authorization": "none",
    "collection": "none",
    "network": "none",
    "persistence": "none",
    "qualification": "none",
    "source_write": "none",
    "target_action": "none",
}


class OfflineTelemetryIngestChainError(ValueError):
    """Raised when a historical telemetry batch chain cannot be replayed."""


def _canonical(value: Any) -> str:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise OfflineTelemetryIngestChainError("chain input is not JSON data") from exc


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def build_offline_telemetry_ingest_chain(
    batches: Sequence[TelemetryIngestBatch],
) -> dict[str, Any]:
    """Check typed batch replay, sequence continuity, and all-history replay."""

    if not isinstance(batches, (list, tuple)) or not 1 <= len(batches) <= MAX_BATCHES:
        raise OfflineTelemetryIngestChainError("telemetry batch count is invalid")
    if any(not isinstance(batch, TelemetryIngestBatch) for batch in batches):
        raise OfflineTelemetryIngestChainError("typed telemetry batches are required")
    rows = []
    first_binding = None
    previous_imported_at = None
    previous_sequence = None
    seen_refs: set[str] = set()
    seen_raw_digests: set[str] = set()
    seen_envelope_digests: set[str] = set()
    seen_batch_digests: set[str] = set()
    total_events = 0
    for batch in batches:
        try:
            checked = TelemetryIngestBatch.from_dict(batch.to_dict())
        except DefenderTelemetryAdapterError as exc:
            raise OfflineTelemetryIngestChainError("telemetry batch replay failed") from exc
        binding_digest = checked.binding.binding_sha256
        if first_binding is None:
            first_binding = binding_digest
        elif binding_digest != first_binding:
            raise OfflineTelemetryIngestChainError("telemetry source binding changed")
        if (
            previous_imported_at is not None
            and _instant(checked.imported_at) <= _instant(previous_imported_at)
        ):
            raise OfflineTelemetryIngestChainError("batch import time did not advance")
        if checked.batch_sha256 in seen_batch_digests:
            raise OfflineTelemetryIngestChainError("telemetry batch replay detected")
        seen_batch_digests.add(checked.batch_sha256)
        for envelope in checked.envelopes:
            if (
                envelope.source_event_ref in seen_refs
                or envelope.raw_event_sha256 in seen_raw_digests
                or envelope.envelope_sha256 in seen_envelope_digests
            ):
                raise OfflineTelemetryIngestChainError("historical telemetry replay detected")
            if (
                previous_sequence is not None
                and envelope.source_sequence != previous_sequence + 1
            ):
                raise OfflineTelemetryIngestChainError("source sequence gap or reversal")
            previous_sequence = envelope.source_sequence
            seen_refs.add(envelope.source_event_ref)
            seen_raw_digests.add(envelope.raw_event_sha256)
            seen_envelope_digests.add(envelope.envelope_sha256)
        total_events += len(checked.envelopes)
        if total_events > MAX_EVENTS:
            raise OfflineTelemetryIngestChainError("telemetry chain event limit exceeded")
        rows.append({
            "batch_sha256": checked.batch_sha256,
            "imported_at": checked.imported_at,
            "first_source_sequence": checked.envelopes[0].source_sequence,
            "last_source_sequence": checked.envelopes[-1].source_sequence,
            "event_count": len(checked.envelopes),
        })
        previous_imported_at = checked.imported_at
    body = {
        "schema_version": 1,
        "binding_sha256": first_binding,
        "batch_count": len(rows),
        "event_count": total_events,
        "first_source_sequence": rows[0]["first_source_sequence"],
        "last_source_sequence": rows[-1]["last_source_sequence"],
        "batches": rows,
        "chain_status": "historical_local_content_replayed",
        "initial_sequence_assurance": "first_supplied_event_only",
        "producer_identity_assurance": "binding_claim_not_authenticated",
        "source_custody_assurance": "typed_receipt_claim_only",
        "live_currentness_verified": False,
        "positive_use_approved": False,
        "effects": dict(NO_EFFECTS),
    }
    return {**body, "chain_sha256": _digest({"domain": DOMAIN, "body": body})}


def verify_offline_telemetry_ingest_chain(
    *, batches: Sequence[TelemetryIngestBatch], document: Mapping[str, Any]
) -> dict[str, Any]:
    expected = build_offline_telemetry_ingest_chain(batches)
    if not isinstance(document, Mapping) or _canonical(document) != _canonical(expected):
        raise OfflineTelemetryIngestChainError("telemetry chain does not match batches")
    return expected


__all__ = [
    "OfflineTelemetryIngestChainError",
    "build_offline_telemetry_ingest_chain",
    "verify_offline_telemetry_ingest_chain",
]
