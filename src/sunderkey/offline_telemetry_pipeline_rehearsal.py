"""Rehearse paged telemetry normalization without a source client or I/O."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from .defender_telemetry_adapters import (
    DefenderTelemetryAdapterError,
    ReplayMarker,
    TelemetryEnvelopeReference,
    TelemetryNormalizer,
    TelemetrySourceBinding,
    normalize_import_batch,
)
from .offline_telemetry_ingest_chain import (
    MAX_BATCHES,
    MAX_EVENTS,
    OfflineTelemetryIngestChainError,
    build_offline_telemetry_ingest_chain,
)

DOMAIN = "sunderkey.offline-telemetry-pipeline-rehearsal.v1"
CURSOR_RE = re.compile(r"cursorref:[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z")
NO_EFFECTS = {
    "authorization": "none",
    "collection": "none",
    "network": "none",
    "persistence": "none",
    "qualification": "none",
    "source_write": "none",
    "target_action": "none",
}


class OfflineTelemetryPipelineError(ValueError):
    """Raised when supplied pages fail local continuity or normalization."""


def _canonical(value: Any) -> str:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise OfflineTelemetryPipelineError("pipeline input is not JSON data") from exc


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _cursor(value: Any) -> str:
    if not isinstance(value, str) or CURSOR_RE.fullmatch(value) is None:
        raise OfflineTelemetryPipelineError("cursor reference is invalid")
    return value


def build_offline_telemetry_pipeline_rehearsal(
    *,
    binding: TelemetrySourceBinding,
    start_cursor: str,
    pages: Sequence[Mapping[str, Any]],
    normalizer: TelemetryNormalizer,
) -> dict[str, Any]:
    """Normalize already-supplied pages and replay one historical chain."""

    if not isinstance(binding, TelemetrySourceBinding):
        raise OfflineTelemetryPipelineError("typed source binding is required")
    if not callable(getattr(normalizer, "normalize", None)):
        raise OfflineTelemetryPipelineError("injected normalizer is required")
    try:
        checked_binding = TelemetrySourceBinding.from_dict(binding.to_dict())
    except DefenderTelemetryAdapterError as exc:
        raise OfflineTelemetryPipelineError("source binding is invalid") from exc
    first_cursor = _cursor(start_cursor)
    if not isinstance(pages, (list, tuple)) or not 1 <= len(pages) <= MAX_BATCHES:
        raise OfflineTelemetryPipelineError("page count is invalid")
    prior_markers: list[ReplayMarker] = []
    batches = []
    rows = []
    cursor = first_cursor
    seen_cursors = {cursor}
    total_events = 0
    for position, page in enumerate(pages):
        if not isinstance(page, Mapping) or set(page) != {
            "cursor_before", "cursor_after", "imported_at", "envelopes",
            "end_of_stream",
        }:
            raise OfflineTelemetryPipelineError("page fields are invalid")
        before = _cursor(page["cursor_before"])
        after = _cursor(page["cursor_after"])
        if before != cursor or after in seen_cursors:
            raise OfflineTelemetryPipelineError("page cursor gap or replay")
        if type(page["end_of_stream"]) is not bool:
            raise OfflineTelemetryPipelineError("end_of_stream must be boolean")
        if page["end_of_stream"] != (position == len(pages) - 1):
            raise OfflineTelemetryPipelineError("end_of_stream position is invalid")
        envelopes = page["envelopes"]
        if (
            not isinstance(envelopes, (list, tuple))
            or not 1 <= len(envelopes) <= 512
            or any(not isinstance(item, TelemetryEnvelopeReference) for item in envelopes)
        ):
            raise OfflineTelemetryPipelineError("page envelopes are invalid")
        total_events += len(envelopes)
        if total_events > MAX_EVENTS:
            raise OfflineTelemetryPipelineError("page event limit exceeded")
        try:
            batch = normalize_import_batch(
                checked_binding,
                envelopes,
                normalizer,
                imported_at=page["imported_at"],
                prior_replay_markers=prior_markers,
            )
        except DefenderTelemetryAdapterError as exc:
            raise OfflineTelemetryPipelineError("page normalization failed") from exc
        batches.append(batch)
        prior_markers.extend(batch.replay_markers)
        row = {
            "cursor_before": before,
            "cursor_after": after,
            "batch_sha256": batch.batch_sha256,
            "event_count": len(batch.envelopes),
        }
        rows.append({**row, "page_sha256": _digest({"position": position, "row": row})})
        cursor = after
        seen_cursors.add(after)
    try:
        chain = build_offline_telemetry_ingest_chain(batches)
    except OfflineTelemetryIngestChainError as exc:
        raise OfflineTelemetryPipelineError("cross-page telemetry chain failed") from exc
    body = {
        "schema_version": 1,
        "binding_sha256": checked_binding.binding_sha256,
        "start_cursor": first_cursor,
        "end_cursor": cursor,
        "page_count": len(rows),
        "event_count": total_events,
        "pages": rows,
        "chain_sha256": chain["chain_sha256"],
        "cursor_assurance": "contiguous_from_supplied_start_only",
        "end_of_stream_assurance": "caller_asserted_only",
        "source_custody_assurance": "typed_receipt_claim_only",
        "live_currentness_verified": False,
        "positive_use_approved": False,
        "effects": dict(NO_EFFECTS),
    }
    return {**body, "rehearsal_sha256": _digest({"domain": DOMAIN, "body": body})}


def verify_offline_telemetry_pipeline_rehearsal(
    *,
    binding: TelemetrySourceBinding,
    start_cursor: str,
    pages: Sequence[Mapping[str, Any]],
    normalizer: TelemetryNormalizer,
    document: Mapping[str, Any],
) -> dict[str, Any]:
    expected = build_offline_telemetry_pipeline_rehearsal(
        binding=binding, start_cursor=start_cursor, pages=pages,
        normalizer=normalizer,
    )
    if not isinstance(document, Mapping) or _canonical(document) != _canonical(expected):
        raise OfflineTelemetryPipelineError("pipeline rehearsal does not match inputs")
    return expected


__all__ = [
    "OfflineTelemetryPipelineError",
    "build_offline_telemetry_pipeline_rehearsal",
    "verify_offline_telemetry_pipeline_rehearsal",
]
