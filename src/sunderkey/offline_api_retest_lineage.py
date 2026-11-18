"""Compose source replay custody with immutable synthetic API world retests."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from .attack_world_model import AttackWorldModelError, AttackWorldSnapshot
from .offline_api_assessment import OfflineApiCaseSource
from .offline_api_source_ledger import (
    OfflineApiSourceLedgerError,
    append_offline_api_source_batch,
    verify_offline_api_source_ledger,
)
from .offline_api_world_projection import (
    OfflineApiWorldProjectionError,
    append_offline_api_world_projection,
    verify_offline_api_world_projection,
)
from .reference_adapters import OfflineReferenceAdapter

LINEAGE_DOMAIN = "sunderkey.offline-api-retest-lineage.v1"
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
NO_EFFECTS = {
    "authority": "none",
    "execution": "none",
    "finding_publication": "none",
    "network": "none",
    "qualification": "none",
    "source_authentication": "none",
}


class OfflineApiRetestLineageError(ValueError):
    """Raised when a retest breaks source or world lineage."""


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _document(
    *,
    ledger: Mapping[str, Any],
    snapshot: AttackWorldSnapshot,
    parent_lineage_sha256: str | None,
) -> dict[str, Any]:
    body = {
        "schema_version": 1,
        "mission_id": ledger["mission_id"],
        "scope_id": ledger["scope_id"],
        "active_batch_sha256": ledger["batch_sha256s"][-1],
        "step_index": len(ledger["batch_sha256s"]),
        "parent_lineage_sha256": parent_lineage_sha256,
        "source_ledger": dict(ledger),
        "world_snapshot": snapshot.to_dict(),
        "world_state": "hypothesis_only",
        "effects": dict(NO_EFFECTS),
    }
    return {
        **body,
        "lineage_sha256": _digest({"domain": LINEAGE_DOMAIN, "lineage": body}),
    }


def verify_offline_api_retest_lineage(
    document: Mapping[str, Any],
    *,
    prior: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Inspect archive integrity; original source replay remains a separate check."""

    fields = {
        "schema_version",
        "mission_id",
        "scope_id",
        "active_batch_sha256",
        "step_index",
        "parent_lineage_sha256",
        "source_ledger",
        "world_snapshot",
        "world_state",
        "effects",
        "lineage_sha256",
    }
    if not isinstance(document, Mapping) or set(document) != fields:
        raise OfflineApiRetestLineageError("retest lineage fields are invalid")
    try:
        value = dict(document)
        ledger = verify_offline_api_source_ledger(value["source_ledger"])
        snapshot = AttackWorldSnapshot.from_dict(value["world_snapshot"])
        if (
            type(value["schema_version"]) is not int
            or value["schema_version"] != 1
            or type(value["step_index"]) is not int
            or value["step_index"] != len(ledger["batch_sha256s"])
            or value["mission_id"] != ledger["mission_id"]
            or value["scope_id"] != ledger["scope_id"]
            or value["active_batch_sha256"] != ledger["batch_sha256s"][-1]
            or value["world_state"] != "hypothesis_only"
            or value["effects"] != NO_EFFECTS
        ):
            raise OfflineApiRetestLineageError("retest lineage context is invalid")
        parent_hash = value["parent_lineage_sha256"]
        if value["step_index"] == 1:
            if parent_hash is not None or snapshot.parent_sha256 is not None:
                raise OfflineApiRetestLineageError("initial lineage has a parent")
        elif not isinstance(parent_hash, str) or SHA256_RE.fullmatch(parent_hash) is None:
            raise OfflineApiRetestLineageError("retest lineage parent is invalid")
        if prior is not None:
            checked_prior = verify_offline_api_retest_lineage(prior)
            prior_ledger = checked_prior["source_ledger"]
            current_cases = {item["case_id"]: item for item in ledger["cases"]}
            if (
                value["step_index"] != checked_prior["step_index"] + 1
                or parent_hash != checked_prior["lineage_sha256"]
                or snapshot.parent_sha256
                != checked_prior["world_snapshot"]["snapshot_sha256"]
                or any(
                    ledger[name] != prior_ledger[name]
                    for name in (
                        "mission_id",
                        "scope_id",
                        "manifest_sha256",
                        "source_mode",
                        "source_scope_sha256",
                    )
                )
                or ledger["batch_sha256s"][:-1] != prior_ledger["batch_sha256s"]
                or any(
                    current_cases.get(item["case_id"]) != item
                    for item in prior_ledger["cases"]
                )
            ):
                raise OfflineApiRetestLineageError("retest lineage does not extend its parent")
        expected = _document(
            ledger=ledger,
            snapshot=snapshot,
            parent_lineage_sha256=parent_hash,
        )
        if _canonical(value) != _canonical(expected):
            raise OfflineApiRetestLineageError("retest lineage content identity is invalid")
        return expected
    except (
        AttackWorldModelError,
        OfflineApiSourceLedgerError,
        TypeError,
        KeyError,
        ValueError,
    ) as exc:
        if isinstance(exc, OfflineApiRetestLineageError):
            raise
        raise OfflineApiRetestLineageError("retest lineage archive is invalid") from exc


def build_initial_offline_api_retest_lineage(
    *,
    adapter: OfflineReferenceAdapter,
    sources: Sequence[OfflineApiCaseSource],
    batch: Mapping[str, Any],
    projection: Mapping[str, Any],
    observed_at: str,
    expires_at: str,
) -> dict[str, Any]:
    """Start one effect-free lineage from fully reproduced synthetic sources."""

    try:
        ledger = append_offline_api_source_batch(
            adapter=adapter, sources=sources, batch=batch
        )
        checked = verify_offline_api_world_projection(
            projection=projection,
            adapter=adapter,
            sources=sources,
            batch=batch,
            observed_at=observed_at,
            expires_at=expires_at,
        )
        snapshot = AttackWorldSnapshot.from_dict(checked["snapshot"])
        return verify_offline_api_retest_lineage(
            _document(ledger=ledger, snapshot=snapshot, parent_lineage_sha256=None)
        )
    except (
        OfflineApiSourceLedgerError,
        OfflineApiWorldProjectionError,
        AttackWorldModelError,
    ) as exc:
        raise OfflineApiRetestLineageError("initial API retest sources are invalid") from exc


def append_offline_api_retest_lineage(
    *,
    prior: Mapping[str, Any],
    adapter: OfflineReferenceAdapter,
    sources: Sequence[OfflineApiCaseSource],
    batch: Mapping[str, Any],
    projection: Mapping[str, Any],
    observed_at: str,
    expires_at: str,
) -> dict[str, Any]:
    """Reject cross-batch source replay before appending child world facts."""

    checked_prior = verify_offline_api_retest_lineage(prior)
    try:
        ledger = append_offline_api_source_batch(
            adapter=adapter,
            sources=sources,
            batch=batch,
            prior_ledger=checked_prior["source_ledger"],
        )
        parent = AttackWorldSnapshot.from_dict(checked_prior["world_snapshot"])
        child = append_offline_api_world_projection(
            parent_snapshot=parent,
            projection=projection,
            adapter=adapter,
            sources=sources,
            batch=batch,
            observed_at=observed_at,
            expires_at=expires_at,
        )
        return verify_offline_api_retest_lineage(
            _document(
                ledger=ledger,
                snapshot=child,
                parent_lineage_sha256=checked_prior["lineage_sha256"],
            ),
            prior=checked_prior,
        )
    except (
        OfflineApiSourceLedgerError,
        OfflineApiWorldProjectionError,
        AttackWorldModelError,
    ) as exc:
        raise OfflineApiRetestLineageError("API retest sources or world delta are invalid") from exc


__all__ = [
    "OfflineApiRetestLineageError",
    "append_offline_api_retest_lineage",
    "build_initial_offline_api_retest_lineage",
    "verify_offline_api_retest_lineage",
]
