"""Append-only, source-replay-aware custody for synthetic API batches."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from .offline_api_assessment import (
    OfflineApiAssessmentError,
    OfflineApiCaseSource,
    verify_offline_api_batch,
)
from .reference_adapters import OfflineReferenceAdapter

LEDGER_DOMAIN = "sunderkey.offline-api-source-ledger.v1"
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
MAX_CASES = 4096
MAX_BATCHES = 256
NO_EFFECTS = {
    "authority": "none",
    "finding_publication": "none",
    "network": "none",
    "qualification": "none",
    "source_authentication": "none",
    "target_execution": "none",
}


class OfflineApiSourceLedgerError(ValueError):
    """Raised when batch lineage or source reuse is inconsistent."""


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _hash(value: Any, label: str) -> str:
    if type(value) is not str or SHA256_RE.fullmatch(value) is None:
        raise OfflineApiSourceLedgerError(f"{label} is invalid")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or IDENTIFIER_RE.fullmatch(value) is None:
        raise OfflineApiSourceLedgerError(f"{label} is invalid")
    return value


def _native_keys(value: Any) -> bool:
    return isinstance(value, Mapping) and all(type(key) is str for key in value)


def _unique_sorted(values: Any, label: str, *, hashes: bool) -> list[str]:
    if not isinstance(values, list):
        raise OfflineApiSourceLedgerError(f"{label} must be a list")
    checked = [_hash(value, label) if hashes else _identifier(value, label) for value in values]
    if checked != sorted(set(checked)):
        raise OfflineApiSourceLedgerError(f"{label} must be sorted and unique")
    return checked


def _entry(raw: Any, mode: str) -> dict[str, Any]:
    expected = {
        "batch_sha256",
        "case_id",
        "invocation_id",
        "target_id",
        "result_sha256",
        "evidence_sha256s",
        "receipt_sha256s",
        "source_target_sha256",
        "session_principals",
    }
    if not _native_keys(raw) or set(raw) != expected:
        raise OfflineApiSourceLedgerError("ledger case entry fields are invalid")
    entry = dict(raw)
    _hash(entry["batch_sha256"], "batch_sha256")
    for name in ("case_id", "invocation_id", "target_id"):
        _identifier(entry[name], name)
    _hash(entry["result_sha256"], "result_sha256")
    evidence = _unique_sorted(entry["evidence_sha256s"], "evidence_sha256s", hashes=True)
    receipts = _unique_sorted(entry["receipt_sha256s"], "receipt_sha256s", hashes=True)
    if not evidence or len(evidence) > 64:
        raise OfflineApiSourceLedgerError("case evidence count is invalid")
    sessions = entry["session_principals"]
    if not isinstance(sessions, list):
        raise OfflineApiSourceLedgerError("session principals must be a list")
    pairs = []
    for item in sessions:
        if not _native_keys(item) or set(item) != {"session_id", "principal_id"}:
            raise OfflineApiSourceLedgerError("session principal fields are invalid")
        pairs.append(
            {
                "session_id": _identifier(item["session_id"], "session_id"),
                "principal_id": _identifier(item["principal_id"], "principal_id"),
            }
        )
    if pairs != sorted(pairs, key=lambda item: (item["session_id"], item["principal_id"])):
        raise OfflineApiSourceLedgerError("session principals are not sorted")
    if len({item["session_id"] for item in pairs}) != len(pairs):
        raise OfflineApiSourceLedgerError("session principal identity is ambiguous")
    if mode == "receipt_sourced":
        _hash(entry["source_target_sha256"], "source_target_sha256")
        if len(receipts) != len(evidence) or not pairs:
            raise OfflineApiSourceLedgerError("receipt-sourced entry is incomplete")
    elif entry["source_target_sha256"] is not None or receipts or pairs:
        raise OfflineApiSourceLedgerError("unsourced entry has receipt metadata")
    return entry


def verify_offline_api_source_ledger(document: Mapping[str, Any]) -> dict[str, Any]:
    """Check archived structure and content identity without original sources."""

    fields = {
        "schema_version",
        "mission_id",
        "scope_id",
        "manifest_sha256",
        "source_mode",
        "source_scope_sha256",
        "batch_sha256s",
        "cases",
        "effects",
        "ledger_id",
        "ledger_sha256",
    }
    if not _native_keys(document) or set(document) != fields:
        raise OfflineApiSourceLedgerError("source ledger fields are invalid")
    try:
        value = dict(document)
        if type(value["schema_version"]) is not int or value["schema_version"] != 1:
            raise OfflineApiSourceLedgerError("source ledger version is invalid")
        if (
            type(value["effects"]) is not dict
            or not _native_keys(value["effects"])
            or set(value["effects"]) != set(NO_EFFECTS)
            or any(type(item) is not str for item in value["effects"].values())
            or value["effects"] != NO_EFFECTS
        ):
            raise OfflineApiSourceLedgerError("source ledger effects are invalid")
        _identifier(value["mission_id"], "mission_id")
        _identifier(value["scope_id"], "scope_id")
        _hash(value["manifest_sha256"], "manifest_sha256")
        mode = value["source_mode"]
        if type(mode) is not str or mode not in {"synthetic_unsourced", "receipt_sourced"}:
            raise OfflineApiSourceLedgerError("source ledger mode is invalid")
        if mode == "receipt_sourced":
            _hash(value["source_scope_sha256"], "source_scope_sha256")
        elif value["source_scope_sha256"] is not None:
            raise OfflineApiSourceLedgerError("unsourced ledger has a scope digest")
        if not isinstance(value["batch_sha256s"], list):
            raise OfflineApiSourceLedgerError("batch_sha256s must be a list")
        batches = [_hash(item, "batch_sha256s") for item in value["batch_sha256s"]]
        if len(set(batches)) != len(batches):
            raise OfflineApiSourceLedgerError("source ledger batch replay detected")
        if not 1 <= len(batches) <= MAX_BATCHES:
            raise OfflineApiSourceLedgerError("source ledger batch count is invalid")
        cases = value["cases"]
        if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
            raise OfflineApiSourceLedgerError("source ledger case count is invalid")
        entries = [_entry(item, mode) for item in cases]
        if {item["batch_sha256"] for item in entries} != set(batches):
            raise OfflineApiSourceLedgerError("source ledger batch case links are invalid")
        if entries != sorted(entries, key=lambda item: item["case_id"]):
            raise OfflineApiSourceLedgerError("source ledger cases are not sorted")
        for name in ("case_id", "invocation_id"):
            if len({item[name] for item in entries}) != len(entries):
                raise OfflineApiSourceLedgerError(f"source ledger {name} replay detected")
        all_evidence = [digest for item in entries for digest in item["evidence_sha256s"]]
        all_receipts = [digest for item in entries for digest in item["receipt_sha256s"]]
        if len(set(all_evidence)) != len(all_evidence):
            raise OfflineApiSourceLedgerError("source ledger evidence replay detected")
        if len(set(all_receipts)) != len(all_receipts):
            raise OfflineApiSourceLedgerError("source ledger receipt replay detected")
        targets: dict[str, str] = {}
        sessions: dict[str, str] = {}
        for item in entries:
            target_digest = item["source_target_sha256"]
            target_id = item["target_id"]
            if target_id in targets and targets[target_id] != target_digest:
                raise OfflineApiSourceLedgerError("source target digest changed")
            targets[target_id] = target_digest
            for pair in item["session_principals"]:
                session = pair["session_id"]
                principal = pair["principal_id"]
                if session in sessions and sessions[session] != principal:
                    raise OfflineApiSourceLedgerError("source session changed principal")
                sessions[session] = principal
        body = {
            key: item for key, item in value.items() if key not in {"ledger_id", "ledger_sha256"}
        }
        digest = _digest({"domain": LEDGER_DOMAIN, "body": body})
        _hash(value["ledger_sha256"], "ledger_sha256")
        _identifier(value["ledger_id"], "ledger_id")
        if value["ledger_sha256"] != digest or value["ledger_id"] != "OAL-" + digest[7:39].upper():
            raise OfflineApiSourceLedgerError("source ledger content identity is invalid")
        _canonical(value)
        return value
    except (TypeError, ValueError, KeyError) as exc:
        if isinstance(exc, OfflineApiSourceLedgerError):
            raise
        raise OfflineApiSourceLedgerError("source ledger document is invalid") from exc


def append_offline_api_source_batch(
    *,
    adapter: OfflineReferenceAdapter,
    sources: Sequence[OfflineApiCaseSource],
    batch: Mapping[str, Any],
    prior_ledger: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Reproduce a new batch and reject replay against retained source lineage."""

    try:
        checked = verify_offline_api_batch(adapter=adapter, sources=sources, batch=batch)
    except OfflineApiAssessmentError as exc:
        raise OfflineApiSourceLedgerError("API batch sources are invalid") from exc
    prior = None if prior_ledger is None else verify_offline_api_source_ledger(prior_ledger)
    source_mode = (
        "receipt_sourced"
        if "source_receipt_sha256" in sources[0].evidence[0].attributes
        else "synthetic_unsourced"
    )
    source_scope_digest = (
        sources[0].evidence[0].attributes["source_scope_sha256"]
        if source_mode == "receipt_sourced"
        else None
    )
    if prior is not None and (
        prior["mission_id"] != checked.mission_id
        or prior["scope_id"] != checked.scope_id
        or prior["manifest_sha256"] != checked.manifest_sha256
        or prior["source_mode"] != source_mode
        or prior["source_scope_sha256"] != source_scope_digest
    ):
        raise OfflineApiSourceLedgerError("new batch changed source ledger context")
    by_case = {source.case_id: source for source in sources}
    entries = []
    for case in checked.cases:
        source = by_case[case.case_id]
        records = source.evidence
        sourced = source_mode == "receipt_sourced"
        entries.append(
            {
                "batch_sha256": checked.batch_sha256,
                "case_id": case.case_id,
                "invocation_id": source.invocation.invocation_id,
                "target_id": case.target_id,
                "result_sha256": case.result_sha256,
                "evidence_sha256s": sorted(record.evidence_sha256 for record in records),
                "receipt_sha256s": (
                    sorted(record.attributes["source_receipt_sha256"] for record in records)
                    if sourced
                    else []
                ),
                "source_target_sha256": (
                    records[0].attributes["source_target_sha256"] if sourced else None
                ),
                "session_principals": (
                    sorted(
                        {
                            (
                                record.attributes["source_session_id"],
                                record.attributes["principal_id"],
                            )
                            for record in records
                        }
                    )
                    if sourced
                    else []
                ),
            }
        )
    for entry in entries:
        entry["session_principals"] = [
            {"session_id": session, "principal_id": principal}
            for session, principal in entry["session_principals"]
        ]
    body = {
        "schema_version": 1,
        "mission_id": checked.mission_id,
        "scope_id": checked.scope_id,
        "manifest_sha256": checked.manifest_sha256,
        "source_mode": source_mode,
        "source_scope_sha256": source_scope_digest,
        "batch_sha256s": [
            *(prior["batch_sha256s"] if prior is not None else []),
            checked.batch_sha256,
        ],
        "cases": sorted(
            [*(prior["cases"] if prior is not None else []), *entries],
            key=lambda item: item["case_id"],
        ),
        "effects": dict(NO_EFFECTS),
    }
    digest = _digest({"domain": LEDGER_DOMAIN, "body": body})
    return verify_offline_api_source_ledger(
        {**body, "ledger_id": "OAL-" + digest[7:39].upper(), "ledger_sha256": digest}
    )


__all__ = [
    "OfflineApiSourceLedgerError",
    "append_offline_api_source_batch",
    "verify_offline_api_source_ledger",
]
