"""Local, non-authoritative custody for offline assessment candidate history."""

from __future__ import annotations

import json
import os
import re
import sqlite3
from dataclasses import dataclass, replace
from datetime import timedelta
from pathlib import Path
from typing import Any

from .event_assessment_planning import (
    MAX_AGE_SECONDS,
    MAX_DAILY_CANDIDATES,
    MAX_EVENTS,
    MAX_PRIOR_CANDIDATES,
    NO_EFFECTS,
    AssessmentCandidate,
    AssessmentCandidateBatch,
    AssessmentChangeEvent,
    EventAssessmentError,
    _positive_limit,
    _sha,
    _time,
    plan_event_assessments,
    verify_assessment_candidate_batch,
)
from .traffic_derived_api_inventory import _canonical_sha

SCHEMA_VERSION = 1
MAX_HISTORY_ENTRIES = 16_384
MAX_DATABASE_BYTES = 128 * 1024 * 1024
REQUEST_ID_RE = re.compile(r"eventreq:[A-Za-z0-9][A-Za-z0-9._/-]{0,126}\Z")
GENESIS_DOMAIN = "sunderkey.event-assessment-history-genesis.v1"
REQUEST_DOMAIN = "sunderkey.event-assessment-history-request.v1"
ENTRY_DOMAIN = "sunderkey.event-assessment-history-entry.v1"

META_SQL = (
    "CREATE TABLE metadata (id INTEGER PRIMARY KEY CHECK (id = 1), "
    "scope_sha256 TEXT NOT NULL, head_sequence INTEGER NOT NULL, "
    "head_sha256 TEXT NOT NULL)"
)
ENTRY_SQL = (
    "CREATE TABLE entries (sequence INTEGER PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, "
    "request_sha256 TEXT NOT NULL, request_json TEXT NOT NULL, "
    "batch_json TEXT NOT NULL, previous_sha256 TEXT NOT NULL, entry_sha256 TEXT NOT NULL)"
)


class EventAssessmentHistoryError(EventAssessmentError):
    """Local history is incomplete, corrupt, or inconsistent with source replay."""


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise EventAssessmentHistoryError("history value is not canonical JSON") from exc


def _read_json(text: Any, label: str) -> Any:
    if not isinstance(text, str) or len(text) > 4_194_304:
        raise EventAssessmentHistoryError(f"{label} storage type or size is invalid")
    try:
        value = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise EventAssessmentHistoryError(f"{label} JSON is invalid") from exc
    if _canonical_json(value) != text:
        raise EventAssessmentHistoryError(f"{label} JSON is not canonical")
    return value


def _event(raw: Any) -> AssessmentChangeEvent:
    expected = {
        "event_id",
        "source_id",
        "kind",
        "scope_sha256",
        "evidence_sha256",
        "occurred_at",
        "change_signal",
        "reason_codes",
        "event_sha256",
    }
    if (
        not isinstance(raw, dict)
        or set(raw) != expected
        or not isinstance(raw["reason_codes"], list)
    ):
        raise EventAssessmentHistoryError("stored event fields are invalid")
    try:
        event = AssessmentChangeEvent(
            event_id=raw["event_id"],
            source_id=raw["source_id"],
            kind=raw["kind"],
            scope_sha256=raw["scope_sha256"],
            evidence_sha256=raw["evidence_sha256"],
            occurred_at=raw["occurred_at"],
            change_signal=raw["change_signal"],
            reason_codes=tuple(raw["reason_codes"]),
            event_sha256=raw["event_sha256"],
        )
    except (EventAssessmentError, TypeError) as exc:
        raise EventAssessmentHistoryError("stored event is invalid") from exc
    if event.to_dict() != raw:
        raise EventAssessmentHistoryError("stored event is not canonical")
    return event


def _candidate(raw: Any) -> AssessmentCandidate:
    if not isinstance(raw, dict) or set(raw) != {
        "event",
        "disposition",
        "evaluated_at",
        "candidate_sha256",
    }:
        raise EventAssessmentHistoryError("stored candidate fields are invalid")
    try:
        candidate = AssessmentCandidate(
            event=_event(raw["event"]),
            disposition=raw["disposition"],
            evaluated_at=raw["evaluated_at"],
            candidate_sha256=raw["candidate_sha256"],
        )
    except EventAssessmentError as exc:
        raise EventAssessmentHistoryError("stored candidate is invalid") from exc
    if candidate.to_dict() != raw:
        raise EventAssessmentHistoryError("stored candidate is not canonical")
    return candidate


def _batch(raw: Any) -> AssessmentCandidateBatch:
    expected = {
        "as_of",
        "scope_sha256",
        "max_event_age_seconds",
        "cooldown_seconds",
        "daily_candidate_budget",
        "intake_stopped",
        "event_set_sha256",
        "prior_candidate_set_sha256",
        "candidates",
        "effects",
        "batch_sha256",
    }
    if (
        not isinstance(raw, dict)
        or set(raw) != expected
        or raw["effects"] != dict(NO_EFFECTS)
        or not isinstance(raw["candidates"], list)
    ):
        raise EventAssessmentHistoryError("stored batch fields or effects are invalid")
    try:
        batch = AssessmentCandidateBatch(
            as_of=raw["as_of"],
            scope_sha256=raw["scope_sha256"],
            max_event_age_seconds=raw["max_event_age_seconds"],
            cooldown_seconds=raw["cooldown_seconds"],
            daily_candidate_budget=raw["daily_candidate_budget"],
            intake_stopped=raw["intake_stopped"],
            event_set_sha256=raw["event_set_sha256"],
            prior_candidate_set_sha256=raw["prior_candidate_set_sha256"],
            candidates=tuple(_candidate(item) for item in raw["candidates"]),
            batch_sha256=raw["batch_sha256"],
        )
    except EventAssessmentError as exc:
        raise EventAssessmentHistoryError("stored batch is invalid") from exc
    if batch.to_dict() != raw:
        raise EventAssessmentHistoryError("stored batch is not canonical")
    return batch


def _request(
    *,
    request_id: str,
    events: tuple[AssessmentChangeEvent, ...],
    scope_sha256: str,
    as_of: str,
    max_event_age_seconds: int,
    cooldown_seconds: int,
    daily_candidate_budget: int,
    intake_stopped: bool,
) -> dict[str, Any]:
    if not isinstance(request_id, str) or REQUEST_ID_RE.fullmatch(request_id) is None:
        raise EventAssessmentHistoryError("request_id is invalid")
    _sha(scope_sha256, "scope_sha256")
    _time(as_of, "as_of")
    _positive_limit(max_event_age_seconds, MAX_AGE_SECONDS, "max_event_age_seconds")
    _positive_limit(cooldown_seconds, MAX_AGE_SECONDS, "cooldown_seconds")
    _positive_limit(daily_candidate_budget, MAX_DAILY_CANDIDATES, "daily_candidate_budget")
    if not isinstance(intake_stopped, bool):
        raise EventAssessmentHistoryError("intake_stopped must be a boolean")
    if not isinstance(events, tuple) or not 1 <= len(events) <= MAX_EVENTS:
        raise EventAssessmentHistoryError("events must be a bounded tuple")
    if any(not isinstance(item, AssessmentChangeEvent) for item in events):
        raise EventAssessmentHistoryError("events must be typed change events")
    for item in events:
        replace(item)
    return {
        "request_id": request_id,
        "events": [item.to_dict() for item in events],
        "scope_sha256": scope_sha256,
        "as_of": as_of,
        "max_event_age_seconds": max_event_age_seconds,
        "cooldown_seconds": cooldown_seconds,
        "daily_candidate_budget": daily_candidate_budget,
        "intake_stopped": intake_stopped,
    }


def _prior_candidates(
    history: list[AssessmentCandidate], request: dict[str, Any]
) -> tuple[AssessmentCandidate, ...]:
    now = _time(request["as_of"], "as_of")
    seconds = max(
        request["max_event_age_seconds"],
        request["cooldown_seconds"],
        86_400,
    )
    cutoff = now - timedelta(seconds=seconds)
    prior = tuple(item for item in history if _time(item.evaluated_at, "evaluated_at") >= cutoff)
    if len(prior) > MAX_PRIOR_CANDIDATES:
        raise EventAssessmentHistoryError("active prior history exceeds the planner limit")
    return prior


@dataclass(frozen=True, slots=True)
class VerifiedAssessmentHistory:
    scope_sha256: str
    head_sequence: int
    head_sha256: str
    last_batch: AssessmentCandidateBatch | None
    active_candidates: tuple[AssessmentCandidate, ...]


@dataclass(frozen=True, slots=True)
class VerifiedAssessmentHistoryEntry:
    """One replay-verified request entry within a checked history snapshot."""

    request_id: str
    request_sha256: str
    sequence: int
    entry_sha256: str
    batch: AssessmentCandidateBatch
    current_head_sequence: int
    current_head_sha256: str


class OfflineEventAssessmentHistoryStore:
    """Durable replayable history with no assessment admission or scheduling effect."""

    def __init__(self, path: str | Path, scope_sha256: str) -> None:
        _sha(scope_sha256, "scope_sha256")
        self.path = Path(path).absolute()
        self.scope_sha256 = scope_sha256

    def _connect(self, *, read_only: bool) -> sqlite3.Connection:
        if not self.path.is_file() or self.path.is_symlink():
            raise EventAssessmentHistoryError("history database is missing or ambiguous")
        try:
            size = self.path.stat().st_size
        except OSError as exc:
            raise EventAssessmentHistoryError("Could not inspect history database") from exc
        if size > MAX_DATABASE_BYTES:
            raise EventAssessmentHistoryError("history database exceeds the local size limit")
        mode = "ro" if read_only else "rw"
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                self.path.as_uri() + f"?mode={mode}",
                uri=True,
                isolation_level=None,
                timeout=5,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            if not read_only:
                connection.execute("PRAGMA synchronous = FULL")
            return connection
        except sqlite3.Error as exc:
            if connection is not None:
                connection.close()
            raise EventAssessmentHistoryError("Could not open history database") from exc

    def initialize(self) -> None:
        """Create a local store once; never accept it as an authority source."""

        if self.path.is_symlink() or not self.path.parent.is_dir():
            raise EventAssessmentHistoryError("history path is ambiguous")
        if self.path.exists():
            self.verify()
            return
        try:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            os.close(descriptor)
            connection = sqlite3.connect(self.path, isolation_level=None, timeout=5)
            try:
                connection.execute("PRAGMA trusted_schema = OFF")
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(META_SQL)
                connection.execute(ENTRY_SQL)
                connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                genesis = _canonical_sha(GENESIS_DOMAIN, {"scope_sha256": self.scope_sha256})
                connection.execute(
                    "INSERT OR IGNORE INTO metadata VALUES (1, ?, 0, ?)",
                    (self.scope_sha256, genesis),
                )
                self._verify_schema(connection)
                self._verify_history(connection)
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
            finally:
                connection.close()
        except (OSError, sqlite3.Error) as exc:
            raise EventAssessmentHistoryError("Could not initialize history database") from exc

    def _verify_schema(self, connection: sqlite3.Connection) -> None:
        if connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
            raise EventAssessmentHistoryError("history schema version is invalid")
        rows = connection.execute(
            "SELECT type, name, sql FROM sqlite_master ORDER BY type, name"
        ).fetchall()
        if [(row[0], row[1], row[2]) for row in rows] != [
            ("index", "sqlite_autoindex_entries_1", None),
            ("table", "entries", ENTRY_SQL),
            ("table", "metadata", META_SQL),
        ]:
            raise EventAssessmentHistoryError("history schema is invalid")

    def _verify_history(self, connection: sqlite3.Connection) -> VerifiedAssessmentHistory:
        self._verify_schema(connection)
        metadata = connection.execute(
            "SELECT id, scope_sha256, head_sequence, head_sha256 FROM metadata"
        ).fetchall()
        if len(metadata) != 1 or metadata[0][0] != 1 or metadata[0][1] != self.scope_sha256:
            raise EventAssessmentHistoryError("history metadata or scope is invalid")
        head_sequence, head_sha256 = metadata[0][2], metadata[0][3]
        if type(head_sequence) is not int or type(head_sha256) is not str:
            raise EventAssessmentHistoryError("history head storage types are invalid")
        previous = _canonical_sha(GENESIS_DOMAIN, {"scope_sha256": self.scope_sha256})
        history: list[AssessmentCandidate] = []
        last_batch: AssessmentCandidateBatch | None = None
        cursor = connection.execute(
            "SELECT sequence, request_id, request_sha256, request_json, batch_json, "
            "previous_sha256, entry_sha256 FROM entries ORDER BY sequence LIMIT ?",
            (MAX_HISTORY_ENTRIES + 1,),
        )
        try:
            rows = cursor.fetchall()
        finally:
            cursor.close()
        if len(rows) > MAX_HISTORY_ENTRIES:
            raise EventAssessmentHistoryError("history entry limit is exceeded")
        sequence = 0
        for sequence, row in enumerate(rows, start=1):
            if type(row[0]) is not int or row[0] != sequence or row[5] != previous:
                raise EventAssessmentHistoryError("history sequence or predecessor is invalid")
            raw_request = _read_json(row[3], "request")
            if not isinstance(raw_request, dict) or set(raw_request) != {
                "request_id",
                "events",
                "scope_sha256",
                "as_of",
                "max_event_age_seconds",
                "cooldown_seconds",
                "daily_candidate_budget",
                "intake_stopped",
            } or not isinstance(raw_request["events"], list):
                raise EventAssessmentHistoryError("stored request fields are invalid")
            events = tuple(_event(item) for item in raw_request["events"])
            request = _request(
                request_id=raw_request["request_id"],
                events=events,
                scope_sha256=raw_request["scope_sha256"],
                as_of=raw_request["as_of"],
                max_event_age_seconds=raw_request["max_event_age_seconds"],
                cooldown_seconds=raw_request["cooldown_seconds"],
                daily_candidate_budget=raw_request["daily_candidate_budget"],
                intake_stopped=raw_request["intake_stopped"],
            )
            if (
                request != raw_request
                or request["scope_sha256"] != self.scope_sha256
                or row[1] != request["request_id"]
                or row[2] != _canonical_sha(REQUEST_DOMAIN, request)
            ):
                raise EventAssessmentHistoryError("stored request identity is invalid")
            if last_batch and _time(request["as_of"], "as_of") < _time(
                last_batch.as_of, "as_of"
            ):
                raise EventAssessmentHistoryError("history time moved backward")
            prior = _prior_candidates(history, request)
            batch = _batch(_read_json(row[4], "batch"))
            try:
                verify_assessment_candidate_batch(batch, events=events, prior_candidates=prior)
            except EventAssessmentError as exc:
                raise EventAssessmentHistoryError("stored batch does not replay") from exc
            expected_entry = _canonical_sha(
                ENTRY_DOMAIN,
                {
                    "sequence": sequence,
                    "previous_sha256": previous,
                    "request_id": request["request_id"],
                    "request_sha256": row[2],
                    "batch_sha256": batch.batch_sha256,
                },
            )
            if type(row[6]) is not str or row[6] != expected_entry:
                raise EventAssessmentHistoryError("history entry content address is invalid")
            previous = expected_entry
            history.extend(batch.candidates)
            cutoff = _time(batch.as_of, "as_of") - timedelta(seconds=MAX_AGE_SECONDS)
            history = [
                item for item in history if _time(item.evaluated_at, "evaluated_at") >= cutoff
            ]
            last_batch = batch
        if head_sequence != sequence or head_sha256 != previous:
            raise EventAssessmentHistoryError("history head does not match entries")
        return VerifiedAssessmentHistory(
            scope_sha256=self.scope_sha256,
            head_sequence=head_sequence,
            head_sha256=head_sha256,
            last_batch=last_batch,
            active_candidates=tuple(history),
        )

    def verify(self) -> VerifiedAssessmentHistory:
        """Verify the exact local chain and replay each batch without mutation."""

        connection = self._connect(read_only=True)
        try:
            connection.execute("BEGIN")
            result = self._verify_history(connection)
            connection.execute("COMMIT")
            return result
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise EventAssessmentHistoryError("Could not verify history database") from exc
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def verify_entry(self, request_id: str) -> VerifiedAssessmentHistoryEntry:
        """Replay the whole chain, then read one request from the same snapshot."""

        if type(request_id) is not str or REQUEST_ID_RE.fullmatch(request_id) is None:
            raise EventAssessmentHistoryError("request_id is invalid")
        connection = self._connect(read_only=True)
        try:
            connection.execute("BEGIN")
            verified = self._verify_history(connection)
            row = connection.execute(
                "SELECT sequence, request_sha256, batch_json, entry_sha256 "
                "FROM entries WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row is None:
                raise EventAssessmentHistoryError("request_id is absent from verified history")
            if type(row[0]) is not int or type(row[1]) is not str or type(row[3]) is not str:
                raise EventAssessmentHistoryError("stored request entry types are invalid")
            result = VerifiedAssessmentHistoryEntry(
                request_id=request_id,
                request_sha256=row[1],
                sequence=row[0],
                entry_sha256=row[3],
                batch=_batch(_read_json(row[2], "batch")),
                current_head_sequence=verified.head_sequence,
                current_head_sha256=verified.head_sha256,
            )
            connection.execute("COMMIT")
            return result
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise EventAssessmentHistoryError("Could not verify history entry") from exc
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def append(
        self,
        *,
        request_id: str,
        events: tuple[AssessmentChangeEvent, ...],
        as_of: str,
        max_event_age_seconds: int = 86_400,
        cooldown_seconds: int = 3_600,
        daily_candidate_budget: int = 8,
        intake_stopped: bool = False,
    ) -> AssessmentCandidateBatch:
        """Atomically record one offline planning result or return its exact replay."""

        request = _request(
            request_id=request_id,
            events=events,
            scope_sha256=self.scope_sha256,
            as_of=as_of,
            max_event_age_seconds=max_event_age_seconds,
            cooldown_seconds=cooldown_seconds,
            daily_candidate_budget=daily_candidate_budget,
            intake_stopped=intake_stopped,
        )
        request_digest = _canonical_sha(REQUEST_DOMAIN, request)
        connection = self._connect(read_only=False)
        try:
            connection.execute("BEGIN IMMEDIATE")
            verified = self._verify_history(connection)
            existing = connection.execute(
                "SELECT request_sha256, batch_json FROM entries WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if existing is not None:
                if existing[0] != request_digest:
                    raise EventAssessmentHistoryError("request_id conflicts with earlier input")
                result = _batch(_read_json(existing[1], "batch"))
                connection.execute("COMMIT")
                return result
            if verified.head_sequence >= MAX_HISTORY_ENTRIES:
                raise EventAssessmentHistoryError("history entry limit is reached")
            if verified.last_batch and _time(as_of, "as_of") < _time(
                verified.last_batch.as_of, "as_of"
            ):
                raise EventAssessmentHistoryError("new request time moved backward")
            prior = _prior_candidates(list(verified.active_candidates), request)
            batch = plan_event_assessments(
                events=events,
                scope_sha256=self.scope_sha256,
                as_of=as_of,
                prior_candidates=prior,
                max_event_age_seconds=max_event_age_seconds,
                cooldown_seconds=cooldown_seconds,
                daily_candidate_budget=daily_candidate_budget,
                intake_stopped=intake_stopped,
            )
            sequence = verified.head_sequence + 1
            entry_digest = _canonical_sha(
                ENTRY_DOMAIN,
                {
                    "sequence": sequence,
                    "previous_sha256": verified.head_sha256,
                    "request_id": request_id,
                    "request_sha256": request_digest,
                    "batch_sha256": batch.batch_sha256,
                },
            )
            connection.execute(
                "INSERT INTO entries VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    sequence,
                    request_id,
                    request_digest,
                    _canonical_json(request),
                    _canonical_json(batch.to_dict()),
                    verified.head_sha256,
                    entry_digest,
                ),
            )
            connection.execute(
                "UPDATE metadata SET head_sequence = ?, head_sha256 = ? WHERE id = 1",
                (sequence, entry_digest),
            )
            page_count = connection.execute("PRAGMA page_count").fetchone()[0]
            page_size = connection.execute("PRAGMA page_size").fetchone()[0]
            if page_count * page_size > MAX_DATABASE_BYTES:
                raise EventAssessmentHistoryError("history database exceeds the local size limit")
            connection.execute("COMMIT")
            return batch
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise EventAssessmentHistoryError("Could not append history entry") from exc
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
