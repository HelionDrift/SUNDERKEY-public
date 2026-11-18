"""Local custody of unsigned cross-domain review assertions.

This journal records what an operator asserted about a freshly replayed
collaboration handoff. It never authenticates a reviewer or accepts a review
for finding, world-model, action, or publication use.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from pathlib import Path
from typing import Any

from . import offline_collaboration_claim_graph as graph
from . import offline_collaboration_review_handoff as handoff

DOMAIN = "sunderkey.offline-collaboration-review-custody.v1"
APPLICATION_ID = 0x53554344
GENESIS = "sha256:" + "0" * 64
MAX_ENTRIES = 4096
MAX_ENTRY_JSON_BYTES = 16_384
MAX_DATABASE_BYTES = 134_217_728
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_ROLES = frozenset({"independent_control", "independent_assurance"})
_DISPOSITIONS = frozenset({"accept_for_review_only", "challenge", "needs_evidence"})
_REASONS = frozenset({
    "declared_match", "source_scope_challenge", "conflict_unresolved",
    "missing_evidence", "semantic_challenge", "reviewer_correction",
})
_DISPOSITION_REASONS = {
    "accept_for_review_only": frozenset({"declared_match"}),
    "challenge": frozenset({
        "source_scope_challenge", "conflict_unresolved", "semantic_challenge",
    }),
    "needs_evidence": frozenset({"missing_evidence"}),
}
_EFFECTS = dict.fromkeys((
    "authority", "target", "network", "credential", "process", "execution",
    "routing", "qualification", "publication", "deployment", "assignment",
    "world_edge_promotion", "finding_eligibility",
), "none")
_SCHEMA = (
    "CREATE TABLE custody_metadata ("
    "key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE custody_entries ("
    "sequence INTEGER PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, "
    "request_sha256 TEXT NOT NULL, entry_sha256 TEXT NOT NULL UNIQUE, "
    "entry_json TEXT NOT NULL)",
    "CREATE TRIGGER custody_entries_no_update BEFORE UPDATE ON custody_entries "
    "BEGIN SELECT RAISE(ABORT, 'custody entries are immutable'); END",
    "CREATE TRIGGER custody_entries_no_delete BEFORE DELETE ON custody_entries "
    "BEGIN SELECT RAISE(ABORT, 'custody entries are append only'); END",
)
_SCHEMA_NAMES = {
    ("table", "custody_metadata"), ("table", "custody_entries"),
    ("trigger", "custody_entries_no_update"),
    ("trigger", "custody_entries_no_delete"),
}


class OfflineCollaborationReviewCustodyError(ValueError):
    """The local review assertion boundary could not be verified."""


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise OfflineCollaborationReviewCustodyError(f"{label} is invalid")
    return value


def _sha(value: Any, label: str) -> str:
    if type(value) is not str or _SHA.fullmatch(value) is None:
        raise OfflineCollaborationReviewCustodyError(f"{label} is invalid")
    return value


def _time(value: Any) -> str:
    if type(value) is not str or _UTC.fullmatch(value) is None:
        raise OfflineCollaborationReviewCustodyError("recorded_at is invalid")
    from datetime import datetime

    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OfflineCollaborationReviewCustodyError("recorded_at is invalid") from exc
    return value


def _canonical(value: Any) -> str:
    try:
        return graph._capture(value, "custody record")[1]
    except graph.OfflineCollaborationClaimGraphError as exc:
        raise OfflineCollaborationReviewCustodyError(
            "custody record exceeds native bounds"
        ) from exc


def _digest(kind: str, value: Any) -> str:
    return "sha256:" + hashlib.sha256(
        (DOMAIN + "." + kind + "\n" + _canonical(value)).encode("ascii")
    ).hexdigest()


def _checked_handoff(
    packet: Any, *, report: Any, model: Any, source_contexts: Any,
    catalog: Any, repository_root: str | Path,
) -> dict:
    try:
        return handoff.verify_offline_collaboration_review_handoff(
            packet, report=report, model=model, source_contexts=source_contexts,
            catalog=catalog, repository_root=repository_root,
        )
    except handoff.OfflineCollaborationReviewHandoffError as exc:
        raise OfflineCollaborationReviewCustodyError(
            "current handoff and original sources do not replay"
        ) from exc


def _selected_item(packet: dict, kind: str, identifier: str, scope_id: str) -> dict:
    if type(kind) is not str or kind not in {"claim", "hypothesis"}:
        raise OfflineCollaborationReviewCustodyError("item kind is invalid")
    field = "claim_review_items" if kind == "claim" else "hypothesis_review_items"
    key = "claim_id" if kind == "claim" else "hypothesis_id"
    selected = [item for item in packet[field] if item[key] == identifier]
    if len(selected) != 1 or selected[0]["scope_id"] != scope_id:
        raise OfflineCollaborationReviewCustodyError("item or declared scope is absent")
    return selected[0]


class OfflineCollaborationReviewCustodyStore:
    """A bounded SQLite history for one asserted tenant and declared scope."""

    def __init__(self, path: str | Path, *, tenant_id: str, declared_scope_id: str) -> None:
        self.path = Path(path).absolute()
        self.tenant_id = _identifier(tenant_id, "tenant_id")
        self.declared_scope_id = _identifier(declared_scope_id, "declared_scope_id")

    def _inspect_path(self, *, require_file: bool) -> None:
        """Reject link and Windows reparse aliases before opening SQLite."""
        for candidate in (self.path, *self.path.parents):
            try:
                info = os.lstat(candidate)
            except FileNotFoundError:
                if candidate == self.path and not require_file:
                    continue
                raise OfflineCollaborationReviewCustodyError(
                    "custody path or parent is missing"
                ) from None
            except OSError as exc:
                raise OfflineCollaborationReviewCustodyError(
                    "custody path cannot be inspected"
                ) from exc
            if stat.S_ISLNK(info.st_mode) or (
                os.name == "nt"
                and getattr(info, "st_file_attributes", 0)
                & stat.FILE_ATTRIBUTE_REPARSE_POINT
            ):
                raise OfflineCollaborationReviewCustodyError(
                    "custody path contains a link or reparse point"
                )
            if candidate == self.path:
                if not stat.S_ISREG(info.st_mode):
                    raise OfflineCollaborationReviewCustodyError(
                        "custody database is not a regular file"
                    )
                if info.st_size > MAX_DATABASE_BYTES:
                    raise OfflineCollaborationReviewCustodyError(
                        "custody database exceeds local size limit"
                    )
            elif not stat.S_ISDIR(info.st_mode):
                raise OfflineCollaborationReviewCustodyError(
                    "custody parent is not a directory"
                )

    def _connect(self, *, read_only: bool = False) -> sqlite3.Connection:
        self._inspect_path(require_file=True)
        mode = "ro" if read_only else "rw"
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                self.path.as_uri() + f"?mode={mode}", uri=True, timeout=10
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA foreign_keys=ON")
            return connection
        except sqlite3.Error as exc:
            if connection is not None:
                connection.close()
            raise OfflineCollaborationReviewCustodyError(
                "custody database could not be opened"
            ) from exc

    @staticmethod
    def _metadata(connection: sqlite3.Connection) -> dict[str, str]:
        return {
            row["key"]: row["value"]
            for row in connection.execute("SELECT key,value FROM custody_metadata")
        }

    def _verify_schema(self, connection: sqlite3.Connection) -> None:
        app_id = connection.execute("PRAGMA application_id").fetchone()[0]
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        schema = {
            (row["type"], row["name"]): row["sql"]
            for row in connection.execute(
                "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            )
        }
        if (
            app_id != APPLICATION_ID or version != 1
            or set(schema) != _SCHEMA_NAMES
            or tuple(schema[(kind, name)] for kind, name in (
                ("table", "custody_metadata"), ("table", "custody_entries"),
                ("trigger", "custody_entries_no_update"),
                ("trigger", "custody_entries_no_delete"),
            )) != _SCHEMA
        ):
            raise OfflineCollaborationReviewCustodyError("custody schema identity is invalid")
        metadata = self._metadata(connection)
        if set(metadata) != {
            "tenant_id", "declared_scope_id", "head_sequence", "head_sha256",
            "handoff_sha256", "graph_sha256", "catalog_sha256",
        }:
            raise OfflineCollaborationReviewCustodyError("custody metadata is invalid")
        if (
            metadata["tenant_id"] != self.tenant_id
            or metadata["declared_scope_id"] != self.declared_scope_id
        ):
            raise OfflineCollaborationReviewCustodyError("custody tenant or scope differs")

    def initialize(self) -> None:
        """Create only an empty new store; never adopt a foreign SQLite file."""
        self._inspect_path(require_file=False)
        if self.path.exists():
            self.verify_history()
            return
        try:
            descriptor = os.open(
                self.path,
                os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_BINARY", 0),
                0o600,
            )
            os.close(descriptor)
        except FileExistsError as exc:
            raise OfflineCollaborationReviewCustodyError(
                "custody path appeared during exclusive creation"
            ) from exc
        except OSError as exc:
            raise OfflineCollaborationReviewCustodyError(
                "custody database could not be exclusively created"
            ) from exc
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            ).fetchone()[0]
            if (
                existing != 0
                or connection.execute("PRAGMA application_id").fetchone()[0] != 0
                or connection.execute("PRAGMA user_version").fetchone()[0] != 0
            ):
                raise OfflineCollaborationReviewCustodyError(
                    "exclusive new database has foreign content"
                )
            for statement in _SCHEMA:
                connection.execute(statement)
            connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
            connection.execute("PRAGMA user_version=1")
            connection.executemany(
                "INSERT INTO custody_metadata(key,value) VALUES(?,?)",
                (
                    ("tenant_id", self.tenant_id),
                    ("declared_scope_id", self.declared_scope_id),
                    ("head_sequence", "0"),
                    ("head_sha256", GENESIS),
                    ("handoff_sha256", ""),
                    ("graph_sha256", ""),
                    ("catalog_sha256", ""),
                ),
            )
            self._verify_locked(connection)
            connection.commit()
        except (sqlite3.Error, OfflineCollaborationReviewCustodyError) as exc:
            connection.rollback()
            raise OfflineCollaborationReviewCustodyError("custody initialization failed") from exc
        finally:
            connection.close()

    def _verify_locked(self, connection: sqlite3.Connection) -> tuple[dict, list[dict], dict]:
        self._inspect_path(require_file=True)
        pages = connection.execute("PRAGMA page_count").fetchone()[0]
        page_bytes = connection.execute("PRAGMA page_size").fetchone()[0]
        if pages * page_bytes > MAX_DATABASE_BYTES:
            raise OfflineCollaborationReviewCustodyError(
                "custody database exceeds local size limit"
            )
        if connection.execute("PRAGMA quick_check(1)").fetchone()[0] != "ok":
            raise OfflineCollaborationReviewCustodyError("custody SQLite integrity failed")
        self._verify_schema(connection)
        metadata = self._metadata(connection)
        try:
            head_sequence = int(metadata["head_sequence"])
        except ValueError as exc:
            raise OfflineCollaborationReviewCustodyError("head sequence is invalid") from exc
        if (
            head_sequence < 0
            or head_sequence > MAX_ENTRIES
            or str(head_sequence) != metadata["head_sequence"]
        ):
            raise OfflineCollaborationReviewCustodyError("head sequence is invalid")
        _sha(metadata["head_sha256"], "head_sha256")
        for field in ("handoff_sha256", "graph_sha256", "catalog_sha256"):
            if head_sequence == 0:
                if metadata[field] != "":
                    raise OfflineCollaborationReviewCustodyError("empty store has source binding")
            else:
                _sha(metadata[field], field)
        entries: list[dict] = []
        active: dict[tuple[str, str, str], dict] = {}
        previous = GENESIS
        rows = connection.execute(
            "SELECT sequence,request_id,request_sha256,entry_sha256,entry_json "
            "FROM custody_entries ORDER BY sequence LIMIT ?",
            (MAX_ENTRIES + 1,),
        ).fetchall()
        if len(rows) > MAX_ENTRIES:
            raise OfflineCollaborationReviewCustodyError("custody history limit exceeded")
        by_digest: dict[str, dict] = {}
        last_time = ""
        for sequence, row in enumerate(rows, start=1):
            entry_json = row["entry_json"]
            if (
                type(entry_json) is not str
                or len(entry_json.encode("utf-8")) > MAX_ENTRY_JSON_BYTES
            ):
                raise OfflineCollaborationReviewCustodyError(
                    "stored entry exceeds byte limit"
                )
            try:
                entry = json.loads(entry_json)
            except (TypeError, ValueError) as exc:
                raise OfflineCollaborationReviewCustodyError("stored entry is invalid") from exc
            if type(entry) is not dict or _canonical(entry) != entry_json or set(entry) != {
                "schema_version", "sequence", "previous_sha256", "request",
                "request_sha256", "entry_id", "entry_sha256",
            }:
                raise OfflineCollaborationReviewCustodyError("stored entry is not canonical")
            request = entry["request"]
            if (
                type(request) is not dict
                or type(request.get("schema_version")) is not int
                or request["schema_version"] != 1
            ):
                raise OfflineCollaborationReviewCustodyError("stored request is invalid")
            request_id = _identifier(request.get("request_id"), "request_id")
            request_sha = _digest("request", request)
            body = {key: value for key, value in entry.items() if key not in {
                "entry_id", "entry_sha256",
            }}
            entry_sha = _digest("entry", body)
            if (
                type(entry["schema_version"]) is not int or entry["schema_version"] != 1
                or type(entry["sequence"]) is not int or entry["sequence"] != sequence
                or entry["previous_sha256"] != previous
                or entry["request_sha256"] != request_sha
                or entry["entry_sha256"] != entry_sha
                or entry["entry_id"] != "OCR-" + entry_sha[7:39].upper()
                or row["sequence"] != sequence
                or row["request_id"] != request_id
                or row["request_sha256"] != request_sha
                or row["entry_sha256"] != entry_sha
            ):
                raise OfflineCollaborationReviewCustodyError("custody chain is invalid")
            recorded_at = _time(request.get("recorded_at"))
            if recorded_at < last_time:
                raise OfflineCollaborationReviewCustodyError("custody time moves backward")
            self._replay_request(request, metadata, active, by_digest, entry_sha)
            last_time = recorded_at
            entries.append(entry)
            by_digest[entry_sha] = entry
            previous = entry_sha
        if head_sequence != len(entries) or metadata["head_sha256"] != previous:
            raise OfflineCollaborationReviewCustodyError("custody head differs from entries")
        return metadata, entries, active

    def _replay_request(
        self, request: dict, metadata: dict[str, str],
        active: dict[tuple[str, str, str], dict], by_digest: dict[str, dict],
        entry_sha: str,
    ) -> None:
        common = {
            "schema_version", "kind", "request_id", "tenant_id", "declared_scope_id",
            "handoff_sha256", "graph_sha256", "catalog_sha256", "reviewer_subject",
            "recorded_at", "reason_code",
        }
        if (
            request.get("tenant_id") != self.tenant_id
            or request.get("declared_scope_id") != self.declared_scope_id
            or request.get("handoff_sha256") != metadata["handoff_sha256"]
            or request.get("graph_sha256") != metadata["graph_sha256"]
            or request.get("catalog_sha256") != metadata["catalog_sha256"]
        ):
            raise OfflineCollaborationReviewCustodyError("request source binding differs")
        _identifier(request.get("reviewer_subject"), "reviewer_subject")
        _time(request.get("recorded_at"))
        if (
            type(request.get("reason_code")) is not str
            or request["reason_code"] not in _REASONS
        ):
            raise OfflineCollaborationReviewCustodyError("reason code is invalid")
        if request.get("kind") == "review":
            if set(request) != common | {
                "item_kind", "item_id", "item_status", "item_sha256",
                "reviewer_role", "disposition",
            }:
                raise OfflineCollaborationReviewCustodyError("review request fields are invalid")
            kind = request["item_kind"]
            item_id = _identifier(request["item_id"], "item_id")
            _sha(request["item_sha256"], "item_sha256")
            if (
                type(kind) is not str or kind not in {"claim", "hypothesis"}
                or type(request["item_status"]) is not str
                or request["item_status"] not in {
                    "matches_declared_expectation", "contradicts_declared_expectation",
                    "unassessed",
                }
            ):
                raise OfflineCollaborationReviewCustodyError("review item is invalid")
            role = request["reviewer_role"]
            if (
                type(role) is not str or role not in _ROLES
                or type(request["disposition"]) is not str
                or request["disposition"] not in _DISPOSITIONS
            ):
                raise OfflineCollaborationReviewCustodyError(
                    "review role or disposition is invalid"
                )
            if (
                request["disposition"] == "accept_for_review_only"
                and request["item_status"] != "matches_declared_expectation"
            ):
                raise OfflineCollaborationReviewCustodyError("nonmatching item cannot be accepted")
            if request["reason_code"] not in _DISPOSITION_REASONS[request["disposition"]]:
                raise OfflineCollaborationReviewCustodyError(
                    "review reason does not match disposition"
                )
            key = (kind, item_id, role)
            if key in active:
                raise OfflineCollaborationReviewCustodyError("role already has an active assertion")
            other = (
                kind, item_id,
                "independent_assurance" if role == "independent_control" else "independent_control",
            )
            if (
                other in active
                and active[other]["request"]["reviewer_subject"]
                == request["reviewer_subject"]
            ):
                raise OfflineCollaborationReviewCustodyError("same subject cannot fill both roles")
            active[key] = {"entry_sha256": entry_sha, "request": request}
        elif request.get("kind") == "revoke":
            if set(request) != common | {"target_entry_sha256"}:
                raise OfflineCollaborationReviewCustodyError("revocation fields are invalid")
            if request["reason_code"] != "reviewer_correction":
                raise OfflineCollaborationReviewCustodyError("revocation reason is invalid")
            target = _sha(request["target_entry_sha256"], "target_entry_sha256")
            original = by_digest.get(target)
            if original is None or original["request"]["kind"] != "review":
                raise OfflineCollaborationReviewCustodyError(
                    "revocation target is not a prior review"
                )
            old = original["request"]
            key = (old["item_kind"], old["item_id"], old["reviewer_role"])
            if (
                key not in active or active[key]["entry_sha256"] != target
                or request["reviewer_subject"] != old["reviewer_subject"]
                or request["recorded_at"] < old["recorded_at"]
            ):
                raise OfflineCollaborationReviewCustodyError(
                    "revocation does not bind active assertion"
                )
            del active[key]
        else:
            raise OfflineCollaborationReviewCustodyError("request kind is invalid")

    def verify_history(self) -> dict:
        """Verify local immutable structure only, not source or reviewer identity."""
        connection = self._connect(read_only=True)
        try:
            connection.execute("BEGIN")
            metadata, entries, active = self._verify_locked(connection)
            connection.commit()
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.rollback()
            raise OfflineCollaborationReviewCustodyError(
                "custody history could not be verified"
            ) from exc
        finally:
            connection.close()
        return {
            "head_sequence": len(entries),
            "head_sha256": metadata["head_sha256"],
            "handoff_sha256": metadata["handoff_sha256"],
            "active_assertion_count": len(active),
            "identity_assurance": "operator_asserted_unsigned",
            "review_status": "assertions_recorded_not_accepted",
            "operational_effects": dict(_EFFECTS),
        }

    def _append(self, request: dict, checked: dict) -> dict:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            metadata, entries, active = self._verify_locked(connection)
            for name, source in (
                ("handoff_sha256", "handoff_sha256"),
                ("graph_sha256", "graph_sha256"),
                ("catalog_sha256", "catalog_sha256"),
            ):
                if metadata[name] and metadata[name] != checked[source]:
                    raise OfflineCollaborationReviewCustodyError("store belongs to another handoff")
                if not metadata[name]:
                    connection.execute(
                        "UPDATE custody_metadata SET value=? WHERE key=?",
                        (checked[source], name),
                    )
                    metadata[name] = checked[source]
            request_sha = _digest("request", request)
            prior = connection.execute(
                "SELECT request_sha256,entry_json FROM custody_entries WHERE request_id=?",
                (request["request_id"],),
            ).fetchone()
            if prior is not None:
                if prior["request_sha256"] != request_sha:
                    raise OfflineCollaborationReviewCustodyError("request ID was rebound")
                connection.commit()
                return json.loads(prior["entry_json"])
            if len(entries) >= MAX_ENTRIES:
                raise OfflineCollaborationReviewCustodyError("custody history limit exceeded")
            if entries and request["recorded_at"] < entries[-1]["request"]["recorded_at"]:
                raise OfflineCollaborationReviewCustodyError("custody time moves backward")
            body = {
                "schema_version": 1,
                "sequence": len(entries) + 1,
                "previous_sha256": metadata["head_sha256"],
                "request": request,
                "request_sha256": request_sha,
            }
            entry_sha = _digest("entry", body)
            entry = {
                **body, "entry_id": "OCR-" + entry_sha[7:39].upper(),
                "entry_sha256": entry_sha,
            }
            entry_text = _canonical(entry)
            if len(entry_text.encode("utf-8")) > MAX_ENTRY_JSON_BYTES:
                raise OfflineCollaborationReviewCustodyError("custody entry exceeds byte limit")
            prior_by_digest = {item["entry_sha256"]: item for item in entries}
            self._replay_request(request, metadata, active, prior_by_digest, entry_sha)
            connection.execute(
                "INSERT INTO custody_entries VALUES(?,?,?,?,?)",
                (
                    len(entries) + 1, request["request_id"], request_sha,
                    entry_sha, entry_text,
                ),
            )
            connection.execute(
                "UPDATE custody_metadata SET value=? WHERE key='head_sequence'",
                (str(len(entries) + 1),),
            )
            connection.execute(
                "UPDATE custody_metadata SET value=? WHERE key='head_sha256'",
                (entry_sha,),
            )
            connection.commit()
            return entry
        except (sqlite3.Error, OfflineCollaborationReviewCustodyError) as exc:
            connection.rollback()
            if isinstance(exc, OfflineCollaborationReviewCustodyError):
                raise
            raise OfflineCollaborationReviewCustodyError("custody append failed") from exc
        finally:
            connection.close()

    def record_review(
        self, *, request_id: str, packet: Any, report: Any, model: Any,
        source_contexts: Any, catalog: Any, repository_root: str | Path,
        item_kind: str, item_id: str, reviewer_role: str, reviewer_subject: str,
        disposition: str, reason_code: str, recorded_at: str,
    ) -> dict:
        """Append one asserted decision after a fresh original-source replay."""
        checked = _checked_handoff(
            packet, report=report, model=model, source_contexts=source_contexts,
            catalog=catalog, repository_root=repository_root,
        )
        selected = _selected_item(
            checked, item_kind, _identifier(item_id, "item_id"), self.declared_scope_id
        )
        if disposition == "accept_for_review_only" and (
            (item_kind == "claim" and selected["ownership_reference"] is None)
            or (item_kind == "hypothesis" and selected["ownership_incomplete"])
        ):
            raise OfflineCollaborationReviewCustodyError(
                "incomplete catalog ownership cannot support a favorable assertion"
            )
        request = {
            "schema_version": 1,
            "kind": "review",
            "request_id": _identifier(request_id, "request_id"),
            "tenant_id": self.tenant_id,
            "declared_scope_id": self.declared_scope_id,
            "handoff_sha256": checked["handoff_sha256"],
            "graph_sha256": checked["graph_sha256"],
            "catalog_sha256": checked["catalog_sha256"],
            "item_kind": item_kind,
            "item_id": item_id,
            "item_status": selected["status"],
            "item_sha256": _digest("item", selected),
            "reviewer_role": reviewer_role,
            "reviewer_subject": _identifier(reviewer_subject, "reviewer_subject"),
            "disposition": disposition,
            "reason_code": reason_code,
            "recorded_at": _time(recorded_at),
        }
        return self._append(request, checked)

    def revoke_review(
        self, *, request_id: str, target_entry_sha256: str,
        reviewer_subject: str, reason_code: str, recorded_at: str,
    ) -> dict:
        """Withdraw an assertion using historical local integrity only.

        Source drift must not prevent a restrictive withdrawal. This method
        does not authenticate the withdrawing subject or establish authority.
        """
        connection = self._connect(read_only=True)
        try:
            connection.execute("BEGIN")
            metadata, entries, _active = self._verify_locked(connection)
            connection.commit()
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.rollback()
            raise OfflineCollaborationReviewCustodyError(
                "custody withdrawal history could not be verified"
            ) from exc
        finally:
            connection.close()
        if not entries:
            raise OfflineCollaborationReviewCustodyError("no assertion can be revoked")
        checked = {
            key: metadata[key]
            for key in ("handoff_sha256", "graph_sha256", "catalog_sha256")
        }
        request = {
            "schema_version": 1,
            "kind": "revoke",
            "request_id": _identifier(request_id, "request_id"),
            "tenant_id": self.tenant_id,
            "declared_scope_id": self.declared_scope_id,
            "handoff_sha256": checked["handoff_sha256"],
            "graph_sha256": checked["graph_sha256"],
            "catalog_sha256": checked["catalog_sha256"],
            "target_entry_sha256": _sha(target_entry_sha256, "target_entry_sha256"),
            "reviewer_subject": _identifier(reviewer_subject, "reviewer_subject"),
            "reason_code": reason_code,
            "recorded_at": _time(recorded_at),
        }
        return self._append(request, checked)

    def verify_current(
        self, *, packet: Any, report: Any, model: Any, source_contexts: Any,
        catalog: Any, repository_root: str | Path,
    ) -> dict:
        """Replay current supplied originals and summarize unsigned assertions."""
        checked = _checked_handoff(
            packet, report=report, model=model, source_contexts=source_contexts,
            catalog=catalog, repository_root=repository_root,
        )
        connection = self._connect(read_only=True)
        try:
            connection.execute("BEGIN")
            metadata, entries, active = self._verify_locked(connection)
            connection.commit()
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.rollback()
            raise OfflineCollaborationReviewCustodyError(
                "current custody history could not be verified"
            ) from exc
        finally:
            connection.close()
        if entries and any(
            metadata[name] != checked[name]
            for name in ("handoff_sha256", "graph_sha256", "catalog_sha256")
        ):
            raise OfflineCollaborationReviewCustodyError("current handoff differs from history")
        items = {
            (kind, item[key]): item
            for kind, field, key in (
                ("claim", "claim_review_items", "claim_id"),
                ("hypothesis", "hypothesis_review_items", "hypothesis_id"),
            )
            for item in checked[field]
            if item["scope_id"] == self.declared_scope_id
        }
        for entry in entries:
            request = entry["request"]
            if request["kind"] != "review":
                continue
            item = items.get((request["item_kind"], request["item_id"]))
            if (
                item is None or item["status"] != request["item_status"]
                or _digest("item", item) != request["item_sha256"]
            ):
                raise OfflineCollaborationReviewCustodyError(
                    "reviewed item differs from current source"
                )
        states = []
        for (kind, identifier), item in sorted(items.items()):
            records = {
                role: active.get((kind, identifier, role))
                for role in sorted(_ROLES)
            }
            dispositions = {
                role: None if record is None else record["request"]["disposition"]
                for role, record in records.items()
            }
            if "challenge" in dispositions.values():
                state = "contested_operator_assertion"
            elif "needs_evidence" in dispositions.values():
                state = "needs_evidence_operator_assertion"
            elif all(value == "accept_for_review_only" for value in dispositions.values()):
                state = "dual_operator_assertions_unverified"
            else:
                state = "pending_operator_assertion"
            states.append({
                "item_kind": kind, "item_id": identifier,
                "declared_scope_id": self.declared_scope_id,
                "source_status": item["status"],
                "role_dispositions": dispositions,
                "state": state,
            })
        return {
            "schema_version": 1,
            "tenant_id": self.tenant_id,
            "declared_scope_id": self.declared_scope_id,
            "handoff_sha256": checked["handoff_sha256"],
            "history_head_sequence": len(entries),
            "history_head_sha256": metadata["head_sha256"],
            "identity_assurance": "operator_asserted_unsigned",
            "scope_assurance": "caller_declared_unverified",
            "review_status": "assertions_recorded_not_accepted",
            "item_review_states": states,
            "independent_review_accepted": False,
            "positive_use_approved": False,
            "operational_effects": dict(_EFFECTS),
        }


__all__ = [
    "OfflineCollaborationReviewCustodyError",
    "OfflineCollaborationReviewCustodyStore",
]
