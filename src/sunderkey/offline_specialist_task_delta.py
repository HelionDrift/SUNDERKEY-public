"""Unsigned, current-source delta of two separately supplied offline tasks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task

DOMAIN = "sunderkey.offline-specialist-task-delta.v1"
SEMANTICS_PROFILE = "current-source-declared-job-label-delta.v1"
MAX_EXTERNAL_BYTES = task.MAX_DOCUMENT_BYTES
MAX_REPORT_BYTES = 524_288
MAX_REPORT_NODES = 8_192
MAX_EXTERNAL_NODES = 200_000
MAX_REPORT_DEPTH = 12
MAX_EXTERNAL_DEPTH = 80
MAX_WORK = 134_217_728
MAX_JOBS_PER_SIDE = 16
MAX_UNION_JOBS = 32
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")
_HEX = frozenset("0123456789abcdefABCDEF")
_ID_ZERO = "OTD-" + "0" * 32
_SHA_ZERO = "sha256:" + "0" * 64
_RELATIONS = (
    "added",
    "removed",
    "selector_changed",
    "request_changed",
    "same_request",
)
_BOUNDS = {
    "jobs_per_side": MAX_JOBS_PER_SIDE,
    "union_jobs": MAX_UNION_JOBS,
    "external_document_bytes": MAX_EXTERNAL_BYTES,
    "report_bytes": MAX_REPORT_BYTES,
    "report_nodes": MAX_REPORT_NODES,
    "report_depth": MAX_REPORT_DEPTH,
    "cumulative_own_work": MAX_WORK,
}
_FLAGS = {
    "offline_only": True,
    "same_target_verified": False,
    "historical_catalog_accepted": False,
    "change_is_improvement": False,
    "positive_use_approved": False,
    "qualification_claimed": False,
}
_EFFECTS = {
    "authority": "none",
    "target": "none",
    "execution": "none",
    "routing": "none",
    "qualification": "none",
    "deployment": "none",
    "provider_requests": "none",
}
_LIMITATIONS = [
    "Equal task and job labels are caller declarations, not shared target evidence.",
    "Only exact current-source task replays are compared; stale catalogs refuse.",
    "A changed request or result address is not a better or worse outcome.",
    "No scheduler, finding, action, publication or positive-use authority follows.",
    "The compact report retains identifiers and digests, not original source bytes.",
]


class OfflineSpecialistTaskDeltaError(ValueError):
    """Closed input, current replay, finite budget or delta integrity refusal."""


@dataclass(slots=True)
class _Work:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or amount > MAX_WORK - self.used:
            raise OfflineSpecialistTaskDeltaError("Cumulative delta work ceiling exhausted")
        self.used += amount


def _text_size(value: str, work: _Work, limit: int) -> int:
    if len(value) > limit:
        raise OfflineSpecialistTaskDeltaError("Native string ceiling exhausted")
    work.charge(len(value) + 2)
    size = 2
    for char in value:
        code = ord(char)
        if 0xD800 <= code <= 0xDFFF:
            raise OfflineSpecialistTaskDeltaError("Unicode scalar text required")
        if char in '\\"' or code in (8, 9, 10, 12, 13):
            size += 2
        elif code < 32 or code >= 127:
            size += 6 if code <= 0xFFFF else 12
        else:
            size += 1
        if size > limit:
            raise OfflineSpecialistTaskDeltaError("Escaped string ceiling exhausted")
    return size


def _measure(value: Any, work: _Work, *, external: bool = False) -> tuple[int, int]:
    maximum = MAX_EXTERNAL_BYTES if external else MAX_REPORT_BYTES
    max_nodes = MAX_EXTERNAL_NODES if external else MAX_REPORT_NODES
    max_depth = MAX_EXTERNAL_DEPTH if external else MAX_REPORT_DEPTH
    nodes = size = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes, size
        work.charge(1)
        nodes += 1
        if nodes > max_nodes or depth > max_depth:
            raise OfflineSpecialistTaskDeltaError("Native node or depth ceiling exhausted")
        family = type(item)
        if family is dict or family is list:
            if id(item) in active:
                raise OfflineSpecialistTaskDeltaError("Cyclic native document")
            children = len(item) * (2 if family is dict else 1)
            if children > max_nodes - nodes:
                raise OfflineSpecialistTaskDeltaError("Queued native node ceiling exhausted")
            size += 2 + max(0, len(item) - 1) + (len(item) if family is dict else 0)
            active.add(id(item))
            try:
                if family is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise OfflineSpecialistTaskDeltaError("Exact native text keys required")
                        nodes += 1
                        if nodes > max_nodes or depth + 1 > max_depth:
                            raise OfflineSpecialistTaskDeltaError("Native key ceiling exhausted")
                        size += _text_size(key, work, maximum)
                        work.charge(len(key) * (len(item).bit_length() + 1))
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        elif family is str:
            size += _text_size(item, work, maximum)
        elif family is int:
            if not -(1 << 63) <= item < 1 << 63:
                raise OfflineSpecialistTaskDeltaError("Native signed64 integer required")
            size += len(str(item))
        elif family is bool:
            size += 4 if item else 5
        elif item is None:
            size += 4
        else:
            raise OfflineSpecialistTaskDeltaError("Exact native JSON families required")
        if size > maximum:
            raise OfflineSpecialistTaskDeltaError("Canonical document ceiling exhausted")

    visit(value, 1)
    return size, nodes


def _clone(value: Any) -> Any:
    if type(value) is dict:
        return {key: _clone(child) for key, child in value.items()}
    if type(value) is list:
        return [_clone(child) for child in value]
    return value


def _capture(value: Any, work: _Work, *, external: bool = False) -> tuple[Any, int, int]:
    size, nodes = _measure(value, work, external=external)
    work.charge(2 * (size + nodes))
    return _clone(value), size, nodes


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _integer(token: str) -> int:
    if len(token) > 20 or _INTEGER.fullmatch(token) is None:
        raise OfflineSpecialistTaskDeltaError("Bounded integer grammar required")
    value = int(token)
    if not -(1 << 63) <= value < 1 << 63:
        raise OfflineSpecialistTaskDeltaError("Signed64 integer ceiling exhausted")
    return value


def _reject_number(_token: str) -> Any:
    raise OfflineSpecialistTaskDeltaError("Floating or nonfinite JSON number refused")


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise OfflineSpecialistTaskDeltaError("Duplicate JSON keys refused")
        result[key] = value
    return result


def _raw_preflight(content: bytes, work: _Work) -> str:
    if type(content) is not bytes or not content or len(content) > MAX_REPORT_BYTES:
        raise OfflineSpecialistTaskDeltaError("Bounded exact native JSON bytes required")
    work.charge(3 * len(content))
    if any(byte > 127 for byte in content):
        raise OfflineSpecialistTaskDeltaError("Canonical report JSON must be ASCII")
    text = content.decode("ascii")
    nodes = depth = 0
    index = 0
    while index < len(text):
        char = text[index]
        if char in " \t\r\n,:":
            index += 1
            continue
        if char in "[{":
            depth += 1
            nodes += 1
            if depth > MAX_REPORT_DEPTH:
                raise OfflineSpecialistTaskDeltaError("Raw JSON depth ceiling exhausted")
            index += 1
        elif char in "]}":
            depth -= 1
            if depth < 0:
                raise OfflineSpecialistTaskDeltaError("Raw JSON nesting invalid")
            index += 1
        elif char == '"':
            nodes += 1
            if depth + 1 > MAX_REPORT_DEPTH:
                raise OfflineSpecialistTaskDeltaError("Raw JSON scalar depth exhausted")
            index += 1
            while index < len(text):
                marker = text[index]
                if marker == '"':
                    index += 1
                    break
                if marker == "\\":
                    index += 1
                    if index >= len(text) or text[index] not in '"\\/bfnrtu':
                        raise OfflineSpecialistTaskDeltaError("Raw JSON escape invalid")
                    if text[index] == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(digit not in _HEX for digit in digits):
                            raise OfflineSpecialistTaskDeltaError("Raw JSON Unicode escape invalid")
                        index += 4
                elif ord(marker) < 32:
                    raise OfflineSpecialistTaskDeltaError("Raw control character refused")
                index += 1
            else:
                raise OfflineSpecialistTaskDeltaError("Unterminated raw JSON string")
        else:
            end = index
            while end < len(text) and text[end] not in ' \t\r\n,:]}[{"':
                end += 1
                if end - index > 20:
                    raise OfflineSpecialistTaskDeltaError("Raw scalar ceiling exhausted")
            token = text[index:end]
            if token not in ("true", "false", "null"):
                _integer(token)
            nodes += 1
            if depth + 1 > MAX_REPORT_DEPTH:
                raise OfflineSpecialistTaskDeltaError("Raw scalar depth exhausted")
            index = end
        if nodes > MAX_REPORT_NODES:
            raise OfflineSpecialistTaskDeltaError("Raw node ceiling exhausted")
    if depth != 0:
        raise OfflineSpecialistTaskDeltaError("Raw JSON nesting incomplete")
    return text


def _decode(content: bytes, work: _Work) -> tuple[dict, str]:
    text = _raw_preflight(content, work)
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_integer,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except (ValueError, RecursionError) as exc:
        raise OfflineSpecialistTaskDeltaError("Invalid bounded delta JSON") from exc
    owned, _, _ = _capture(parsed, work)
    if type(owned) is not dict or _canonical(owned) != text:
        raise OfflineSpecialistTaskDeltaError("Exact canonical delta JSON required")
    work.charge(len(text))
    return owned, text


def _identifier(value: Any) -> None:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise OfflineSpecialistTaskDeltaError("Bounded native identity required")


def _sha(value: Any) -> None:
    if type(value) is not str or _SHA.fullmatch(value) is None:
        raise OfflineSpecialistTaskDeltaError("Exact sha256 identity required")


def _address(value: Any, digest: Any, prefix: str) -> None:
    _sha(digest)
    if type(value) is not str or value != prefix + digest[7:39].upper():
        raise OfflineSpecialistTaskDeltaError("Content identity and digest differ")


def _side(document: dict) -> dict:
    return {
        key: document[key]
        for key in (
            "task_id",
            "task_result_id",
            "task_result_sha256",
            "model_sha256",
            "catalog_id",
            "catalog_sha256",
            "job_count",
        )
    }


def _snapshots(document: dict, model: dict) -> dict[str, dict]:
    requests = {row["job_id"]: row["request"] for row in model["jobs"]}
    snapshots = {}
    for job, ownership in zip(document["jobs"], document["ownership_index"], strict=True):
        job_id = job["job_id"]
        request = requests[job_id]
        result = job["result"]
        snapshots[job_id] = {
            "component_id": ownership["component_id"],
            "profile_id": ownership["profile_id"],
            "selector": request.get("component_id"),
            "request_sha256": result["request_sha256"],
            "result_id": result["result_id"],
            "result_sha256": result["result_sha256"],
        }
    return snapshots


def _relation(before: dict | None, after: dict | None) -> str:
    if before is None:
        return "added"
    if after is None:
        return "removed"
    if any(before[key] != after[key] for key in ("selector", "component_id", "profile_id")):
        return "selector_changed"
    if before["request_sha256"] != after["request_sha256"]:
        return "request_changed"
    if (before["result_id"], before["result_sha256"]) != (
        after["result_id"],
        after["result_sha256"],
    ):
        raise OfflineSpecialistTaskDeltaError(
            "Equal current requests cannot yield differing component results"
        )
    return "same_request"


def _rows(before: dict[str, dict], after: dict[str, dict]) -> list[dict]:
    return [
        {
            "job_id": job_id,
            "relation": _relation(before.get(job_id), after.get(job_id)),
            "before": before.get(job_id),
            "after": after.get(job_id),
        }
        for job_id in sorted(before.keys() | after.keys())
    ]


def _counts(rows: list[dict]) -> dict[str, int]:
    return {relation: sum(row["relation"] == relation for row in rows) for relation in _RELATIONS}


def _validate_side(side: Any) -> None:
    fields = {
        "task_id",
        "task_result_id",
        "task_result_sha256",
        "model_sha256",
        "catalog_id",
        "catalog_sha256",
        "job_count",
    }
    if type(side) is not dict or side.keys() != fields:
        raise OfflineSpecialistTaskDeltaError("Closed task side identity required")
    _identifier(side["task_id"])
    _address(side["task_result_id"], side["task_result_sha256"], "OST-")
    _sha(side["model_sha256"])
    _address(side["catalog_id"], side["catalog_sha256"], "OSC-")
    if type(side["job_count"]) is not int or not 1 <= side["job_count"] <= MAX_JOBS_PER_SIDE:
        raise OfflineSpecialistTaskDeltaError("Native task job count invalid")


def _validate_snapshot(value: Any) -> None:
    fields = {
        "component_id",
        "profile_id",
        "selector",
        "request_sha256",
        "result_id",
        "result_sha256",
    }
    if type(value) is not dict or value.keys() != fields:
        raise OfflineSpecialistTaskDeltaError("Closed component identity required")
    _identifier(value["component_id"])
    _identifier(value["profile_id"])
    if value["selector"] is not None:
        _identifier(value["selector"])
    _sha(value["request_sha256"])
    _address(value["result_id"], value["result_sha256"], "OSR-")


def _validate_body(body: Any) -> None:
    fields = {
        "schema_version",
        "semantics_profile",
        "before",
        "after",
        "rows",
        "counts",
        "join_basis",
        "flags",
        "effects",
        "bounds",
        "limitations",
    }
    if type(body) is not dict or body.keys() != fields:
        raise OfflineSpecialistTaskDeltaError("Closed delta report fields required")
    if type(body["schema_version"]) is not int or body["schema_version"] != 1:
        raise OfflineSpecialistTaskDeltaError("Native delta schema version one required")
    if body["semantics_profile"] != SEMANTICS_PROFILE:
        raise OfflineSpecialistTaskDeltaError("Delta semantics profile differs")
    before, after = body["before"], body["after"]
    _validate_side(before)
    _validate_side(after)
    if before["task_id"] != after["task_id"]:
        raise OfflineSpecialistTaskDeltaError("Different declared task labels cannot be joined")
    if (before["catalog_id"], before["catalog_sha256"]) != (
        after["catalog_id"],
        after["catalog_sha256"],
    ):
        raise OfflineSpecialistTaskDeltaError("Both tasks require one current catalog")
    rows = body["rows"]
    if type(rows) is not list or not 1 <= len(rows) <= MAX_UNION_JOBS:
        raise OfflineSpecialistTaskDeltaError("Bounded nonempty delta rows required")
    before_count = after_count = 0
    identities = []
    for row in rows:
        if type(row) is not dict or row.keys() != {"job_id", "relation", "before", "after"}:
            raise OfflineSpecialistTaskDeltaError("Closed delta row required")
        _identifier(row["job_id"])
        identities.append(row["job_id"])
        if row["before"] is None and row["after"] is None:
            raise OfflineSpecialistTaskDeltaError("Delta row needs a task-side identity")
        if row["before"] is not None:
            _validate_snapshot(row["before"])
            before_count += 1
        if row["after"] is not None:
            _validate_snapshot(row["after"])
            after_count += 1
        if row["relation"] != _relation(row["before"], row["after"]):
            raise OfflineSpecialistTaskDeltaError("Delta relation contradicts task identities")
    if identities != sorted(set(identities)):
        raise OfflineSpecialistTaskDeltaError("Delta job labels must be sorted and unique")
    if before_count != before["job_count"] or after_count != after["job_count"]:
        raise OfflineSpecialistTaskDeltaError("Delta rows omit a task job")
    if type(body["counts"]) is not dict or _canonical(body["counts"]) != _canonical(_counts(rows)):
        raise OfflineSpecialistTaskDeltaError("Delta relation counts differ")
    fixed = {
        "join_basis": "caller_declared_equal_task_and_job_labels_only",
        "flags": _FLAGS,
        "effects": _EFFECTS,
        "bounds": _BOUNDS,
        "limitations": _LIMITATIONS,
    }
    if any(_canonical(body[key]) != _canonical(value) for key, value in fixed.items()):
        raise OfflineSpecialistTaskDeltaError("Fixed no-authority metadata differs")


def _finish(body: dict, work: _Work) -> tuple[dict, str]:
    _validate_body(body)
    owned, size, nodes = _capture(body, work)
    provisional = {**owned, "delta_id": _ID_ZERO, "delta_sha256": _SHA_ZERO}
    final_size, final_nodes = _measure(provisional, work)
    body_text = _canonical(owned)
    if len(body_text) != size or final_size > MAX_REPORT_BYTES:
        raise OfflineSpecialistTaskDeltaError("Final delta report byte ceiling exhausted")
    # Own copying, address input, equality replay and final JSON export are funded
    # before the first delta hash. Parent task/catalog/leaf budgets are separate.
    work.charge(12 * final_size + 8 * final_nodes + 4 * nodes + len(DOMAIN) + 1)
    digest = "sha256:" + sha256((DOMAIN + "\n" + body_text).encode("ascii")).hexdigest()
    document = {**owned, "delta_id": "OTD-" + digest[7:39].upper(), "delta_sha256": digest}
    return document, _canonical(document)


def _metadata(document: Any, work: _Work) -> tuple[dict, str]:
    owned, _ = _precheck_report(document, work)
    body = {key: value for key, value in owned.items() if key not in ("delta_id", "delta_sha256")}
    expected, text = _finish(body, work)
    if owned != expected:
        raise OfflineSpecialistTaskDeltaError("Delta metadata or address differs")
    return owned, text


def _precheck_report(document: Any, work: _Work) -> tuple[dict, str]:
    owned, size, _ = _capture(document, work)
    if type(owned) is not dict or owned.keys() != {
        "schema_version",
        "semantics_profile",
        "before",
        "after",
        "rows",
        "counts",
        "join_basis",
        "flags",
        "effects",
        "bounds",
        "limitations",
        "delta_id",
        "delta_sha256",
    }:
        raise OfflineSpecialistTaskDeltaError("Closed addressed delta report required")
    body = {key: value for key, value in owned.items() if key not in ("delta_id", "delta_sha256")}
    _validate_body(body)
    _address(owned["delta_id"], owned["delta_sha256"], "OTD-")
    work.charge(2 * size)
    return owned, _canonical(owned)


def _external_model(model: Any, work: _Work) -> tuple[dict, str]:
    owned, size, _ = _capture(model, work, external=True)
    if type(owned) is not dict:
        raise OfflineSpecialistTaskDeltaError("Exact native task model required")
    work.charge(2 * size)
    text = _canonical(owned)
    try:
        checked = task.parse_offline_specialist_task_model(text.encode("ascii"))
    except ValueError as exc:
        raise OfflineSpecialistTaskDeltaError("Closed original task model refused") from exc
    if checked != owned:
        raise OfflineSpecialistTaskDeltaError("Original task model projection differs")
    return owned, text


def _external_report(report: Any, work: _Work) -> str:
    if type(report) is not task.OfflineSpecialistTaskResult:
        raise OfflineSpecialistTaskDeltaError("Exact task result wrapper required")
    text = getattr(report, "document_json", None)
    if type(text) is not str or len(text) > MAX_EXTERNAL_BYTES:
        raise OfflineSpecialistTaskDeltaError("Bounded task result wrapper required")
    work.charge(3 * len(text))
    return text


def _derive(
    *,
    before_report: Any,
    before_model: Any,
    after_report: Any,
    after_model: Any,
    catalog: Any,
    repository_root: str | Path,
    work: _Work,
) -> tuple[dict, str]:
    before_owned, before_text = _external_model(before_model, work)
    after_owned, after_text = _external_model(after_model, work)
    if before_owned.get("task_id") != after_owned.get("task_id"):
        raise OfflineSpecialistTaskDeltaError("Exact declared task labels must agree")
    before_original = _external_report(before_report, work)
    after_original = _external_report(after_report, work)
    if type(catalog) is not components.OfflineSpecialistComponentCatalog:
        raise OfflineSpecialistTaskDeltaError("Exact native current catalog required")
    try:
        before_verified = task.verify_offline_specialist_task(
            before_report, model=before_owned, catalog=catalog, repository_root=repository_root
        )
        after_verified = task.verify_offline_specialist_task(
            after_report, model=after_owned, catalog=catalog, repository_root=repository_root
        )
    except ValueError as exc:
        raise OfflineSpecialistTaskDeltaError(
            "Separate original/current task replay refused"
        ) from exc
    before_late, _, _ = _capture(before_model, work, external=True)
    after_late, _, _ = _capture(after_model, work, external=True)
    before_late_text = getattr(before_report, "document_json", None)
    after_late_text = getattr(after_report, "document_json", None)
    if (
        type(before_late_text) is not str
        or type(after_late_text) is not str
        or before_late_text != before_original
        or after_late_text != after_original
        or _canonical(before_late) != before_text
        or _canonical(after_late) != after_text
        or before_verified.document_json != before_original
        or after_verified.document_json != after_original
    ):
        raise OfflineSpecialistTaskDeltaError("Original task delivery changed during replay")
    before_doc = before_verified.to_dict()
    after_doc = after_verified.to_dict()
    if (
        before_doc["catalog_id"] != after_doc["catalog_id"]
        or before_doc["catalog_sha256"] != after_doc["catalog_sha256"]
    ):
        raise OfflineSpecialistTaskDeltaError("Current task catalogs differ")
    before_jobs = _snapshots(before_doc, before_owned)
    after_jobs = _snapshots(after_doc, after_owned)
    rows = _rows(before_jobs, after_jobs)
    body = {
        "schema_version": 1,
        "semantics_profile": SEMANTICS_PROFILE,
        "before": _side(before_doc),
        "after": _side(after_doc),
        "rows": rows,
        "counts": _counts(rows),
        "join_basis": "caller_declared_equal_task_and_job_labels_only",
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "bounds": dict(_BOUNDS),
        "limitations": list(_LIMITATIONS),
    }
    # A final source binding check narrows demonstrated late local catalog drift.
    try:
        current = components.OfflineSpecialistComponentCatalog.from_dict(
            catalog.to_dict(), repository_root=repository_root
        ).to_dict()
    except ValueError as exc:
        raise OfflineSpecialistTaskDeltaError("Final current catalog validation refused") from exc
    if (current["catalog_id"], current["catalog_sha256"]) != (
        before_doc["catalog_id"],
        before_doc["catalog_sha256"],
    ):
        raise OfflineSpecialistTaskDeltaError("Current catalog changed during delta derivation")
    return _finish(body, work)


@dataclass(frozen=True, slots=True, init=False)
class OfflineSpecialistTaskDelta:
    """Addressed metadata; exports do not replay task originals or repository sources."""

    document_json: str

    def __init__(self, _document_json: Any = None) -> None:
        raise OfflineSpecialistTaskDeltaError("Use analysis or source-replaying parsers")

    @classmethod
    def _owned(cls, text: str) -> OfflineSpecialistTaskDelta:
        result = object.__new__(cls)
        object.__setattr__(result, "document_json", text)
        return result

    def _read(self, work: _Work | None = None) -> tuple[dict, str]:
        if type(self) is not OfflineSpecialistTaskDelta:
            raise OfflineSpecialistTaskDeltaError("Exact native delta wrapper required")
        text = getattr(self, "document_json", None)
        if type(text) is not str or len(text) > MAX_REPORT_BYTES:
            raise OfflineSpecialistTaskDeltaError("Bounded delta wrapper text required")
        work = _Work() if work is None else work
        try:
            encoded = text.encode("utf-8")
        except UnicodeError as exc:
            raise OfflineSpecialistTaskDeltaError("Delta wrapper text is invalid") from exc
        owned, canonical = _decode(encoded, work)
        document, checked = _metadata(owned, work)
        if canonical != checked:
            raise OfflineSpecialistTaskDeltaError("Delta wrapper text differs")
        return document, checked

    def to_dict(self) -> dict:
        return self._read()[0]

    def to_json(self) -> str:
        return self._read()[1]

    @classmethod
    def from_dict(
        cls,
        document: Any,
        *,
        before_report: Any,
        before_model: Any,
        after_report: Any,
        after_model: Any,
        catalog: Any,
        repository_root: str | Path,
    ) -> OfflineSpecialistTaskDelta:
        work = _Work()
        supplied, _ = _precheck_report(document, work)
        expected, text = _derive(
            before_report=before_report,
            before_model=before_model,
            after_report=after_report,
            after_model=after_model,
            catalog=catalog,
            repository_root=repository_root,
            work=work,
        )
        if supplied != expected:
            raise OfflineSpecialistTaskDeltaError("Delta differs from separate current originals")
        return cls._owned(text)

    @classmethod
    def from_json(
        cls,
        content: Any,
        *,
        before_report: Any,
        before_model: Any,
        after_report: Any,
        after_model: Any,
        catalog: Any,
        repository_root: str | Path,
    ) -> OfflineSpecialistTaskDelta:
        if type(content) is not str or len(content) > MAX_REPORT_BYTES:
            raise OfflineSpecialistTaskDeltaError("Bounded exact native delta JSON text required")
        work = _Work()
        try:
            encoded = content.encode("utf-8")
        except UnicodeError as exc:
            raise OfflineSpecialistTaskDeltaError("Delta JSON text is invalid") from exc
        supplied, canonical = _decode(encoded, work)
        _precheck_report(supplied, work)
        expected, text = _derive(
            before_report=before_report,
            before_model=before_model,
            after_report=after_report,
            after_model=after_model,
            catalog=catalog,
            repository_root=repository_root,
            work=work,
        )
        if supplied != expected or canonical != text:
            raise OfflineSpecialistTaskDeltaError("Delta differs from separate current originals")
        return cls._owned(text)


def analyze_offline_specialist_task_delta(
    *,
    before_report: Any,
    before_model: Any,
    after_report: Any,
    after_model: Any,
    catalog: Any,
    repository_root: str | Path,
) -> OfflineSpecialistTaskDelta:
    _document, text = _derive(
        before_report=before_report,
        before_model=before_model,
        after_report=after_report,
        after_model=after_model,
        catalog=catalog,
        repository_root=repository_root,
        work=_Work(),
    )
    return OfflineSpecialistTaskDelta._owned(text)


def analyze_offline_specialist_task_delta_bytes(
    *,
    before_report: Any,
    before_model_bytes: Any,
    after_report: Any,
    after_model_bytes: Any,
    catalog: Any,
    repository_root: str | Path,
) -> OfflineSpecialistTaskDelta:
    work = _Work()
    if any(
        type(content) is not bytes or not content or len(content) > MAX_EXTERNAL_BYTES
        for content in (before_model_bytes, after_model_bytes)
    ):
        raise OfflineSpecialistTaskDeltaError("Bounded exact native task model bytes required")
    work.charge(3 * (len(before_model_bytes) + len(after_model_bytes)))
    try:
        before_model = task.parse_offline_specialist_task_model(before_model_bytes)
        after_model = task.parse_offline_specialist_task_model(after_model_bytes)
    except ValueError as exc:
        raise OfflineSpecialistTaskDeltaError("Closed original task model bytes refused") from exc
    _document, text = _derive(
        before_report=before_report,
        before_model=before_model,
        after_report=after_report,
        after_model=after_model,
        catalog=catalog,
        repository_root=repository_root,
        work=work,
    )
    return OfflineSpecialistTaskDelta._owned(text)


def verify_offline_specialist_task_delta(
    report: Any,
    *,
    before_report: Any,
    before_model: Any,
    after_report: Any,
    after_model: Any,
    catalog: Any,
    repository_root: str | Path,
) -> OfflineSpecialistTaskDelta:
    if type(report) is not OfflineSpecialistTaskDelta:
        raise OfflineSpecialistTaskDeltaError("Exact native delta wrapper required")
    work = _Work()
    raw_text = getattr(report, "document_json", None)
    if type(raw_text) is not str or len(raw_text) > MAX_REPORT_BYTES:
        raise OfflineSpecialistTaskDeltaError("Bounded exact delta wrapper required")
    try:
        encoded = raw_text.encode("utf-8")
    except UnicodeError as exc:
        raise OfflineSpecialistTaskDeltaError("Delta wrapper text is invalid") from exc
    supplied, supplied_text = _decode(encoded, work)
    _precheck_report(supplied, work)
    expected, text = _derive(
        before_report=before_report,
        before_model=before_model,
        after_report=after_report,
        after_model=after_model,
        catalog=catalog,
        repository_root=repository_root,
        work=work,
    )
    if supplied != expected or supplied_text != text:
        raise OfflineSpecialistTaskDeltaError("Delta differs from separate current originals")
    return OfflineSpecialistTaskDelta._owned(text)


__all__ = [
    "OfflineSpecialistTaskDelta",
    "OfflineSpecialistTaskDeltaError",
    "analyze_offline_specialist_task_delta",
    "analyze_offline_specialist_task_delta_bytes",
    "verify_offline_specialist_task_delta",
]
