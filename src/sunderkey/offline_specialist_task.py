"""Bounded, source-replaying composition of inert partial specialist analyses."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import offline_specialist_components as components
from .offline_cookie_selection import component_fixture as cookie_fixture
from .offline_tls_hello_analysis import component_fixture as tls_fixture

DOMAIN = "sunderkey.offline-specialist-task-result.v1"
MAX_JOBS = 16
MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_NATIVE_NODES = 200_000
MAX_NATIVE_DEPTH = 80
MAX_WORK = 128 * 1024 * 1024
MIN_INTEGER = -(1 << 63)
MAX_INTEGER = (1 << 63) - 1
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_STRING_BOUNDARY = re.compile(r'["\\\x00-\x1f]')
_HEX = frozenset("0123456789abcdefABCDEF")
_DIGEST_PLACEHOLDER = "sha256:" + "0" * 64
_ID_PLACEHOLDER = "OST-" + "0" * 32
_EFFECTS = {
    "target_authority": "none",
    "qualification": "none",
    "routing": "none",
    "execution": "none",
    "deployment": "none",
    "provider_requests": "none",
    "assignment": "none",
    "finding_publication": "none",
}
_WARNING = (
    "Complete requests and results retain unsanitized supplied source content; "
    "this result is not redaction, safe rendering or a secret-free export."
)
_LIMITATIONS = [
    "The task identifier is an unsigned grouping label, not a target or identity join.",
    "Jobs have no inferred dependencies, output-to-input wiring or automatic retries.",
    "Each job remains a partial offline analysis, not an assembled or qualified candidate.",
    "Ownership comes from the current catalog, not assignment or independent review acceptance.",
    "Exports validate metadata only; current-source verification requires separate originals.",
    "Catalog/source reads are bounded development I/O, not a filesystem containment guarantee.",
    "Orchestration work bounds do not count internal catalog or leaf algorithm work.",
    "A failed task returns no partial result, although earlier pure calculations may have run.",
]
_BOUNDS = {
    "max_jobs": MAX_JOBS,
    "max_model_bytes": MAX_DOCUMENT_BYTES,
    "max_result_bytes": MAX_DOCUMENT_BYTES,
    "max_native_nodes": MAX_NATIVE_NODES,
    "max_native_depth": MAX_NATIVE_DEPTH,
    "max_orchestration_work": MAX_WORK,
    "max_preparation_calls": MAX_JOBS,
    "max_analyzer_calls_per_pass": MAX_JOBS,
}


class OfflineSpecialistTaskError(components.OfflineSpecialistComponentError):
    """Invalid task, cost exhaustion, source drift or inconsistent result metadata."""


@dataclass(slots=True)
class _Work:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or self.used + amount > MAX_WORK:
            raise OfflineSpecialistTaskError("Orchestration work budget exceeded")
        self.used += amount


def _text_size(text: str, work: _Work) -> int:
    if type(text) is not str or len(text) > MAX_DOCUMENT_BYTES:
        raise OfflineSpecialistTaskError("Bounded exact native JSON text is required")
    work.charge(len(text) + 1)
    size = 2
    for character in text:
        value = ord(character)
        if 0xD800 <= value <= 0xDFFF:
            raise OfflineSpecialistTaskError("JSON text must contain Unicode scalar values")
        if character in '"\\' or character in "\b\f\n\r\t":
            size += 2
        elif value < 32 or value >= 127:
            size += 6 if value <= 0xFFFF else 12
        else:
            size += 1
        if size > MAX_DOCUMENT_BYTES:
            raise OfflineSpecialistTaskError("Escaped JSON text exceeds the byte budget")
    return size


def _measure(value: Any, work: _Work, maximum_bytes: int | None = None) -> int:
    """Charge every occurrence, including shared subtrees, before serialization."""
    maximum_bytes = MAX_DOCUMENT_BYTES if maximum_bytes is None else maximum_bytes
    pending = [(value, 0)]
    nodes = size = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        work.charge(1)
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise OfflineSpecialistTaskError("Native JSON node or depth budget exceeded")
        family = type(item)
        if family is dict:
            if item and depth + 1 > MAX_NATIVE_DEPTH:
                raise OfflineSpecialistTaskError("Native JSON key depth budget exceeded")
            if nodes + len(pending) + 2 * len(item) > MAX_NATIVE_NODES:
                raise OfflineSpecialistTaskError("Queued native JSON node budget exceeded")
            size += 2 + max(0, len(item) - 1) + len(item)
            for key, child in item.items():
                if type(key) is not str:
                    raise OfflineSpecialistTaskError("JSON keys must be exact native text")
                nodes += 1
                size += _text_size(key, work)
                pending.append((child, depth + 1))
        elif family is list:
            if nodes + len(pending) + len(item) > MAX_NATIVE_NODES:
                raise OfflineSpecialistTaskError("Queued native JSON node budget exceeded")
            size += 2 + max(0, len(item) - 1)
            pending.extend((child, depth + 1) for child in item)
        elif family is str:
            size += _text_size(item, work)
        elif family is int:
            if not MIN_INTEGER <= item <= MAX_INTEGER:
                raise OfflineSpecialistTaskError("JSON integer is outside signed int64")
            size += len(str(item))
        elif family is bool:
            size += 4 if item else 5
        elif item is None:
            size += 4
        else:
            raise OfflineSpecialistTaskError("JSON values must use exact supported native types")
        if size > maximum_bytes:
            raise OfflineSpecialistTaskError("Aggregate canonical JSON byte budget exceeded")
    return size


def _dump(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    )


def _serialize(value: Any, work: _Work, maximum_bytes: int | None = None) -> str:
    size = _measure(value, work, maximum_bytes)
    work.charge(size)
    return _dump(value)


def _snapshot(value: Any, work: _Work, maximum_bytes: int | None = None) -> tuple[Any, str]:
    text = _serialize(value, work, maximum_bytes)
    work.charge(len(text))
    return json.loads(text), text


def _integer(token: str) -> int:
    if _NUMBER.fullmatch(token) is None:
        raise OfflineSpecialistTaskError("JSON integer lexical form is invalid or oversized")
    value = int(token)
    if not MIN_INTEGER <= value <= MAX_INTEGER:
        raise OfflineSpecialistTaskError("JSON integer is outside signed int64")
    return value


def _raw_preflight(text: str, work: _Work) -> None:
    """Bound raw value/key allocation, escaped strings and scalars before JSON decode."""
    work.charge(len(text))
    index = nodes = depth = canonical_bytes = 0
    while index < len(text):
        character = text[index]
        if character in " \t\r\n":
            index += 1
            continue
        if character in "[{":
            if depth > MAX_NATIVE_DEPTH:
                raise OfflineSpecialistTaskError("Raw JSON depth budget exceeded")
            depth += 1
            nodes += 1
            canonical_bytes += 1
            index += 1
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise OfflineSpecialistTaskError("Raw JSON nesting is invalid")
            canonical_bytes += 1
            index += 1
        elif character in ",:":
            canonical_bytes += 1
            index += 1
        elif character == '"':
            if depth > MAX_NATIVE_DEPTH:
                raise OfflineSpecialistTaskError("Raw JSON scalar depth budget exceeded")
            nodes += 1
            canonical_bytes += 2
            index += 1
            while True:
                boundary = _STRING_BOUNDARY.search(text, index)
                if boundary is None:
                    raise OfflineSpecialistTaskError("Raw JSON string is incomplete")
                for literal in text[index : boundary.start()]:
                    number = ord(literal)
                    if 0xD800 <= number <= 0xDFFF:
                        raise OfflineSpecialistTaskError("Raw JSON contains a lone surrogate")
                    canonical_bytes += 1 if number < 127 else (6 if number <= 0xFFFF else 12)
                index = boundary.start()
                marker = text[index]
                if marker == '"':
                    index += 1
                    break
                if marker != "\\" or index + 1 >= len(text):
                    raise OfflineSpecialistTaskError("Raw JSON string escape is invalid")
                escaped = text[index + 1]
                if escaped in '"\\/bfnrt':
                    canonical_bytes += 1 if escaped == "/" else 2
                    index += 2
                elif escaped == "u":
                    digits = text[index + 2 : index + 6]
                    if len(digits) != 4 or any(part not in _HEX for part in digits):
                        raise OfflineSpecialistTaskError("Raw JSON Unicode escape is invalid")
                    number = int(digits, 16)
                    index += 6
                    if 0xD800 <= number <= 0xDBFF:
                        following = text[index : index + 6]
                        if (
                            len(following) != 6
                            or not following.startswith("\\u")
                            or any(part not in _HEX for part in following[2:])
                            or not 0xDC00 <= int(following[2:], 16) <= 0xDFFF
                        ):
                            raise OfflineSpecialistTaskError("Raw JSON surrogate pair is invalid")
                        index += 6
                        canonical_bytes += 12
                    elif 0xDC00 <= number <= 0xDFFF:
                        raise OfflineSpecialistTaskError("Raw JSON contains a lone surrogate")
                    elif number in (8, 9, 10, 12, 13, 34, 92):
                        canonical_bytes += 2
                    else:
                        canonical_bytes += 6 if number < 32 or number >= 127 else 1
                else:
                    raise OfflineSpecialistTaskError("Raw JSON string escape is invalid")
                if canonical_bytes > MAX_DOCUMENT_BYTES:
                    raise OfflineSpecialistTaskError("Raw escaped JSON byte budget exceeded")
        else:
            end = index
            while end < len(text) and text[end] not in ' \t\r\n,:]}[{"':
                end += 1
                if end - index > 20:
                    raise OfflineSpecialistTaskError("Raw JSON scalar exceeds the lexical budget")
            token = text[index:end]
            if token not in ("null", "true", "false"):
                _integer(token)
            if depth > MAX_NATIVE_DEPTH:
                raise OfflineSpecialistTaskError("Raw JSON scalar depth budget exceeded")
            nodes += 1
            canonical_bytes += len(token)
            index = end
        if nodes > MAX_NATIVE_NODES or canonical_bytes > MAX_DOCUMENT_BYTES:
            raise OfflineSpecialistTaskError("Raw JSON node or canonical byte budget exceeded")
    if depth:
        raise OfflineSpecialistTaskError("Raw JSON nesting is incomplete")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OfflineSpecialistTaskError("Duplicate JSON keys are not permitted")
        result[key] = value
    return result


def _reject_number(_token: str) -> Any:
    raise OfflineSpecialistTaskError("Floating and nonfinite JSON numbers are not permitted")


def _decode(content: Any, work: _Work) -> Any:
    if type(content) is not bytes or not content or len(content) > MAX_DOCUMENT_BYTES:
        raise OfflineSpecialistTaskError("Nonempty bounded exact native UTF-8 bytes are required")
    try:
        text = content.decode("utf-8")
        _raw_preflight(text, work)
        work.charge(len(content))
        raw = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_integer,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise OfflineSpecialistTaskError("Invalid bounded task JSON") from exc
    _measure(raw, work)
    return raw


def _identifier(value: Any, label: str) -> None:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise OfflineSpecialistTaskError(f"{label} must be bounded native ASCII identifier text")


def _model(raw: Any, work: _Work) -> tuple[dict[str, Any], str]:
    owned, text = _snapshot(raw, work)
    if type(owned) is not dict or owned.keys() != {"schema_version", "task_id", "jobs"}:
        raise OfflineSpecialistTaskError("Task model fields are invalid")
    if type(owned["schema_version"]) is not int or owned["schema_version"] != 1:
        raise OfflineSpecialistTaskError("Task schema_version must be the native integer 1")
    _identifier(owned["task_id"], "task_id")
    jobs = owned["jobs"]
    if type(jobs) is not list or not 1 <= len(jobs) <= MAX_JOBS:
        raise OfflineSpecialistTaskError("Task requires 1 through 16 native jobs")
    identities = set()
    for job in jobs:
        if type(job) is not dict or job.keys() != {"job_id", "request"}:
            raise OfflineSpecialistTaskError("Task job fields are invalid")
        _identifier(job["job_id"], "job_id")
        if job["job_id"] in identities:
            raise OfflineSpecialistTaskError("Task job identifiers must be unique")
        identities.add(job["job_id"])
        if type(job["request"]) is not dict:
            raise OfflineSpecialistTaskError(
                "Each job requires a complete native component request"
            )
    return owned, text


def _catalog(catalog: Any, repository_root: str | Path, work: _Work) -> tuple[Any, dict]:
    if type(catalog) is not components.OfflineSpecialistComponentCatalog:
        raise OfflineSpecialistTaskError("Exact native current component catalog is required")
    raw, text = _snapshot(catalog.to_dict(), work, components.MAX_CATALOG_BYTES)
    current = components.OfflineSpecialistComponentCatalog.from_dict(
        raw, repository_root=repository_root
    )
    if _serialize(current.to_dict(), work, components.MAX_CATALOG_BYTES) != text:
        raise OfflineSpecialistTaskError("Current catalog snapshot differs")
    return current, raw


def _digest(content: str) -> str:
    return "sha256:" + hashlib.sha256(content.encode("ascii")).hexdigest()


def _index(job_id: str, result: dict) -> dict:
    descriptor = result.get("component")
    required = (
        "component_id",
        "profile_id",
        "package_id",
        "commander_profile_id",
        "independent_validator_id",
    )
    if (
        type(descriptor) is not dict
        or any(type(descriptor.get(key)) is not str or not descriptor[key] for key in required)
        or type(result.get("result_id")) is not str
        or type(result.get("result_sha256")) is not str
    ):
        raise OfflineSpecialistTaskError("Component ownership metadata is incomplete or nonnative")
    return {
        "job_id": job_id,
        "component_id": descriptor["component_id"],
        "profile_id": descriptor["profile_id"],
        "package_id": descriptor["package_id"],
        "commander_profile_id": descriptor["commander_profile_id"],
        "independent_validator_id": descriptor["independent_validator_id"],
        "result_id": result["result_id"],
        "result_sha256": result["result_sha256"],
        "independent_review_required": True,
    }


def _finalize(body: dict, model_json: str, work: _Work) -> tuple[dict, str]:
    """Reserve full final retention/serialization/address work before task digests."""
    body["model_sha256"] = _DIGEST_PLACEHOLDER
    document = {
        **body,
        "task_result_id": _ID_PLACEHOLDER,
        "task_result_sha256": _DIGEST_PLACEHOLDER,
    }
    final_size = _measure(document, work)
    address_json = _serialize({"domain": DOMAIN, "content": body}, work, MAX_DOCUMENT_BYTES + 256)
    # Actual address serialization, both digests and final export serialization.
    work.charge(2 * len(address_json) + len(model_json) + final_size)
    body["model_sha256"] = _digest(model_json)
    digest = _digest(_dump({"domain": DOMAIN, "content": body}))
    document = {
        **body,
        "task_result_id": "OST-" + digest[7:39].upper(),
        "task_result_sha256": digest,
    }
    return document, _dump(document)


def _derive(model: Any, catalog: Any, repository_root: str | Path, work: _Work) -> tuple[dict, str]:
    owned, model_json = _model(model, work)
    current, catalog_document = _catalog(catalog, repository_root, work)
    prepared = []
    for job in sorted(owned["jobs"], key=lambda item: item["job_id"]):
        delivered, original_json = _snapshot(job["request"], work)
        selected = components.prepare_offline_specialist_component_request(
            delivered, catalog=current, repository_root=repository_root
        )
        selected, selected_json = _snapshot(selected, work)
        if selected_json != original_json:
            raise OfflineSpecialistTaskError("Preparation changed the original request")
        prepared.append((job["job_id"], selected))
    jobs = []
    ownership = []
    for job_id, request in prepared:
        delivered, _text = _snapshot(request, work)
        try:
            produced = components.run_offline_specialist_component(
                delivered, catalog=current, repository_root=repository_root
            )
        except ValueError as exc:
            raise OfflineSpecialistTaskError(
                "Component analysis rejected its supplied input"
            ) from exc
        result, _result_json = _snapshot(produced, work)
        jobs.append({"job_id": job_id, "result": result})
        ownership.append(_index(job_id, result))
        # Cumulative retained documents are bounded before the next analysis.
        _measure({"model": owned, "jobs": jobs, "ownership_index": ownership}, work)
    body = {
        "schema_version": 1,
        "task_id": owned["task_id"],
        "model": owned,
        "catalog_id": catalog_document["catalog_id"],
        "catalog_sha256": catalog_document["catalog_sha256"],
        "jobs": jobs,
        "ownership_index": ownership,
        "job_count": len(jobs),
        "distinct_component_count": len({item["component_id"] for item in ownership}),
        "distinct_profile_count": len({item["profile_id"] for item in ownership}),
        "input_provenance": "operator_supplied_unverified",
        "source_hash_profile": "canonical_native_ordered_task_model",
        "bounds": dict(_BOUNDS),
        "operational_effects": dict(_EFFECTS),
        "offline_only": True,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "source_content_warning": _WARNING,
        "limitations": list(_LIMITATIONS),
    }
    # No old catalog is accepted if current sources changed during composition.
    components.OfflineSpecialistComponentCatalog.from_dict(
        catalog_document, repository_root=repository_root
    )
    return _finalize(body, model_json, work)


def _metadata(document: Any, work: _Work) -> tuple[dict, str]:
    """Replay self-contained metadata only, never current repository or leaf semantics."""
    raw, text = _snapshot(document, work)
    fields = {
        "schema_version",
        "task_id",
        "model",
        "model_sha256",
        "catalog_id",
        "catalog_sha256",
        "jobs",
        "ownership_index",
        "job_count",
        "distinct_component_count",
        "distinct_profile_count",
        "input_provenance",
        "source_hash_profile",
        "bounds",
        "operational_effects",
        "offline_only",
        "full_candidate_assembled",
        "positive_use_approved",
        "qualification_claimed",
        "source_content_warning",
        "limitations",
        "task_result_id",
        "task_result_sha256",
    }
    if type(raw) is not dict or raw.keys() != fields:
        raise OfflineSpecialistTaskError("Task result fields are invalid")
    model, model_json = _model(raw["model"], work)
    if type(raw["jobs"]) is not list or len(raw["jobs"]) != len(model["jobs"]):
        raise OfflineSpecialistTaskError("Task result job collection is invalid")
    expected_ids = sorted(job["job_id"] for job in model["jobs"])
    requests = {job["job_id"]: job["request"] for job in model["jobs"]}
    ownership = []
    addresses = []
    for item, job_id in zip(raw["jobs"], expected_ids, strict=True):
        if (
            type(item) is not dict
            or item.keys() != {"job_id", "result"}
            or item["job_id"] != job_id
        ):
            raise OfflineSpecialistTaskError("Task result job identity/order is invalid")
        result = item["result"]
        component_fields = {
            "schema_version",
            "catalog_id",
            "catalog_sha256",
            "component",
            "request_sha256",
            "input_provenance",
            "source_hash_profile",
            "analysis",
            "operational_effects",
            "full_candidate_assembled",
            "positive_use_approved",
            "result_id",
            "result_sha256",
        }
        if type(result) is not dict or result.keys() != component_fields:
            raise OfflineSpecialistTaskError("Task result must retain complete component metadata")
        ownership.append(_index(job_id, result))
        component_fixed = {
            "schema_version": 1,
            "catalog_id": raw["catalog_id"],
            "catalog_sha256": raw["catalog_sha256"],
            "input_provenance": "operator_supplied_unverified",
            "source_hash_profile": "canonical_native_request_with_embedded_source_text",
            "operational_effects": dict(components.EFFECTS),
            "full_candidate_assembled": False,
            "positive_use_approved": False,
        }
        if _serialize({key: result[key] for key in component_fixed}, work) != _serialize(
            component_fixed, work
        ):
            raise OfflineSpecialistTaskError("Component result contradicts task metadata")
        request_json = _serialize(requests[job_id], work)
        result_body = {
            key: value for key, value in result.items() if key not in ("result_id", "result_sha256")
        }
        result_json = _serialize(
            {"domain": components.RESULT_DOMAIN, "content": result_body},
            work,
            MAX_DOCUMENT_BYTES + 256,
        )
        addresses.append((result, request_json, result_json))
    fixed = {
        "schema_version": 1,
        "task_id": model["task_id"],
        "ownership_index": ownership,
        "job_count": len(expected_ids),
        "distinct_component_count": len({item["component_id"] for item in ownership}),
        "distinct_profile_count": len({item["profile_id"] for item in ownership}),
        "input_provenance": "operator_supplied_unverified",
        "source_hash_profile": "canonical_native_ordered_task_model",
        "bounds": dict(_BOUNDS),
        "operational_effects": dict(_EFFECTS),
        "offline_only": True,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "source_content_warning": _WARNING,
        "limitations": list(_LIMITATIONS),
    }
    actual = {key: raw[key] for key in fixed}
    if _serialize(actual, work) != _serialize(fixed, work):
        raise OfflineSpecialistTaskError("Task result fixed metadata or ownership is inconsistent")
    body = {
        key: value
        for key, value in raw.items()
        if key not in ("task_result_id", "task_result_sha256")
    }
    address_json = _serialize({"domain": DOMAIN, "content": body}, work, MAX_DOCUMENT_BYTES + 256)
    work.charge(
        len(address_json)
        + len(model_json)
        + sum(
            len(request_json) + len(result_json) for _result, request_json, result_json in addresses
        )
    )
    for result, request_json, result_json in addresses:
        result_digest = _digest(result_json)
        if (
            result["request_sha256"] != _digest(request_json)
            or result["result_sha256"] != result_digest
            or result["result_id"] != "OSR-" + result_digest[7:39].upper()
        ):
            raise OfflineSpecialistTaskError("Component result content address is inconsistent")
    digest = _digest(address_json)
    if (
        raw["model_sha256"] != _digest(model_json)
        or raw["task_result_sha256"] != digest
        or raw["task_result_id"] != "OST-" + digest[7:39].upper()
    ):
        raise OfflineSpecialistTaskError("Task result content address is inconsistent")
    return raw, text


@dataclass(frozen=True, slots=True, init=False)
class OfflineSpecialistTaskResult:
    """Owned result; exports are metadata checks, explicit parsers replay current sources."""

    document_json: str

    def __init__(self, _document_json: Any = None) -> None:
        raise OfflineSpecialistTaskError("Use task composition or source-replaying parsers")

    @classmethod
    def _owned(cls, text: str) -> OfflineSpecialistTaskResult:
        result = object.__new__(cls)
        object.__setattr__(result, "document_json", text)
        return result

    def _capture(self, work: _Work) -> tuple[dict, str]:
        text = getattr(self, "document_json", None)
        if type(self) is not OfflineSpecialistTaskResult or type(text) is not str:
            raise OfflineSpecialistTaskError("Incomplete or nonnative task result wrapper")
        if len(text) > MAX_DOCUMENT_BYTES:
            raise OfflineSpecialistTaskError("Task result wrapper exceeds the byte budget")
        try:
            raw = _decode(text.encode("utf-8"), work)
        except UnicodeError as exc:
            raise OfflineSpecialistTaskError("Task result wrapper text is invalid") from exc
        document, canonical = _snapshot(raw, work)
        if canonical != text:
            raise OfflineSpecialistTaskError("Task result wrapper must contain canonical JSON")
        return document, canonical

    def _read(self, work: _Work) -> tuple[dict, str]:
        document, _text = self._capture(work)
        return _metadata(document, work)

    def to_dict(self) -> dict[str, Any]:
        return self._read(_Work())[0]

    def to_json(self) -> str:
        return self._read(_Work())[1]

    @classmethod
    def from_dict(
        cls, document: Any, *, model: Any, catalog: Any, repository_root: str | Path
    ) -> OfflineSpecialistTaskResult:
        work = _Work()
        _supplied, supplied_text = _snapshot(document, work)
        _expected, text = _derive(model, catalog, repository_root, work)
        if supplied_text != text:
            raise OfflineSpecialistTaskError(
                "Task result does not replay separate original/current sources"
            )
        return cls._owned(text)

    @classmethod
    def from_json(
        cls, document_json: Any, *, model: Any, catalog: Any, repository_root: str | Path
    ) -> OfflineSpecialistTaskResult:
        if type(document_json) is not str or len(document_json) > MAX_DOCUMENT_BYTES:
            raise OfflineSpecialistTaskError("Bounded exact native task result JSON is required")
        work = _Work()
        try:
            document = _decode(document_json.encode("utf-8"), work)
        except UnicodeError as exc:
            raise OfflineSpecialistTaskError("Task result JSON is invalid") from exc
        _supplied, supplied_text = _snapshot(document, work)
        _expected, text = _derive(model, catalog, repository_root, work)
        if supplied_text != text:
            raise OfflineSpecialistTaskError(
                "Task result does not replay separate original/current sources"
            )
        return cls._owned(text)


def parse_offline_specialist_task_model(content: bytes) -> dict[str, Any]:
    """Read one bounded supplied model, without catalog, algorithm or resource dispatch."""
    work = _Work()
    return _model(_decode(content, work), work)[0]


def load_offline_specialist_task_model(path: str | Path) -> dict[str, Any]:
    """Use the existing bounded local regular-file development reader, not a resource grant."""
    return parse_offline_specialist_task_model(
        components._read_local_regular_file(path, MAX_DOCUMENT_BYTES)
    )


def run_offline_specialist_task(
    model: Any, *, catalog: Any, repository_root: str | Path
) -> OfflineSpecialistTaskResult:
    """Preflight every shared envelope, then run each independent pure job exactly once."""
    try:
        _document, text = _derive(model, catalog, repository_root, _Work())
    except components.OfflineSpecialistComponentError as exc:
        if type(exc) is OfflineSpecialistTaskError:
            raise
        raise OfflineSpecialistTaskError(
            "Task component input or current source validation failed"
        ) from exc
    return OfflineSpecialistTaskResult._owned(text)


def run_offline_specialist_task_bytes(
    *, model_bytes: bytes, catalog: Any, repository_root: str | Path
) -> OfflineSpecialistTaskResult:
    work = _Work()
    try:
        _document, text = _derive(_decode(model_bytes, work), catalog, repository_root, work)
    except components.OfflineSpecialistComponentError as exc:
        if type(exc) is OfflineSpecialistTaskError:
            raise
        raise OfflineSpecialistTaskError(
            "Task input or component/source validation failed"
        ) from exc
    return OfflineSpecialistTaskResult._owned(text)


def verify_offline_specialist_task(
    report: Any, *, model: Any, catalog: Any, repository_root: str | Path
) -> OfflineSpecialistTaskResult:
    """Replay all original inputs/current sources; a digest or wrapper alone is insufficient."""
    if type(report) is not OfflineSpecialistTaskResult:
        raise OfflineSpecialistTaskError("Exact native task result wrapper is required")
    work = _Work()
    _supplied, supplied_text = report._capture(work)
    _expected, text = _derive(model, catalog, repository_root, work)
    if supplied_text != text:
        raise OfflineSpecialistTaskError(
            "Task result does not replay separate original/current sources"
        )
    return OfflineSpecialistTaskResult._owned(text)


def component_fixture() -> dict[str, Any]:
    """Return fresh, independently supplied TLS/cookie models, with no cross-source relation."""

    def request(profile: str, component: str, model: dict) -> dict:
        return {
            "schema_version": 1,
            "profile_id": profile,
            "component_id": component,
            "environment": "synthetic",
            "action_tier": "R0",
            "dry_run": True,
            "credential_refs": [],
            "resources": {"network": [], "filesystem": [], "process": [], "credential": []},
            "payload": {"model": model},
        }

    return {
        "schema_version": 1,
        "task_id": "synthetic.protocol-review",
        "jobs": [
            {
                "job_id": "tls",
                "request": request(
                    "AOE-GE-D22-S02", "tls13_supplied_hello_offer_selection", tls_fixture()
                ),
            },
            {
                "job_id": "cookies",
                "request": request(
                    "AOE-GB-D05-S11", "retained_cookie_candidate_predicates", cookie_fixture()
                ),
            },
        ],
    }


__all__ = [
    "OfflineSpecialistTaskError",
    "OfflineSpecialistTaskResult",
    "component_fixture",
    "load_offline_specialist_task_model",
    "parse_offline_specialist_task_model",
    "run_offline_specialist_task",
    "run_offline_specialist_task_bytes",
    "verify_offline_specialist_task",
]
