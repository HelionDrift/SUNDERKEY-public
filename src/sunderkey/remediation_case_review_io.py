"""Bounded local JSON inputs for source-replayed, advisory remediation review."""

from __future__ import annotations

import os
import stat
from dataclasses import fields
from pathlib import Path
from typing import Any

from .remediation_case_review import (
    build_remediation_case_review,
    verify_remediation_case_review,
)
from .remediation_validation_contracts import (
    MAX_ITEMS,
    ClosureDecision,
    ContextBinding,
    RemediationPlan,
    RemediationValidationError,
    RetestObservation,
    RetestPlan,
    RiskException,
    canonical_json,
)
from .remediation_workflow_visibility import (
    MAX_OBSERVATIONS,
    RemediationDeliveryObservation,
    RemediationServiceTarget,
)
from .validation import loads_json_without_duplicate_keys

MAX_SOURCE_BYTES = 8_000_000
MAX_REVIEW_BYTES = 4_000_000
MAX_JSON_DEPTH = 24
MAX_JSON_NODES = 200_000
REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "context",
        "plan",
        "as_of",
        "targets",
        "delivery_observations",
        "retest",
        "retest_observation",
        "closure",
        "exception",
        "max_delivery_observation_age_seconds",
    }
)


class RemediationCaseInputError(RemediationValidationError):
    """An archive has unbounded, invalid, or changing local input."""


def _bounded_json(value: Any, maximum_bytes: int) -> None:
    pending = [(value, 0)]
    nodes = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if depth > MAX_JSON_DEPTH or nodes > MAX_JSON_NODES:
            raise RemediationCaseInputError("remediation JSON exceeds its structural limit")
        if type(current) is dict:
            if len(current) > 64 or any(type(key) is not str for key in current):
                raise RemediationCaseInputError("remediation JSON object is invalid")
            pending.extend((child, depth + 1) for child in current.values())
        elif type(current) is list:
            if len(current) > MAX_OBSERVATIONS:
                raise RemediationCaseInputError("remediation JSON list exceeds its limit")
            pending.extend((child, depth + 1) for child in current)
        elif current is not None and type(current) not in {str, bool, int}:
            raise RemediationCaseInputError("remediation JSON value is unsupported")
    if len(canonical_json(value).encode("ascii")) > maximum_bytes:
        raise RemediationCaseInputError("remediation JSON exceeds its byte limit")


def _record(raw: Any, record_type: type[Any], label: str) -> Any:
    if type(raw) is not dict:
        raise RemediationCaseInputError(f"{label} must be an exact contract object")
    try:
        record = record_type.from_dict(raw)
        if canonical_json(raw) != canonical_json(record.to_dict()):
            raise RemediationCaseInputError(f"{label} is not an exact serialized contract")
    except (KeyError, TypeError, ValueError) as exc:
        raise RemediationCaseInputError(f"{label} contract is invalid") from exc
    return record


def _workflow_records(raw: Any, record_type: type[Any], limit: int, label: str) -> tuple[Any, ...]:
    if type(raw) is not list or len(raw) > limit:
        raise RemediationCaseInputError(f"{label} must be a bounded list")
    expected = {field.name for field in fields(record_type)}
    result = []
    for item in raw:
        if type(item) is not dict or set(item) != expected:
            raise RemediationCaseInputError(f"{label} record fields are invalid")
        try:
            record = record_type(**item)
            if canonical_json(item) != canonical_json(record.to_dict()):
                raise RemediationCaseInputError(f"{label} record content address is invalid")
        except (TypeError, ValueError) as exc:
            raise RemediationCaseInputError(f"{label} record is invalid") from exc
        result.append(record)
    return tuple(result)


def _sources(request: Any) -> dict[str, Any]:
    _bounded_json(request, MAX_SOURCE_BYTES)
    if type(request) is not dict or set(request) != REQUEST_FIELDS:
        raise RemediationCaseInputError("remediation request fields are invalid")
    if type(request["schema_version"]) is not int or request["schema_version"] != 1:
        raise RemediationCaseInputError("remediation request schema version is invalid")
    result = {
        "context": _record(request["context"], ContextBinding, "context"),
        "plan": _record(request["plan"], RemediationPlan, "plan"),
        "as_of": request["as_of"],
        "targets": _workflow_records(
            request["targets"], RemediationServiceTarget, MAX_ITEMS, "targets"
        ),
        "delivery_observations": _workflow_records(
            request["delivery_observations"],
            RemediationDeliveryObservation,
            MAX_OBSERVATIONS,
            "delivery observations",
        ),
        "max_delivery_observation_age_seconds": request["max_delivery_observation_age_seconds"],
    }
    for name, record_type in (
        ("retest", RetestPlan),
        ("retest_observation", RetestObservation),
        ("closure", ClosureDecision),
        ("exception", RiskException),
    ):
        raw = request[name]
        result[name] = None if raw is None else _record(raw, record_type, name)
    return result


def build_remediation_case_review_from_request(request: Any) -> dict[str, Any]:
    """Validate a closed source archive before producing any advisory result."""

    review = build_remediation_case_review(**_sources(request))
    _bounded_json(review, MAX_REVIEW_BYTES)
    return review


def verify_remediation_case_review_from_request(request: Any, review: Any) -> None:
    """Replay a saved review without admitting or publishing its historical outcome."""

    _bounded_json(review, MAX_REVIEW_BYTES)
    verify_remediation_case_review(review, **_sources(request))


def serialize_remediation_case_review(review: Any) -> str:
    """Format bounded JSON, not an attestation, reserving its terminating newline."""

    _bounded_json(review, MAX_REVIEW_BYTES - 1)
    return canonical_json(review) + "\n"


def _file_stamp(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    identity_time = (
        getattr(metadata, "st_birthtime_ns", metadata.st_ctime_ns)
        if os.name == "nt"
        else metadata.st_ctime_ns
    )
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        identity_time,
    )


def _linked(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _read_local_json(filename: str | Path, maximum_bytes: int) -> Any:
    descriptor = None
    try:
        if str(filename).startswith(("\\\\", "//")):
            raise RemediationCaseInputError("remediation source must be a local file")
        path = Path(filename).absolute()
        if str(path).startswith(("\\\\", "//")):
            raise RemediationCaseInputError("remediation source must be a local file")
        for parent in reversed(path.parents):
            if _linked(parent.lstat()):
                raise RemediationCaseInputError("remediation source parents must not be links")
        before = path.lstat()
        if _linked(before) or not stat.S_ISREG(before.st_mode):
            raise RemediationCaseInputError("remediation source must be a regular non-linked file")
        if before.st_size > maximum_bytes:
            raise RemediationCaseInputError("remediation source exceeds its byte limit")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or _file_stamp(opened) != _file_stamp(before):
                raise RemediationCaseInputError("remediation source changed before reading")
            data = stream.read(maximum_bytes + 1)
            after_open = os.fstat(stream.fileno())
        after_path = path.lstat()
        if (
            len(data) > maximum_bytes
            or len(data) != before.st_size
            or _linked(after_path)
            or _file_stamp(after_open) != _file_stamp(before)
            or _file_stamp(after_path) != _file_stamp(before)
        ):
            raise RemediationCaseInputError("remediation source changed while reading")
        value = loads_json_without_duplicate_keys(data.decode("utf-8"))
        _bounded_json(value, maximum_bytes)
        return value
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError) as exc:
        if isinstance(exc, RemediationCaseInputError):
            raise
        raise RemediationCaseInputError("could not validate local remediation JSON") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def load_remediation_case_request(filename: str | Path) -> Any:
    """Read bounded JSON only; full source validation remains mandatory for use."""

    return _read_local_json(filename, MAX_SOURCE_BYTES)


def load_remediation_case_review(filename: str | Path) -> Any:
    """Read bounded saved review JSON, without trusting its self-asserted digest."""

    return _read_local_json(filename, MAX_REVIEW_BYTES)
