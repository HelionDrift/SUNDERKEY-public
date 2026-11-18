"""Common replay boundary for caller-supplied firmware projections."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class FirmwareProjectionError(ValueError):
    """A declaration or original-model replay was refused."""


def model_base(value: Any, *, collection: str, maximum: int = 64) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", collection},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise FirmwareProjectionError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    entries = core.bounded_list(model[collection], maximum, collection)
    if not entries:
        raise FirmwareProjectionError(f"At least one {collection} entry is required")
    return model, core.canonical(model)


def digest_or_none(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if (
        type(value) is not str
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in value[7:])
    ):
        raise FirmwareProjectionError(f"{label} must be a SHA-256 digest or null")
    return value


def unique_id(value: Any, *, seen: set[str], label: str) -> str:
    result = core.identifier(value, label)
    if result in seen:
        raise FirmwareProjectionError(f"Duplicate {label}")
    seen.add(result)
    return result


def report_document(
    *,
    model_text: str,
    component_id: str,
    profile_id: str,
    work_package_id: str,
    blueprint_sha256: str,
    domain: str,
    prefix: str,
    row_key: str,
    rows: list[dict],
    limitations: list[str],
    additional_false_flags: tuple[str, ...],
) -> dict:
    body = {
        "schema_version": 1,
        "component_id": component_id,
        "profile_id": profile_id,
        "work_package_id": work_package_id,
        "blueprint_sha256": blueprint_sha256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        row_key: rows,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in rows),
        "unknown_count": sum(row["disposition"] == "unknown" for row in rows),
        "source_authenticated": False,
        "hardware_contacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": limitations,
    }
    for flag in additional_false_flags:
        body[flag] = False
    report_id, report_sha256 = core.report_address(body, domain=domain, prefix=prefix)
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class FirmwareProjectionReport:
    """Unsigned projection that can only be replayed against the original model."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise FirmwareProjectionError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> FirmwareProjectionReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def verify_report(
    report: Any,
    *,
    model: Any,
    derive: Callable[[Any], dict],
    report_type: type[FirmwareProjectionReport],
) -> FirmwareProjectionReport:
    if type(report) is not report_type:
        raise FirmwareProjectionError("Exact projection report wrapper required")
    expected = derive(model)
    if report.to_json() != core.canonical(expected):
        raise FirmwareProjectionError("Report differs from original-model replay")
    return report_type._owned(expected)


def verify_report_bytes(
    report_bytes: bytes,
    *,
    model: Any,
    derive: Callable[[Any], dict],
    report_type: type[FirmwareProjectionReport],
) -> FirmwareProjectionReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    expected = derive(model)
    if type(report) is not dict or core.canonical(report) != core.canonical(expected):
        raise FirmwareProjectionError("Exported report differs from original-model replay")
    return report_type._owned(expected)
