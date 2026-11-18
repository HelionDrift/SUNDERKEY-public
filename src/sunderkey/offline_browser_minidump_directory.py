"""Inspect only the directory geometry of a supplied synthetic minidump."""

from __future__ import annotations

import hashlib
import json
import re
import struct
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "exploit_supplied_browser_minidump_directory"
PROFILE_ID = "AOE-GE-D21-S07"
CAPABILITY_ID = "army.ge.d21.s07"
VECTOR_ID = "AV-GE-D21-S07-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D21-S07"
WAVE_ID = "IW2-019"
COMMANDER_ID = "AOE-GE-D21-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:f8e046009da0264ee1c092e8c930540569456d79c09da2158e9a7067f1e65760"
DOMAIN = "sunderkey.offline-browser-minidump-directory.v1"
MAX_DUMP_BYTES = 4_096
MAX_MODEL_BYTES = 8_512
MAX_REPORT_BYTES = 32_768
HEX = re.compile(r"[0-9a-f]+\Z")
HEADER = struct.Struct("<IIIIIIQ")
DIRECTORY = struct.Struct("<III")
KNOWN_STREAMS = {3: "thread_list", 4: "module_list", 6: "exception", 7: "system_info"}
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class BrowserMinidumpDirectoryError(ValueError):
    """The synthetic dump or its original-model replay is invalid."""


def _canonical(value: Any) -> str:
    try:
        result = json.dumps(
            value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise BrowserMinidumpDirectoryError("Model must be bounded native JSON") from exc
    if len(result) > MAX_MODEL_BYTES:
        raise BrowserMinidumpDirectoryError("Model exceeds byte bound")
    return result


def _derive(value: Any) -> dict:
    model_text = _canonical(value)
    model = core.exact(
        json.loads(model_text),
        {"schema_version", "source_id", "synthetic_fixture", "dump_hex"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise BrowserMinidumpDirectoryError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise BrowserMinidumpDirectoryError("Only synthetic fixtures are accepted")
    raw_hex = model["dump_hex"]
    if (type(raw_hex) is not str or len(raw_hex) < HEADER.size * 2
            or len(raw_hex) > MAX_DUMP_BYTES * 2 or len(raw_hex) % 2
            or HEX.fullmatch(raw_hex) is None):
        raise BrowserMinidumpDirectoryError("Bounded lowercase dump hex required")
    dump = bytes.fromhex(raw_hex)
    signature, version, count, directory_rva, _, _, _ = HEADER.unpack_from(dump)
    if signature != 0x504D444D or version & 0xFFFF != 42899:
        raise BrowserMinidumpDirectoryError("Minidump signature or version invalid")
    if count < 1 or count > 16 or directory_rva < HEADER.size:
        raise BrowserMinidumpDirectoryError("Bounded stream directory required")
    directory_end = directory_rva + count * DIRECTORY.size
    if directory_end > len(dump):
        raise BrowserMinidumpDirectoryError("Stream directory exceeds dump")
    streams = []
    seen = set()
    ranges = [(0, HEADER.size), (directory_rva, directory_end)]
    for index in range(count):
        stream_type, size, rva = DIRECTORY.unpack_from(
            dump, directory_rva + index * DIRECTORY.size
        )
        if stream_type in seen or size == 0 or rva < HEADER.size or rva + size > len(dump):
            raise BrowserMinidumpDirectoryError("Duplicate or out-of-bounds stream")
        seen.add(stream_type)
        ranges.append((rva, rva + size))
        streams.append({
            "type": stream_type,
            "name": KNOWN_STREAMS.get(stream_type, "opaque_other"),
            "size": size,
        })
    ordered = sorted(ranges)
    if any(left[1] > right[0] for left, right in zip(ordered, ordered[1:])):
        raise BrowserMinidumpDirectoryError("Structural ranges overlap")
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_id": COMMANDER_ID,
        "group_owner_id": GROUP_OWNER_ID,
        "independent_validator_id": INDEPENDENT_VALIDATOR_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "dump_sha256": "sha256:" + hashlib.sha256(dump).hexdigest(),
        "synthetic_fixture_asserted": True,
        "dump_size": len(dump),
        "stream_count": count,
        "stream_directory": streams,
        "directory_geometry_valid": True,
        "stream_contents_interpreted": False,
        "browser_origin_verified": False,
        "crash_cause_verified": False,
        "exploitability_verified": False,
        "candidate_count": 0,
        "uncertainty": [
            "browser_origin_unverified",
            "stream_semantics_and_crash_cause_unverified",
            "exploitability_unverified",
        ],
        "unknown_count": 3,
        "disposition": "unknown",
        "source_authenticated": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Only the header and stream directory of a synthetic supplied minidump are read.",
            "Stream payloads are not parsed, copied into the report, or executed.",
            "Directory consistency does not prove browser origin, crash cause, or exploitability.",
            "No browser, debugger, process, or target is contacted.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="BMD-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class BrowserMinidumpDirectoryReport:
    """Unsigned directory projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise BrowserMinidumpDirectoryError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> BrowserMinidumpDirectoryReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_browser_minidump_directory(model: Any) -> BrowserMinidumpDirectoryReport:
    return BrowserMinidumpDirectoryReport._owned(_derive(model))


def verify_supplied_browser_minidump_directory(
    report: Any, *, model: Any
) -> BrowserMinidumpDirectoryReport:
    if type(report) is not BrowserMinidumpDirectoryReport:
        raise BrowserMinidumpDirectoryError("Exact minidump wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise BrowserMinidumpDirectoryError("Report differs from separate original model")
    return BrowserMinidumpDirectoryReport._owned(expected)


def component_fixture() -> dict:
    header = HEADER.pack(0x504D444D, 42899, 2, 32, 0, 0, 0)
    directory = DIRECTORY.pack(6, 4, 56) + DIRECTORY.pack(7, 4, 60)
    return {
        "schema_version": 1,
        "source_id": "synthetic-browser-minidump",
        "synthetic_fixture": True,
        "dump_hex": (header + directory + b"EXCP" + b"SYSI").hex(),
    }
