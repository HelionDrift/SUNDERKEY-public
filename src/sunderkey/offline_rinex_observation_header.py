"""Project a bounded synthetic RINEX 4.02 observation-header subset."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "transport_supplied_rinex_observation_header_projection"
PROFILE_ID = "AOE-GD-D25-S09"
CAPABILITY_ID = "army.gd.d25.s09"
VECTOR_ID = "AV-GD-D25-S09-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D25-S09"
WAVE_ID = "IW2-009"
COMMANDER_ID = "AOE-GD-D25-CMD"
GROUP_OWNER_ID = "AOE-HQ-06"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:c5ea103b667f3c45d0110d9077fecf09efe577b688677b99fdb375c06ed84879"
DOMAIN = "sunderkey.offline-rinex-observation-header.v1"
MAX_MODEL_BYTES = 8_192
MAX_REPORT_BYTES = 32_768
MAX_HEADER_BYTES = 3_000
MAX_HEADER_LINES = 32
SYSTEMS = frozenset("GREJCIS")
OBSERVATION_CODE = re.compile(r"[CLDS][0-9][A-Z0-9]\Z")
LABELS = frozenset((
    "RINEX VERSION / TYPE", "PGM / RUN BY / DATE", "MARKER NAME",
    "SYS / # / OBS TYPES", "END OF HEADER",
))
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class RinexObservationHeaderError(ValueError):
    """A supplied header model or original-model replay is invalid."""


def _canonical(value: Any) -> str:
    try:
        result = json.dumps(
            value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise RinexObservationHeaderError("Model must be bounded native JSON") from exc
    if len(result) > MAX_MODEL_BYTES:
        raise RinexObservationHeaderError("Model exceeds byte bound")
    return result


def _derive(value: Any) -> dict:
    model_text = _canonical(value)
    model = core.exact(
        json.loads(model_text),
        {"schema_version", "source_id", "synthetic_fixture", "header_base64"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise RinexObservationHeaderError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise RinexObservationHeaderError("Only synthetic fixtures are accepted")
    encoded = model["header_base64"]
    if type(encoded) is not str or len(encoded) > 4 * ((MAX_HEADER_BYTES + 2) // 3):
        raise RinexObservationHeaderError("Bounded header base64 is required")
    try:
        raw = base64.b64decode(encoded, validate=True)
        header = raw.decode("ascii")
    except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
        raise RinexObservationHeaderError("Header encoding is invalid") from exc
    if not raw or len(raw) > MAX_HEADER_BYTES or "\r" in header:
        raise RinexObservationHeaderError("Header byte count or line ending is invalid")
    lines = header.split("\n")
    if not 5 <= len(lines) <= MAX_HEADER_LINES or any(len(line) != 80 for line in lines):
        raise RinexObservationHeaderError("Five or more 80-column header lines required")
    records = []
    for line in lines:
        value, label_field = line[:60], line[60:80]
        label = label_field.rstrip()
        if label not in LABELS or label_field != label.ljust(20):
            raise RinexObservationHeaderError("Unsupported or misplaced header label")
        records.append((label, value))
    if records[0][0] != "RINEX VERSION / TYPE" or records[1][0] != "PGM / RUN BY / DATE":
        raise RinexObservationHeaderError("Version and program records must lead")
    if records[-1] != ("END OF HEADER", " " * 60):
        raise RinexObservationHeaderError("Blank end-of-header record must finish")
    if records[0][1][:9].strip() != "4.02" or records[0][1][20] != "O":
        raise RinexObservationHeaderError("RINEX 4.02 observation type required")
    system_scope = records[0][1][40]
    if system_scope not in SYSTEMS | {"M"}:
        raise RinexObservationHeaderError("Unsupported observation system")
    if not records[1][1].strip():
        raise RinexObservationHeaderError("Program record is empty")
    marker_values = [value for label, value in records if label == "MARKER NAME"]
    if len(marker_values) != 1 or not marker_values[0].strip():
        raise RinexObservationHeaderError("One nonempty marker name is required")
    declarations = []
    seen = set()
    for label, value in records[2:-1]:
        if label == "MARKER NAME":
            continue
        if label != "SYS / # / OBS TYPES":
            raise RinexObservationHeaderError("Only the supported header subset is accepted")
        system = value[0]
        if system not in SYSTEMS or system in seen:
            raise RinexObservationHeaderError("System declaration is invalid or repeated")
        if system_scope != "M" and system != system_scope:
            raise RinexObservationHeaderError("System differs from file scope")
        count_text = value[3:6]
        if not count_text.strip().isdigit():
            raise RinexObservationHeaderError("Observation count is invalid")
        count = int(count_text)
        codes = value[6:].split()
        if not 1 <= count <= 13 or len(codes) != count:
            raise RinexObservationHeaderError("One-line observation count differs")
        if len(set(codes)) != len(codes) or any(
            OBSERVATION_CODE.fullmatch(code) is None for code in codes
        ):
            raise RinexObservationHeaderError("Observation codes are invalid or repeated")
        declarations.append({"system": system, "observation_codes": codes})
        seen.add(system)
    if not declarations:
        raise RinexObservationHeaderError("Observation declaration is required")
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
        "source_header_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "synthetic_fixture_asserted": True,
        "header_line_count": len(lines),
        "rinex_version": "4.02",
        "file_system_scope": system_scope,
        "marker_name_sha256": "sha256:" + hashlib.sha256(
            marker_values[0].rstrip().encode("ascii")
        ).hexdigest(),
        "observation_declarations": declarations,
        "header_subset_geometry_valid": True,
        "full_rinex_conformance_verified": False,
        "observation_data_verified": False,
        "position_or_time_accuracy_verified": False,
        "station_identity_verified": False,
        "candidate_count": 0,
        "uncertainty": [
            "observation_records_not_supplied",
            "station_and_receiver_provenance_unverified",
            "position_time_and_signal_accuracy_unassessed",
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
            "Only a synthetic supplied RINEX 4.02 observation-header subset is inspected.",
            "Continuations, optional records, observations, and navigation data are excluded.",
            "Declared codes do not prove signal quality, position, time or station identity.",
            "No file is acquired from a receiver or target; no GNSS activity occurs.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="ROH-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class RinexObservationHeaderReport:
    """Unsigned header projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise RinexObservationHeaderError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> RinexObservationHeaderReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_rinex_observation_header(model: Any) -> RinexObservationHeaderReport:
    return RinexObservationHeaderReport._owned(_derive(model))


def verify_supplied_rinex_observation_header(
    report: Any, *, model: Any
) -> RinexObservationHeaderReport:
    if type(report) is not RinexObservationHeaderReport:
        raise RinexObservationHeaderError("Exact RINEX wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise RinexObservationHeaderError("Report differs from separate original model")
    return RinexObservationHeaderReport._owned(expected)


def component_fixture() -> dict:
    version = f"{4.02:9.2f}" + " " * 11 + "O" + " " * 19 + "G" + " " * 19
    records = (
        ("RINEX VERSION / TYPE", version),
        ("PGM / RUN BY / DATE", "Synthetic generator"),
        ("MARKER NAME", "SYNTHETIC STATION"),
        ("SYS / # / OBS TYPES", "G  " + f"{4:3d}" + " C1C L1C D1C S1C"),
        ("END OF HEADER", ""),
    )
    header = "\n".join(value.ljust(60) + label.ljust(20) for label, value in records)
    return {
        "schema_version": 1,
        "source_id": "synthetic-rinex-observation-header",
        "synthetic_fixture": True,
        "header_base64": base64.b64encode(header.encode("ascii")).decode("ascii"),
    }
