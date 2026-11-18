"""Bounded, unsigned observations of one supplied DICOM P-DATA-TF PDU."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "dicom_supplied_pdata_pdv_structure"
PROFILE_ID = "AOE-GD-D25-S12"
CAPABILITY_ID = "army.gd.d25.s12"
VECTOR_ID = "AV-GD-D25-S12-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D25-S12"
WAVE_ID = "IW2-012"
COMMANDER_ID = "AOE-GD-D25-CMD"
GROUP_OWNER_ID = "AOE-HQ-06"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:8e9af3b53e84ef732bd0cfff19b58d3f0734288d78e757533adaded191735754"
SEMANTICS_PROFILE = "supplied-dicom-ps38-pdata-pdv-structure.v1"
DOMAIN = "sunderkey.offline-dicom-pdv-analysis.v1"
MODEL_DOMAIN = "sunderkey.offline-dicom-pdv-model.v1"
MAX_PDU_BYTES = 262_144
MAX_MODEL_BYTES = 524_288
MAX_REPORT_BYTES = 1_048_576
MAX_MODEL_NODES = 2_048
MAX_REPORT_NODES = 8_192
MAX_DEPTH = 12
MAX_PDVS = 128
MAX_WORK = 33_554_432
MAX_TEXT = 4 * ((MAX_PDU_BYTES + 2) // 3)
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SOURCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_PLACEHOLDER = "sha256:" + "0" * 64
_ID_PLACEHOLDER = "DPV-" + "0" * 32
_DECLARED_BOUNDS = {
    "pdu_bytes": MAX_PDU_BYTES,
    "model_bytes": MAX_MODEL_BYTES,
    "report_bytes": MAX_REPORT_BYTES,
    "model_nodes": MAX_MODEL_NODES,
    "report_nodes": MAX_REPORT_NODES,
    "native_depth": MAX_DEPTH,
    "pdv_items": MAX_PDVS,
    "cumulative_work": MAX_WORK,
}
_FLAGS = {
    "offline_only": True,
    "pdu_source_authenticated": False,
    "association_state_verified": False,
    "patient_content_interpreted": False,
    "message_semantics_verified": False,
    "network_traffic_observed": False,
    "clinical_use_approved": False,
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
    "The supplied PDU bytes are unauthenticated and no association was observed.",
    "Only one complete P-DATA-TF PDU and its PDV item extents are inspected.",
    "Sender-side deviations are observations, not receiver rejection predictions.",
    "No cross-PDU fragment continuity, transfer syntax or message content is parsed.",
    "The complete supplied bytes remain in the report; never supply patient data.",
    "No network, clinical action, current authority or qualification is established.",
]


class DicomPdvError(ValueError):
    """Closed source, structural extent, budget or replay refusal."""


@dataclass(slots=True)
class _Budget:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or amount > MAX_WORK - self.used:
            raise DicomPdvError("Cumulative software work ceiling exhausted")
        self.used += amount


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _measure(value: Any, budget: _Budget, *, report: bool = False) -> tuple[int, int]:
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    size = nodes = 0
    active: set[int] = set()

    def add(amount: int) -> None:
        nonlocal size
        if amount > byte_limit - size:
            raise DicomPdvError("Canonical document byte ceiling exhausted")
        budget.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        budget.charge(1)
        nodes += 1
        if depth > MAX_DEPTH or nodes > node_limit:
            raise DicomPdvError("Native node/depth ceiling exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_TEXT:
                raise DicomPdvError("Native string ceiling exhausted")
            add(2 + len(item))
            for char in item:
                budget.charge(1)
                if not 32 <= ord(char) <= 126:
                    raise DicomPdvError("Printable ASCII metadata required")
                if char in '\\"':
                    add(1)
        elif kind is bool:
            add(4 if item else 5)
        elif item is None:
            add(4)
        elif kind is int:
            if not -(1 << 63) <= item < 1 << 63:
                raise DicomPdvError("Exact native signed64 integer required")
            add(len(str(item)))
        elif kind in (dict, list):
            if id(item) in active:
                raise DicomPdvError("Cyclic native document")
            queued = len(item) * (2 if kind is dict else 1)
            if queued > node_limit - nodes:
                raise DicomPdvError("Queued native node ceiling exhausted")
            add(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise DicomPdvError("Exact native text keys required")
                        visit(key, depth + 1)
                        budget.charge(len(key) * (len(item).bit_length() + 1))
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise DicomPdvError("Exact native integer-only JSON families required")

    visit(value, 1)
    return size, nodes


def _clone(value: Any) -> Any:
    if type(value) is dict:
        return {key: _clone(child) for key, child in value.items()}
    if type(value) is list:
        return [_clone(child) for child in value]
    return value


def _capture(value: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int, int]:
    size, nodes = _measure(value, budget, report=report)
    budget.charge(4 * (size + nodes))
    return _clone(value), size, nodes


def _integer(text: str) -> int:
    if len(text) > 20 or _INTEGER.fullmatch(text) is None:
        raise DicomPdvError("Raw bounded integer grammar required")
    negative = text.startswith("-")
    digits = text[1:] if negative else text
    limit = "9223372036854775808" if negative else "9223372036854775807"
    if len(digits) > 19 or (len(digits) == 19 and digits > limit):
        raise DicomPdvError("Raw signed64 integer ceiling exhausted")
    return int(text)


def _decode(text: Any, budget: _Budget, *, report: bool = False) -> Any:
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    if type(text) is not str or not text or len(text) > byte_limit:
        raise DicomPdvError("Bounded exact native JSON text required")
    budget.charge(2 * len(text))
    if not text.isascii():
        raise DicomPdvError("ASCII raw JSON metadata required")
    index = nodes = 0
    stack: list[str] = []
    while index < len(text):
        char = text[index]
        if char in " \t\r\n,:":
            index += 1
            continue
        if char in "]}":
            if not stack or stack.pop() != ("[" if char == "]" else "{"):
                raise DicomPdvError("Malformed raw JSON containers")
            index += 1
            continue
        nodes += 1
        if nodes > node_limit or len(stack) + 1 > MAX_DEPTH:
            raise DicomPdvError("Pre-decoder node/depth ceiling exhausted")
        if char in "[{":
            stack.append(char)
            index += 1
        elif char == '"':
            index += 1
            length = 0
            while index < len(text) and text[index] != '"':
                budget.charge(1)
                code = ord(text[index])
                if text[index] == "\\":
                    index += 1
                    if index >= len(text):
                        raise DicomPdvError("Incomplete JSON escape")
                    if text[index] == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            c not in "0123456789abcdefABCDEF" for c in digits
                        ):
                            raise DicomPdvError("Malformed JSON Unicode escape")
                        code = int(digits, 16)
                        index += 4
                    elif text[index] in '\\"/':
                        code = ord(text[index])
                    else:
                        raise DicomPdvError("Unsupported JSON string escape")
                if not 32 <= code <= 126:
                    raise DicomPdvError("Printable ASCII JSON strings required")
                length += 1
                if length > MAX_TEXT:
                    raise DicomPdvError("Pre-decoder string ceiling exhausted")
                index += 1
            if index >= len(text):
                raise DicomPdvError("Unterminated JSON string")
            index += 1
        else:
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}[{\\"':
                index += 1
                if index - start > 20:
                    raise DicomPdvError("Pre-decoder scalar lexical ceiling exhausted")
            token = text[start:index]
            if token not in ("true", "false", "null"):
                _integer(token)
    if stack:
        raise DicomPdvError("Unterminated JSON containers")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                raise DicomPdvError("Duplicate raw JSON key")
            result[key] = value
        return result

    def unsupported(_: str) -> None:
        raise DicomPdvError("Integer-only raw JSON required")

    budget.charge(4 * len(text) + 32 * nodes)
    try:
        document = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=_integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise DicomPdvError("Malformed bounded JSON document") from exc
    _measure(document, budget, report=report)
    return document


def _bounded_pdu(model: dict, budget: _Budget) -> bytes:
    text = model["pdu_base64"]
    if type(text) is not str or not text or len(text) > MAX_TEXT:
        raise DicomPdvError("Bounded exact native PDU base64 required")
    budget.charge(4 * len(text) + MAX_PDU_BYTES)
    try:
        pdu = base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DicomPdvError("Malformed PDU base64") from exc
    if len(pdu) > MAX_PDU_BYTES or base64.b64encode(pdu).decode("ascii") != text:
        raise DicomPdvError("PDU byte bound or canonical base64 is invalid")
    return pdu


def _parse_pdu(pdu: bytes, budget: _Budget) -> tuple[dict, list[dict], list[str]]:
    if len(pdu) < 12 or pdu[0] != 0x04:
        raise DicomPdvError("Complete P-DATA-TF header and one PDV item required")
    declared = int.from_bytes(pdu[2:6], "big")
    if declared != len(pdu) - 6:
        raise DicomPdvError("PDU length does not span exactly the supplied bytes")
    rows: list[dict] = []
    deviations: list[str] = []
    if pdu[1] != 0:
        deviations.append("pdu_reserved_byte_nonzero_sender_observation")
    first_context = None
    offset = 6
    while offset < len(pdu):
        budget.charge(64)
        if len(rows) >= MAX_PDVS:
            raise DicomPdvError("PDV item ceiling exhausted")
        if len(pdu) - offset < 6:
            raise DicomPdvError("Incomplete PDV item length, context or control header")
        item_length = int.from_bytes(pdu[offset : offset + 4], "big")
        if item_length < 2 or item_length > len(pdu) - offset - 4:
            raise DicomPdvError("PDV item length is too short or exceeds the PDU")
        item_end = offset + 4 + item_length
        context = pdu[offset + 4]
        control = pdu[offset + 5]
        fragment_start = offset + 6
        fragment_bytes = item_length - 2
        row = {
            "index": len(rows),
            "item_start": offset,
            "item_end": item_end,
            "item_length": item_length,
            "presentation_context_id": context,
            "control_byte": control,
            "fragment_kind": "command" if control & 1 else "data_set",
            "last_fragment": bool(control & 2),
            "control_reserved_bits": control & 0xFC,
            "fragment_start": fragment_start,
            "fragment_end": item_end,
            "fragment_bytes": fragment_bytes,
        }
        rows.append(row)
        if context == 0 or context % 2 == 0:
            deviations.append("even_or_zero_presentation_context_id_sender_observation")
        if first_context is None:
            first_context = context
        elif context != first_context and "mixed_context_ids_sender_observation" not in deviations:
            deviations.append("mixed_context_ids_sender_observation")
        if control & 0xFC:
            deviations.append("control_reserved_bits_nonzero_sender_observation")
        if fragment_bytes == 0:
            deviations.append("empty_fragment_sender_observation")
        elif fragment_bytes % 2:
            deviations.append("odd_fragment_byte_count_sender_observation")
        offset = item_end
    header = {
        "pdu_type": pdu[0],
        "reserved_byte": pdu[1],
        "declared_payload_length": declared,
        "actual_pdu_bytes": len(pdu),
        "pdv_count": len(rows),
    }
    return header, rows, deviations


@dataclass(slots=True)
class _Plan:
    document: dict
    size: int
    pdu: bytes


def _plan(model: Any, budget: _Budget) -> _Plan:
    if type(model) is not dict:
        raise DicomPdvError("Exact native source model required")
    source, source_size, _ = _capture(model, budget)
    if set(source) != {"schema_version", "source_id", "pdu_base64"}:
        raise DicomPdvError("Closed source model fields required")
    if type(source["schema_version"]) is not int or source["schema_version"] != 1:
        raise DicomPdvError("Exact native schema version one required")
    if type(source["source_id"]) is not str or _SOURCE.fullmatch(source["source_id"]) is None:
        raise DicomPdvError("Bounded source identifier required")
    pdu = _bounded_pdu(source, budget)
    header, rows, deviations = _parse_pdu(pdu, budget)
    document = {
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
        "semantics_profile": SEMANTICS_PROFILE,
        "roadmap_package_ids": ["A7.4"],
        "source_model": source,
        "source_model_sha256": _PLACEHOLDER,
        "source_pdu_sha256": _PLACEHOLDER,
        "pdu_header": header,
        "pdv_items": rows,
        "sender_deviation_observations": deviations,
        "analysis_status": (
            "sender_deviations_observed" if deviations else "bounded_structure_observed"
        ),
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "bounds": dict(_DECLARED_BOUNDS),
        "limitations": list(_LIMITATIONS),
        "analysis_id": _ID_PLACEHOLDER,
        "analysis_sha256": _PLACEHOLDER,
    }
    document, size, nodes = _capture(document, budget, report=True)
    budget.charge(18 * size + 8 * source_size + 8 * nodes + 6 * len(pdu))
    budget.charge(len(DOMAIN) + len(MODEL_DOMAIN) + 2)
    return _Plan(document, size, pdu)


def _digest(domain: str, value: dict) -> str:
    return (
        "sha256:" + hashlib.sha256((domain + "\n" + _canonical(value)).encode("ascii")).hexdigest()
    )


def _materialize(plan: _Plan) -> str:
    document = plan.document
    document["source_model_sha256"] = _digest(MODEL_DOMAIN, document["source_model"])
    document["source_pdu_sha256"] = "sha256:" + hashlib.sha256(plan.pdu).hexdigest()
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = _digest(DOMAIN, body)
    document["analysis_id"] = "DPV-" + digest[7:39].upper()
    document["analysis_sha256"] = digest
    return _canonical(document)


def _report_plan(document: Any, budget: _Budget) -> tuple[dict, str, _Plan]:
    if type(document) is not dict:
        raise DicomPdvError("Exact native report object required")
    owned, size, nodes = _capture(document, budget, report=True)
    if "source_model" not in owned:
        raise DicomPdvError("Report requires complete original source model")
    expected = _plan(owned["source_model"], budget)
    for field in ("source_model_sha256", "source_pdu_sha256", "analysis_sha256"):
        if type(owned.get(field)) is not str or _SHA.fullmatch(owned[field]) is None:
            raise DicomPdvError("Exact SHA256 report address required")
    if (
        type(owned.get("analysis_id")) is not str
        or owned["analysis_id"] != "DPV-" + owned["analysis_sha256"][7:39].upper()
    ):
        raise DicomPdvError("Exact report ID/address join required")
    budget.charge(12 * size + 4 * expected.size + 8 * nodes)
    placeholder = {
        **owned,
        "source_model_sha256": _PLACEHOLDER,
        "source_pdu_sha256": _PLACEHOLDER,
        "analysis_id": _ID_PLACEHOLDER,
        "analysis_sha256": _PLACEHOLDER,
    }
    if _canonical(placeholder) != _canonical(expected.document):
        raise DicomPdvError("Report metadata does not replay supplied PDU bytes")
    return owned, _canonical(owned), expected


def _replay_text(text: Any, budget: _Budget) -> dict:
    document, canonical, plan = _report_plan(_decode(text, budget, report=True), budget)
    if text != canonical:
        raise DicomPdvError("Exact canonical retained report JSON required")
    if _materialize(plan) != canonical:
        raise DicomPdvError("Report addresses do not replay original PDU bytes")
    return document


def _stored(report: Any) -> str:
    if type(report) is not DicomPdvAnalysis:
        raise DicomPdvError("Exact native report wrapper required")
    text = getattr(report, "document_json", None)
    if type(text) is not str:
        raise DicomPdvError("Exact native retained report text required")
    return text


def _owned(text: str) -> DicomPdvAnalysis:
    report = object.__new__(DicomPdvAnalysis)
    object.__setattr__(report, "document_json", text)
    return report


@dataclass(frozen=True, slots=True)
class DicomPdvAnalysis:
    """Detached unsigned structural report retaining exact supplied PDU bytes."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not DicomPdvAnalysis:
            raise DicomPdvError("Exact native report family required")
        _replay_text(self.document_json, _Budget())

    @classmethod
    def from_dict(cls, document: Any) -> DicomPdvAnalysis:
        if cls is not DicomPdvAnalysis:
            raise DicomPdvError("Exact native report family required")
        budget = _Budget()
        _document, text, plan = _report_plan(document, budget)
        if _materialize(plan) != text:
            raise DicomPdvError("Report addresses do not replay source")
        return _owned(text)

    @classmethod
    def from_json(cls, document_json: Any) -> DicomPdvAnalysis:
        if cls is not DicomPdvAnalysis:
            raise DicomPdvError("Exact native report family required")
        _replay_text(document_json, _Budget())
        return _owned(document_json)

    def to_dict(self) -> dict:
        return _replay_text(_stored(self), _Budget())

    def to_json(self) -> str:
        text = _stored(self)
        _replay_text(text, _Budget())
        return text

    @property
    def analysis_id(self) -> str:
        return self.to_dict()["analysis_id"]

    @property
    def analysis_sha256(self) -> str:
        return self.to_dict()["analysis_sha256"]


def analyze_supplied_dicom_pdv(model: Any) -> DicomPdvAnalysis:
    """Inspect a supplied P-DATA-TF PDU without transport or message parsing."""
    return _owned(_materialize(_plan(model, _Budget())))


def analyze_supplied_dicom_pdv_bytes(*, model_bytes: Any) -> DicomPdvAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise DicomPdvError("Bounded exact native model JSON bytes required")
    budget = _Budget()
    budget.charge(2 * len(model_bytes))
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise DicomPdvError("ASCII source JSON bytes required") from exc
    return _owned(_materialize(_plan(_decode(text, budget), budget)))


def verify_supplied_dicom_pdv_analysis(report: Any, *, model: Any) -> DicomPdvAnalysis:
    """Replay embedded and separately supplied original PDUs within one budget."""
    budget = _Budget()
    text = _stored(report)
    _document, canonical, embedded = _report_plan(_decode(text, budget, report=True), budget)
    original = _plan(model, budget)
    budget.charge(4 * (embedded.size + original.size))
    if text != canonical:
        raise DicomPdvError("Exact canonical retained report JSON required")
    expected = _materialize(embedded)
    separate = _materialize(original)
    if expected != text or expected != separate:
        raise DicomPdvError("Report differs from embedded or separately original PDU")
    return _owned(separate)


def component_fixture() -> dict:
    """Return a fresh, inert P-DATA-TF structure with synthetic fragment bytes."""
    first = bytes((0x01, 0x01)) + b"AB"
    second = bytes((0x01, 0x02)) + b"CD"
    items = len(first).to_bytes(4, "big") + first + len(second).to_bytes(4, "big") + second
    pdu = bytes((0x04, 0x00)) + len(items).to_bytes(4, "big") + items
    return {
        "schema_version": 1,
        "source_id": "synthetic-dicom-pdv",
        "pdu_base64": base64.b64encode(pdu).decode("ascii"),
    }


__all__ = [
    "DicomPdvAnalysis",
    "DicomPdvError",
    "analyze_supplied_dicom_pdv",
    "analyze_supplied_dicom_pdv_bytes",
    "verify_supplied_dicom_pdv_analysis",
    "component_fixture",
]
