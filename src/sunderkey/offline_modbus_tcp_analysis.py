"""Pure bounded structure arithmetic over one supplied Modbus TCP read exchange."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "modbus_supplied_tcp_read_exchange_structure"
PROFILE_ID = "AOE-GD-D19-S06"
CAPABILITY_ID = "army.gd.d19.s06"
VECTOR_ID = "AV-GD-D19-S06-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D19-S06"
WAVE_ID = "IW2-016"
BLUEPRINT_SHA256 = "sha256:d5e11b6e2210e57a627a4b7da3c0ad7036434345cb9246b6a3059b7011d43e41"
SEMANTICS_PROFILE = "modbus-v1.1b3-tcp-v1.0b-supplied-read-structure.v1"
DOMAIN = "sunderkey.offline-modbus-tcp-analysis.v1"
MODEL_DOMAIN = "sunderkey.offline-modbus-tcp-model.v1"
MAX_ADU_BYTES = 260
MAX_MODEL_BYTES = 16_384
MAX_REPORT_BYTES = 131_072
MAX_NODES = 8_192
MAX_DEPTH = 16
MAX_STRING_BYTES = 2_048
MAX_OBSERVATIONS = 32
MAX_WORK = 4_194_304
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1
_MODEL_FIELDS = {"schema_version", "routing_context", "request_base64", "response_base64"}
_SHA_PLACEHOLDER = "sha256:" + "0" * 64
_ID_PLACEHOLDER = "MBA-" + "0" * 32
_READ_FUNCTIONS = {1, 2, 3, 4}
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "target",
        "network",
        "provider",
        "credential",
        "process",
        "execution",
        "routing",
        "qualification",
        "deployment",
        "publication",
    ),
    "none",
)
_CLAIMS = dict.fromkeys(
    (
        "source_authenticated",
        "shared_connection_proven",
        "device_identity_proven",
        "register_or_coil_truth_proven",
        "successful_read_proven",
        "protocol_conformance_proven",
        "vulnerability_proven",
        "process_safety_proven",
        "live_use_approved",
        "qualification_claimed",
    ),
    False,
)
_LIMITATIONS = (
    "One supplied request and response are declarations, not authenticated traffic.",
    "Only MBAP framing and FC01, FC02, FC03 and FC04 read structure are projected.",
    "Direct TCP discards Unit Identifier for correlation; bridge equality is conditional "
    "on the supplied context; unknown routing withholds a comprehensive conclusion.",
    "Transaction equality does not prove a shared TCP connection or actual device identity.",
    "Exception responses do not establish a successful read or the truth of an error.",
    "No transmission, writes, serial/RTU, CRC, TCP reassembly or retry is performed.",
    "No actual PLC address map, data meaning, vulnerability, safety or authority is proven.",
    "The model address binds canonical parsed JSON, not original raw JSON byte provenance.",
    "Finite software ceilings can reject documents independently of protocol semantics.",
    "No full specialist, qualification, routing or deployment approval follows.",
)


class ModbusTcpAnalysisError(ValueError):
    """An exact contract, software ceiling or complete source replay was rejected."""


@dataclass
class _Budget:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or amount > MAX_WORK - self.used:
            raise ModbusTcpAnalysisError("Cumulative operation work ceiling exceeded")
        self.used += amount


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _string_size(value: str, budget: _Budget) -> int:
    if len(value) > MAX_STRING_BYTES:
        raise ModbusTcpAnalysisError("Native string software ceiling exceeded")
    size = 2
    for char in value:
        budget.charge(1)
        code = ord(char)
        if code > 127:
            raise ModbusTcpAnalysisError("The closed projection requires ASCII strings")
        size += 2 if char in '\\"\b\t\n\f\r' else 6 if code < 32 or code == 127 else 1
    return size


def _capture(value: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int]:
    """Bound repeated occurrences before copying or canonical serialization."""
    maximum = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    size = nodes = 0
    active: set[int] = set()

    def reserve(amount: int) -> None:
        nonlocal size
        if amount > maximum - size:
            raise ModbusTcpAnalysisError("Escaped native document byte ceiling exceeded")
        budget.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes
        budget.charge(1)
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise ModbusTcpAnalysisError("Native node/depth ceiling exceeded")
        kind = type(item)
        if kind is str:
            reserve(_string_size(item, budget))
            return item
        if kind is bool:
            reserve(4 if item else 5)
            return item
        if item is None:
            reserve(4)
            return None
        if kind is int:
            if not MIN_INTEGER <= item <= MAX_INTEGER:
                raise ModbusTcpAnalysisError("Exact signed 64-bit native integer required")
            budget.charge(20)
            reserve(len(str(item)))
            return item
        if kind not in (dict, list):
            raise ModbusTcpAnalysisError("Exact native integer-only JSON families required")
        if id(item) in active:
            raise ModbusTcpAnalysisError("Cyclic native documents are rejected")
        children = len(item) * (2 if kind is dict else 1)
        if children > MAX_NODES - nodes:
            raise ModbusTcpAnalysisError("Collection exceeds remaining native node ceiling")
        reserve(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
        active.add(id(item))
        try:
            if kind is list:
                return [visit(child, depth + 1) for child in item]
            owned = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise ModbusTcpAnalysisError("Exact native text keys required")
                owned[visit(key, depth + 1)] = visit(child, depth + 1)
            return owned
        finally:
            active.remove(id(item))

    return visit(value, 1), size


def _integer(text: str) -> int:
    negative = text.startswith("-")
    digits = text[1:] if negative else text
    if (
        not digits
        or len(digits) > 19
        or any(not "0" <= char <= "9" for char in digits)
        or (len(digits) > 1 and digits[0] == "0")
    ):
        raise ModbusTcpAnalysisError("Bounded raw integer grammar required")
    limit = "9223372036854775808" if negative else "9223372036854775807"
    if len(digits) == 19 and digits > limit:
        raise ModbusTcpAnalysisError("Raw signed 64-bit integer ceiling exceeded")
    return int(text)


def _raw_string(text: str, start: int, budget: _Budget) -> int:
    index = start + 1
    count = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            return index + 1
        budget.charge(1)
        if char == "\\":
            index += 1
            if index >= len(text):
                raise ModbusTcpAnalysisError("Incomplete raw JSON escape")
            escape = text[index]
            if escape == "u":
                digits = text[index + 1 : index + 5]
                if len(digits) != 4 or any(c not in "0123456789abcdefABCDEF" for c in digits):
                    raise ModbusTcpAnalysisError("Malformed raw Unicode escape")
                if int(digits, 16) > 127:
                    raise ModbusTcpAnalysisError("The closed projection requires ASCII strings")
                index += 4
            elif escape not in '\\"/bfnrt':
                raise ModbusTcpAnalysisError("Malformed raw JSON escape")
        elif ord(char) < 32:
            raise ModbusTcpAnalysisError("Invalid literal JSON string character")
        count += 1
        if count > MAX_STRING_BYTES:
            raise ModbusTcpAnalysisError("Pre-decoder string ceiling exceeded")
        index += 1
    raise ModbusTcpAnalysisError("Unterminated raw JSON string")


def _decode(text: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int]:
    maximum = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    if type(text) is not str or not text or len(text) > maximum or not text.isascii():
        raise ModbusTcpAnalysisError("Bounded exact native ASCII JSON text required")
    budget.charge(2 * len(text))
    index = nodes = 0
    stack: list[str] = []
    while index < len(text):
        char = text[index]
        if char in " \t\r\n,:":
            index += 1
            continue
        if char in "]}":
            if not stack or stack.pop() != ("[" if char == "]" else "{"):
                raise ModbusTcpAnalysisError("Malformed raw JSON containers")
            index += 1
            continue
        nodes += 1
        if nodes > MAX_NODES or len(stack) + 1 > MAX_DEPTH:
            raise ModbusTcpAnalysisError("Pre-decoder node/depth ceiling exceeded")
        if char in "[{":
            stack.append(char)
            index += 1
        elif char == '"':
            index = _raw_string(text, index, budget)
        else:
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}{["':
                index += 1
                if index - start > 20:
                    raise ModbusTcpAnalysisError("Pre-decoder scalar lexical ceiling exceeded")
            token = text[start:index]
            if token not in ("true", "false", "null"):
                _integer(token)
    if stack:
        raise ModbusTcpAnalysisError("Unterminated raw JSON containers")

    def pairs(rows: list[tuple[str, Any]]) -> dict:
        owned = {}
        for key, child in rows:
            if key in owned:
                raise ModbusTcpAnalysisError("Duplicate raw JSON key")
            owned[key] = child
        return owned

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_int=_integer)
    except (ValueError, RecursionError, OverflowError) as exc:
        raise ModbusTcpAnalysisError("Invalid bounded JSON document") from exc
    return _capture(value, budget, report=report)


def _wire(text: Any, budget: _Budget) -> bytes:
    if type(text) is not str or len(text) > 4 * ((MAX_ADU_BYTES + 2) // 3):
        raise ModbusTcpAnalysisError("Bounded exact native canonical base64 required")
    budget.charge(3 * len(text) + MAX_ADU_BYTES)
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ModbusTcpAnalysisError("Invalid supplied base64") from exc
    if len(raw) > MAX_ADU_BYTES or base64.b64encode(raw).decode("ascii") != text:
        raise ModbusTcpAnalysisError("Canonical base64 or ADU software ceiling rejected")
    return raw


def _u16(raw: bytes, offset: int) -> int:
    return raw[offset] * 256 + raw[offset + 1]


def _append(rows: list[str], code: str, budget: _Budget) -> None:
    budget.charge(1 + sum(len(item) + len(code) for item in rows))
    if code in rows:
        return
    if len(rows) >= MAX_OBSERVATIONS:
        raise ModbusTcpAnalysisError("Observation software ceiling exceeded")
    budget.charge(1 + len(code))
    rows.append(code)


def _adu(raw: bytes, side: str, budget: _Budget, violations: list[str], unknown: list[str]) -> dict:
    budget.charge(4 * len(raw) + 128)
    result = {
        "byte_length": len(raw),
        "header_complete": len(raw) >= 7,
        "transaction_id": None,
        "protocol_id": None,
        "declared_length": None,
        "unit_id": None,
        "expected_adu_length": None,
        "framing_complete": False,
        "function_code": None,
        "pdu_length": None,
    }
    if len(raw) < 7:
        _append(unknown, side + "_truncated_mbap_header", budget)
        return result
    length = _u16(raw, 4)
    expected = 6 + length
    result.update(
        transaction_id=_u16(raw, 0),
        protocol_id=_u16(raw, 2),
        declared_length=length,
        unit_id=raw[6],
        expected_adu_length=expected,
    )
    if length < 2:
        _append(violations, side + "_mbap_length_below_unit_and_function", budget)
    if expected > MAX_ADU_BYTES:
        _append(violations, side + "_mbap_length_above_protocol_adu_limit", budget)
    if len(raw) < expected:
        _append(unknown, side + "_truncated_declared_adu", budget)
    elif len(raw) > expected:
        _append(violations, side + "_trailing_bytes_after_declared_adu", budget)
    result["framing_complete"] = 2 <= length <= 254 and len(raw) == expected
    if result["protocol_id"] != 0:
        _append(unknown, side + "_non_modbus_protocol_identifier", budget)
    if result["framing_complete"]:
        result["function_code"] = raw[7]
        result["pdu_length"] = length - 1
    return result


def _relations(request: bytes, response: bytes, context: str, budget: _Budget) -> dict[str, Any]:
    budget.charge(512)
    violations: list[str] = []
    unknown: list[str] = []
    req = _adu(request, "request", budget, violations, unknown)
    rsp = _adu(response, "response", budget, violations, unknown)
    req.update(starting_address=None, quantity=None, last_requested_address=None)
    rsp.update(
        byte_count=None, data_hex=None, bit_values=[], register_values=[], exception_code=None
    )
    checks = {
        "transaction_ids_equal": None,
        "unit_ids_equal": None,
        "unit_identifier_rule": "unavailable",
        "function_correlated": None,
        "expected_response_data_bytes": None,
        "response_data_length_matches_request": None,
        "zero_unused_padding_bits": None,
    }
    if req["header_complete"] and rsp["header_complete"]:
        checks["transaction_ids_equal"] = req["transaction_id"] == rsp["transaction_id"]
        if not checks["transaction_ids_equal"]:
            _append(violations, "transaction_identifier_mismatch", budget)
        checks["unit_ids_equal"] = req["unit_id"] == rsp["unit_id"]
        if context == "bridge":
            checks["unit_identifier_rule"] = "equality_under_supplied_bridge_context"
            if not checks["unit_ids_equal"]:
                _append(violations, "bridge_unit_identifier_mismatch", budget)
        elif context == "direct":
            checks["unit_identifier_rule"] = "ignored_for_direct_tcp_correlation"
        else:
            checks["unit_identifier_rule"] = "routing_context_unassessed"
    if context == "unknown":
        _append(unknown, "routing_context_unknown", budget)
    eligible_req = req["framing_complete"] and req["protocol_id"] == 0
    eligible_rsp = rsp["framing_complete"] and rsp["protocol_id"] == 0
    function = req["function_code"]
    valid_request = False
    if eligible_req:
        if function == 0 or function >= 128:
            _append(violations, "invalid_request_function_code", budget)
        elif function not in _READ_FUNCTIONS:
            _append(unknown, "request_function_outside_read_projection", budget)
        elif req["pdu_length"] != 5:
            _append(violations, "read_request_pdu_length_mismatch", budget)
        else:
            start = _u16(request, 8)
            quantity = _u16(request, 10)
            req.update(
                starting_address=start,
                quantity=quantity,
                last_requested_address=start + quantity - 1 if quantity else None,
            )
            maximum = 2000 if function in (1, 2) else 125
            valid_request = 1 <= quantity <= maximum and start + quantity <= 65_536
            if not 1 <= quantity <= maximum:
                _append(violations, "read_quantity_outside_function_range", budget)
            if start + quantity > 65_536:
                _append(violations, "read_address_range_exceeds_unsigned16", budget)
    response_kind = "unassessed"
    if eligible_rsp:
        response_function = rsp["function_code"]
        if response_function == 0:
            _append(violations, "invalid_response_function_code", budget)
        if eligible_req and function in _READ_FUNCTIONS:
            checks["function_correlated"] = response_function in (function, function + 128)
            if not checks["function_correlated"]:
                _append(violations, "response_function_not_correlated", budget)
        if response_function in (129, 130, 131, 132):
            response_kind = "exception"
            if rsp["pdu_length"] != 2:
                _append(violations, "exception_response_pdu_length_mismatch", budget)
            else:
                rsp["exception_code"] = response[8]
                if response[8] not in (1, 2, 3, 4):
                    _append(unknown, "exception_code_outside_read_projection", budget)
        elif response_function not in _READ_FUNCTIONS:
            _append(unknown, "response_function_outside_read_projection", budget)
        elif rsp["pdu_length"] < 2:
            _append(violations, "read_response_byte_count_absent", budget)
        else:
            response_kind = "ordinary_read"
            count = response[8]
            payload_size = len(response) - 9
            rsp.update(byte_count=count, data_hex=response[9:].hex())
            if count != payload_size:
                _append(violations, "response_byte_count_not_payload_length", budget)
            if valid_request and response_function == function:
                expected = (req["quantity"] + 7) // 8 if function in (1, 2) else 2 * req["quantity"]
                checks["expected_response_data_bytes"] = expected
                checks["response_data_length_matches_request"] = count == payload_size == expected
                if not checks["response_data_length_matches_request"]:
                    _append(violations, "response_data_length_not_requested_quantity", budget)
                else:
                    budget.charge(4 * req["quantity"] + payload_size)
                    if function in (1, 2):
                        remainder = req["quantity"] % 8
                        padding_ok = not remainder or response[-1] >> remainder == 0
                        checks["zero_unused_padding_bits"] = padding_ok
                        if not padding_ok:
                            _append(violations, "nonzero_unused_response_padding_bits", budget)
                        rsp["bit_values"] = [
                            (response[9 + index // 8] >> (index % 8)) & 1
                            for index in range(req["quantity"])
                        ]
                    else:
                        rsp["register_values"] = [
                            _u16(response, 9 + 2 * index) for index in range(req["quantity"])
                        ]
    complete = eligible_req and eligible_rsp and valid_request and not unknown
    outcome = "structural_contradictions_observed" if violations else "incomplete_or_unassessed"
    if not violations and complete:
        outcome = (
            "consistent_supported_exception_structure"
            if response_kind == "exception"
            else "consistent_supported_read_structure"
        )
    return {
        "request": req,
        "response": rsp,
        "correlation_checks": checks,
        "response_kind": response_kind,
        "outcome": outcome,
        "supported_checks_complete": bool(complete),
        "contradictions": violations,
        "unassessed_reasons": unknown,
    }


@dataclass(frozen=True)
class _Plan:
    document: dict
    size: int
    request: bytes
    response: bytes


def _plan(model: Any, budget: _Budget) -> _Plan:
    owned, source_size = _capture(model, budget)
    if type(owned) is not dict or owned.keys() != _MODEL_FIELDS:
        raise ModbusTcpAnalysisError("Exact closed source-model fields required")
    if type(owned["schema_version"]) is not int or owned["schema_version"] != 1:
        raise ModbusTcpAnalysisError("Exact native model schema version 1 required")
    if type(owned["routing_context"]) is not str or owned["routing_context"] not in {
        "direct",
        "bridge",
        "unknown",
    }:
        raise ModbusTcpAnalysisError("Explicit direct, bridge or unknown routing context required")
    request = _wire(owned["request_base64"], budget)
    response = _wire(owned["response_base64"], budget)
    relations = _relations(request, response, owned["routing_context"], budget)
    document = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_profile_id": "AOE-GD-D19-CMD",
        "group_commander_profile_id": "AOE-HQ-06",
        "independent_validator_id": "AOE-HQ-33",
        "blueprint_sha256": BLUEPRINT_SHA256,
        "roadmap_package_ids": ["A7.4"],
        "semantics_profile": SEMANTICS_PROFILE,
        "analysis_id": _ID_PLACEHOLDER,
        "analysis_sha256": _SHA_PLACEHOLDER,
        "source_model": owned,
        "source_model_sha256": _SHA_PLACEHOLDER,
        "source_bytes": {
            "request_sha256": _SHA_PLACEHOLDER,
            "response_sha256": _SHA_PLACEHOLDER,
            "request_length": len(request),
            "response_length": len(response),
        },
        "effects": _EFFECTS,
        "claims": _CLAIMS,
        "limitations": list(_LIMITATIONS),
        "bounds": {
            "maximum_adu_bytes": MAX_ADU_BYTES,
            "maximum_model_bytes": MAX_MODEL_BYTES,
            "maximum_report_bytes": MAX_REPORT_BYTES,
            "maximum_native_nodes": MAX_NODES,
            "maximum_native_depth": MAX_DEPTH,
            "maximum_string_bytes": MAX_STRING_BYTES,
            "maximum_observations_per_kind": MAX_OBSERVATIONS,
            "maximum_cumulative_work": MAX_WORK,
        },
        **relations,
    }
    # Fund complete retained output and all final byte/address/encoding passes before ANY SHA.
    document, size = _capture(document, budget, report=True)
    budget.charge(
        4 * size
        + 2 * source_size
        + len(request)
        + len(response)
        + len(DOMAIN)
        + len(MODEL_DOMAIN)
        + 2
    )
    return _Plan(document, size, request, response)


def _digest(domain: str, document: dict) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            domain.encode("ascii") + b"\n" + _canonical(document).encode("ascii")
        ).hexdigest()
    )


def _materialize(plan: _Plan) -> str:
    document = plan.document
    document["source_model_sha256"] = _digest(MODEL_DOMAIN, document["source_model"])
    document["source_bytes"]["request_sha256"] = (
        "sha256:" + hashlib.sha256(plan.request).hexdigest()
    )
    document["source_bytes"]["response_sha256"] = (
        "sha256:" + hashlib.sha256(plan.response).hexdigest()
    )
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = _digest(DOMAIN, body)
    document["analysis_sha256"] = digest
    document["analysis_id"] = "MBA-" + digest[7:39].upper()
    return _canonical(document)


def _replay_plan(text: Any, budget: _Budget) -> tuple[dict, _Plan]:
    document, size = _decode(text, budget, report=True)
    if type(document) is not dict or "source_model" not in document:
        raise ModbusTcpAnalysisError("Report requires its exact embedded source model")
    expected = _plan(document["source_model"], budget)
    budget.charge(3 * size + expected.size)
    return document, expected


def _compare(text: str, document: dict, expected: str) -> None:
    actual = _canonical(document)
    if text != actual or actual != expected:
        raise ModbusTcpAnalysisError("Canonical report does not replay its full embedded source")


def _replay(text: Any, budget: _Budget) -> dict:
    document, plan = _replay_plan(text, budget)
    _compare(text, document, _materialize(plan))
    return document


def _stored(report: Any) -> str:
    if type(report) is not ModbusTcpAnalysis or not hasattr(report, "document_json"):
        raise ModbusTcpAnalysisError("Exact complete native report wrapper required")
    text = report.document_json
    if type(text) is not str:
        raise ModbusTcpAnalysisError("Exact native report text required")
    return text


@dataclass(frozen=True, slots=True)
class ModbusTcpAnalysis:
    """Detached unsigned structure observations, not industrial or mission authority."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not ModbusTcpAnalysis:
            raise ModbusTcpAnalysisError("Exact native report family required")
        _replay(self.document_json, _Budget())

    @classmethod
    def from_dict(cls, document: Any) -> ModbusTcpAnalysis:
        if cls is not ModbusTcpAnalysis:
            raise ModbusTcpAnalysisError("Exact native report family required")
        budget = _Budget()
        owned, size = _capture(document, budget, report=True)
        budget.charge(size)
        text = _canonical(owned)
        _replay(text, budget)
        return _owned(text)

    @classmethod
    def from_json(cls, document_json: Any) -> ModbusTcpAnalysis:
        if cls is not ModbusTcpAnalysis:
            raise ModbusTcpAnalysisError("Exact native report family required")
        _replay(document_json, _Budget())
        return _owned(document_json)

    def to_dict(self) -> dict:
        return _replay(_stored(self), _Budget())

    def to_json(self) -> str:
        text = _stored(self)
        _replay(text, _Budget())
        return text


def _owned(text: str) -> ModbusTcpAnalysis:
    result = object.__new__(ModbusTcpAnalysis)
    object.__setattr__(result, "document_json", text)
    return result


def analyze_supplied_modbus_tcp(model: Any) -> ModbusTcpAnalysis:
    """Analyze one supplied inert exchange, never send a Modbus message."""
    return _owned(_materialize(_plan(model, _Budget())))


def analyze_supplied_modbus_tcp_bytes(*, model_bytes: Any) -> ModbusTcpAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise ModbusTcpAnalysisError("Bounded exact native model bytes required")
    budget = _Budget()
    budget.charge(len(model_bytes))
    try:
        text = model_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ModbusTcpAnalysisError("Model bytes must be well-formed UTF-8") from exc
    model, _ = _decode(text, budget)
    return _owned(_materialize(_plan(model, budget)))


def verify_supplied_modbus_tcp_analysis(report: Any, *, model: Any) -> ModbusTcpAnalysis:
    budget = _Budget()
    text = _stored(report)
    document, embedded = _replay_plan(text, budget)
    original = _plan(model, budget)
    budget.charge(embedded.size + original.size)
    expected = _materialize(embedded)
    original_expected = _materialize(original)
    _compare(text, document, expected)
    if expected != original_expected:
        raise ModbusTcpAnalysisError("Report differs from separately supplied original model")
    return _owned(original_expected)


def component_fixture() -> dict:
    """Fresh synthetic FC03 bytes, not a captured device or authenticated connection."""
    return {
        "schema_version": 1,
        "routing_context": "bridge",
        "request_base64": "EjQAAAAGAQMAawAD",
        "response_base64": "EjQAAAAJAQMGAisAAABk",
    }
