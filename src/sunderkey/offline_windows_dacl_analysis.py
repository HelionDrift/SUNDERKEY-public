"""Finite ordered supplied-DACL arithmetic, never a Windows access grant."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

DOMAIN = "sunderkey.offline-windows-dacl-analysis.v1"
PROFILE_ID = "AOE-GC-D11-S05"
CAPABILITY_ID = "army.gc.d11.s05"
VECTOR_ID = "AV-GC-D11-S05-01"
WAVE_ID = "IW2-005"
SEMANTICS_PROFILE = "ordered-supplied-specific-low16-dacl-v1"
MAX_DOCUMENT_BYTES = 1_048_576
MAX_NATIVE_NODES = 8192
MAX_NATIVE_DEPTH = 12
MAX_STRING_BYTES = 512
MAX_ACES = 256
MAX_TOKEN_SIDS = 128
_UINT32 = 2**32 - 1
_SPECIFIC_MASK = 2**16 - 1
_SID = re.compile(r"S-1-(?:0|[1-9][0-9]{0,9})(?:-(?:0|[1-9][0-9]{0,9})){1,15}\Z")
_JSON_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_MODEL_FIELDS = {"schema_version", "security_descriptor", "token_sids", "desired_access"}
_BOUNDS = {
    "maximum_document_bytes": MAX_DOCUMENT_BYTES,
    "maximum_native_nodes": MAX_NATIVE_NODES,
    "maximum_native_depth": MAX_NATIVE_DEPTH,
    "maximum_string_bytes": MAX_STRING_BYTES,
    "maximum_aces": MAX_ACES,
    "maximum_token_sids": MAX_TOKEN_SIDS,
    "maximum_trace_entries": MAX_ACES,
}
_EFFECTS = {
    name: "none"
    for name in (
        "authority",
        "target",
        "execution",
        "routing",
        "qualification",
        "deployment",
        "network",
        "provider_requests",
        "credentials",
        "process",
    )
}
_FLAGS = {
    "offline_only": True,
    "descriptor_authenticated": False,
    "token_authenticated": False,
    "effective_access_proven": False,
    "live_use_approved": False,
    "qualification_claimed": False,
}
_LIMITATIONS = [
    "The security descriptor projection and SID usage are caller assertions.",
    "Only ordered standard ACE arithmetic for specific low16 rights is supported.",
    "Unsupported semantics anywhere withhold every supported access conclusion.",
    "No owner rights, privileges, restricted token pass or implicit groups are supplied.",
    "No SACL, integrity, conditional, object GUID or central access policy is evaluated.",
    "Inherited ACEs are supplied current-object entries, not synthesized inheritance.",
    "No SDDL, binary descriptor, Windows API, runtime authority or qualification is used.",
]
_REPORT_FIELDS = {
    "analysis_id",
    "analysis_sha256",
    "schema_version",
    "profile_id",
    "capability_id",
    "vector_id",
    "wave_id",
    "semantics_profile",
    "source_model",
    "source_model_sha256",
    "bounds",
    "evaluation",
    "incomplete_reasons",
    "input_provenance",
    "effects",
    "limitations",
    *_FLAGS,
}


class WindowsDaclAnalysisError(ValueError):
    """Supplied native shape, finite costs or original-source replay failed."""


def _capture(value: Any) -> Any:
    """Charge all repeated native nodes and canonical bytes before copying them."""
    nodes = size = 0
    active: set[int] = set()

    def charge(amount: int) -> None:
        nonlocal size
        size += amount
        if size > MAX_DOCUMENT_BYTES:
            raise WindowsDaclAnalysisError("Native document exceeds its canonical byte budget")

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise WindowsDaclAnalysisError("Native document exceeds its node or depth budget")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES:
                raise WindowsDaclAnalysisError("Native text exceeds its supported length")
            charge(len(item) + 2)
            if not item.isascii() or any(not 32 <= ord(char) <= 126 for char in item):
                raise WindowsDaclAnalysisError("Native text must be printable ASCII")
            charge(item.count('"') + item.count("\\"))
            return item
        if kind is bool:
            charge(4 if item else 5)
            return item
        if item is None:
            charge(4)
            return None
        if kind is int:
            if item.bit_length() > 63:
                raise WindowsDaclAnalysisError("Native integer exceeds its finite magnitude")
            charge(len(str(item)))
            return item
        if kind not in (dict, list):
            raise WindowsDaclAnalysisError("Only exact native JSON families are supported")
        if id(item) in active or len(item) * (2 if kind is dict else 1) > MAX_NATIVE_NODES - nodes:
            raise WindowsDaclAnalysisError("Native collection is oversized or cyclic")
        charge(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
        active.add(id(item))
        try:
            if kind is list:
                return [visit(child, depth + 1) for child in item]
            result = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise WindowsDaclAnalysisError("Native object keys must be exact text")
                result[visit(key, depth + 1)] = visit(child, depth + 1)
            return result
        finally:
            active.remove(id(item))

    return visit(value, 0)


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _address(body: dict[str, Any]) -> dict[str, Any]:
    owned = _capture(body)
    digest = _sha(DOMAIN.encode("ascii") + b"\n" + _canonical(owned).encode("ascii"))
    return {"analysis_id": "WDA-" + digest[7:39].upper(), "analysis_sha256": digest, **owned}


def _json(text: Any) -> Any:
    """Refuse lexical costs before entering the software JSON decoder."""
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES or not text.isascii():
        raise WindowsDaclAnalysisError("JSON must be bounded exact native ASCII text")
    depth = nodes = index = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            nodes += 1
            length = 0
            index += 1
            closed = False
            while index < len(text):
                char = text[index]
                if char == '"':
                    index += 1
                    closed = True
                    break
                if char == "\\":
                    index += 1
                    if index >= len(text):
                        raise WindowsDaclAnalysisError("JSON string escape is incomplete")
                    escape = text[index]
                    if escape == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            c not in "0123456789abcdefABCDEF" for c in digits
                        ):
                            raise WindowsDaclAnalysisError("JSON Unicode escape is invalid")
                        if not 32 <= int(digits, 16) <= 126:
                            raise WindowsDaclAnalysisError("JSON text is outside printable ASCII")
                        index += 5
                    elif escape in '"\\/':
                        index += 1
                    else:
                        raise WindowsDaclAnalysisError("JSON escape is outside printable ASCII")
                else:
                    if not 32 <= ord(char) <= 126:
                        raise WindowsDaclAnalysisError("JSON text is outside printable ASCII")
                    index += 1
                length += 1
                if length > MAX_STRING_BYTES:
                    raise WindowsDaclAnalysisError("JSON text exceeds its pre-decoder bound")
            if not closed:
                raise WindowsDaclAnalysisError("JSON string is incomplete")
        elif char in "[{":
            depth += 1
            nodes += 1
            index += 1
        elif char in "]}":
            depth -= 1
            index += 1
        elif char in " \t\r\n,:":
            index += 1
        else:
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}{["':
                index += 1
            if index == start:
                raise WindowsDaclAnalysisError("JSON token is invalid")
            lexical = text[start:index]
            nodes += 1
            if lexical not in {"true", "false", "null"}:
                if _JSON_INTEGER.fullmatch(lexical) is None:
                    raise WindowsDaclAnalysisError("JSON number is outside the integer subset")
                if int(lexical).bit_length() > 63:
                    raise WindowsDaclAnalysisError("JSON integer exceeds its finite magnitude")
        if depth < 0 or depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise WindowsDaclAnalysisError("JSON exceeds pre-decoder node or depth limits")
    if depth:
        raise WindowsDaclAnalysisError("JSON structure is incomplete")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in items:
            if key in result:
                raise WindowsDaclAnalysisError("JSON contains a duplicate field")
            result[key] = value
        return result

    def unsupported(_: str) -> None:
        raise WindowsDaclAnalysisError("Fractional or nonfinite JSON numbers are unsupported")

    try:
        document = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, WindowsDaclAnalysisError):
            raise
        raise WindowsDaclAnalysisError("JSON is malformed") from exc
    return _capture(document)


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise WindowsDaclAnalysisError(f"{label} has missing or unsupported fields")
    return value


def _integer(value: Any, maximum: int, label: str) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise WindowsDaclAnalysisError(f"{label} must be a bounded native integer")
    return value


def _sid(value: Any) -> str:
    if type(value) is not str or _SID.fullmatch(value) is None:
        raise WindowsDaclAnalysisError("SID must use the supported canonical decimal notation")
    if any(int(part) > _UINT32 for part in value.split("-")[2:]):
        raise WindowsDaclAnalysisError("SID components exceed this decimal uint32 subset")
    return value


def _model(value: Any) -> dict[str, Any]:
    model = _exact(_capture(value), _MODEL_FIELDS, "DACL model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise WindowsDaclAnalysisError("Model schema version must be native integer one")
    _integer(model["desired_access"], _UINT32, "Desired access")
    descriptor = _exact(
        model["security_descriptor"], {"owner_sid", "group_sid", "dacl_state", "aces"}, "Descriptor"
    )
    _sid(descriptor["owner_sid"])
    _sid(descriptor["group_sid"])
    state = descriptor["dacl_state"]
    if type(state) is not str or state not in {"absent", "null", "present"}:
        raise WindowsDaclAnalysisError("DACL state is outside the explicit supported declarations")
    aces = descriptor["aces"]
    if type(aces) is not list or len(aces) > MAX_ACES:
        raise WindowsDaclAnalysisError("ACE count is outside the finite bound")
    if state != "present" and aces:
        raise WindowsDaclAnalysisError("An absent or null DACL cannot declare ACEs")
    for ace in aces:
        _exact(ace, {"ace_type", "sid", "mask", "flags"}, "ACE projection")
        _integer(ace["ace_type"], 255, "ACE type")
        _sid(ace["sid"])
        _integer(ace["mask"], _UINT32, "ACE mask")
        _integer(ace["flags"], 255, "ACE flags")
    sids = model["token_sids"]
    if type(sids) is not list or not 1 <= len(sids) <= MAX_TOKEN_SIDS:
        raise WindowsDaclAnalysisError("Token SID count is outside the finite bound")
    seen = set()
    for item in sids:
        _exact(item, {"sid", "usage"}, "Token SID assertion")
        sid = _sid(item["sid"])
        if sid in seen:
            raise WindowsDaclAnalysisError("Token SID declarations cannot repeat or conflict")
        seen.add(sid)
        if type(item["usage"]) is not str or item["usage"] not in {
            "enabled",
            "deny_only",
            "disabled",
        }:
            raise WindowsDaclAnalysisError("Every token SID requires exact explicit usage")
    return model


def _special_sid(sid: str) -> bool:
    return sid.startswith("S-1-3-") or sid == "S-1-5-10"


def _evaluation(model: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    descriptor = model["security_descriptor"]
    requested = model["desired_access"]
    incomplete: list[dict[str, Any]] = []

    def note(code: str, index: int | None = None) -> None:
        item = {"code": code, "ace_index": index}
        if item not in incomplete:
            incomplete.append(item)

    if not 1 <= requested <= _SPECIFIC_MASK:
        note("desired_access_outside_specific_low16_subset")
    if any(_special_sid(sid) for sid in (descriptor["owner_sid"], descriptor["group_sid"])):
        note("descriptor_substitution_sid_unsupported")
    if any(_special_sid(item["sid"]) for item in model["token_sids"]):
        note("token_substitution_sid_unsupported")
    # Inspect every entry, including after a sufficient allow or INHERIT_ONLY.
    for index, ace in enumerate(descriptor["aces"]):
        if ace["ace_type"] not in {0, 1}:
            note("ace_type_unsupported", index)
        if ace["mask"] > _SPECIFIC_MASK:
            note("ace_mask_outside_specific_low16_subset", index)
        if ace["flags"] & ~31:
            note("ace_flags_unsupported", index)
        if _special_sid(ace["sid"]):
            note("ace_substitution_sid_unsupported", index)
    evaluation = {
        "outcome": "incomplete",
        "reason": "unsupported_semantics",
        "requested_mask": requested,
        "allowed_mask": 0,
        "remaining_mask": requested,
        "decisive_ace_index": None,
        "trace": [],
    }
    if incomplete:
        return evaluation, incomplete
    if descriptor["dacl_state"] in {"absent", "null"}:
        evaluation.update(
            outcome="supplied_dacl_allows_requested_bits",
            reason="no_dacl_restriction",
            allowed_mask=requested,
            remaining_mask=0,
        )
        return evaluation, incomplete
    usages = {item["sid"]: item["usage"] for item in model["token_sids"]}
    remaining = requested
    trace = evaluation["trace"]
    for index, ace in enumerate(descriptor["aces"]):
        before = remaining
        usage = usages.get(ace["sid"])
        intersection = remaining & ace["mask"]
        matched = 0
        if ace["flags"] & 8:
            disposition = "inherit_only_skipped"
        elif usage is None:
            disposition = "sid_not_supplied"
        elif usage == "disabled":
            disposition = "disabled_sid_skipped"
        elif usage == "deny_only" and ace["ace_type"] == 0:
            disposition = "deny_only_allow_skipped"
        elif ace["ace_type"] == 0:
            disposition = "allow_remaining_bits"
            matched = intersection
            remaining &= ~ace["mask"]
        else:
            matched = intersection
            disposition = "deny_remaining_bits" if matched else "deny_no_remaining_bits"
        trace.append(
            {
                "ace_index": index,
                "disposition": disposition,
                "inherited": bool(ace["flags"] & 16),
                "matched_mask": matched,
                "remaining_before": before,
                "remaining_after": remaining,
            }
        )
        if disposition == "deny_remaining_bits":
            evaluation.update(
                outcome="supplied_dacl_denies_requested_bits",
                reason="explicit_remaining_bit_denial",
                remaining_mask=remaining,
                decisive_ace_index=index,
            )
            return evaluation, incomplete
        if not remaining:
            evaluation.update(
                outcome="supplied_dacl_allows_requested_bits",
                reason="remaining_mask_satisfied",
                allowed_mask=requested,
                remaining_mask=0,
                decisive_ace_index=index,
            )
            return evaluation, incomplete
    evaluation.update(
        outcome="supplied_dacl_denies_requested_bits",
        reason="remaining_mask_not_allowed",
        remaining_mask=remaining,
    )
    return evaluation, incomplete


def _derive(model: dict[str, Any]) -> dict[str, Any]:
    evaluation, incomplete = _evaluation(model)
    body = {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "wave_id": WAVE_ID,
        "semantics_profile": SEMANTICS_PROFILE,
        "source_model": model,
        "source_model_sha256": _sha(_canonical(model).encode("ascii")),
        "bounds": dict(_BOUNDS),
        "evaluation": evaluation,
        "incomplete_reasons": incomplete,
        "input_provenance": "operator_supplied_unverified",
        **_FLAGS,
        "effects": dict(_EFFECTS),
        "limitations": list(_LIMITATIONS),
    }
    return _address(body)


def _report(value: Any) -> dict[str, Any]:
    report = _exact(_capture(value), _REPORT_FIELDS, "DACL analysis")
    model = _model(report["source_model"])
    expected = _derive(model)
    if _canonical(report) != _canonical(expected):
        raise WindowsDaclAnalysisError("Analysis does not exactly replay its declared source model")
    return report


@dataclass(frozen=True, slots=True)
class WindowsDaclAnalysis:
    """Owned unsigned supplied-model replay, not authenticated descriptor or token truth."""

    document_json: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "document_json", _canonical(self._read()))

    def _read(self) -> dict[str, Any]:
        try:
            text = self.document_json
        except AttributeError as exc:
            raise WindowsDaclAnalysisError("Analysis native slots are incomplete") from exc
        return _report(_json(text))

    def to_dict(self) -> dict[str, Any]:
        return self._read()

    def to_json(self) -> str:
        return _canonical(self._read())

    @classmethod
    def from_dict(cls, document: Any) -> WindowsDaclAnalysis:
        return cls(_canonical(_report(document)))

    @classmethod
    def from_json(cls, document: str) -> WindowsDaclAnalysis:
        return cls(document)


def analyze_supplied_windows_dacl(model: dict[str, Any]) -> WindowsDaclAnalysis:
    """Observe bounded standard DACL arithmetic with no Windows or runtime invocation."""
    return WindowsDaclAnalysis.from_dict(_derive(_model(model)))


def verify_supplied_windows_dacl_analysis(
    report: WindowsDaclAnalysis, *, model: dict[str, Any]
) -> WindowsDaclAnalysis:
    """Replay the complete original supplied model without authenticating its assertions."""
    if type(report) is not WindowsDaclAnalysis:
        raise WindowsDaclAnalysisError("Report must be the exact native analysis family")
    actual = report.to_json()
    expected = analyze_supplied_windows_dacl(model)
    if actual != expected.to_json():
        raise WindowsDaclAnalysisError("Analysis differs from the exact original supplied model")
    return WindowsDaclAnalysis.from_json(expected.to_json())


__all__ = [
    "CAPABILITY_ID",
    "DOMAIN",
    "PROFILE_ID",
    "SEMANTICS_PROFILE",
    "VECTOR_ID",
    "WAVE_ID",
    "WindowsDaclAnalysis",
    "WindowsDaclAnalysisError",
    "analyze_supplied_windows_dacl",
    "verify_supplied_windows_dacl_analysis",
]
