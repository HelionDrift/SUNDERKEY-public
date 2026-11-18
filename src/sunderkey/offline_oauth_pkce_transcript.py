"""Unsigned, supplied OAuth code-flow and PKCE digest-binding arithmetic."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "oauth_supplied_code_pkce_transcript"
PROFILE_ID = "AOE-GA-D03-S04"
CAPABILITY_ID = "identity.oauth-oidc"
VECTOR_ID = "AV-GA-D03-S04-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D03-S04"
WAVE_ID = "IW2-005"
COMMANDER_ID = "AOE-GA-D03-CMD"
GROUP_OWNER_ID = "AOE-HQ-03"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:d194f3d0b1c6f384a679c104bc4dfd91e5ef5d4685cf9c837827401153eacc7a"
SEMANTICS_PROFILE = "supplied-oauth-code-pkce-s256-digests.v1"
DOMAIN = "sunderkey.offline-oauth-pkce-transcript.v1"
MODEL_DOMAIN = "sunderkey.offline-oauth-pkce-model.v1"

MAX_MODEL_BYTES = 262_144
MAX_REPORT_BYTES = 524_288
MAX_MODEL_NODES = 4_096
MAX_REPORT_NODES = 8_192
MAX_NATIVE_DEPTH = 16
MAX_TEXT = 512
MAX_WORK = 33_554_432

_BOUNDS = {
    "model_bytes": MAX_MODEL_BYTES,
    "report_bytes": MAX_REPORT_BYTES,
    "model_nodes": MAX_MODEL_NODES,
    "report_nodes": MAX_REPORT_NODES,
    "native_depth": MAX_NATIVE_DEPTH,
    "text_characters": MAX_TEXT,
    "cumulative_work": MAX_WORK,
}
_FLAGS = {
    "offline_only": True,
    "authorization_code_authenticated": False,
    "verifier_observed": False,
    "pkce_server_verification_proven": False,
    "token_validated": False,
    "login_authorized": False,
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
    "All stages and completeness claims are supplied and unauthenticated.",
    "Only a declared public-client code flow with S256 is supported.",
    "Code, state, redirect and verifier values are retained only as supplied digests.",
    "A verifier digest is not proof of the verifier sent to a token endpoint.",
    "Callback redirect-target normalization is a supplied, unauthenticated premise.",
    "No URI parsing, parameter decoding, server exchange or code redemption occurs.",
    "No token, OIDC assertion, identity, login or permission is validated.",
]
_SOURCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_CLIENT = re.compile(r"[\x21-\x7e]{1,128}\Z")
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")
_PLACEHOLDER = "sha256:" + "0" * 64
_ID_PLACEHOLDER = "OAT-" + "0" * 32
_CHECK_IDS = (
    "client_id_binding",
    "authorization_code_binding",
    "state_binding",
    "callback_redirect_binding",
    "token_redirect_binding",
    "pkce_s256_digest_binding",
)


class OAuthPkceTranscriptError(ValueError):
    """Closed-input, bounded-cost, or original-source replay refusal."""


@dataclass(slots=True)
class _Budget:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or amount > MAX_WORK - self.used:
            raise OAuthPkceTranscriptError("Cumulative software work ceiling exhausted")
        self.used += amount


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _text_size(value: str) -> int:
    size = 2
    for character in value:
        code = ord(character)
        if not 32 <= code <= 126:
            raise OAuthPkceTranscriptError("Printable ASCII metadata required")
        size += 2 if character in '\\"' else 1
    return size


def _measure(value: Any, budget: _Budget, *, report: bool = False) -> tuple[int, int]:
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    size = nodes = 0
    active: set[int] = set()

    def add(amount: int) -> None:
        nonlocal size
        if amount > byte_limit - size:
            raise OAuthPkceTranscriptError("Canonical document byte ceiling exhausted")
        budget.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        budget.charge(1)
        nodes += 1
        if depth > MAX_NATIVE_DEPTH or nodes > node_limit:
            raise OAuthPkceTranscriptError("Native node/depth ceiling exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_TEXT:
                raise OAuthPkceTranscriptError("Native string ceiling exhausted")
            budget.charge(len(item))
            add(_text_size(item))
        elif kind is bool:
            add(4 if item else 5)
        elif item is None:
            add(4)
        elif kind is int:
            if not -(1 << 63) <= item < 1 << 63:
                raise OAuthPkceTranscriptError("Exact signed64 integer required")
            add(len(str(item)))
        elif kind in (dict, list):
            if id(item) in active:
                raise OAuthPkceTranscriptError("Cyclic native document")
            if len(item) * (2 if kind is dict else 1) > node_limit - nodes:
                raise OAuthPkceTranscriptError("Queued native node ceiling exhausted")
            add(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise OAuthPkceTranscriptError("Exact native text keys required")
                        visit(key, depth + 1)
                        budget.charge(len(key) * (len(item).bit_length() + 1))
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise OAuthPkceTranscriptError("Exact native JSON families required")

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
        raise OAuthPkceTranscriptError("Bounded raw integer grammar required")
    negative = text.startswith("-")
    digits = text[1:] if negative else text
    limit = "9223372036854775808" if negative else "9223372036854775807"
    if len(digits) > 19 or (len(digits) == 19 and digits > limit):
        raise OAuthPkceTranscriptError("Raw signed64 integer ceiling exhausted")
    return int(text)


def _decode(text: Any, budget: _Budget, *, report: bool = False) -> Any:
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    if type(text) is not str or not text or len(text) > byte_limit:
        raise OAuthPkceTranscriptError("Bounded native JSON text required")
    budget.charge(2 * len(text))
    if not text.isascii():
        raise OAuthPkceTranscriptError("ASCII raw JSON metadata required")
    index = nodes = 0
    stack: list[str] = []
    while index < len(text):
        char = text[index]
        if char in " \t\r\n,:":
            index += 1
            continue
        if char in "]}":
            if not stack or stack.pop() != ("[" if char == "]" else "{"):
                raise OAuthPkceTranscriptError("Malformed raw JSON containers")
            index += 1
            continue
        nodes += 1
        if nodes > node_limit or len(stack) + 1 > MAX_NATIVE_DEPTH:
            raise OAuthPkceTranscriptError("Pre-decoder node/depth ceiling exhausted")
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
                        raise OAuthPkceTranscriptError("Incomplete JSON escape")
                    if text[index] == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            c not in "0123456789abcdefABCDEF" for c in digits
                        ):
                            raise OAuthPkceTranscriptError("Malformed JSON Unicode escape")
                        code = int(digits, 16)
                        index += 4
                    elif text[index] in '\\"/':
                        code = ord(text[index])
                    else:
                        raise OAuthPkceTranscriptError("Unsupported JSON string escape")
                if not 32 <= code <= 126:
                    raise OAuthPkceTranscriptError("Printable ASCII JSON strings required")
                length += 1
                if length > MAX_TEXT:
                    raise OAuthPkceTranscriptError("Pre-decoder string ceiling exhausted")
                index += 1
            if index >= len(text):
                raise OAuthPkceTranscriptError("Unterminated JSON string")
            index += 1
        elif char in "-0123456789":
            start = index
            while index < len(text) and text[index] in "-+0123456789.eE":
                index += 1
                if index - start > 20:
                    raise OAuthPkceTranscriptError("Pre-decoder number ceiling exhausted")
            _integer(text[start:index])
        elif text.startswith("true", index):
            index += 4
        elif text.startswith("false", index):
            index += 5
        elif text.startswith("null", index):
            index += 4
        else:
            raise OAuthPkceTranscriptError("Unsupported raw JSON token")
    if stack:
        raise OAuthPkceTranscriptError("Unclosed raw JSON container")
    budget.charge(8 * nodes + len(text))

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                raise OAuthPkceTranscriptError("Duplicate JSON key")
            result[key] = value
        return result

    def unsupported(_: str) -> None:
        raise OAuthPkceTranscriptError("Unsupported raw JSON numeric token")

    try:
        return json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=_integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (ValueError, TypeError, RecursionError) as exc:
        if isinstance(exc, OAuthPkceTranscriptError):
            raise
        raise OAuthPkceTranscriptError("Malformed bounded JSON document") from exc


def _exact(value: Any, fields: set[str], label: str) -> dict:
    if type(value) is not dict or set(value) != fields:
        raise OAuthPkceTranscriptError(f"Closed {label} fields required")
    return value


def _source_id(value: Any) -> str:
    if type(value) is not str or _SOURCE.fullmatch(value) is None:
        raise OAuthPkceTranscriptError("Bounded source identifier required")
    return value


def _client_id(value: Any, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if type(value) is not str or _CLIENT.fullmatch(value) is None:
        raise OAuthPkceTranscriptError("Bounded supplied client identifier required")
    return value


def _sha(value: Any, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if type(value) is not str or _SHA.fullmatch(value) is None:
        raise OAuthPkceTranscriptError("Exact SHA256 digest required")
    return value


def _challenge(value: Any) -> str:
    if type(value) is not str or _CHALLENGE.fullmatch(value) is None:
        raise OAuthPkceTranscriptError("Canonical S256 code challenge required")
    try:
        decoded = base64.urlsafe_b64decode(value + "=")
    except (ValueError, binascii.Error) as exc:
        raise OAuthPkceTranscriptError("Canonical S256 code challenge required") from exc
    if (
        len(decoded) != 32
        or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value
    ):
        raise OAuthPkceTranscriptError("Canonical S256 code challenge required")
    return value


def _completeness(value: Any) -> bool:
    if type(value) is not bool:
        raise OAuthPkceTranscriptError("Exact native stage completeness required")
    return value


def _binding(
    check_id: str,
    expected: str | None,
    observed: str | None,
    expected_complete: bool,
    observed_complete: bool,
    source_ids: list[str],
    *,
    required: bool = False,
) -> dict:
    if expected is not None and observed is not None:
        status = "matched" if expected == observed else "contradicted"
        reason = "exact_supplied_values_equal" if status == "matched" else "supplied_values_differ"
    elif required and (
        (expected is None and expected_complete) or (observed is None and observed_complete)
    ):
        status, reason = "contradicted", "required_value_declared_absent"
    elif expected is not None and observed is None and observed_complete:
        status, reason = "contradicted", "requested_value_declared_absent"
    else:
        status, reason = "unknown", "binding_evidence_unavailable"
    return {"check_id": check_id, "status": status, "reason": reason, "source_ids": source_ids}


def _checks(source: dict, budget: _Budget) -> list[dict]:
    authorization = source["authorization_request"]
    response = source["authorization_response"]
    token = source["token_request"]
    a = authorization["source_id"]
    r = response["source_id"]
    t = token["source_id"]
    callback_check = (
        _binding(
            "callback_redirect_binding",
            authorization["redirect_uri_sha256"],
            response["callback_redirect_uri_sha256"],
            authorization["complete"],
            response["complete"],
            [a, r],
        )
        if response["callback_redirect_target_declared"]
        and response["callback_redirect_uri_sha256"] is not None
        else {
            "check_id": "callback_redirect_binding",
            "status": "unknown",
            "reason": "normalized_callback_target_unavailable",
            "source_ids": [a, r],
        }
    )
    checks = [
        _binding(
            "client_id_binding",
            authorization["client_id"],
            token["client_id"],
            authorization["complete"],
            token["complete"],
            [a, t],
            required=True,
        ),
        _binding(
            "authorization_code_binding",
            response["code_sha256"],
            token["code_sha256"],
            response["complete"],
            token["complete"],
            [r, t],
            required=True,
        ),
        _binding(
            "state_binding",
            authorization["state_sha256"],
            response["state_sha256"],
            authorization["complete"],
            response["complete"],
            [a, r],
        ),
        callback_check,
        _binding(
            "token_redirect_binding",
            authorization["redirect_uri_sha256"],
            token["redirect_uri_sha256"],
            authorization["complete"],
            token["complete"],
            [a, t],
        ),
    ]
    verifier = token["code_verifier_sha256"]
    if verifier is None:
        pkce = _binding(
            "pkce_s256_digest_binding",
            authorization["code_challenge"],
            None,
            authorization["complete"],
            token["complete"],
            [a, t],
            required=True,
        )
    else:
        budget.charge(256)
        challenge = (
            base64.urlsafe_b64encode(bytes.fromhex(verifier[7:])).rstrip(b"=").decode("ascii")
        )
        pkce = _binding(
            "pkce_s256_digest_binding",
            authorization["code_challenge"],
            challenge,
            authorization["complete"],
            token["complete"],
            [a, t],
            required=True,
        )
    checks.append(pkce)
    return checks


@dataclass(slots=True)
class _Plan:
    document: dict
    size: int


def _plan(model: Any, budget: _Budget) -> _Plan:
    if type(model) is not dict:
        raise OAuthPkceTranscriptError("Exact native source model required")
    source, source_size, _ = _capture(model, budget)
    _exact(
        source,
        {
            "schema_version",
            "source_id",
            "authorization_request",
            "authorization_response",
            "token_request",
        },
        "source model",
    )
    if type(source["schema_version"]) is not int or source["schema_version"] != 1:
        raise OAuthPkceTranscriptError("Exact native schema version one required")
    _source_id(source["source_id"])
    authorization = _exact(
        source["authorization_request"],
        {
            "source_id",
            "complete",
            "response_type",
            "client_id",
            "redirect_uri_sha256",
            "state_sha256",
            "code_challenge_method",
            "code_challenge",
        },
        "authorization request",
    )
    response = _exact(
        source["authorization_response"],
        {
            "source_id",
            "complete",
            "callback_redirect_target_declared",
            "callback_redirect_uri_sha256",
            "state_sha256",
            "code_sha256",
        },
        "authorization response",
    )
    token = _exact(
        source["token_request"],
        {
            "source_id",
            "complete",
            "grant_type",
            "client_id",
            "redirect_uri_sha256",
            "code_sha256",
            "code_verifier_sha256",
        },
        "token request",
    )
    identifiers = [source["source_id"]]
    for stage in (authorization, response, token):
        identifiers.append(_source_id(stage["source_id"]))
        _completeness(stage["complete"])
    if len(set(identifiers)) != len(identifiers):
        raise OAuthPkceTranscriptError("Stage source identifiers must be distinct")
    if type(response["callback_redirect_target_declared"]) is not bool:
        raise OAuthPkceTranscriptError("Exact native callback target premise required")
    if authorization["response_type"] != "code" or type(authorization["response_type"]) is not str:
        raise OAuthPkceTranscriptError("Only authorization-code response type is supported")
    if token["grant_type"] != "authorization_code" or type(token["grant_type"]) is not str:
        raise OAuthPkceTranscriptError("Only authorization-code token grant is supported")
    if (
        type(authorization["code_challenge_method"]) is not str
        or authorization["code_challenge_method"] != "S256"
    ):
        raise OAuthPkceTranscriptError("Only explicit S256 PKCE is supported")
    _client_id(authorization["client_id"])
    _client_id(token["client_id"], optional=True)
    _challenge(authorization["code_challenge"])
    for stage, names in (
        (authorization, ("redirect_uri_sha256", "state_sha256")),
        (response, ("callback_redirect_uri_sha256", "state_sha256", "code_sha256")),
        (token, ("redirect_uri_sha256", "code_sha256", "code_verifier_sha256")),
    ):
        for name in names:
            _sha(stage[name], optional=True)

    checks = _checks(source, budget)
    if [item["check_id"] for item in checks] != list(_CHECK_IDS):
        raise OAuthPkceTranscriptError("Internal check order is invalid")
    statuses = {item["status"] for item in checks}
    status = (
        "contradicted"
        if "contradicted" in statuses
        else "unknown"
        if "unknown" in statuses
        else "consistent_with_supplied_bindings"
    )
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
        "checks": checks,
        "analysis_status": status,
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "bounds": dict(_BOUNDS),
        "limitations": list(_LIMITATIONS),
        "analysis_id": _ID_PLACEHOLDER,
        "analysis_sha256": _PLACEHOLDER,
    }
    document, size, nodes = _capture(document, budget, report=True)
    # One complete operation funds canonical source/body/report serialization,
    # both fixed-width digests, retained copies, equality and export before SHA.
    budget.charge(24 * size + 16 * source_size + 16 * nodes + len(DOMAIN) + len(MODEL_DOMAIN) + 256)
    return _Plan(document, size)


def _digest(domain: str, value: dict) -> str:
    payload = (domain + "\n" + _canonical(value)).encode("ascii")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _materialize(plan: _Plan) -> str:
    document = plan.document
    document["source_model_sha256"] = _digest(MODEL_DOMAIN, document["source_model"])
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = _digest(DOMAIN, body)
    document["analysis_id"] = "OAT-" + digest[7:39].upper()
    document["analysis_sha256"] = digest
    return _canonical(document)


def _report_plan(document: Any, budget: _Budget) -> tuple[dict, str, _Plan]:
    if type(document) is not dict:
        raise OAuthPkceTranscriptError("Exact native report object required")
    owned, size, nodes = _capture(document, budget, report=True)
    if "source_model" not in owned:
        raise OAuthPkceTranscriptError("Report requires complete original source model")
    expected = _plan(owned["source_model"], budget)
    for field in ("source_model_sha256", "analysis_sha256"):
        if type(owned.get(field)) is not str or _SHA.fullmatch(owned[field]) is None:
            raise OAuthPkceTranscriptError("Exact SHA256 report address required")
    if (
        type(owned.get("analysis_id")) is not str
        or owned["analysis_id"] != "OAT-" + owned["analysis_sha256"][7:39].upper()
    ):
        raise OAuthPkceTranscriptError("Exact report ID/address join required")
    budget.charge(16 * size + 8 * expected.size + 8 * nodes)
    return owned, _canonical(owned), expected


def _replay_text(text: Any, budget: _Budget) -> dict:
    document, canonical, plan = _report_plan(_decode(text, budget, report=True), budget)
    if text != canonical:
        raise OAuthPkceTranscriptError("Exact canonical retained report JSON required")
    if _materialize(plan) != canonical:
        raise OAuthPkceTranscriptError("Report does not replay its original source")
    return document


def _stored(report: Any) -> str:
    if type(report) is not OAuthPkceTranscriptAnalysis:
        raise OAuthPkceTranscriptError("Exact native report wrapper required")
    text = getattr(report, "document_json", None)
    if type(text) is not str:
        raise OAuthPkceTranscriptError("Exact native retained report text required")
    return text


def _owned(text: str) -> OAuthPkceTranscriptAnalysis:
    report = object.__new__(OAuthPkceTranscriptAnalysis)
    object.__setattr__(report, "document_json", text)
    return report


@dataclass(frozen=True, slots=True)
class OAuthPkceTranscriptAnalysis:
    """Detached unsigned result retaining only digest-based transcript sources."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not OAuthPkceTranscriptAnalysis:
            raise OAuthPkceTranscriptError("Exact native report family required")
        _replay_text(self.document_json, _Budget())

    @classmethod
    def from_dict(cls, document: Any) -> OAuthPkceTranscriptAnalysis:
        if cls is not OAuthPkceTranscriptAnalysis:
            raise OAuthPkceTranscriptError("Exact native report family required")
        budget = _Budget()
        _owned_document, text, plan = _report_plan(document, budget)
        if _materialize(plan) != text:
            raise OAuthPkceTranscriptError("Report does not replay its original source")
        return _owned(text)

    @classmethod
    def from_json(cls, document_json: Any) -> OAuthPkceTranscriptAnalysis:
        if cls is not OAuthPkceTranscriptAnalysis:
            raise OAuthPkceTranscriptError("Exact native report family required")
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


def analyze_supplied_oauth_pkce_transcript(model: Any) -> OAuthPkceTranscriptAnalysis:
    """Compare only the declared digest bindings of one synthetic code flow."""
    return _owned(_materialize(_plan(model, _Budget())))


def analyze_supplied_oauth_pkce_transcript_bytes(
    *, model_bytes: Any
) -> OAuthPkceTranscriptAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise OAuthPkceTranscriptError("Bounded exact native model JSON bytes required")
    budget = _Budget()
    budget.charge(2 * len(model_bytes))
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise OAuthPkceTranscriptError("ASCII source JSON bytes required") from exc
    return _owned(_materialize(_plan(_decode(text, budget), budget)))


def verify_supplied_oauth_pkce_transcript(
    report: Any, *, model: Any
) -> OAuthPkceTranscriptAnalysis:
    """Replay embedded and separately supplied originals under one work budget."""
    budget = _Budget()
    text = _stored(report)
    _document, canonical, embedded = _report_plan(_decode(text, budget, report=True), budget)
    original = _plan(model, budget)
    budget.charge(8 * (embedded.size + original.size))
    if text != canonical:
        raise OAuthPkceTranscriptError("Exact canonical retained report JSON required")
    expected = _materialize(embedded)
    separate = _materialize(original)
    if expected != text or expected != separate:
        raise OAuthPkceTranscriptError("Report differs from embedded or separately original source")
    return _owned(separate)


def component_fixture() -> dict:
    """Fresh digest-only synthetic success-path declarations, never raw secrets."""
    return {
        "schema_version": 1,
        "source_id": "synthetic-oauth-transcript",
        "authorization_request": {
            "source_id": "synthetic-authorization-request",
            "complete": True,
            "response_type": "code",
            "client_id": "client.invalid",
            "redirect_uri_sha256": "sha256:" + "1" * 64,
            "state_sha256": "sha256:" + "2" * 64,
            "code_challenge_method": "S256",
            "code_challenge": "A" * 43,
        },
        "authorization_response": {
            "source_id": "synthetic-authorization-response",
            "complete": True,
            "callback_redirect_target_declared": True,
            "callback_redirect_uri_sha256": "sha256:" + "1" * 64,
            "state_sha256": "sha256:" + "2" * 64,
            "code_sha256": "sha256:" + "3" * 64,
        },
        "token_request": {
            "source_id": "synthetic-token-request",
            "complete": True,
            "grant_type": "authorization_code",
            "client_id": "client.invalid",
            "redirect_uri_sha256": "sha256:" + "1" * 64,
            "code_sha256": "sha256:" + "3" * 64,
            "code_verifier_sha256": "sha256:" + "0" * 64,
        },
    }


__all__ = [
    "OAuthPkceTranscriptAnalysis",
    "OAuthPkceTranscriptError",
    "analyze_supplied_oauth_pkce_transcript",
    "analyze_supplied_oauth_pkce_transcript_bytes",
    "verify_supplied_oauth_pkce_transcript",
    "component_fixture",
]
