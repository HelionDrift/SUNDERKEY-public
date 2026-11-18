"""Bounded supplied iOS entitlement allowlist arithmetic, without signing or I/O."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "ios_supplied_entitlement_declaration_consistency"
PROFILE_ID = "AOE-GB-D08-S07"
CAPABILITY_ID = "army.gb.d08.s07"
VECTOR_ID = "AV-GB-D08-S07-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D08-S07"
WAVE_ID = "IW2-011"
COMMANDER_ID = "AOE-GB-D08-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:4c60c70e0dc5c482d661650a82790226acf8b54b540db5cdde766a8ea19a04e6"
DOMAIN = "sunderkey.offline-ios-entitlement-analysis.v1"
MODEL_DOMAIN = "sunderkey.offline-ios-entitlement-model.v1"
SEMANTICS_PROFILE = "apple-tn3125-tn2415-supplied-three-entitlement-allowlist.v1"
MAX_MODEL_BYTES = 262_144
MAX_REPORT_BYTES = 1_048_576
MAX_MODEL_NODES = 8192
MAX_REPORT_NODES = 32_768
MAX_MODEL_DEPTH = 16
MAX_REPORT_DEPTH = 20
MAX_STRING_BYTES = 512
MAX_ENTITLEMENT_VALUE_BYTES = 256
MAX_ENTITLEMENT_KEYS = 64
MAX_KEYCHAIN_GROUPS = 64
MAX_WORK = 8_388_608
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1
APPLICATION_IDENTIFIER = "application-identifier"
TEAM_IDENTIFIER = "com.apple.developer.team-identifier"
KEYCHAIN_GROUPS = "keychain-access-groups"
_KEYS = {APPLICATION_IDENTIFIER, TEAM_IDENTIFIER, KEYCHAIN_GROUPS}
_FIELDS = {
    "schema_version",
    "application_entitlements",
    "profile_entitlements",
    "coverage",
    "unmodeled_application_entitlement_keys",
    "unmodeled_profile_entitlement_keys",
}
_IDENTIFIER_PART = re.compile(r"[A-Za-z0-9-]+\Z")
_TEAM = re.compile(r"[A-Za-z0-9]{10}\Z")
_ENTITLEMENT_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_PLACEHOLDER = "sha256:" + "0" * 64
_ID_PLACEHOLDER = "IEA-" + "0" * 32
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "code_signing",
        "credential",
        "execution",
        "installation",
        "keychain",
        "network",
        "process",
        "provider",
        "publication",
        "qualification",
        "target",
    ),
    "none",
)
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "cms_or_der_verified",
        "signature_verified",
        "profile_currentness_verified",
        "complete_entitlement_semantics_verified",
        "entitlement_authorization_proven",
        "installation_approved",
        "keychain_access_proven",
        "live_use_approved",
        "qualification_claimed",
    ),
    False,
)
_BOUNDS = {
    "model_bytes": MAX_MODEL_BYTES,
    "report_bytes": MAX_REPORT_BYTES,
    "model_nodes": MAX_MODEL_NODES,
    "report_nodes": MAX_REPORT_NODES,
    "model_depth": MAX_MODEL_DEPTH,
    "report_depth": MAX_REPORT_DEPTH,
    "string_bytes": MAX_STRING_BYTES,
    "entitlement_value_bytes": MAX_ENTITLEMENT_VALUE_BYTES,
    "entitlement_keys_per_map_or_unmodeled_list": MAX_ENTITLEMENT_KEYS,
    "keychain_groups_per_side": MAX_KEYCHAIN_GROUPS,
    "cumulative_work_per_public_operation": MAX_WORK,
}
_LIMITATIONS = (
    "All maps, completeness and unmodeled keys are unauthenticated caller declarations.",
    "Only application-identifier, team-identifier and keychain-access-groups are projected.",
    "Profile grants are an allowlist; unused grants are not contradictions.",
    "Only literal grants or a single final dotted-component wildcard are supported.",
    "Application claims must be concrete; App ID prefix and Team ID are not equated.",
    "No default keychain group or common-prefix constraint is synthesized.",
    "Incomplete or unmodeled declarations withhold comprehensive subset consistency.",
    "Modern DER truth, CMS, certificates, signatures and plist/IPA/MachO are not inspected.",
    "Profile lifetime, devices, distribution, installation and effective access are unassessed.",
    "Source addresses bind canonical declarations, not original bytes or acquisition.",
    "This record contains supplied identifiers and is not sanitized for publication.",
    "No signing, runtime, credentials, current authority or qualification is established.",
)


class IosEntitlementAnalysisError(ValueError):
    """The exact supplied software subset, resource bound or replay was rejected."""


@dataclass(slots=True)
class _Budget:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount > MAX_WORK - self.used:
            raise IosEntitlementAnalysisError("Cumulative operation work budget exceeded")
        self.used += amount


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _capture(value: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int, int]:
    """Charge native occurrences, structural bytes and escapes before retaining copies."""
    size = nodes = 0
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    depth_limit = MAX_REPORT_DEPTH if report else MAX_MODEL_DEPTH
    active: set[int] = set()

    def bytes_used(amount: int) -> None:
        nonlocal size
        if amount > byte_limit - size:
            raise IosEntitlementAnalysisError("Escaped document byte budget exceeded")
        budget.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes
        budget.charge(1)
        nodes += 1
        if nodes > node_limit or depth > depth_limit:
            raise IosEntitlementAnalysisError("Native node/depth budget exceeded")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES:
                raise IosEntitlementAnalysisError("Native string budget exceeded")
            bytes_used(len(item) + 2)
            for char in item:
                if not 32 <= ord(char) <= 126:
                    raise IosEntitlementAnalysisError("Printable ASCII strings required")
                if char in '\\"':
                    bytes_used(1)
            return item
        if kind is bool:
            bytes_used(4 if item else 5)
            return item
        if item is None:
            bytes_used(4)
            return None
        if kind is int:
            if item.bit_length() > 64 or not MIN_INTEGER <= item <= MAX_INTEGER:
                raise IosEntitlementAnalysisError("Signed 64-bit native integers required")
            budget.charge(20)
            bytes_used(len(str(item)))
            return item
        if kind not in (dict, list):
            raise IosEntitlementAnalysisError("Exact native integer-only JSON families required")
        if id(item) in active:
            raise IosEntitlementAnalysisError("Cyclic native input")
        count = len(item)
        children = count * (2 if kind is dict else 1)
        if children > node_limit - nodes:
            raise IosEntitlementAnalysisError("Collection exceeds remaining node budget")
        bytes_used(2 + max(0, count - 1) + (count if kind is dict else 0))
        active.add(id(item))
        try:
            if kind is list:
                return [visit(child, depth + 1) for child in item]
            owned = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise IosEntitlementAnalysisError("Exact native string object keys required")
                owned[visit(key, depth + 1)] = visit(child, depth + 1)
            return owned
        finally:
            active.remove(id(item))

    return visit(value, 1), size, nodes


def _integer(text: str) -> int:
    negative = text.startswith("-")
    digits = text[1:] if negative else text
    if (
        not digits
        or len(digits) > 19
        or any(not "0" <= char <= "9" for char in digits)
        or (len(digits) > 1 and digits[0] == "0")
    ):
        raise IosEntitlementAnalysisError("Bounded raw integer grammar required")
    limit = "9223372036854775808" if negative else "9223372036854775807"
    if len(digits) == 19 and digits > limit:
        raise IosEntitlementAnalysisError("Raw signed 64-bit integer budget exceeded")
    return int(text)


def _raw_string(text: str, start: int) -> int:
    index = start + 1
    count = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            return index + 1
        if char == "\\":
            index += 1
            if index >= len(text):
                raise IosEntitlementAnalysisError("Incomplete JSON escape")
            escape = text[index]
            if escape == "u":
                digits = text[index + 1 : index + 5]
                if len(digits) != 4 or any(c not in "0123456789abcdefABCDEF" for c in digits):
                    raise IosEntitlementAnalysisError("Malformed Unicode escape")
                if not 32 <= int(digits, 16) <= 126:
                    raise IosEntitlementAnalysisError("Raw strings exceed printable ASCII")
                index += 4
            elif escape not in '\\"/':
                raise IosEntitlementAnalysisError("Unsupported JSON string escape")
        elif not 32 <= ord(char) <= 126:
            raise IosEntitlementAnalysisError("Raw strings exceed printable ASCII")
        count += 1
        if count > MAX_STRING_BYTES:
            raise IosEntitlementAnalysisError("Raw string budget exceeded")
        index += 1
    raise IosEntitlementAnalysisError("Unterminated JSON string")


def _decode(text: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int, int]:
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    depth_limit = MAX_REPORT_DEPTH if report else MAX_MODEL_DEPTH
    if type(text) is not str or not text or len(text) > byte_limit:
        raise IosEntitlementAnalysisError("Bounded exact native ASCII JSON required")
    budget.charge(len(text))
    if not text.isascii():
        raise IosEntitlementAnalysisError("Exact native ASCII JSON required")
    stack: list[str] = []
    index = nodes = 0
    while index < len(text):
        char = text[index]
        if char in " \t\r\n,:":
            index += 1
            continue
        if char in "]}":
            if not stack or stack.pop() != ("[" if char == "]" else "{"):
                raise IosEntitlementAnalysisError("Malformed raw JSON containers")
            index += 1
            continue
        nodes += 1
        if nodes > node_limit or len(stack) + 1 > depth_limit:
            raise IosEntitlementAnalysisError("Pre-decoder node/depth budget exceeded")
        if char in "[{":
            stack.append(char)
            index += 1
        elif char == '"':
            index = _raw_string(text, index)
        else:
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}{["':
                index += 1
                if index - start > 20:
                    raise IosEntitlementAnalysisError("Raw scalar lexical budget exceeded")
            token = text[start:index]
            if token not in ("true", "false", "null"):
                _integer(token)
    if stack:
        raise IosEntitlementAnalysisError("Unterminated raw JSON containers")

    def pairs(rows: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, child in rows:
            if key in result:
                raise IosEntitlementAnalysisError("Duplicate JSON member")
            result[key] = child
        return result

    try:
        decoded = json.loads(text, object_pairs_hook=pairs, parse_int=_integer)
    except (ValueError, RecursionError, OverflowError) as exc:
        raise IosEntitlementAnalysisError("Invalid bounded JSON") from exc
    return _capture(decoded, budget, report=report)


def _fields(value: Any, fields: set[str], label: str) -> dict:
    if type(value) is not dict or value.keys() != fields:
        raise IosEntitlementAnalysisError(f"{label} requires exact closed fields")
    return value


def _identifier(value: Any, *, wildcard: bool = False, app_id: bool = False) -> str:
    if type(value) is not str or not 1 <= len(value) <= MAX_ENTITLEMENT_VALUE_BYTES:
        raise IosEntitlementAnalysisError("Bounded exact native entitlement text required")
    pattern = wildcard and value.endswith(".*")
    base = value[:-2] if pattern else value
    if "*" in base or "?" in base:
        raise IosEntitlementAnalysisError("Only a final dotted profile wildcard is supported")
    parts = base.split(".")
    if any(_IDENTIFIER_PART.fullmatch(part) is None for part in parts):
        raise IosEntitlementAnalysisError("Closed dotted ASCII entitlement syntax required")
    if app_id and (_TEAM.fullmatch(parts[0]) is None or (len(parts) < 2 and not pattern)):
        raise IosEntitlementAnalysisError(
            "Application identifier requires App ID prefix and suffix"
        )
    return value


def _map(value: Any, *, profile: bool, budget: _Budget) -> dict:
    if type(value) is not dict or len(value) > MAX_ENTITLEMENT_KEYS or value.keys() - _KEYS:
        raise IosEntitlementAnalysisError("Exact supported entitlement map required")
    for key, declared in value.items():
        budget.charge(1)
        if key == TEAM_IDENTIFIER:
            if type(declared) is not str or _TEAM.fullmatch(declared) is None:
                raise IosEntitlementAnalysisError("Literal ten-character Team ID required")
        elif key == APPLICATION_IDENTIFIER:
            _identifier(declared, wildcard=profile, app_id=True)
        else:
            if type(declared) is not list or len(declared) > MAX_KEYCHAIN_GROUPS:
                raise IosEntitlementAnalysisError(
                    "Bounded exact native keychain group array required"
                )
            seen = set()
            for item in declared:
                budget.charge(1)
                _identifier(item, wildcard=profile)
                if item in seen:
                    raise IosEntitlementAnalysisError("Duplicate keychain group declaration")
                seen.add(item)
    return value


def _unmodeled(value: Any, budget: _Budget) -> list:
    if type(value) is not list or len(value) > MAX_ENTITLEMENT_KEYS:
        raise IosEntitlementAnalysisError("Bounded exact unmodeled entitlement key array required")
    seen = set()
    for item in value:
        budget.charge(1)
        if type(item) is not str or _ENTITLEMENT_KEY.fullmatch(item) is None:
            raise IosEntitlementAnalysisError("Closed unmodeled entitlement key syntax required")
        if item in _KEYS or item in seen:
            raise IosEntitlementAnalysisError(
                "Distinct unmodeled keys must not shadow projected keys"
            )
        seen.add(item)
    return value


def _validate(model: Any, budget: _Budget) -> None:
    _fields(model, _FIELDS, "Model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise IosEntitlementAnalysisError("Exact native schema version 1 required")
    _map(model["application_entitlements"], profile=False, budget=budget)
    _map(model["profile_entitlements"], profile=True, budget=budget)
    coverage = _fields(
        model["coverage"],
        {"application_entitlements_complete", "profile_entitlements_complete"},
        "Coverage",
    )
    for value in coverage.values():
        if type(value) is not bool:
            raise IosEntitlementAnalysisError("Exact native completeness booleans required")
    _unmodeled(model["unmodeled_application_entitlement_keys"], budget)
    _unmodeled(model["unmodeled_profile_entitlement_keys"], budget)


@dataclass(slots=True)
class _Retained:
    size: int
    nodes: int
    budget: _Budget

    def row(self, value: dict) -> dict:
        owned, size, nodes = _capture(value, self.budget, report=True)
        if size + 1 > MAX_REPORT_BYTES - self.size or nodes > MAX_REPORT_NODES - self.nodes:
            raise IosEntitlementAnalysisError("Cumulative retained report budget exceeded")
        self.size += size + 1
        self.nodes += nodes
        return owned


def _logic(model: dict, size: int, nodes: int, budget: _Budget) -> dict:
    app = model["application_entitlements"]
    profile = model["profile_entitlements"]
    retained = _Retained(size, nodes, budget)
    observations: list[dict] = []
    uncertainties: list[dict] = []
    unmodeled: list[dict] = []
    matched = mismatched = unavailable = grants = 0
    for key, complete in sorted(model["coverage"].items()):
        if not complete:
            uncertainties.append(
                retained.row({"code": "entitlement_projection_incomplete", "source_path": key})
            )
    for side in ("application", "profile"):
        for key in sorted(model[f"unmodeled_{side}_entitlement_keys"]):
            budget.charge(1)
            unmodeled.append(retained.row({"side": side, "entitlement_key": key}))
    if unmodeled:
        uncertainties.append(
            retained.row({"code": "unmodeled_entitlement_semantics", "source_path": "unmodeled"})
        )
    for key, values in profile.items():
        budget.charge(1)
        grants += len(values) if key == KEYCHAIN_GROUPS else 1
    for key, values in sorted(app.items()):
        claims = sorted(values) if key == KEYCHAIN_GROUPS else [values]
        candidates = profile.get(key, [] if key == KEYCHAIN_GROUPS else None)
        candidates = (
            candidates
            if key == KEYCHAIN_GROUPS
            else ([candidates] if candidates is not None else [])
        )
        for claim in claims:
            matches = []
            for grant in candidates:
                budget.charge(1 + len(claim) + len(grant))
                if grant == claim or (
                    key != TEAM_IDENTIFIER and grant.endswith(".*") and claim.startswith(grant[:-1])
                ):
                    matches.append(grant)
            if matches:
                outcome = "matched_profile_allowlist"
                matched += 1
            elif model["coverage"]["profile_entitlements_complete"]:
                outcome = "not_in_profile_allowlist"
                mismatched += 1
            else:
                outcome = "profile_allowlist_unavailable"
                unavailable += 1
            observations.append(
                retained.row(
                    {
                        "entitlement_key": key,
                        "claim_value": claim,
                        "outcome": outcome,
                        "matched_profile_grants": sorted(matches),
                    }
                )
            )
    budget.charge(4 * (len(observations) + len(unmodeled) + len(uncertainties)))
    status = (
        "inconclusive"
        if uncertainties
        else ("inconsistent_supplied_subset" if mismatched else "consistent_supplied_subset")
    )
    return {
        "summary": {
            "status": status,
            "application_claim_count": len(observations),
            "profile_grant_count": grants,
            "matched_claim_count": matched,
            "mismatched_claim_count": mismatched,
            "unavailable_claim_count": unavailable,
        },
        "entitlement_observations": observations,
        "unmodeled_entitlements": unmodeled,
        "uncertainties": uncertainties,
    }


def _digest(domain: str, value: dict) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            domain.encode("ascii") + b"\n" + _canonical(value).encode("ascii")
        ).hexdigest()
    )


@dataclass(slots=True)
class _Plan:
    document: dict
    size: int


def _plan(model: Any, budget: _Budget) -> _Plan:
    owned, size, nodes = _capture(model, budget)
    _validate(owned, budget)
    logic = _logic(owned, size, nodes, budget)
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
        "source_model": owned,
        "source_model_sha256": _PLACEHOLDER,
        "analysis_id": _ID_PLACEHOLDER,
        "analysis_sha256": _PLACEHOLDER,
        "flags": _FLAGS,
        "effects": _EFFECTS,
        "bounds": _BOUNDS,
        "limitations": list(_LIMITATIONS),
        **logic,
    }
    document, report_size, _ = _capture(document, budget, report=True)
    # Source hash, result hash and full final serialization are funded before any digest.
    budget.charge(4 * report_size + 2 * size + len(DOMAIN) + len(MODEL_DOMAIN) + 2)
    return _Plan(document, report_size)


def _materialize(plan: _Plan) -> str:
    document = plan.document
    document["source_model_sha256"] = _digest(MODEL_DOMAIN, document["source_model"])
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = _digest(DOMAIN, body)
    document["analysis_sha256"] = digest
    document["analysis_id"] = "IEA-" + digest[7:39].upper()
    return _canonical(document)


def _replay_plan(text: Any, budget: _Budget) -> tuple[dict, _Plan, int]:
    document, size, _ = _decode(text, budget, report=True)
    if type(document) is not dict or "source_model" not in document:
        raise IosEntitlementAnalysisError("Report requires its complete embedded source model")
    plan = _plan(document["source_model"], budget)
    budget.charge(2 * size + plan.size)
    return document, plan, size


def _compare_replay(text: str, document: dict, expected: str) -> None:
    actual = _canonical(document)
    if actual != expected or text != actual:
        raise IosEntitlementAnalysisError("Canonical report does not replay its embedded source")


def _replay(text: Any, budget: _Budget) -> dict:
    document, plan, _ = _replay_plan(text, budget)
    _compare_replay(text, document, _materialize(plan))
    return document


@dataclass(frozen=True, slots=True)
class IosEntitlementAnalysis:
    """Detached supplied arithmetic, not an authenticated profile or entitlement grant."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not IosEntitlementAnalysis:
            raise IosEntitlementAnalysisError("Exact native report family required")
        _replay(self.document_json, _Budget())

    @classmethod
    def from_dict(cls, document: Any) -> IosEntitlementAnalysis:
        if cls is not IosEntitlementAnalysis:
            raise IosEntitlementAnalysisError("Exact native report family required")
        budget = _Budget()
        owned, size, _ = _capture(document, budget, report=True)
        budget.charge(size)
        text = _canonical(owned)
        _replay(text, budget)
        return _owned(text)

    @classmethod
    def from_json(cls, document_json: Any) -> IosEntitlementAnalysis:
        if cls is not IosEntitlementAnalysis:
            raise IosEntitlementAnalysisError("Exact native report family required")
        _replay(document_json, _Budget())
        return _owned(document_json)

    def to_dict(self) -> dict:
        if type(self) is not IosEntitlementAnalysis or not hasattr(self, "document_json"):
            raise IosEntitlementAnalysisError("Exact complete report wrapper required")
        return _replay(self.document_json, _Budget())

    def to_json(self) -> str:
        self.to_dict()
        return self.document_json


def _owned(text: str) -> IosEntitlementAnalysis:
    result = object.__new__(IosEntitlementAnalysis)
    object.__setattr__(result, "document_json", text)
    return result


def analyze_supplied_ios_entitlements(model: Any) -> IosEntitlementAnalysis:
    """Compare exact owned declarations without trusting signatures or profile provenance."""
    return _owned(_materialize(_plan(model, _Budget())))


def analyze_supplied_ios_entitlements_bytes(*, model_bytes: Any) -> IosEntitlementAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise IosEntitlementAnalysisError("Bounded exact native model bytes required")
    budget = _Budget()
    budget.charge(len(model_bytes))
    if not model_bytes.isascii():
        raise IosEntitlementAnalysisError("ASCII JSON subset required")
    model, _, _ = _decode(model_bytes.decode("ascii"), budget)
    return _owned(_materialize(_plan(model, budget)))


def verify_supplied_ios_entitlement_analysis(report: Any, *, model: Any) -> IosEntitlementAnalysis:
    if type(report) is not IosEntitlementAnalysis or not hasattr(report, "document_json"):
        raise IosEntitlementAnalysisError("Exact complete report wrapper required")
    budget = _Budget()
    actual, embedded, size = _replay_plan(report.document_json, budget)
    original = _plan(model, budget)
    budget.charge(size + original.size)
    expected = _materialize(embedded)
    original_expected = _materialize(original)
    _compare_replay(report.document_json, actual, expected)
    if _canonical(actual) != original_expected:
        raise IosEntitlementAnalysisError(
            "Report does not match separately supplied original model"
        )
    return _owned(original_expected)


def component_fixture() -> dict:
    """Fresh synthetic decoded declarations, not an acquired or authenticated app/profile."""
    return {
        "schema_version": 1,
        "application_entitlements": {
            APPLICATION_IDENTIFIER: "APPID00001.com.example.reader",
            TEAM_IDENTIFIER: "TEAMID0001",
            KEYCHAIN_GROUPS: ["APPID00001.com.example.shared", "com.apple.token"],
        },
        "profile_entitlements": {
            APPLICATION_IDENTIFIER: "APPID00001.com.example.*",
            TEAM_IDENTIFIER: "TEAMID0001",
            KEYCHAIN_GROUPS: ["APPID00001.*", "com.apple.token", "OTHER00001.unused"],
        },
        "coverage": {
            "application_entitlements_complete": True,
            "profile_entitlements_complete": True,
        },
        "unmodeled_application_entitlement_keys": [],
        "unmodeled_profile_entitlement_keys": [],
    }
