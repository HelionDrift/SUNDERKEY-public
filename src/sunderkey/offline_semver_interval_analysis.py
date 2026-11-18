"""Bounded SemVer label precedence and explicit caller-declared interval arithmetic."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "javascript_supplied_semver_interval_arithmetic"
PROFILE_ID = "AOE-GC-D17-S04"
CAPABILITY_ID = "army.gc.d17.s04"
VECTOR_ID = "AV-GC-D17-S04-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D17-S04"
WAVE_ID = "IW2-016"
BLUEPRINT_SHA256 = "sha256:db4571f5aec671c800119f2dbb1b2b25442d818e3f3a76ae95fc3fa0f4203849"
SEMANTICS_PROFILE = "semver-2.0.0-explicit-order-intervals.v1"
DOMAIN = "sunderkey.offline-semver-interval-analysis.v1"
MODEL_DOMAIN = "sunderkey.offline-semver-interval-model.v1"
MAX_MODEL_BYTES = 1_048_576
MAX_REPORT_BYTES = 2_097_152
MAX_MODEL_NODES = 32_768
MAX_REPORT_NODES = 65_536
MAX_MODEL_DEPTH = 16
MAX_REPORT_DEPTH = 20
MAX_VERSIONS = 256
MAX_COMPARISONS = 256
MAX_INTERVALS = 128
MAX_MEMBERSHIPS = 512
MAX_VERSION_BYTES = 512
MAX_IDENTIFIER_BYTES = 64
MAX_VERSION_IDENTIFIERS = 64
MAX_WORK = 4_194_304
MAX_INTEGER = 2**63 - 1
MIN_INTEGER = -(2**63)
_PLACEHOLDER = "sha256:" + "0" * 64
_MODEL_FIELDS = {"schema_version", "versions", "comparisons", "intervals", "membership_queries"}
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "target",
        "execution",
        "network",
        "provider",
        "credential",
        "process",
        "routing",
        "qualification",
        "deployment",
        "publication",
    ),
    "none",
)
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "advisory_truth_verified",
        "vulnerability_verified",
        "package_availability_verified",
        "compatibility_verified",
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
    "versions": MAX_VERSIONS,
    "comparisons": MAX_COMPARISONS,
    "intervals": MAX_INTERVALS,
    "memberships": MAX_MEMBERSHIPS,
    "version_bytes": MAX_VERSION_BYTES,
    "identifier_bytes": MAX_IDENTIFIER_BYTES,
    "prerelease_and_build_identifiers": MAX_VERSION_IDENTIFIERS,
    "cumulative_work_per_public_operation": MAX_WORK,
}
_LIMITATIONS = (
    "Only supplied SemVer labels and explicitly declared precedence intervals are evaluated.",
    "Build metadata remains source identity but does not affect precedence.",
    "Intervals are caller declarations, not npm ranges or authenticated advisories.",
    "No npm resolution, fetching, package publication or availability is evaluated.",
    "Version labels do not prove API compatibility, immutable contents or vulnerability truth.",
    "No target, provider, credential, process or external callback is used.",
    "Finite software ceilings are narrower than the unbounded SemVer specification.",
    "No current authority, live use, full specialist completion or qualification follows.",
)


class SemverIntervalAnalysisError(ValueError):
    """Closed input, software cost or exact source-derived replay was rejected."""


@dataclass
class _Budget:
    work: int = 0

    def charge(self, amount: int) -> None:
        if amount > MAX_WORK - self.work:
            raise SemverIntervalAnalysisError("Cumulative operation work budget exceeded")
        self.work += amount


def _string_size(value: Any, budget: _Budget) -> int:
    if type(value) is not str or len(value) > MAX_VERSION_BYTES:
        raise SemverIntervalAnalysisError("Bounded exact native ASCII strings are required")
    budget.charge(len(value) + 2)
    size = len(value) + 2
    for char in value:
        if not 32 <= ord(char) <= 126:
            raise SemverIntervalAnalysisError("Printable ASCII strings are required")
        if char in '\\"':
            budget.charge(1)
            size += 1
    return size


def _capture(value: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int, int]:
    """Own repeated occurrences with bounded depth, escapes, nodes and allocation."""
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    depth_limit = MAX_REPORT_DEPTH if report else MAX_MODEL_DEPTH
    nodes = size = 0
    active: set[int] = set()

    def add_size(amount: int) -> None:
        nonlocal size
        if amount > byte_limit - size:
            raise SemverIntervalAnalysisError("Escaped native document byte budget exceeded")
        size += amount

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes
        budget.charge(1)
        nodes += 1
        if nodes > node_limit or depth > depth_limit:
            raise SemverIntervalAnalysisError("Native document node/depth budget exceeded")
        kind = type(item)
        if kind is str:
            add_size(_string_size(item, budget))
            return item
        if kind is int:
            if not MIN_INTEGER <= item <= MAX_INTEGER:
                raise SemverIntervalAnalysisError("Signed 64-bit native integers are required")
            budget.charge(20)
            add_size(len(str(item)))
            return item
        if kind is bool:
            amount = 4 if item else 5
            budget.charge(amount)
            add_size(amount)
            return item
        if item is None:
            budget.charge(4)
            add_size(4)
            return None
        if kind not in (dict, list):
            raise SemverIntervalAnalysisError(
                "Exact native integer-only JSON families are required"
            )
        if id(item) in active:
            raise SemverIntervalAnalysisError("Cyclic input is rejected")
        count = len(item)
        children = count * (2 if kind is dict else 1)
        if children > node_limit - nodes:
            raise SemverIntervalAnalysisError("Collection exceeds remaining native node budget")
        punctuation = 2 + max(0, count - 1) + (count if kind is dict else 0)
        budget.charge(punctuation)
        add_size(punctuation)
        active.add(id(item))
        try:
            if kind is list:
                return [visit(child, depth + 1) for child in item]
            owned = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise SemverIntervalAnalysisError("Exact native string keys are required")
                owned[visit(key, depth + 1)] = visit(child, depth + 1)
            return owned
        finally:
            active.remove(id(item))

    return visit(value, 1), size, nodes


def _canonical(owned: Any) -> str:
    return json.dumps(owned, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _integer(text: str) -> int:
    negative = text.startswith("-")
    digits = text[1:] if negative else text
    if (
        not digits
        or len(digits) > 19
        or any(not "0" <= char <= "9" for char in digits)
        or (len(digits) > 1 and digits[0] == "0")
    ):
        raise SemverIntervalAnalysisError("Bounded JSON integer grammar is required")
    limit = "9223372036854775808" if negative else "9223372036854775807"
    if len(digits) == 19 and digits > limit:
        raise SemverIntervalAnalysisError("Signed 64-bit raw integer budget exceeded")
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
                raise SemverIntervalAnalysisError("Incomplete JSON escape")
            escape = text[index]
            if escape == "u":
                digits = text[index + 1 : index + 5]
                if len(digits) != 4 or any(c not in "0123456789abcdefABCDEF" for c in digits):
                    raise SemverIntervalAnalysisError("Malformed Unicode escape")
                if not 32 <= int(digits, 16) <= 126:
                    raise SemverIntervalAnalysisError("Raw strings exceed the ASCII subset")
                index += 4
            elif escape not in '\\"/':
                raise SemverIntervalAnalysisError("Raw strings exceed the printable subset")
        elif not 32 <= ord(char) <= 126:
            raise SemverIntervalAnalysisError("Invalid raw ASCII string")
        count += 1
        if count > MAX_VERSION_BYTES:
            raise SemverIntervalAnalysisError("Raw string budget exceeded")
        index += 1
    raise SemverIntervalAnalysisError("Unterminated JSON string")


def _decode(text: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int]:
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    depth_limit = MAX_REPORT_DEPTH if report else MAX_MODEL_DEPTH
    if type(text) is not str or not text or len(text) > byte_limit or not text.isascii():
        raise SemverIntervalAnalysisError("Bounded exact native ASCII JSON text is required")
    budget.charge(len(text))
    index = nodes = 0
    stack = []
    while index < len(text):
        char = text[index]
        if char in " \t\r\n,:":
            index += 1
            continue
        if char in "]}":
            if not stack or stack.pop() != ("[" if char == "]" else "{"):
                raise SemverIntervalAnalysisError("Malformed raw JSON container")
            index += 1
            continue
        nodes += 1
        if nodes > node_limit or len(stack) + 1 > depth_limit:
            raise SemverIntervalAnalysisError("Raw JSON node/depth budget exceeded")
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
                    raise SemverIntervalAnalysisError("Raw integer lexical budget exceeded")
            token = text[start:index]
            if token not in ("true", "false", "null"):
                _integer(token)
    if stack:
        raise SemverIntervalAnalysisError("Unterminated JSON container")

    def pairs(rows: list[tuple[str, Any]]) -> dict:
        owned = {}
        for key, child in rows:
            if key in owned:
                raise SemverIntervalAnalysisError("Duplicate JSON member")
            owned[key] = child
        return owned

    try:
        decoded = json.loads(text, object_pairs_hook=pairs, parse_int=_integer)
    except (ValueError, RecursionError, OverflowError) as exc:
        raise SemverIntervalAnalysisError("Invalid bounded JSON document") from exc
    owned, size, _ = _capture(decoded, budget, report=report)
    return owned, size


def _fields(value: Any, required: set[str], label: str) -> dict:
    if type(value) is not dict or value.keys() != required:
        raise SemverIntervalAnalysisError(f"{label} requires its exact closed fields")
    return value


def _id(value: Any) -> str:
    if type(value) is not str or not 1 <= len(value) <= MAX_IDENTIFIER_BYTES:
        raise SemverIntervalAnalysisError("Bounded native record identifiers are required")
    if (
        not value[0].isascii()
        or not value[0].isalnum()
        or any(
            not ("0" <= char <= "9" or "A" <= char <= "Z" or "a" <= char <= "z" or char in "_.-")
            for char in value
        )
    ):
        raise SemverIntervalAnalysisError("Record identifiers exceed the closed ASCII grammar")
    return value


def _rows(value: Any, maximum: int, label: str) -> list:
    if type(value) is not list or len(value) > maximum:
        raise SemverIntervalAnalysisError(f"{label} exceeds its finite exact native array")
    return value


def _bound(value: Any) -> None:
    if value is None:
        return
    _fields(value, {"version", "inclusive"}, "Interval bound")
    if type(value["version"]) is not str or type(value["inclusive"]) is not bool:
        raise SemverIntervalAnalysisError("Bounds require native version text and a native boolean")


def _validate_model(model: dict, budget: _Budget) -> dict[str, str]:
    _fields(model, _MODEL_FIELDS, "Model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise SemverIntervalAnalysisError("Native schema version 1 is required")
    versions = _rows(model["versions"], MAX_VERSIONS, "Versions")
    comparisons = _rows(model["comparisons"], MAX_COMPARISONS, "Comparisons")
    intervals = _rows(model["intervals"], MAX_INTERVALS, "Intervals")
    queries = _rows(model["membership_queries"], MAX_MEMBERSHIPS, "Membership queries")
    budget.charge(4 * (len(versions) + len(comparisons) + len(intervals) + len(queries)))
    version_map = {}
    interval_ids = set()
    for row in versions:
        _fields(row, {"version_id", "version"}, "Version")
        identifier = _id(row["version_id"])
        if identifier in version_map or type(row["version"]) is not str:
            raise SemverIntervalAnalysisError("Version IDs must be unique and version text native")
        version_map[identifier] = row["version"]
    comparison_ids = set()
    for row in comparisons:
        _fields(row, {"comparison_id", "left_version_id", "right_version_id"}, "Comparison")
        identifier = _id(row["comparison_id"])
        if identifier in comparison_ids:
            raise SemverIntervalAnalysisError("Comparison IDs must be unique")
        comparison_ids.add(identifier)
        for key in ("left_version_id", "right_version_id"):
            if _id(row[key]) not in version_map:
                raise SemverIntervalAnalysisError("Comparison names an absent version ID")
    for row in intervals:
        _fields(row, {"interval_id", "lower", "upper"}, "Interval")
        identifier = _id(row["interval_id"])
        if identifier in interval_ids:
            raise SemverIntervalAnalysisError("Interval IDs must be unique")
        interval_ids.add(identifier)
        _bound(row["lower"])
        _bound(row["upper"])
    query_ids = set()
    for row in queries:
        _fields(row, {"query_id", "version_id", "interval_id"}, "Membership query")
        identifier = _id(row["query_id"])
        if identifier in query_ids:
            raise SemverIntervalAnalysisError("Membership query IDs must be unique")
        query_ids.add(identifier)
        if _id(row["version_id"]) not in version_map or _id(row["interval_id"]) not in interval_ids:
            raise SemverIntervalAnalysisError("Membership query has an absent typed source ID")
    return version_map


@dataclass(frozen=True, slots=True)
class _Version:
    core: tuple[str, str, str]
    prerelease: tuple[tuple[str, bool], ...]
    build: tuple[str, ...]


def _parse(version: str, budget: _Budget) -> _Version:
    if not version or len(version) > MAX_VERSION_BYTES:
        raise SemverIntervalAnalysisError("Version label exceeds the finite syntax subset")
    budget.charge(4 * len(version) + 8)
    if version.count("+") > 1:
        raise SemverIntervalAnalysisError("SemVer has at most one build separator")
    main, plus, build_text = version.partition("+")
    core_text, hyphen, prerelease_text = main.partition("-")
    if (plus and not build_text) or (hyphen and not prerelease_text):
        raise SemverIntervalAnalysisError("SemVer identifiers cannot be empty")
    if core_text.count(".") != 2:
        raise SemverIntervalAnalysisError("SemVer requires three exact numeric core components")
    prerelease_count = prerelease_text.count(".") + 1 if hyphen else 0
    build_count = build_text.count(".") + 1 if plus else 0
    if prerelease_count + build_count > MAX_VERSION_IDENTIFIERS:
        raise SemverIntervalAnalysisError("Version identifier-count software limit exceeded")
    budget.charge(3 + prerelease_count + build_count)
    core = tuple(core_text.split("."))
    for number in core:
        if (
            not number
            or any(not "0" <= char <= "9" for char in number)
            or (len(number) > 1 and number[0] == "0")
        ):
            raise SemverIntervalAnalysisError("Core numbers require digits without leading zeroes")

    def identifiers(text: str, present: bool) -> tuple[str, ...]:
        if not present:
            return ()
        result = tuple(text.split("."))
        for item in result:
            if not item or any(
                not ("0" <= char <= "9" or "A" <= char <= "Z" or "a" <= char <= "z" or char == "-")
                for char in item
            ):
                raise SemverIntervalAnalysisError(
                    "SemVer identifiers require ASCII alphanumerics/hyphens"
                )
        return result

    prerelease = []
    for item in identifiers(prerelease_text, bool(hyphen)):
        numeric = all("0" <= char <= "9" for char in item)
        if numeric and len(item) > 1 and item[0] == "0":
            raise SemverIntervalAnalysisError(
                "Numeric prerelease identifiers cannot have leading zeroes"
            )
        prerelease.append((item, numeric))
    return _Version(core, tuple(prerelease), identifiers(build_text, bool(plus)))


def _decimal(left: str, right: str) -> int:
    if len(left) != len(right):
        return -1 if len(left) < len(right) else 1
    return (left > right) - (left < right)


def _compare(left: _Version, right: _Version, budget: _Budget) -> int:
    for a, b in zip(left.core, right.core, strict=True):
        budget.charge(len(a) + len(b) + 1)
        relation = _decimal(a, b)
        if relation:
            return relation
    if not left.prerelease or not right.prerelease:
        return (not left.prerelease) - (not right.prerelease)
    for (a, a_numeric), (b, b_numeric) in zip(left.prerelease, right.prerelease, strict=False):
        budget.charge(len(a) + len(b) + 2)
        if a_numeric != b_numeric:
            return -1 if a_numeric else 1
        relation = _decimal(a, b) if a_numeric else (a > b) - (a < b)
        if relation:
            return relation
    budget.charge(1)
    return (len(left.prerelease) > len(right.prerelease)) - (
        len(left.prerelease) < len(right.prerelease)
    )


class _Output:
    def __init__(self, body: dict, budget: _Budget) -> None:
        self.budget = budget
        _, self.size, self.nodes = _capture(body, budget, report=True)

    def append(self, target: list, record: dict) -> None:
        owned, size, nodes = _capture(record, self.budget, report=True)
        if size + 1 > MAX_REPORT_BYTES - self.size or nodes > MAX_REPORT_NODES - self.nodes:
            raise SemverIntervalAnalysisError("Cumulative retained result budget exceeded")
        self.size += size + 1
        self.nodes += nodes
        target.append(owned)


def _derive(model: Any, budget: _Budget) -> tuple[dict, str]:
    source, model_size, _ = _capture(model, budget)
    _validate_model(source, budget)
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_id": "AOE-GC-D17-CMD",
        "group_owner_id": "AOE-HQ-05",
        "independent_validator_id": "AOE-HQ-19",
        "blueprint_sha256": BLUEPRINT_SHA256,
        "roadmap_package_ids": ["A7.4"],
        "semantics_profile": SEMANTICS_PROFILE,
        "input_provenance": "caller_supplied_unverified",
        "source_model": source,
        "source_model_sha256": _PLACEHOLDER,
        "parsed_versions": [],
        "comparisons": [],
        "intervals": [],
        "memberships": [],
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "bounds": dict(_BOUNDS),
        "limitations": list(_LIMITATIONS),
        "analysis_id": "SVA-" + "0" * 32,
        "analysis_sha256": _PLACEHOLDER,
    }
    output = _Output(body, budget)
    cache: dict[str, _Version] = {}

    def parsed(text: str) -> _Version:
        budget.charge(len(text) + 1)
        if text not in cache:
            cache[text] = _parse(text, budget)
        return cache[text]

    compiled = {}
    for row in source["versions"]:
        value = parsed(row["version"])
        compiled[row["version_id"]] = value
        budget.charge(8 + 3 * len(value.prerelease) + len(value.build))
        output.append(
            body["parsed_versions"],
            {
                **row,
                "core": dict(zip(("major", "minor", "patch"), value.core, strict=True)),
                "prerelease": [
                    {"identifier": text, "numeric": numeric} for text, numeric in value.prerelease
                ],
                "build_metadata": list(value.build),
            },
        )
    for row in source["comparisons"]:
        relation = _compare(
            compiled[row["left_version_id"]], compiled[row["right_version_id"]], budget
        )
        output.append(
            body["comparisons"],
            {
                **row,
                "relation": ("less" if relation < 0 else "greater" if relation > 0 else "equal"),
                "precedence_equal": relation == 0,
            },
        )
    compiled_intervals = {}
    for row in source["intervals"]:
        lower = parsed(row["lower"]["version"]) if row["lower"] is not None else None
        upper = parsed(row["upper"]["version"]) if row["upper"] is not None else None
        relation = (
            _compare(lower, upper, budget) if lower is not None and upper is not None else None
        )
        if relation is not None and relation > 0:
            raise SemverIntervalAnalysisError("Declared interval lower bound exceeds upper bound")
        empty = relation == 0 and not (row["lower"]["inclusive"] and row["upper"]["inclusive"])
        compiled_intervals[row["interval_id"]] = (lower, upper, row["lower"], row["upper"], empty)
        output.append(body["intervals"], {**row, "empty": empty})
    for row in source["membership_queries"]:
        lower, upper, lower_source, upper_source, empty = compiled_intervals[row["interval_id"]]
        value = compiled[row["version_id"]]
        lower_relation = _compare(value, lower, budget) if lower is not None else None
        upper_relation = _compare(value, upper, budget) if upper is not None else None
        lower_pass = (
            lower_relation is None
            or lower_relation > 0
            or (lower_relation == 0 and lower_source["inclusive"])
        )
        upper_pass = (
            upper_relation is None
            or upper_relation < 0
            or (upper_relation == 0 and upper_source["inclusive"])
        )
        output.append(
            body["memberships"],
            {
                **row,
                "membership": "inside" if lower_pass and upper_pass and not empty else "outside",
                "lower_check": "unbounded"
                if lower is None
                else "passes"
                if lower_pass
                else "fails",
                "upper_check": "unbounded"
                if upper is None
                else "passes"
                if upper_pass
                else "fails",
                "interval_empty": empty,
            },
        )
    # The complete result, address preimages and final export are all reserved
    # before the first digest. Fixed-width placeholders preserve exact sizes.
    owned, report_size, _ = _capture(body, budget, report=True)
    budget.charge(len(owned))
    addressed = {
        key: value for key, value in owned.items() if key not in {"analysis_id", "analysis_sha256"}
    }
    addressed, addressed_size, _ = _capture(addressed, budget, report=True)
    model_preimage_size = len(MODEL_DOMAIN) + 1 + model_size
    analysis_preimage_size = len(DOMAIN) + 1 + addressed_size
    budget.charge(model_size + addressed_size + report_size)
    budget.charge(2 * (model_preimage_size + analysis_preimage_size))
    model_json = _canonical(source)
    model_digest = (
        "sha256:"
        + hashlib.sha256(
            MODEL_DOMAIN.encode("ascii") + b"\n" + model_json.encode("ascii")
        ).hexdigest()
    )
    addressed["source_model_sha256"] = model_digest
    analysis_json = _canonical(addressed)
    digest = (
        "sha256:"
        + hashlib.sha256(DOMAIN.encode("ascii") + b"\n" + analysis_json.encode("ascii")).hexdigest()
    )
    owned["source_model_sha256"] = model_digest
    owned["analysis_id"] = "SVA-" + digest[7:39].upper()
    owned["analysis_sha256"] = digest
    text = _canonical(owned)
    if len(text) != report_size:
        raise SemverIntervalAnalysisError(
            "Fixed-width report serialization differs from its reservation"
        )
    return owned, text


def _replay_owned(document: Any, size: int, budget: _Budget) -> tuple[dict, str]:
    if type(document) is not dict or "source_model" not in document:
        raise SemverIntervalAnalysisError("A source-bearing exact report is required")
    # Prepay both the supplied canonical write and the exact equality scan.
    budget.charge(2 * size)
    supplied = _canonical(document)
    expected, text = _derive(document["source_model"], budget)
    if supplied != text:
        raise SemverIntervalAnalysisError(
            "Report differs from full embedded-source semantic replay"
        )
    return expected, text


def _freeze(text: str) -> SemverIntervalAnalysis:
    result = object.__new__(SemverIntervalAnalysis)
    object.__setattr__(result, "_document_json", text)
    return result


@dataclass(frozen=True, slots=True, init=False)
class SemverIntervalAnalysis:
    """Owned unsigned arithmetic, not an advisory, compatibility proof or grant."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(self) is not SemverIntervalAnalysis:
            raise SemverIntervalAnalysisError("The exact native report family is required")
        budget = _Budget()
        owned, size, _ = _capture(document, budget, report=True)
        _, text = _replay_owned(owned, size, budget)
        object.__setattr__(self, "_document_json", text)

    @classmethod
    def from_dict(cls, document: Any) -> SemverIntervalAnalysis:
        if cls is not SemverIntervalAnalysis:
            raise SemverIntervalAnalysisError("The exact native report family is required")
        return cls(document)

    @classmethod
    def from_json(cls, document_json: Any) -> SemverIntervalAnalysis:
        if cls is not SemverIntervalAnalysis:
            raise SemverIntervalAnalysisError("The exact native report family is required")
        budget = _Budget()
        document, size = _decode(document_json, budget, report=True)
        _, text = _replay_owned(document, size, budget)
        return _freeze(text)

    def to_dict(self) -> dict:
        return _capture_report(self, _Budget())[0]

    def to_json(self) -> str:
        return _capture_report(self, _Budget())[1]

    @property
    def analysis_id(self) -> str:
        return self.to_dict()["analysis_id"]

    @property
    def analysis_sha256(self) -> str:
        return self.to_dict()["analysis_sha256"]


def _capture_report(report: Any, budget: _Budget) -> tuple[dict, str]:
    if type(report) is not SemverIntervalAnalysis:
        raise SemverIntervalAnalysisError("The exact native report family is required")
    document, size = _decode(getattr(report, "_document_json", None), budget, report=True)
    return _replay_owned(document, size, budget)


def analyze_supplied_semver_intervals(model: Any) -> SemverIntervalAnalysis:
    """Evaluate only the supplied labels and explicitly declared order intervals."""
    _, text = _derive(model, _Budget())
    return _freeze(text)


def analyze_supplied_semver_intervals_bytes(*, model_bytes: Any) -> SemverIntervalAnalysis:
    """Consume local native ASCII JSON bytes without resolving any package."""
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise SemverIntervalAnalysisError("Bounded exact native model bytes are required")
    budget = _Budget()
    budget.charge(len(model_bytes))
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SemverIntervalAnalysisError("Model bytes exceed the ASCII software subset") from exc
    source, _ = _decode(text, budget)
    _, result = _derive(source, budget)
    return _freeze(result)


def verify_supplied_semver_interval_analysis(report: Any, *, model: Any) -> SemverIntervalAnalysis:
    """Reconstruct separately supplied originals without authenticating labels or bounds."""
    budget = _Budget()
    _, supplied = _capture_report(report, budget)
    budget.charge(len(supplied))
    _, expected = _derive(model, budget)
    if supplied != expected:
        raise SemverIntervalAnalysisError(
            "Report is not bound to the separately supplied original model"
        )
    return _freeze(expected)


def component_fixture() -> dict[str, Any]:
    """Return fresh declared labels and intervals, not package or advisory evidence."""
    return {
        "schema_version": 1,
        "versions": [
            {"version_id": "beta2", "version": "1.0.0-beta.2"},
            {"version_id": "beta11", "version": "1.0.0-beta.11"},
            {"version_id": "linux", "version": "1.0.0+linux"},
            {"version_id": "windows", "version": "1.0.0+windows"},
        ],
        "comparisons": [
            {
                "comparison_id": "numeric-prerelease",
                "left_version_id": "beta2",
                "right_version_id": "beta11",
            },
            {
                "comparison_id": "release-higher",
                "left_version_id": "beta11",
                "right_version_id": "linux",
            },
            {
                "comparison_id": "build-equal",
                "left_version_id": "linux",
                "right_version_id": "windows",
            },
        ],
        "intervals": [
            {
                "interval_id": "prerelease-window",
                "lower": {"version": "1.0.0-beta.2", "inclusive": True},
                "upper": {"version": "1.0.0", "inclusive": False},
            },
            {
                "interval_id": "stable-class",
                "lower": {"version": "1.0.0+left", "inclusive": True},
                "upper": {"version": "1.0.0+right", "inclusive": True},
            },
        ],
        "membership_queries": [
            {"query_id": "beta-inside", "version_id": "beta11", "interval_id": "prerelease-window"},
            {
                "query_id": "stable-outside",
                "version_id": "linux",
                "interval_id": "prerelease-window",
            },
            {"query_id": "build-inside", "version_id": "windows", "interval_id": "stable-class"},
        ],
    }


__all__ = [
    "SemverIntervalAnalysis",
    "SemverIntervalAnalysisError",
    "analyze_supplied_semver_intervals",
    "analyze_supplied_semver_intervals_bytes",
    "verify_supplied_semver_interval_analysis",
    "component_fixture",
]
