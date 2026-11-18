"""Finite supplied Linux DAC arithmetic, not effective filesystem access."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "linux_supplied_posix_acl_arithmetic"
PROFILE_ID = "AOE-GC-D12-S01"
CAPABILITY_ID = "host.linux.local-privilege-escalation"
VECTOR_ID = "AV-GC-D12-S01-01"
WAVE_ID = "IW2-001"
BLUEPRINT_SHA256 = "sha256:0eeeef8de9328721551f481082889213dbcca8240ad9ebd9ca679ba006415d8c"
DOMAIN = "sunderkey.offline-posix-acl-analysis.v1"
MODEL_DOMAIN = "sunderkey.offline-posix-acl-model.v1"
REQUEST_DOMAIN = "sunderkey.offline-posix-acl-request.v1"
MAX_DOCUMENT_BYTES = 65_536
MAX_NATIVE_NODES = 8192
MAX_NATIVE_DEPTH = 12
MAX_REPORT_BYTES = 1_048_576
MAX_REPORT_NODES = 32_768
MAX_REPORT_DEPTH = 16
MAX_STRING_BYTES = 256
MAX_ID = 4_294_967_294
MAX_SUPPLEMENTARY_GROUPS = 128
MAX_ACL_ENTRIES = 256
MAX_REQUESTS = 64
MAX_MATCHING_STEPS = 32_768
MAX_WITNESSES = 8192
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TAGS = ("user_obj", "user", "group_obj", "group", "mask", "other")
_DECISIONS = ("allowed_by_supplied_posix_dac", "not_allowed_by_supplied_posix_dac")
_FLAGS = {
    "offline_only": True,
    "source_authenticated": False,
    "filesystem_observed": False,
    "effective_access_proven": False,
    "live_use_approved": False,
    "qualification_claimed": False,
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
        "filesystem",
    )
}
_BOUNDS = {
    "maximum_document_bytes": MAX_DOCUMENT_BYTES,
    "maximum_native_nodes": MAX_NATIVE_NODES,
    "maximum_native_depth": MAX_NATIVE_DEPTH,
    "maximum_report_bytes": MAX_REPORT_BYTES,
    "maximum_report_nodes": MAX_REPORT_NODES,
    "maximum_report_depth": MAX_REPORT_DEPTH,
    "maximum_string_bytes": MAX_STRING_BYTES,
    "maximum_uid_gid": MAX_ID,
    "maximum_supplementary_groups": MAX_SUPPLEMENTARY_GROUPS,
    "maximum_acl_entries": MAX_ACL_ENTRIES,
    "maximum_requests": MAX_REQUESTS,
    "maximum_matching_steps": MAX_MATCHING_STEPS,
    "maximum_witnesses": MAX_WITNESSES,
}
_SEMANTICS = {
    "linux_version": "6.17",
    "source": "https://raw.githubusercontent.com/torvalds/linux/v6.17/fs/posix_acl.c",
    "manual": "https://man7.org/linux/man-pages/man5/acl.5.html",
    "implementation": "independent_mathematical_supplied_model",
    "identity_space": "declared_unsigned_32_bit_ids_without_invalid_sentinel",
    "mode_scope": "nine_discretionary_access_bits_only",
}
_LIMITATIONS = [
    "Source identities, mode, ACL and principal groups are unauthenticated declarations.",
    "The result is a supplied DAC projection, not an observed filesystem permission decision.",
    "Root and capability overrides, idmapped mounts and user namespace mappings are not modeled.",
    "MAC, parent traversal, sticky or special mode bits, creation "
    "and default ACLs are not modeled.",
    "NFSv4, remote filesystem semantics and actual kernel or filesystem execution are not modeled.",
    "Canonical parsed JSON provenance is not raw byte, filesystem acquisition "
    "or custody provenance.",
    "No source currentness, authority, live use, specialist completion or qualification is proved.",
]
_MODEL_FIELDS = {"schema_version", "object", "principal", "requests"}
_OBJECT_FIELDS = {"object_ref", "owner_uid", "owner_gid", "rwx_mode", "access_acl"}
_PRINCIPAL_FIELDS = {"principal_ref", "fsuid", "fsgid", "supplementary_gids"}
_ENTRY_FIELDS = {"tag", "qualifier", "permission_mask"}
_REQUEST_FIELDS = {"request_id", "requested_mask"}
_SELECTION_FIELDS = {
    "source",
    "selected_class",
    "mode_permission_mask",
    "mask_entry_index",
    "mask_permission_mask",
    "candidate_entries",
}
_CANDIDATE_FIELDS = {"entry_index", "permission_mask", "effective_permission_mask"}
_RESULT_FIELDS = {
    "request_id",
    "request_sha256",
    "requested_mask",
    "decision",
    "witness_entry_index",
    "reason",
}
_SUMMARY_FIELDS = {
    "request_count",
    "acl_entry_count",
    "candidate_count",
    "matching_steps",
    "witness_count",
    *_DECISIONS,
}
_REPORT_FIELDS = {
    "analysis_id",
    "analysis_sha256",
    "schema_version",
    "component_id",
    "profile_id",
    "capability_id",
    "vector_id",
    "wave_id",
    "blueprint_sha256",
    "source_model",
    "source_model_sha256",
    "selection",
    "request_results",
    "summary",
    "semantics",
    "bounds",
    "effects",
    "limitations",
    *_FLAGS,
}


class PosixAclAnalysisError(ValueError):
    """Closed native input, resource budget or exact source replay was rejected."""


def _own(value: Any, *, report: bool = False) -> Any:
    maximum_bytes = MAX_REPORT_BYTES if report else MAX_DOCUMENT_BYTES
    maximum_nodes = MAX_REPORT_NODES if report else MAX_NATIVE_NODES
    maximum_depth = MAX_REPORT_DEPTH if report else MAX_NATIVE_DEPTH
    nodes = size = 0
    active: set[int] = set()

    def charge(amount: int) -> None:
        nonlocal size
        size += amount
        if size > maximum_bytes:
            raise PosixAclAnalysisError("Canonical JSON exceeds its byte budget")

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        if nodes > maximum_nodes or depth > maximum_depth:
            raise PosixAclAnalysisError("Native JSON exceeds its node or depth budget")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES or any(not 32 <= ord(c) <= 126 for c in item):
                raise PosixAclAnalysisError("Text must be bounded printable ASCII")
            charge(2 + len(item) + item.count('"') + item.count("\\"))
            return item
        if kind is bool:
            charge(4 if item else 5)
            return item
        if item is None:
            charge(4)
            return None
        if kind is int:
            if item.bit_length() > 63:
                raise PosixAclAnalysisError("Integer exceeds its finite magnitude")
            charge(len(str(item)))
            return item
        if kind not in (dict, list):
            raise PosixAclAnalysisError("Only exact native JSON families are accepted")
        if id(item) in active:
            raise PosixAclAnalysisError("Cyclic inputs are refused")
        if len(item) > maximum_nodes - nodes:
            raise PosixAclAnalysisError("Collection exceeds the remaining node budget")
        charge(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
        active.add(id(item))
        try:
            if kind is list:
                return [visit(child, depth + 1) for child in item]
            result = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise PosixAclAnalysisError("Object keys must be exact native strings")
                result[visit(key, depth + 1)] = visit(child, depth + 1)
            return result
        finally:
            active.remove(id(item))

    return visit(value, 1)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _hash(domain: str, value: Any) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            domain.encode("ascii") + b"\n" + _canonical(value).encode("ascii")
        ).hexdigest()
    )


def _integer_token(token: str) -> bool:
    if _INTEGER.fullmatch(token) is None:
        return False
    magnitude = token[1:] if token.startswith("-") else token
    return len(magnitude) < 19 or magnitude <= "9223372036854775807"


def _decode(text: Any, *, report: bool = False) -> Any:
    maximum_bytes = MAX_REPORT_BYTES if report else MAX_DOCUMENT_BYTES
    maximum_nodes = MAX_REPORT_NODES if report else MAX_NATIVE_NODES
    maximum_depth = MAX_REPORT_DEPTH if report else MAX_NATIVE_DEPTH
    if type(text) is not str or not text or len(text) > maximum_bytes or not text.isascii():
        raise PosixAclAnalysisError("JSON requires bounded exact native ASCII text")
    depth = nodes = position = 0
    while position < len(text):
        char = text[position]
        if char == '"':
            if depth + 1 > maximum_depth:
                raise PosixAclAnalysisError("Raw JSON exceeds its scalar depth budget")
            position += 1
            nodes += 1
            length = 0
            closed = False
            while position < len(text):
                char = text[position]
                if char == '"':
                    position += 1
                    closed = True
                    break
                if char == "\\":
                    position += 1
                    if position >= len(text):
                        raise PosixAclAnalysisError("Incomplete JSON string escape")
                    escape = text[position]
                    if escape == "u":
                        digits = text[position + 1 : position + 5]
                        if len(digits) != 4 or any(
                            c not in "0123456789abcdefABCDEF" for c in digits
                        ):
                            raise PosixAclAnalysisError("Invalid JSON Unicode escape")
                        if not 32 <= int(digits, 16) <= 126:
                            raise PosixAclAnalysisError("JSON text is outside printable ASCII")
                        position += 5
                    elif escape in '\\"/':
                        position += 1
                    else:
                        raise PosixAclAnalysisError("Unsupported JSON string escape")
                else:
                    if not 32 <= ord(char) <= 126:
                        raise PosixAclAnalysisError("JSON text is outside printable ASCII")
                    position += 1
                length += 1
                if length > MAX_STRING_BYTES:
                    raise PosixAclAnalysisError("Raw JSON string exceeds its budget")
            if not closed:
                raise PosixAclAnalysisError("Incomplete JSON string")
        elif char in "[{":
            depth += 1
            nodes += 1
            position += 1
        elif char in "]}":
            depth -= 1
            position += 1
        elif char in " \t\r\n,:":
            position += 1
        else:
            if depth + 1 > maximum_depth:
                raise PosixAclAnalysisError("Raw JSON exceeds its scalar depth budget")
            start = position
            while position < len(text) and text[position] not in ' \t\r\n,:]}{["':
                position += 1
            token = text[start:position]
            nodes += 1
            if token not in {"true", "false", "null"} and not _integer_token(token):
                raise PosixAclAnalysisError("JSON number is outside the finite integer subset")
        if depth < 0 or depth > maximum_depth or nodes > maximum_nodes:
            raise PosixAclAnalysisError("Raw JSON exceeds its node or depth budget")
    if depth:
        raise PosixAclAnalysisError("Incomplete JSON structure")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in items:
            if key in result:
                raise PosixAclAnalysisError("Duplicate JSON object member")
            result[key] = value
        return result

    def integer(token: str) -> int:
        if not _integer_token(token):
            raise PosixAclAnalysisError("JSON integer exceeds its finite magnitude")
        return int(token)

    def unsupported(_: str) -> None:
        raise PosixAclAnalysisError("Floating or nonfinite JSON numbers are refused")

    try:
        decoded = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (json.JSONDecodeError, RecursionError, OverflowError) as exc:
        raise PosixAclAnalysisError("Malformed bounded JSON") from exc
    return _own(decoded, report=report)


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or len(value) != len(fields) or set(value) != fields:
        raise PosixAclAnalysisError(label + " requires its exact closed fields")
    return value


def _text(value: Any, label: str) -> str:
    if type(value) is not str or not value or not value.strip():
        raise PosixAclAnalysisError(label + " requires nonblank native text")
    return value


def _int(value: Any, maximum: int, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise PosixAclAnalysisError(label + " requires a bounded exact native integer")
    return value


def _list(value: Any, maximum: int, label: str, *, nonempty: bool = False) -> list[Any]:
    if type(value) is not list or len(value) > maximum or (nonempty and not value):
        raise PosixAclAnalysisError(label + " requires a bounded exact native list")
    return value


def _model(value: Any) -> dict[str, Any]:
    model = _exact(_own(value), _MODEL_FIELDS, "Model")
    _int(model["schema_version"], 1, "Schema", minimum=1)
    item = _exact(model["object"], _OBJECT_FIELDS, "Object")
    _text(item["object_ref"], "Object reference")
    _int(item["owner_uid"], MAX_ID, "Owner UID")
    _int(item["owner_gid"], MAX_ID, "Owner GID")
    mode = _int(item["rwx_mode"], 511, "Nine-bit mode")
    principal = _exact(model["principal"], _PRINCIPAL_FIELDS, "Principal")
    _text(principal["principal_ref"], "Principal reference")
    _int(principal["fsuid"], MAX_ID, "FSUID")
    _int(principal["fsgid"], MAX_ID, "FSGID")
    groups = _list(principal["supplementary_gids"], MAX_SUPPLEMENTARY_GROUPS, "Groups")
    for group in groups:
        _int(group, MAX_ID, "Supplementary GID")
    if len(set(groups)) != len(groups):
        raise PosixAclAnalysisError("Duplicate supplementary GIDs are refused")
    requests = _list(model["requests"], MAX_REQUESTS, "Requests", nonempty=True)
    request_ids = set()
    for request in requests:
        _exact(request, _REQUEST_FIELDS, "Request")
        identifier = _text(request["request_id"], "Request identity")
        if identifier in request_ids:
            raise PosixAclAnalysisError("Duplicate request identities are refused")
        request_ids.add(identifier)
        _int(request["requested_mask"], 7, "Requested mask", minimum=1)
    acl = item["access_acl"]
    if acl is None:
        return model
    _list(acl, MAX_ACL_ENTRIES, "Access ACL", nonempty=True)
    counts = {tag: 0 for tag in _TAGS}
    last_rank = -1
    last_qualifier = {"user": -1, "group": -1}
    unqualified = {}
    for entry in acl:
        _exact(entry, _ENTRY_FIELDS, "ACL entry")
        tag = entry["tag"]
        if type(tag) is not str or tag not in counts:
            raise PosixAclAnalysisError("Unsupported access ACL tag")
        rank = _TAGS.index(tag)
        if rank < last_rank:
            raise PosixAclAnalysisError("Access ACL tags require canonical order")
        last_rank = rank
        counts[tag] += 1
        _int(entry["permission_mask"], 7, "ACL permission mask")
        if tag in last_qualifier:
            qualifier = _int(entry["qualifier"], MAX_ID, "ACL qualifier")
            if qualifier <= last_qualifier[tag]:
                raise PosixAclAnalysisError("Named ACL qualifiers must be unique and increasing")
            last_qualifier[tag] = qualifier
        else:
            if entry["qualifier"] is not None or counts[tag] != 1:
                raise PosixAclAnalysisError(
                    "Unqualified ACL tags must be unique with null qualifier"
                )
            unqualified[tag] = entry["permission_mask"]
    if any(counts[tag] != 1 for tag in ("user_obj", "group_obj", "other")):
        raise PosixAclAnalysisError("Access ACL requires owner, owning group and other entries")
    if (counts["user"] or counts["group"]) and counts["mask"] != 1:
        raise PosixAclAnalysisError("Named ACL entries require exactly one mask")
    group_mode = unqualified.get("mask", unqualified["group_obj"])
    projected_mode = (unqualified["user_obj"] << 6) | (group_mode << 3) | unqualified["other"]
    if projected_mode != mode:
        raise PosixAclAnalysisError("Supplied mode and access ACL class bits disagree")
    return model


class _Work:
    def __init__(self) -> None:
        self.steps = 0

    def charge(self, count: int = 1) -> None:
        self.steps += count
        if self.steps > MAX_MATCHING_STEPS:
            raise PosixAclAnalysisError("Matching work exceeds its finite budget")


def _selection(model: dict[str, Any], work: _Work) -> dict[str, Any]:
    item, principal = model["object"], model["principal"]
    groups = {principal["fsgid"], *principal["supplementary_gids"]}
    acl = item["access_acl"]
    work.charge()
    if acl is None:
        if principal["fsuid"] == item["owner_uid"]:
            selected, shift = "owner", 6
        elif item["owner_gid"] in groups:
            selected, shift = "group", 3
        else:
            selected, shift = "other", 0
        return {
            "source": "rwx_mode",
            "selected_class": selected,
            "mode_permission_mask": (item["rwx_mode"] >> shift) & 7,
            "mask_entry_index": None,
            "mask_permission_mask": None,
            "candidate_entries": [],
        }
    candidates = []
    mask_index = None
    named_user = None
    owner_index = other_index = None
    matching_groups = []
    for index, entry in enumerate(acl):
        work.charge()
        tag = entry["tag"]
        if tag == "user_obj":
            owner_index = index
        elif tag == "user" and entry["qualifier"] == principal["fsuid"]:
            named_user = index
        elif tag == "group_obj" and item["owner_gid"] in groups:
            matching_groups.append(index)
        elif tag == "group" and entry["qualifier"] in groups:
            matching_groups.append(index)
        elif tag == "mask":
            mask_index = index
        elif tag == "other":
            other_index = index
    if principal["fsuid"] == item["owner_uid"]:
        selected, indexes = "owner", [owner_index]
    elif named_user is not None:
        selected, indexes = "named_user", [named_user]
    elif matching_groups:
        selected, indexes = "group", matching_groups
    else:
        selected, indexes = "other", [other_index]
    applied_mask_index = mask_index if selected in {"named_user", "group"} else None
    mask = 7 if applied_mask_index is None else acl[applied_mask_index]["permission_mask"]
    for index in indexes:
        permission = acl[index]["permission_mask"]
        candidates.append(
            {
                "entry_index": index,
                "permission_mask": permission,
                "effective_permission_mask": permission & mask,
            }
        )
    return {
        "source": "access_acl",
        "selected_class": selected,
        "mode_permission_mask": None,
        "mask_entry_index": applied_mask_index,
        "mask_permission_mask": None if applied_mask_index is None else mask,
        "candidate_entries": candidates,
    }


def _derive(value: Any) -> dict[str, Any]:
    model = _model(value)
    work = _Work()
    selection = _selection(model, work)
    results = []
    witness_count = len(selection["candidate_entries"])
    for request in sorted(model["requests"], key=lambda item: item["request_id"]):
        requested = request["requested_mask"]
        witness = None
        if selection["source"] == "rwx_mode":
            work.charge()
            allowed = (selection["mode_permission_mask"] & requested) == requested
        else:
            allowed = False
            for candidate in selection["candidate_entries"]:
                work.charge()
                if (candidate["effective_permission_mask"] & requested) == requested:
                    allowed = True
                    if witness is None:
                        witness = candidate["entry_index"]
            if witness is not None:
                witness_count += 1
        if witness_count > MAX_WITNESSES:
            raise PosixAclAnalysisError("Entry-reference witnesses exceed their finite budget")
        results.append(
            {
                "request_id": request["request_id"],
                "request_sha256": "sha256:" + "0" * 64,
                "requested_mask": requested,
                "decision": _DECISIONS[0] if allowed else _DECISIONS[1],
                "witness_entry_index": witness,
                "reason": "selected_class_satisfies_requested_mask"
                if allowed
                else "selected_class_lacks_requested_mask",
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "wave_id": WAVE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model": model,
        "source_model_sha256": "sha256:" + "0" * 64,
        "selection": selection,
        "request_results": results,
        "summary": {
            "request_count": len(results),
            "acl_entry_count": len(model["object"]["access_acl"] or []),
            "candidate_count": len(selection["candidate_entries"]),
            "matching_steps": work.steps,
            "witness_count": witness_count,
            **{
                decision: sum(row["decision"] == decision for row in results)
                for decision in _DECISIONS
            },
        },
        "semantics": _SEMANTICS,
        "bounds": _BOUNDS,
        "effects": _EFFECTS,
        "limitations": _LIMITATIONS,
        **_FLAGS,
    }
    # Prove the complete fixed-width address projection fits before any hashing.
    _own(
        {"analysis_id": "LPA-" + "0" * 32, "analysis_sha256": "sha256:" + "0" * 64, **body},
        report=True,
    )
    body["source_model_sha256"] = _hash(MODEL_DOMAIN, model)
    requests_by_id = {request["request_id"]: request for request in model["requests"]}
    for row in results:
        row["request_sha256"] = _hash(REQUEST_DOMAIN, requests_by_id[row["request_id"]])
    digest = _hash(DOMAIN, body)
    return _own(
        {"analysis_id": "LPA-" + digest[7:39].upper(), "analysis_sha256": digest, **body},
        report=True,
    )


def _digest(value: Any) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise PosixAclAnalysisError("Address requires its exact digest syntax")


def _report(value: Any) -> dict[str, Any]:
    document = _exact(_own(value, report=True), _REPORT_FIELDS, "Analysis")
    _int(document["schema_version"], 1, "Analysis schema", minimum=1)
    _digest(document["analysis_sha256"])
    _digest(document["source_model_sha256"])
    _text(document["analysis_id"], "Analysis identity")
    selection = _exact(document["selection"], _SELECTION_FIELDS, "Selection")
    for candidate in _list(selection["candidate_entries"], MAX_ACL_ENTRIES, "Candidates"):
        _exact(candidate, _CANDIDATE_FIELDS, "Candidate")
        _int(candidate["entry_index"], MAX_ACL_ENTRIES - 1, "Candidate index")
        _int(candidate["permission_mask"], 7, "Candidate permission")
        _int(candidate["effective_permission_mask"], 7, "Candidate effective permission")
    for name in ("mode_permission_mask", "mask_permission_mask"):
        if selection[name] is not None:
            _int(selection[name], 7, "Selection permission")
    if selection["mask_entry_index"] is not None:
        _int(selection["mask_entry_index"], MAX_ACL_ENTRIES - 1, "Mask index")
    rows = _list(document["request_results"], MAX_REQUESTS, "Results", nonempty=True)
    for row in rows:
        _exact(row, _RESULT_FIELDS, "Result")
        _text(row["request_id"], "Result request identity")
        _digest(row["request_sha256"])
        _int(row["requested_mask"], 7, "Result requested mask", minimum=1)
        if row["witness_entry_index"] is not None:
            _int(row["witness_entry_index"], MAX_ACL_ENTRIES - 1, "Witness index")
    summary = _exact(document["summary"], _SUMMARY_FIELDS, "Summary")
    for name in ("request_count", *_DECISIONS):
        _int(summary[name], MAX_REQUESTS, "Request counter")
    for name in ("acl_entry_count", "candidate_count"):
        _int(summary[name], MAX_ACL_ENTRIES, "Entry counter")
    _int(summary["matching_steps"], MAX_MATCHING_STEPS, "Work counter")
    _int(summary["witness_count"], MAX_WITNESSES, "Witness counter")
    for name, expected_flag in _FLAGS.items():
        if type(document[name]) is not bool or document[name] is not expected_flag:
            raise PosixAclAnalysisError("Analysis cannot change its qualification flags")
    if _canonical(document["effects"]) != _canonical(_EFFECTS):
        raise PosixAclAnalysisError("Analysis cannot introduce effects")
    expected = _derive(document["source_model"])
    if _canonical(document) != _canonical(expected):
        raise PosixAclAnalysisError("Analysis does not replay its exact supplied source")
    return document


@dataclass(frozen=True, slots=True)
class PosixAclAnalysis:
    document_json: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "document_json", _canonical(self._read()))

    def _read(self) -> dict[str, Any]:
        try:
            document = self.document_json
        except AttributeError as exc:
            raise PosixAclAnalysisError("Analysis wrapper is incomplete") from exc
        return _report(_decode(document, report=True))

    def to_dict(self) -> dict[str, Any]:
        return self._read()

    def to_json(self) -> str:
        return _canonical(self._read())

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> PosixAclAnalysis:
        return cls(_canonical(_report(document)))

    @classmethod
    def from_json(cls, document: str) -> PosixAclAnalysis:
        return cls(document)


def analyze_supplied_posix_acl(model: dict[str, Any]) -> PosixAclAnalysis:
    return PosixAclAnalysis(_canonical(_derive(model)))


def analyze_supplied_posix_acl_bytes(*, model_bytes: bytes) -> PosixAclAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_DOCUMENT_BYTES:
        raise PosixAclAnalysisError("Model requires bounded exact native bytes")
    if not model_bytes.isascii():
        raise PosixAclAnalysisError("Model bytes must use the ASCII JSON subset")
    return analyze_supplied_posix_acl(_decode(model_bytes.decode("ascii")))


def verify_supplied_posix_acl_analysis(
    report: PosixAclAnalysis | dict[str, Any], *, model: dict[str, Any]
) -> PosixAclAnalysis:
    if type(report) is PosixAclAnalysis:
        observed = report.to_dict()
    elif type(report) is dict:
        observed = _report(report)
    else:
        raise PosixAclAnalysisError("Analysis requires an exact supported native family")
    expected = _derive(model)
    if _canonical(observed) != _canonical(expected):
        raise PosixAclAnalysisError(
            "Analysis does not match the separately supplied original model"
        )
    return PosixAclAnalysis(_canonical(expected))


__all__ = [
    "PosixAclAnalysis",
    "PosixAclAnalysisError",
    "analyze_supplied_posix_acl",
    "analyze_supplied_posix_acl_bytes",
    "verify_supplied_posix_acl_analysis",
]
