"""Bounded offline lifecycle consistency projection for supplied directory snapshots."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

PROFILE_ID = "AOE-GA-D03-S15"
CAPABILITY_ID = "army.ga.d03.s15"
VECTOR_ID = "AV-GA-D03-S15-01"
DOMAIN = "sunderkey.offline-scim-lifecycle.v1"
ANALYSIS_PROFILE = "supplied-user-group-deprovision-consistency.v1"
MAX_MODEL_BYTES = 131_072
MAX_REPORT_BYTES = 524_288
MAX_DEPTH = 24
MAX_NODES = 32_768
MAX_USERS = 256
MAX_GROUPS = 128
MAX_MEMBERS_PER_GROUP = 256
MAX_MEMBERSHIPS = 4_096
MAX_OPERATIONS = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_KINDS = frozenset(("disable_user", "delete_user", "remove_membership"))
_EFFECTS = {
    "authority": "none",
    "credential_resolution": "none",
    "execution": "none",
    "network": "none",
    "target_interaction": "none",
    "finding_publication": "none",
    "qualification": "none",
}


class ScimLifecycleError(ValueError):
    """Invalid, unsupported, or over-budget supplied lifecycle evidence."""


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys or any(type(key) is not str for key in value):
        raise ScimLifecycleError(f"{label} must have exact native fields")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ScimLifecycleError(f"{label} must be a bounded opaque identifier")
    return value


def _canonical(value: Any, *, maximum: int) -> str:
    stack = [(value, 1)]
    nodes = size = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise ScimLifecycleError("Native node or depth limit exceeded")
        kind = type(item)
        if kind is dict:
            if nodes + len(stack) + 2 * len(item) > MAX_NODES:
                raise ScimLifecycleError("Native node limit exceeded")
            size += 2 + len(item)
            for key, child in item.items():
                if type(key) is not str:
                    raise ScimLifecycleError("Native mapping keys must be strings")
                stack.append((child, depth + 1))
                stack.append((key, depth + 1))
        elif kind is list:
            if nodes + len(stack) + len(item) > MAX_NODES:
                raise ScimLifecycleError("Native node limit exceeded")
            size += 2 + len(item)
            stack.extend((child, depth + 1) for child in item)
        elif kind is str:
            try:
                encoded = item.encode("utf-8")
            except UnicodeError as exc:
                raise ScimLifecycleError("Invalid Unicode scalar text") from exc
            if len(encoded) > MAX_MODEL_BYTES:
                raise ScimLifecycleError("Native string exceeds bound")
            size += 2 + 12 * len(item)
        elif kind is int:
            if item.bit_length() > 63:
                raise ScimLifecycleError("Native integer exceeds 64 bits")
            size += len(str(item))
        elif kind is bool:
            size += 5
        elif item is None:
            size += 4
        else:
            raise ScimLifecycleError("Unsupported native primitive")
        if size > 12 * maximum:
            raise ScimLifecycleError("Native serialized size limit exceeded")
    result = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(result) > maximum:
        raise ScimLifecycleError("Canonical byte limit exceeded")
    return result


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise ScimLifecycleError("JSON duplicate key rejected")
        result[key] = value
    return result


def _json_integer(text: str) -> int:
    if len(text.lstrip("-")) > 19:
        raise ScimLifecycleError("JSON integer exceeds bound")
    result = int(text)
    if result.bit_length() > 63:
        raise ScimLifecycleError("JSON integer exceeds bound")
    return result


def _unsupported_number(_text: str) -> None:
    raise ScimLifecycleError("JSON float or nonfinite number is unsupported")


def _decode(text: Any, label: str, maximum: int) -> Any:
    if type(text) is not str or not text:
        raise ScimLifecycleError(f"{label} must be nonempty native JSON text")
    try:
        length = len(text.encode("utf-8"))
    except UnicodeError as exc:
        raise ScimLifecycleError(f"{label} contains invalid Unicode") from exc
    if length > maximum:
        raise ScimLifecycleError(f"{label} exceeds byte limit")
    depth = 0
    quoted = escaped = False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise ScimLifecycleError("JSON depth limit exceeded")
        elif character in "]}":
            depth -= 1
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_json_integer,
            parse_float=_unsupported_number,
            parse_constant=_unsupported_number,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, ScimLifecycleError):
            raise
        raise ScimLifecycleError(f"{label} is malformed JSON") from exc
    _canonical(value, maximum=maximum)
    return value


def _sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("ascii")).hexdigest()


def _snapshot(value: Any, label: str) -> tuple[str, dict[str, bool], dict[str, set[str]]]:
    snapshot = _exact(value, {"source_id", "users", "groups"}, label)
    source_id = _identifier(snapshot["source_id"], f"{label} source_id")
    users = snapshot["users"]
    groups = snapshot["groups"]
    if type(users) is not list or len(users) > MAX_USERS:
        raise ScimLifecycleError("Users must be a bounded list")
    if type(groups) is not list or len(groups) > MAX_GROUPS:
        raise ScimLifecycleError("Groups must be a bounded list")
    user_map: dict[str, bool] = {}
    group_map: dict[str, set[str]] = {}
    for raw in users:
        user = _exact(raw, {"user_id", "active"}, "user")
        user_id = _identifier(user["user_id"], "user_id")
        if user_id in user_map or type(user["active"]) is not bool:
            raise ScimLifecycleError("Duplicate user or invalid active flag")
        user_map[user_id] = user["active"]
    memberships = 0
    for raw in groups:
        group = _exact(raw, {"group_id", "members"}, "group")
        group_id = _identifier(group["group_id"], "group_id")
        if group_id in group_map:
            raise ScimLifecycleError("Duplicate group identity")
        members = group["members"]
        if type(members) is not list or len(members) > MAX_MEMBERS_PER_GROUP:
            raise ScimLifecycleError("Group members must be a bounded list")
        member_ids: set[str] = set()
        for raw_member in members:
            member = _identifier(raw_member, "member user_id")
            if member in member_ids:
                raise ScimLifecycleError("Duplicate group member identity")
            member_ids.add(member)
        memberships += len(member_ids)
        if memberships > MAX_MEMBERSHIPS:
            raise ScimLifecycleError("Membership limit exceeded")
        group_map[group_id] = member_ids
    return source_id, user_map, group_map


def _operations(value: Any) -> tuple[str, list[dict[str, Any]]]:
    record = _exact(value, {"source_id", "operations"}, "deprovision record")
    source_id = _identifier(record["source_id"], "deprovision source_id")
    operations = record["operations"]
    if type(operations) is not list or len(operations) > MAX_OPERATIONS:
        raise ScimLifecycleError("Operations must be a bounded list")
    ids = set()
    identities = set()
    for raw in operations:
        operation = _exact(raw, {"operation_id", "kind", "user_id", "group_id"}, "operation")
        operation_id = _identifier(operation["operation_id"], "operation_id")
        kind = operation["kind"]
        if type(kind) is not str or kind not in _KINDS:
            raise ScimLifecycleError("Unsupported deprovision operation")
        user_id = _identifier(operation["user_id"], "operation user_id")
        group_id = operation["group_id"]
        if kind == "remove_membership":
            _identifier(group_id, "operation group_id")
        elif group_id is not None:
            raise ScimLifecycleError("User operation must not name a group")
        identity = (kind, user_id, group_id)
        if operation_id in ids or identity in identities:
            raise ScimLifecycleError("Duplicate operation identity")
        ids.add(operation_id)
        identities.add(identity)
    return source_id, operations


def _model(
    value: Any,
) -> tuple[
    str,
    str,
    dict[str, bool],
    dict[str, set[str]],
    str,
    dict[str, bool],
    dict[str, set[str]],
    str,
    list[dict[str, Any]],
    bool,
]:
    model = _exact(
        value,
        {
            "schema_version",
            "source_id",
            "directory_kind",
            "snapshots_complete",
            "before",
            "after",
            "deprovision",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ScimLifecycleError("Unsupported schema version")
    source_id = _identifier(model["source_id"], "model source_id")
    if type(model["directory_kind"]) is not str or model["directory_kind"] not in {"ldap", "scim"}:
        raise ScimLifecycleError("Unsupported directory kind")
    complete = model["snapshots_complete"]
    if type(complete) is not bool:
        raise ScimLifecycleError("Snapshot completeness must be a native boolean")
    before_id, before_users, before_groups = _snapshot(model["before"], "before")
    after_id, after_users, after_groups = _snapshot(model["after"], "after")
    deprovision_id, operations = _operations(model["deprovision"])
    if len({source_id, before_id, after_id, deprovision_id}) != 4:
        raise ScimLifecycleError("Source identifiers must be distinct")
    return (
        source_id,
        before_id,
        before_users,
        before_groups,
        after_id,
        after_users,
        after_groups,
        deprovision_id,
        operations,
        complete,
    )


def _before_present(
    operation: dict[str, Any], users: dict[str, bool], groups: dict[str, set[str]]
) -> bool:
    user_id = operation["user_id"]
    if operation["kind"] == "remove_membership":
        return user_id in groups.get(operation["group_id"], set())
    return user_id in users


def _after_unreflected(
    operation: dict[str, Any], users: dict[str, bool], groups: dict[str, set[str]]
) -> bool:
    user_id = operation["user_id"]
    kind = operation["kind"]
    if kind == "disable_user":
        return users.get(user_id) is True
    if kind == "delete_user":
        return user_id in users
    return user_id in groups.get(operation["group_id"], set())


def _projection(model: Any) -> dict[str, Any]:
    model_text = _canonical(model, maximum=MAX_MODEL_BYTES)
    (
        source_id,
        before_id,
        before_users,
        before_groups,
        after_id,
        after_users,
        after_groups,
        deprovision_id,
        operations,
        complete,
    ) = _model(model)
    orphan_candidates = []
    unknowns = []
    for group_id in sorted(after_groups):
        for user_id in sorted(after_groups[group_id] - after_users.keys()):
            row = {"group_id": group_id, "user_id": user_id}
            if complete:
                orphan_candidates.append(row)
            else:
                unknowns.append(
                    {
                        "kind": "orphan_membership",
                        "group_id": group_id,
                        "user_id": user_id,
                        "reason": "after_user_set_incomplete",
                    }
                )
    outcomes = []
    unreflected = []
    for operation in operations:
        operation_id = operation["operation_id"]
        if not complete:
            disposition = "unknown"
            unknowns.append(
                {
                    "kind": "deprovision_operation",
                    "operation_id": operation_id,
                    "reason": "snapshots_incomplete",
                }
            )
        elif not _before_present(operation, before_users, before_groups):
            disposition = "not_present_in_before_snapshot"
        elif _after_unreflected(operation, after_users, after_groups):
            disposition = "unreflected_candidate"
            unreflected.append(
                {
                    "operation_id": operation_id,
                    "kind": operation["kind"],
                    "user_id": operation["user_id"],
                    "group_id": operation["group_id"],
                }
            )
        else:
            disposition = "no_unreflected_indicator"
        outcomes.append({"operation_id": operation_id, "disposition": disposition})
    if not complete and not unknowns:
        unknowns.append({"kind": "snapshot_scope", "reason": "snapshots_incomplete"})
    report = {
        "schema_version": 1,
        "analysis_profile": ANALYSIS_PROFILE,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "source": {
            "source_id": source_id,
            "model_sha256": _sha(model_text),
            "before": {
                "source_id": before_id,
                "sha256": _sha(_canonical(model["before"], maximum=MAX_MODEL_BYTES)),
            },
            "after": {
                "source_id": after_id,
                "sha256": _sha(_canonical(model["after"], maximum=MAX_MODEL_BYTES)),
            },
            "deprovision": {
                "source_id": deprovision_id,
                "sha256": _sha(_canonical(model["deprovision"], maximum=MAX_MODEL_BYTES)),
            },
        },
        "supplied_model": model,
        "analysis_status": (
            "complete_snapshot_projection" if complete else "unknown_incomplete_snapshots"
        ),
        "orphan_membership_candidates": orphan_candidates,
        "unreflected_deprovision_candidates": unreflected,
        "operation_outcomes": outcomes,
        "unknowns": unknowns,
        "uncertainty": [
            "Snapshot completeness and source identity are caller declarations, "
            "not verified facts.",
            "Opaque IDs are compared exactly without LDAP DN or SCIM filter normalization.",
            "Candidates describe supplied snapshot inconsistency, not provider execution.",
            "No effective access, token invalidation, or revocation outcome is established.",
        ],
        "offline_only": True,
        "provider_behavior_verified": False,
        "effective_access_revoked": None,
        "effects": dict(_EFFECTS),
    }
    digest = hashlib.sha256(
        _canonical({"domain": DOMAIN, "report": report}, maximum=MAX_REPORT_BYTES).encode("ascii")
    ).hexdigest()
    report["report_id"] = "SLC-" + digest[:32].upper()
    report["report_sha256"] = "sha256:" + digest
    _canonical(report, maximum=MAX_REPORT_BYTES)
    return report


_REPORT_FIELDS = {
    "schema_version",
    "analysis_profile",
    "profile_id",
    "capability_id",
    "vector_id",
    "source",
    "supplied_model",
    "analysis_status",
    "orphan_membership_candidates",
    "unreflected_deprovision_candidates",
    "operation_outcomes",
    "unknowns",
    "uncertainty",
    "offline_only",
    "provider_behavior_verified",
    "effective_access_revoked",
    "effects",
    "report_id",
    "report_sha256",
}


def _replay(document: Any) -> str:
    _exact(document, _REPORT_FIELDS, "report")
    expected = _projection(document["supplied_model"])
    if document != expected:
        raise ScimLifecycleError("Report does not replay supplied model")
    return _canonical(expected, maximum=MAX_REPORT_BYTES)


def _owned(text: str) -> ScimLifecycleReport:
    report = object.__new__(ScimLifecycleReport)
    object.__setattr__(report, "document_json", text)
    return report


@dataclass(frozen=True, slots=True)
class ScimLifecycleReport:
    """Detached unsigned lifecycle projection with exact source replay."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not ScimLifecycleReport:
            raise ScimLifecycleError("Exact report family required")
        self.to_dict()

    @classmethod
    def from_dict(cls, value: Any) -> ScimLifecycleReport:
        if cls is not ScimLifecycleReport:
            raise ScimLifecycleError("Exact report family required")
        return _owned(_replay(value))

    @classmethod
    def from_json(cls, value: Any) -> ScimLifecycleReport:
        if cls is not ScimLifecycleReport or type(value) is not str:
            raise ScimLifecycleError("Exact native report JSON required")
        document = _decode(value, "report", MAX_REPORT_BYTES)
        canonical = _replay(document)
        if value != canonical:
            raise ScimLifecycleError("Canonical report JSON required")
        return _owned(canonical)

    def to_dict(self) -> dict[str, Any]:
        if type(self) is not ScimLifecycleReport or type(self.document_json) is not str:
            raise ScimLifecycleError("Exact native report wrapper required")
        return ScimLifecycleReport.from_json(self.document_json)._document()

    def _document(self) -> dict[str, Any]:
        return _decode(self.document_json, "report", MAX_REPORT_BYTES)

    def to_json(self) -> str:
        self.to_dict()
        return self.document_json


def analyze_supplied_scim_lifecycle(model: Any) -> ScimLifecycleReport:
    """Project only supplied user, group, and deprovision records."""
    return _owned(_canonical(_projection(model), maximum=MAX_REPORT_BYTES))


def analyze_supplied_scim_lifecycle_bytes(*, model_bytes: Any) -> ScimLifecycleReport:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise ScimLifecycleError("Bounded native model bytes required")
    try:
        text = model_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ScimLifecycleError("Model bytes must be UTF-8") from exc
    return analyze_supplied_scim_lifecycle(_decode(text, "model", MAX_MODEL_BYTES))


def verify_supplied_scim_lifecycle(report: Any, *, model: Any) -> ScimLifecycleReport:
    if type(report) is not ScimLifecycleReport:
        raise ScimLifecycleError("Exact native report wrapper required")
    retained = report.to_json()
    expected = _canonical(_projection(model), maximum=MAX_REPORT_BYTES)
    if retained != expected:
        raise ScimLifecycleError("Report differs from separately supplied model")
    return _owned(expected)


def component_fixture() -> dict[str, Any]:
    """Return a fresh synthetic pair with no directory or provider destination."""
    return {
        "schema_version": 1,
        "source_id": "synthetic-lifecycle-model",
        "directory_kind": "scim",
        "snapshots_complete": True,
        "before": {
            "source_id": "before-snapshot",
            "users": [
                {"user_id": "u-alex", "active": True},
                {"user_id": "u-river", "active": True},
            ],
            "groups": [
                {"group_id": "g-review", "members": ["u-alex", "u-river"]},
            ],
        },
        "after": {
            "source_id": "after-snapshot",
            "users": [
                {"user_id": "u-alex", "active": True},
            ],
            "groups": [
                {"group_id": "g-review", "members": ["u-alex", "u-river"]},
            ],
        },
        "deprovision": {
            "source_id": "requested-operations",
            "operations": [
                {
                    "operation_id": "disable-alex",
                    "kind": "disable_user",
                    "user_id": "u-alex",
                    "group_id": None,
                },
                {
                    "operation_id": "delete-river",
                    "kind": "delete_user",
                    "user_id": "u-river",
                    "group_id": None,
                },
                {
                    "operation_id": "remove-alex",
                    "kind": "remove_membership",
                    "user_id": "u-alex",
                    "group_id": "g-review",
                },
            ],
        },
    }


__all__ = [
    "ScimLifecycleError",
    "ScimLifecycleReport",
    "analyze_supplied_scim_lifecycle",
    "analyze_supplied_scim_lifecycle_bytes",
    "verify_supplied_scim_lifecycle",
    "component_fixture",
]
