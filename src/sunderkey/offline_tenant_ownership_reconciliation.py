"""Join supplied tenant ownership declarations without checking a target."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_tenant_ownership_reconciliation"
PROFILE_ID = "AOE-GB-D09-S06"
CAPABILITY_ID = "army.gb.d09.s06"
VECTOR_ID = "AV-GB-D09-S06-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D09-S06"
WAVE_ID = "IW2-006"
COMMANDER_ID = "AOE-GB-D09-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:0c458c258f8aaf1190a619735a9493e02fc5dfc412195816c99a9496027ccbca"
SEMANTICS_PROFILE = "supplied-tenant-ownership-reconciliation-v1"
DOMAIN = "sunderkey.offline-tenant-ownership-reconciliation.v1"
MAX_TENANTS = 128
MAX_MEMBERSHIPS = 512
MAX_RESOURCES = 512
MAX_EVENTS = 512
MAX_DOCUMENT_BYTES = 1_048_576
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_TENANT = re.compile(r"tenant:sha256:[0-9a-f]{64}\Z")
_PRINCIPAL = re.compile(r"principal:sha256:[0-9a-f]{64}\Z")
_RESOURCE = re.compile(r"resource:sha256:[0-9a-f]{64}\Z")
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "credential",
        "execution",
        "filesystem",
        "network",
        "publication",
        "qualification",
        "resource_write",
        "target",
    ),
    "none",
)


class TenantOwnershipReconciliationError(ValueError):
    """The supplied ownership model or replay document was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise TenantOwnershipReconciliationError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise TenantOwnershipReconciliationError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise TenantOwnershipReconciliationError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise TenantOwnershipReconciliationError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise TenantOwnershipReconciliationError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise TenantOwnershipReconciliationError(
                            "Native JSON text keys are required"
                        )
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            else:
                for child in item:
                    visit(child, depth + 1)
        finally:
            active.remove(id(item))

    visit(value, 1)
    encoded = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise TenantOwnershipReconciliationError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise TenantOwnershipReconciliationError(f"{label} fields are invalid")


def _reference(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise TenantOwnershipReconciliationError(f"Opaque {label} reference is invalid")
    return value


def _plan(model: Any) -> dict:
    model = json.loads(_canonical(model))
    _fields(
        model,
        {
            "schema_version",
            "semantics_profile",
            "tenants",
            "memberships",
            "resources",
            "access_events",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise TenantOwnershipReconciliationError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise TenantOwnershipReconciliationError("Semantics profile is invalid")
    tenants = model["tenants"]
    if type(tenants) is not list or not 1 <= len(tenants) <= MAX_TENANTS:
        raise TenantOwnershipReconciliationError("Tenant count is invalid")
    tenant_ids = {_reference(item, _TENANT, "tenant") for item in tenants}
    if len(tenant_ids) != len(tenants):
        raise TenantOwnershipReconciliationError("Duplicate tenant reference")
    memberships = model["memberships"]
    if type(memberships) is not list or len(memberships) > MAX_MEMBERSHIPS:
        raise TenantOwnershipReconciliationError("Membership count is invalid")
    membership_pairs: set[tuple[str, str]] = set()
    for membership in memberships:
        _fields(membership, {"principal_ref", "tenant_ref"}, "membership")
        principal = _reference(membership["principal_ref"], _PRINCIPAL, "principal")
        tenant = _reference(membership["tenant_ref"], _TENANT, "tenant")
        if tenant not in tenant_ids or (principal, tenant) in membership_pairs:
            raise TenantOwnershipReconciliationError("Membership is undeclared or duplicate")
        membership_pairs.add((principal, tenant))
    resources = model["resources"]
    if type(resources) is not list or not 1 <= len(resources) <= MAX_RESOURCES:
        raise TenantOwnershipReconciliationError("Resource count is invalid")
    resource_ids: set[str] = set()
    for resource in resources:
        _fields(resource, {"resource_ref", "owner_tenant_ref"}, "resource")
        resource_id = _reference(resource["resource_ref"], _RESOURCE, "resource")
        owner = _reference(resource["owner_tenant_ref"], _TENANT, "owner tenant")
        if resource_id in resource_ids or owner not in tenant_ids:
            raise TenantOwnershipReconciliationError("Resource is duplicate or owner undeclared")
        resource_ids.add(resource_id)
    events = model["access_events"]
    if type(events) is not list or not 1 <= len(events) <= MAX_EVENTS:
        raise TenantOwnershipReconciliationError("Access event count is invalid")
    event_ids: set[str] = set()
    for event in events:
        _fields(
            event,
            {"event_id", "principal_ref", "resource_ref", "action", "declared_allowed"},
            "event",
        )
        event_id = event["event_id"]
        if type(event_id) is not str or _ID.fullmatch(event_id) is None or event_id in event_ids:
            raise TenantOwnershipReconciliationError("Event identifier is invalid or duplicate")
        event_ids.add(event_id)
        _reference(event["principal_ref"], _PRINCIPAL, "event principal")
        if _reference(event["resource_ref"], _RESOURCE, "event resource") not in resource_ids:
            raise TenantOwnershipReconciliationError("Event resource is undeclared")
        if event["action"] not in ("read", "write"):
            raise TenantOwnershipReconciliationError("Event action is invalid")
        if type(event["declared_allowed"]) is not bool:
            raise TenantOwnershipReconciliationError("Declared access outcome is invalid")
    return model


def _derive(model: Any) -> dict:
    plan = _plan(model)
    memberships: dict[str, set[str]] = {}
    for row in plan["memberships"]:
        memberships.setdefault(row["principal_ref"], set()).add(row["tenant_ref"])
    owners = {row["resource_ref"]: row["owner_tenant_ref"] for row in plan["resources"]}
    rows = []
    for position, event in enumerate(plan["access_events"]):
        owner = owners[event["resource_ref"]]
        declared_member = owner in memberships.get(event["principal_ref"], set())
        flags = []
        if event["declared_allowed"] and not declared_member:
            flags.append("allowed_without_declared_owner_tenant_membership")
        if not event["declared_allowed"] and declared_member:
            flags.append("denied_despite_declared_owner_tenant_membership")
        rows.append(
            {
                "position": position,
                "event_id": event["event_id"],
                "principal_ref": event["principal_ref"],
                "resource_ref": event["resource_ref"],
                "owner_tenant_ref": owner,
                "declared_common_tenant": declared_member,
                "anomaly_flags": flags,
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": plan,
        "events": rows,
        "flags": {
            "tenant_source_authenticated": False,
            "membership_currentness_proven": False,
            "resource_ownership_proven": False,
            "application_policy_proven": False,
            "access_observed": False,
            "authorization_defect_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Tenant, principal, membership, resource and access labels are caller-supplied.",
            "Same declared tenant is not sufficient authorization; other policy may govern access.",
            "A mismatch is a review signal, not proof of cross-tenant access or denial defect.",
            "No account, resource, credential, service, or target is contacted or changed.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "TOR-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class TenantOwnershipReconciliation:
    """Replay-checked local join of supplied tenant and ownership labels."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise TenantOwnershipReconciliationError(
                "Exact native report with source model required"
            )
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise TenantOwnershipReconciliationError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_tenant_ownership(model: Any) -> TenantOwnershipReconciliation:
    """Derive only a supplied tenant/owner membership comparison."""
    return TenantOwnershipReconciliation(_derive(model))


def verify_supplied_tenant_ownership(report: Any, *, model: Any) -> TenantOwnershipReconciliation:
    """Recompute the report from current supplied model bytes."""
    if type(report) is not TenantOwnershipReconciliation:
        raise TenantOwnershipReconciliationError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise TenantOwnershipReconciliationError("Report differs from supplied model replay")
    return TenantOwnershipReconciliation(expected)


__all__ = [
    "COMPONENT_ID",
    "PROFILE_ID",
    "TenantOwnershipReconciliation",
    "TenantOwnershipReconciliationError",
    "analyze_supplied_tenant_ownership",
    "verify_supplied_tenant_ownership",
]
