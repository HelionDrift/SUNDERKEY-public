"""Bounded collaboration ownership-chain and Control revocation contracts."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .collaboration import WorkItem
from .errors import CollaborationPlanError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
ENTRY_DOMAIN = "sunderkey.collaboration-ownership-chain-entry.v1"
REVOCATION_DOMAIN = "sunderkey.collaboration-ownership-revocation.v1"
CHAIN_DOMAIN = "sunderkey.collaboration-ownership-chain.v1"
WORK_ITEM_OBJECTIVE_DOMAIN = "sunderkey.collaboration-work-item-objective.v1"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}")
REASON_PATTERN = re.compile(r"[a-z0-9][a-z0-9_]{2,95}")
TIMESTAMP_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
)
TRANSITION_KINDS = {
    "delegation",
    "return_to_planned_owner",
    "control_revocation",
    "privileged_reassignment",
}


def collaboration_work_item_objective_sha256(item: WorkItem) -> str:
    """Bind one complete immutable collaboration work-item objective."""

    if not isinstance(item, WorkItem):
        raise TypeError("item must be a WorkItem")
    parsed = WorkItem.from_dict(item.to_dict())
    return _canonical_sha256(
        {
            "domain": WORK_ITEM_OBJECTIVE_DOMAIN,
            "work_item": parsed.to_dict(),
        }
    )


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise CollaborationPlanError(f"{label} is invalid")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise CollaborationPlanError(f"{label} is invalid")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise CollaborationPlanError(f"{label} is invalid")
    try:
        datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise CollaborationPlanError(f"{label} is invalid") from exc
    return value


def _timestamp_value(value: str) -> datetime:
    return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")


def _positive_integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise CollaborationPlanError(f"{label} must be a positive integer")
    return value


def _optional_identifier(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _identifier(value, label)


def _authority_bindings(raw: Any, transition_kind: str) -> dict[str, Any]:
    value = _mapping(raw, "ownership authority_bindings")
    fields = {
        "current_owner_authorization_id",
        "proposed_owner_acceptance_id",
        "independent_control_approval_id",
        "second_control_or_mission_authority_id",
    }
    _exact_fields(value, fields, "ownership authority_bindings")
    current = _optional_identifier(
        value.get("current_owner_authorization_id"),
        "current_owner_authorization_id",
    )
    proposed = _identifier(
        value.get("proposed_owner_acceptance_id"),
        "proposed_owner_acceptance_id",
    )
    control = _identifier(
        value.get("independent_control_approval_id"),
        "independent_control_approval_id",
    )
    second = _optional_identifier(
        value.get("second_control_or_mission_authority_id"),
        "second_control_or_mission_authority_id",
    )
    if transition_kind == "control_revocation":
        if current is not None:
            raise CollaborationPlanError(
                "Control revocation cannot require current-owner authorization"
            )
    elif current is None:
        raise CollaborationPlanError("Current-owner authorization is required")
    return {
        "current_owner_authorization_id": current,
        "proposed_owner_acceptance_id": proposed,
        "independent_control_approval_id": control,
        "second_control_or_mission_authority_id": second,
    }


def _chain_id(anchor: dict[str, str]) -> str:
    digest = _canonical_sha256({"domain": CHAIN_DOMAIN, "anchor": anchor})
    return "OCN-" + digest.removeprefix("sha256:")[:32].upper()


@dataclass(frozen=True)
class CollaborationOwnershipChainEntry:
    """One immutable transition in a bounded ownership chain."""

    entry_id: str
    entry_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationOwnershipChainEntry:
        value = _mapping(raw, "collaboration ownership-chain entry")
        fields = {
            "schema_version",
            "entry_id",
            "entry_sha256",
            "chain_id",
            "sequence",
            "owner_epoch",
            "mission_id",
            "collaboration_plan_id",
            "collaboration_plan_sha256",
            "work_item_id",
            "work_item_objective_sha256",
            "planned_owner_id",
            "transition_kind",
            "from_owner_id",
            "to_owner_id",
            "previous_entry_sha256",
            "reason_code",
            "requested_at",
            "expires_at",
            "control_role_replacement",
            "authority_bindings",
            "runtime_effect",
        }
        _exact_fields(value, fields, "collaboration ownership-chain entry")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Ownership-chain entry schema is invalid")
        entry_id = value.get("entry_id")
        entry_sha256 = value.get("entry_sha256")
        chain_id = value.get("chain_id")
        if (
            not isinstance(entry_id, str)
            or re.fullmatch(r"OCE-[0-9A-F]{32}", entry_id) is None
            or not isinstance(chain_id, str)
            or re.fullmatch(r"OCN-[0-9A-F]{32}", chain_id) is None
        ):
            raise CollaborationPlanError("Ownership-chain identity is invalid")
        _sha256(entry_sha256, "entry_sha256")
        sequence = _positive_integer(value.get("sequence"), "sequence")
        _positive_integer(value.get("owner_epoch"), "owner_epoch")
        anchor = {
            "mission_id": _identifier(value.get("mission_id"), "mission_id"),
            "collaboration_plan_id": _identifier(
                value.get("collaboration_plan_id"), "collaboration_plan_id"
            ),
            "collaboration_plan_sha256": _sha256(
                value.get("collaboration_plan_sha256"),
                "collaboration_plan_sha256",
            ),
            "work_item_id": _identifier(value.get("work_item_id"), "work_item_id"),
            "work_item_objective_sha256": _sha256(
                value.get("work_item_objective_sha256"),
                "work_item_objective_sha256",
            ),
            "planned_owner_id": _identifier(
                value.get("planned_owner_id"), "planned_owner_id"
            ),
        }
        if chain_id != _chain_id(anchor):
            raise CollaborationPlanError("Ownership-chain anchor is invalid")
        transition_kind = value.get("transition_kind")
        if transition_kind not in TRANSITION_KINDS:
            raise CollaborationPlanError("Ownership transition kind is invalid")
        from_owner = _identifier(value.get("from_owner_id"), "from_owner_id")
        to_owner = _identifier(value.get("to_owner_id"), "to_owner_id")
        if from_owner == to_owner:
            raise CollaborationPlanError("Ownership transition must change owner")
        previous = value.get("previous_entry_sha256")
        if sequence == 1:
            if previous is not None:
                raise CollaborationPlanError("Initial ownership transition has no predecessor")
        else:
            _sha256(previous, "previous_entry_sha256")
        reason = value.get("reason_code")
        if not isinstance(reason, str) or REASON_PATTERN.fullmatch(reason) is None:
            raise CollaborationPlanError("Ownership reason code is invalid")
        requested_at = _timestamp(value.get("requested_at"), "requested_at")
        expires_at = _timestamp(value.get("expires_at"), "expires_at")
        if _timestamp_value(expires_at) <= _timestamp_value(requested_at):
            raise CollaborationPlanError("Ownership transition expiry is invalid")
        control_role_replacement = value.get("control_role_replacement")
        if not isinstance(control_role_replacement, bool):
            raise CollaborationPlanError("control_role_replacement is invalid")
        bindings = _authority_bindings(value.get("authority_bindings"), transition_kind)
        if control_role_replacement and bindings[
            "second_control_or_mission_authority_id"
        ] is None:
            raise CollaborationPlanError(
                "Control-role replacement requires second independent authority"
            )
        if transition_kind in {"return_to_planned_owner", "control_revocation"}:
            if to_owner != anchor["planned_owner_id"]:
                raise CollaborationPlanError(
                    "Return and revocation must restore the planned owner"
                )
        elif transition_kind == "delegation" and to_owner == anchor["planned_owner_id"]:
            raise CollaborationPlanError("Delegation cannot target the planned owner")
        if value.get("runtime_effect") != "none":
            raise CollaborationPlanError("Ownership-chain entry runtime effect is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"entry_id", "entry_sha256"}
        }
        digest = _canonical_sha256({"domain": ENTRY_DOMAIN, "entry": body})
        expected_id = "OCE-" + digest.removeprefix("sha256:")[:32].upper()
        if entry_sha256 != digest or entry_id != expected_id:
            raise CollaborationPlanError("Ownership-chain entry hash is invalid")
        return cls(
            entry_id,
            entry_sha256,
            _canonical_json({**value, "authority_bindings": bindings}),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Ownership-chain entry is invalid")
        return value


@dataclass(frozen=True)
class CollaborationOwnershipRevocation:
    """Independent Control request to restore the planned owner."""

    revocation_id: str
    revocation_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationOwnershipRevocation:
        value = _mapping(raw, "collaboration ownership revocation")
        fields = {
            "schema_version",
            "revocation_id",
            "revocation_sha256",
            "chain_id",
            "current_head_entry_id",
            "current_head_sha256",
            "current_owner_id",
            "planned_owner_id",
            "independent_control_id",
            "independent_control_approval_id",
            "planned_owner_acceptance_id",
            "reason_code",
            "requested_at",
            "expires_at",
            "runtime_effect",
        }
        _exact_fields(value, fields, "collaboration ownership revocation")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Ownership revocation schema is invalid")
        revocation_id = value.get("revocation_id")
        revocation_sha256 = value.get("revocation_sha256")
        if (
            not isinstance(revocation_id, str)
            or re.fullmatch(r"OCR-[0-9A-F]{32}", revocation_id) is None
            or not isinstance(revocation_sha256, str)
            or SHA256_PATTERN.fullmatch(revocation_sha256) is None
        ):
            raise CollaborationPlanError("Ownership revocation identity is invalid")
        identifiers = (
            "current_owner_id",
            "planned_owner_id",
            "independent_control_id",
            "independent_control_approval_id",
            "planned_owner_acceptance_id",
        )
        for field in identifiers:
            _identifier(value.get(field), field)
        if (
            not isinstance(value.get("chain_id"), str)
            or re.fullmatch(r"OCN-[0-9A-F]{32}", value["chain_id"]) is None
            or not isinstance(value.get("current_head_entry_id"), str)
            or re.fullmatch(r"OCE-[0-9A-F]{32}", value["current_head_entry_id"])
            is None
        ):
            raise CollaborationPlanError("Ownership revocation chain binding is invalid")
        _sha256(value.get("current_head_sha256"), "current_head_sha256")
        if value.get("current_owner_id") == value.get("planned_owner_id"):
            raise CollaborationPlanError("Planned owner already owns the work item")
        reason = value.get("reason_code")
        if not isinstance(reason, str) or REASON_PATTERN.fullmatch(reason) is None:
            raise CollaborationPlanError("Ownership revocation reason is invalid")
        requested_at = _timestamp(value.get("requested_at"), "requested_at")
        expires_at = _timestamp(value.get("expires_at"), "expires_at")
        if _timestamp_value(expires_at) <= _timestamp_value(requested_at):
            raise CollaborationPlanError("Ownership revocation expiry is invalid")
        if value.get("runtime_effect") != "none":
            raise CollaborationPlanError("Ownership revocation runtime effect is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"revocation_id", "revocation_sha256"}
        }
        digest = _canonical_sha256({"domain": REVOCATION_DOMAIN, "revocation": body})
        expected_id = "OCR-" + digest.removeprefix("sha256:")[:32].upper()
        if revocation_sha256 != digest or revocation_id != expected_id:
            raise CollaborationPlanError("Ownership revocation hash is invalid")
        return cls(revocation_id, revocation_sha256, _canonical_json(value))

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Ownership revocation is invalid")
        return value


@dataclass(frozen=True)
class VerifiedCollaborationOwnershipChain:
    chain_id: str
    head_entry_id: str
    head_sha256: str
    current_owner_id: str
    owner_epoch: int
    active_delegation_depth: int
    entry_count: int


def build_collaboration_ownership_chain_entry(
    *,
    mission_id: str,
    collaboration_plan_id: str,
    collaboration_plan_sha256: str,
    work_item_id: str,
    work_item_objective_sha256: str,
    planned_owner_id: str,
    sequence: int,
    owner_epoch: int,
    transition_kind: str,
    from_owner_id: str,
    to_owner_id: str,
    previous_entry_sha256: str | None,
    reason_code: str,
    requested_at: str,
    expires_at: str,
    control_role_replacement: bool,
    authority_bindings: dict[str, Any],
) -> CollaborationOwnershipChainEntry:
    anchor = {
        "mission_id": mission_id,
        "collaboration_plan_id": collaboration_plan_id,
        "collaboration_plan_sha256": collaboration_plan_sha256,
        "work_item_id": work_item_id,
        "work_item_objective_sha256": work_item_objective_sha256,
        "planned_owner_id": planned_owner_id,
    }
    body = {
        "schema_version": SCHEMA_VERSION,
        "chain_id": _chain_id(anchor),
        "sequence": sequence,
        "owner_epoch": owner_epoch,
        **anchor,
        "transition_kind": transition_kind,
        "from_owner_id": from_owner_id,
        "to_owner_id": to_owner_id,
        "previous_entry_sha256": previous_entry_sha256,
        "reason_code": reason_code,
        "requested_at": requested_at,
        "expires_at": expires_at,
        "control_role_replacement": control_role_replacement,
        "authority_bindings": authority_bindings,
        "runtime_effect": "none",
    }
    digest = _canonical_sha256({"domain": ENTRY_DOMAIN, "entry": body})
    return CollaborationOwnershipChainEntry.from_dict(
        {
            **body,
            "entry_id": "OCE-" + digest.removeprefix("sha256:")[:32].upper(),
            "entry_sha256": digest,
        }
    )


def build_collaboration_ownership_revocation(
    *,
    head: CollaborationOwnershipChainEntry,
    independent_control_id: str,
    independent_control_approval_id: str,
    planned_owner_acceptance_id: str,
    reason_code: str,
    requested_at: str,
    expires_at: str,
) -> CollaborationOwnershipRevocation:
    head = CollaborationOwnershipChainEntry.from_dict(head.to_dict())
    document = head.to_dict()
    body = {
        "schema_version": SCHEMA_VERSION,
        "chain_id": document["chain_id"],
        "current_head_entry_id": head.entry_id,
        "current_head_sha256": head.entry_sha256,
        "current_owner_id": document["to_owner_id"],
        "planned_owner_id": document["planned_owner_id"],
        "independent_control_id": independent_control_id,
        "independent_control_approval_id": independent_control_approval_id,
        "planned_owner_acceptance_id": planned_owner_acceptance_id,
        "reason_code": reason_code,
        "requested_at": requested_at,
        "expires_at": expires_at,
        "runtime_effect": "none",
    }
    digest = _canonical_sha256({"domain": REVOCATION_DOMAIN, "revocation": body})
    return CollaborationOwnershipRevocation.from_dict(
        {
            **body,
            "revocation_id": "OCR-" + digest.removeprefix("sha256:")[:32].upper(),
            "revocation_sha256": digest,
        }
    )


def validate_collaboration_ownership_chain(
    entries: Iterable[CollaborationOwnershipChainEntry],
    *,
    maximum_delegation_depth: int,
) -> VerifiedCollaborationOwnershipChain:
    maximum = _positive_integer(maximum_delegation_depth, "maximum_delegation_depth")
    if maximum > 8:
        raise CollaborationPlanError("maximum_delegation_depth exceeds the policy contract")
    parsed = [CollaborationOwnershipChainEntry.from_dict(item.to_dict()) for item in entries]
    if not parsed:
        raise CollaborationPlanError("Ownership chain cannot be empty")
    anchor_fields = (
        "chain_id",
        "mission_id",
        "collaboration_plan_id",
        "collaboration_plan_sha256",
        "work_item_id",
        "work_item_objective_sha256",
        "planned_owner_id",
    )
    first = parsed[0].to_dict()
    current_owner = first["planned_owner_id"]
    active_depth = 0
    prior_nonplanned_owners: set[str] = set()
    previous: CollaborationOwnershipChainEntry | None = None
    for index, entry in enumerate(parsed, start=1):
        document = entry.to_dict()
        if any(document[field] != first[field] for field in anchor_fields):
            raise CollaborationPlanError("Ownership chain anchor changed")
        if document["sequence"] != index or document["owner_epoch"] != index:
            raise CollaborationPlanError("Ownership chain sequence or epoch is invalid")
        if document["from_owner_id"] != current_owner:
            raise CollaborationPlanError("Ownership chain current owner is stale")
        expected_previous = None if previous is None else previous.entry_sha256
        if document["previous_entry_sha256"] != expected_previous:
            raise CollaborationPlanError("Ownership chain predecessor is stale")
        transition_kind = document["transition_kind"]
        to_owner = document["to_owner_id"]
        if transition_kind in {"return_to_planned_owner", "control_revocation"}:
            active_depth = 0
            prior_nonplanned_owners.clear()
        else:
            if to_owner in prior_nonplanned_owners:
                raise CollaborationPlanError("Ownership cycle is not permitted")
            prior_nonplanned_owners.add(to_owner)
            active_depth += 1
            if active_depth > maximum:
                raise CollaborationPlanError("Maximum delegation depth is exceeded")
        current_owner = to_owner
        previous = entry
    head = parsed[-1]
    return VerifiedCollaborationOwnershipChain(
        chain_id=first["chain_id"],
        head_entry_id=head.entry_id,
        head_sha256=head.entry_sha256,
        current_owner_id=current_owner,
        owner_epoch=len(parsed),
        active_delegation_depth=active_depth,
        entry_count=len(parsed),
    )


def apply_collaboration_ownership_revocation(
    entries: Iterable[CollaborationOwnershipChainEntry],
    revocation: CollaborationOwnershipRevocation,
    *,
    maximum_delegation_depth: int,
) -> tuple[CollaborationOwnershipChainEntry, VerifiedCollaborationOwnershipChain]:
    parsed = [CollaborationOwnershipChainEntry.from_dict(item.to_dict()) for item in entries]
    verified = validate_collaboration_ownership_chain(
        parsed, maximum_delegation_depth=maximum_delegation_depth
    )
    revocation = CollaborationOwnershipRevocation.from_dict(revocation.to_dict())
    request = revocation.to_dict()
    head = parsed[-1]
    head_document = head.to_dict()
    if request["chain_id"] != verified.chain_id:
        raise CollaborationPlanError("Ownership revocation chain is stale")
    if (
        request["current_head_entry_id"] != verified.head_entry_id
        or request["current_head_sha256"] != verified.head_sha256
        or request["current_owner_id"] != verified.current_owner_id
    ):
        raise CollaborationPlanError("Ownership revocation head is stale")
    if request["planned_owner_id"] != head_document["planned_owner_id"]:
        raise CollaborationPlanError("Ownership revocation planned owner is invalid")
    entry = build_collaboration_ownership_chain_entry(
        mission_id=head_document["mission_id"],
        collaboration_plan_id=head_document["collaboration_plan_id"],
        collaboration_plan_sha256=head_document["collaboration_plan_sha256"],
        work_item_id=head_document["work_item_id"],
        work_item_objective_sha256=head_document["work_item_objective_sha256"],
        planned_owner_id=head_document["planned_owner_id"],
        sequence=verified.entry_count + 1,
        owner_epoch=verified.owner_epoch + 1,
        transition_kind="control_revocation",
        from_owner_id=verified.current_owner_id,
        to_owner_id=request["planned_owner_id"],
        previous_entry_sha256=verified.head_sha256,
        reason_code=request["reason_code"],
        requested_at=request["requested_at"],
        expires_at=request["expires_at"],
        control_role_replacement=False,
        authority_bindings={
            "current_owner_authorization_id": None,
            "proposed_owner_acceptance_id": request["planned_owner_acceptance_id"],
            "independent_control_approval_id": request[
                "independent_control_approval_id"
            ],
            "second_control_or_mission_authority_id": None,
        },
    )
    completed = validate_collaboration_ownership_chain(
        [*parsed, entry], maximum_delegation_depth=maximum_delegation_depth
    )
    return entry, completed


def load_collaboration_ownership_chain_entry(
    path: str | Path,
) -> CollaborationOwnershipChainEntry:
    resolved = Path(path).resolve()
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise CollaborationPlanError(f"Could not load ownership-chain entry: {resolved}") from exc
    return CollaborationOwnershipChainEntry.from_dict(raw)


def load_collaboration_ownership_revocation(
    path: str | Path,
) -> CollaborationOwnershipRevocation:
    resolved = Path(path).resolve()
    try:
        raw = loads_json_without_duplicate_keys(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise CollaborationPlanError(f"Could not load ownership revocation: {resolved}") from exc
    return CollaborationOwnershipRevocation.from_dict(raw)


__all__ = [
    "CollaborationOwnershipChainEntry",
    "CollaborationOwnershipRevocation",
    "VerifiedCollaborationOwnershipChain",
    "apply_collaboration_ownership_revocation",
    "build_collaboration_ownership_chain_entry",
    "build_collaboration_ownership_revocation",
    "collaboration_work_item_objective_sha256",
    "load_collaboration_ownership_chain_entry",
    "load_collaboration_ownership_revocation",
    "validate_collaboration_ownership_chain",
]
