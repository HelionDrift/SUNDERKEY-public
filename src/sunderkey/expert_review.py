"""Strict records for independent review of durable expert work products.

This module is deliberately independent of MissionStore.  It validates the
portable records that a later authenticated MissionStore service will persist,
and it verifies their closed quorum semantics.  It performs no authentication,
authorization, model call, network call, tool use, or target action.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from .errors import StoreError, StoreIntegrityError
from .qualification import _canonical_json, _canonical_sha256
from .registry import ExpertRegistry
from .validation import DuplicateJsonKeyError, loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
MAX_RECORD_BYTES = 8_388_608
MAX_REVIEW_SLOTS = 32_768
MAX_TEXT_ITEMS = 512
MAX_RATIONALE_CHARACTERS = 16_384

SNAPSHOT_DOMAIN = "sunderkey.expert-review-snapshot.v1"
SUBMISSION_DOMAIN = "sunderkey.expert-review-submission.v1"
RECEIPT_DOMAIN = "sunderkey.authenticated-expert-review-receipt.v1"
CLOSURE_REQUEST_DOMAIN = "sunderkey.expert-review-closure-request.v1"
CLOSURE_DOMAIN = "sunderkey.expert-review-closure-certificate.v1"
REVOCATION_DOMAIN = "sunderkey.expert-review-closure-revocation.v1"
APPLICATION_DOMAIN = "sunderkey.expert-workspace-closure-application.v1"

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{2,255}")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_PROFILE_ID = re.compile(r"AOE-(?:G[A-E]-D[0-9]{2}-(?:S[0-9]{2}|CMD)|HQ-[0-9]{2})")
_RECORD_IDS = {
    "expert_review_snapshot": re.compile(r"ERS-[0-9A-F]{32}"),
    "expert_review_submission": re.compile(r"ERSU-[0-9A-F]{32}"),
    "authenticated_expert_review_receipt": re.compile(r"ERR-[0-9A-F]{32}"),
    "expert_review_closure_request": re.compile(r"ECRQ-[0-9A-F]{32}"),
    "expert_review_closure_certificate": re.compile(r"ERC-[0-9A-F]{32}"),
    "expert_review_closure_revocation": re.compile(r"ECRV-[0-9A-F]{32}"),
    "expert_workspace_closure_application": re.compile(r"ECAP-[0-9A-F]{32}"),
}
_PREFIXES = {
    "expert_review_snapshot": "ERS",
    "expert_review_submission": "ERSU",
    "authenticated_expert_review_receipt": "ERR",
    "expert_review_closure_request": "ECRQ",
    "expert_review_closure_certificate": "ERC",
    "expert_review_closure_revocation": "ECRV",
    "expert_workspace_closure_application": "ECAP",
}
_DOMAINS = {
    "expert_review_snapshot": SNAPSHOT_DOMAIN,
    "expert_review_submission": SUBMISSION_DOMAIN,
    "authenticated_expert_review_receipt": RECEIPT_DOMAIN,
    "expert_review_closure_request": CLOSURE_REQUEST_DOMAIN,
    "expert_review_closure_certificate": CLOSURE_DOMAIN,
    "expert_review_closure_revocation": REVOCATION_DOMAIN,
    "expert_workspace_closure_application": APPLICATION_DOMAIN,
}
_ID_FIELDS = {
    "expert_review_snapshot": "snapshot_id",
    "expert_review_submission": "submission_id",
    "authenticated_expert_review_receipt": "receipt_id",
    "expert_review_closure_request": "closure_request_id",
    "expert_review_closure_certificate": "closure_id",
    "expert_review_closure_revocation": "revocation_id",
    "expert_workspace_closure_application": "application_id",
}
_HASH_FIELDS = {
    "expert_review_snapshot": "snapshot_sha256",
    "expert_review_submission": "submission_sha256",
    "authenticated_expert_review_receipt": "receipt_sha256",
    "expert_review_closure_request": "closure_request_sha256",
    "expert_review_closure_certificate": "closure_sha256",
    "expert_review_closure_revocation": "revocation_sha256",
    "expert_workspace_closure_application": "application_sha256",
}

NO_EFFECTS = MappingProxyType(
    {
        "authorization_effect": "none",
        "model_call_performed": False,
        "network_call_performed": False,
        "qualification_effect": "none",
        "target_action_performed": False,
        "tool_effect": "none",
    }
)


class ReviewerRole(StrEnum):
    TECHNICAL_EVALUATOR = "technical_evaluator"
    INDEPENDENT_CONTROL = "independent_control"
    INDEPENDENT_ASSURANCE = "independent_assurance"


class ReviewDecision(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    REWORK_REQUIRED = "rework_required"


class ClosureDisposition(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    REWORK_REQUIRED = "rework_required"


class ReconciliationStatus(StrEnum):
    CONSISTENT = "consistent"
    CLOSURE_PENDING_WORKSPACE_APPLICATION = "closure_pending_workspace_application"
    REVOCATION_PENDING_WORKSPACE_APPLICATION = "revocation_pending_workspace_application"
    WORKSPACE_PROJECTION_MISSING_MISSION_RECORD = "workspace_projection_missing_mission_record"
    SNAPSHOT_MISMATCH = "snapshot_mismatch"
    CERTIFICATE_MISMATCH = "certificate_mismatch"


def _strict_json(value: Any, label: str, depth: int = 0) -> None:
    if depth > 32:
        raise StoreError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not -(2**63) <= value <= 2**63 - 1:
            raise StoreError(f"{label} integer is outside the signed 64-bit range")
        return
    if isinstance(value, float):
        raise StoreError(f"{label} cannot contain floating-point values")
    if isinstance(value, str):
        if (
            len(value) > MAX_RATIONALE_CHARACTERS
            or not value.isascii()
            or any(ord(character) < 0x20 and character not in "\t\n\r" for character in value)
        ):
            raise StoreError(f"{label} contains invalid text")
        return
    if isinstance(value, list):
        if len(value) > MAX_REVIEW_SLOTS:
            raise StoreError(f"{label} contains too many values")
        for index, item in enumerate(value):
            _strict_json(item, f"{label}[{index}]", depth + 1)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or not key or not key.isascii():
                raise StoreError(f"{label} contains an invalid key")
            _strict_json(item, f"{label}.{key}", depth + 1)
        return
    raise StoreError(f"{label} contains an unsupported value")


def _mapping(raw: Any, label: str) -> dict[str, Any]:
    if isinstance(raw, str):
        if not raw or len(raw.encode("utf-8")) > MAX_RECORD_BYTES:
            raise StoreError(f"{label} exceeds the JSON byte ceiling")
        try:
            value = loads_json_without_duplicate_keys(raw)
        except (json.JSONDecodeError, DuplicateJsonKeyError) as exc:
            raise StoreError(f"{label} JSON is invalid") from exc
        if _canonical_json(value) != raw:
            raise StoreError(f"{label} JSON is not canonical")
        raw = value
    if not isinstance(raw, Mapping):
        raise StoreError(f"{label} must be an object")
    value = dict(raw)
    _strict_json(value, label)
    if len(_canonical_json(value).encode("ascii")) > MAX_RECORD_BYTES:
        raise StoreError(f"{label} exceeds the JSON byte ceiling")
    return value


def _exact(value: Mapping[str, Any], fields: set[str], label: str) -> None:
    if set(value) != fields:
        raise StoreError(f"{label} fields are invalid")


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise StoreError(f"{label} is invalid")
    return value


def _profile_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or _PROFILE_ID.fullmatch(value) is None:
        raise StoreError(f"{label} is invalid")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise StoreError(f"{label} is invalid")
    return value


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise StoreError(f"{label} is invalid")
    return value


def _ordered_strings(
    value: Any,
    label: str,
    *,
    allow_empty: bool = True,
    profiles: bool = False,
) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or len(value) > MAX_TEXT_ITEMS
        or (not allow_empty and not value)
    ):
        raise StoreError(f"{label} is invalid")
    parser = _profile_id if profiles else _identifier
    items = tuple(parser(item, f"{label} item") for item in value)
    if len(items) != len(set(items)) or items != tuple(sorted(items)):
        raise StoreError(f"{label} must be unique and ordered")
    return items


def _ordered_hashes(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > MAX_TEXT_ITEMS:
        raise StoreError(f"{label} is invalid")
    items = tuple(_sha256(item, f"{label} item") for item in value)
    if len(items) != len(set(items)) or items != tuple(sorted(items)):
        raise StoreError(f"{label} must be unique and ordered")
    return items


def _record_identity(kind: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = _canonical_sha256({"domain": _DOMAINS[kind], "record": dict(body)})
    return f"{_PREFIXES[kind]}-{digest.removeprefix('sha256:')[:32].upper()}", digest


def _address_record(kind: str, body: Mapping[str, Any]) -> dict[str, Any]:
    record_id, digest = _record_identity(kind, body)
    return {
        **dict(body),
        _ID_FIELDS[kind]: record_id,
        _HASH_FIELDS[kind]: digest,
    }


def _validate_addressed_record(value: Mapping[str, Any], kind: str) -> None:
    id_field = _ID_FIELDS[kind]
    hash_field = _HASH_FIELDS[kind]
    if (
        type(value.get("schema_version")) is not int
        or value.get("schema_version") != SCHEMA_VERSION
        or type(value.get("kind")) is not str
        or value.get("kind") != kind
    ):
        raise StoreError(f"{kind} metadata is invalid")
    effects = value.get("effects")
    if not isinstance(effects, Mapping) or set(effects) != set(NO_EFFECTS):
        raise StoreError(f"{kind} claims a prohibited effect")
    for field, expected in NO_EFFECTS.items():
        actual = effects[field]
        if type(actual) is not type(expected) or actual != expected:
            raise StoreError(f"{kind} claims a prohibited effect")
    record_id = value.get(id_field)
    if not isinstance(record_id, str) or _RECORD_IDS[kind].fullmatch(record_id) is None:
        raise StoreError(f"{kind} ID is invalid")
    digest = _sha256(value.get(hash_field), f"{kind} hash")
    body = {key: item for key, item in value.items() if key not in {id_field, hash_field}}
    expected_id, expected_digest = _record_identity(kind, body)
    if record_id != expected_id or digest != expected_digest:
        raise StoreError(f"{kind} content address is invalid")


@dataclass(frozen=True)
class _PortableRecord:
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @property
    def kind(self) -> str:
        return str(self.to_dict()["kind"])

    @property
    def record_id(self) -> str:
        return str(self.to_dict()[_ID_FIELDS[self.kind]])

    @property
    def content_sha256(self) -> str:
        return str(self.to_dict()[_HASH_FIELDS[self.kind]])


@dataclass(frozen=True)
class ExpertReviewSnapshot(_PortableRecord):
    @property
    def snapshot_id(self) -> str:
        return self.record_id

    @property
    def snapshot_sha256(self) -> str:
        return self.content_sha256


@dataclass(frozen=True)
class ExpertReviewSubmission(_PortableRecord):
    @property
    def submission_id(self) -> str:
        return self.record_id

    @property
    def submission_sha256(self) -> str:
        return self.content_sha256


@dataclass(frozen=True)
class AuthenticatedExpertReviewReceipt(_PortableRecord):
    @property
    def receipt_id(self) -> str:
        return self.record_id

    @property
    def receipt_sha256(self) -> str:
        return self.content_sha256


@dataclass(frozen=True)
class ExpertReviewClosureRequest(_PortableRecord):
    @property
    def closure_request_id(self) -> str:
        return self.record_id

    @property
    def closure_request_sha256(self) -> str:
        return self.content_sha256


@dataclass(frozen=True)
class ExpertReviewClosureCertificate(_PortableRecord):
    @property
    def closure_id(self) -> str:
        return self.record_id

    @property
    def closure_sha256(self) -> str:
        return self.content_sha256


@dataclass(frozen=True)
class ExpertReviewClosureRevocation(_PortableRecord):
    @property
    def revocation_id(self) -> str:
        return self.record_id

    @property
    def revocation_sha256(self) -> str:
        return self.content_sha256


@dataclass(frozen=True)
class ExpertWorkspaceClosureApplication(_PortableRecord):
    @property
    def application_id(self) -> str:
        return self.record_id

    @property
    def application_sha256(self) -> str:
        return self.content_sha256


@dataclass(frozen=True)
class ExpertReviewRecordSet:
    snapshot: ExpertReviewSnapshot
    receipts: tuple[AuthenticatedExpertReviewReceipt, ...]
    closure_request: ExpertReviewClosureRequest
    closure: ExpertReviewClosureCertificate
    revocation: ExpertReviewClosureRevocation | None = None


@dataclass(frozen=True)
class ExpertReviewReconciliationReport:
    status: ReconciliationStatus
    workspace_id: str
    snapshot_id: str
    snapshot_sha256: str
    closure_id: str
    closure_sha256: str
    local_application_id: str | None
    revocation_id: str | None
    local_revocation_id: str | None
    store_write_performed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "status": self.status.value,
            "workspace_id": self.workspace_id,
            "snapshot_id": self.snapshot_id,
            "snapshot_sha256": self.snapshot_sha256,
            "closure_id": self.closure_id,
            "closure_sha256": self.closure_sha256,
            "local_application_id": self.local_application_id,
            "revocation_id": self.revocation_id,
            "local_revocation_id": self.local_revocation_id,
            "store_write_performed": self.store_write_performed,
        }


def derive_reviewer_role(
    registry: ExpertRegistry,
    profile_id: str,
) -> dict[str, str]:
    if type(registry) is not ExpertRegistry:
        raise StoreError("A validated expert registry is required")
    profile = registry.profiles_by_id.get(_profile_id(profile_id, "reviewer profile ID"))
    if profile is None:
        raise StoreError("Reviewer profile is absent from the exact Army registry")
    policy = next((item for item in registry.policies if item.id == profile.policy_template), None)
    if policy is None:
        raise StoreError("Reviewer policy is absent from the exact Army registry")
    role = {
        "independent-control-v1": ReviewerRole.INDEPENDENT_CONTROL.value,
        "independent-assurance-v1": ReviewerRole.INDEPENDENT_ASSURANCE.value,
    }.get(policy.id, ReviewerRole.TECHNICAL_EVALUATOR.value)
    registry_sha256 = _canonical_sha256(registry.to_dict())
    return {
        "reviewer_profile_id": profile.id,
        "reviewer_role": role,
        "profile_sha256": _canonical_sha256(
            {"domain": "sunderkey.expert-profile.v2", "profile": profile.to_dict()}
        ),
        "policy_template_id": policy.id,
        "policy_template_sha256": _canonical_sha256(
            {"domain": "sunderkey.policy-template.v2", "policy": policy.to_dict()}
        ),
        "registry_sha256": registry_sha256,
    }


def _validate_snapshot(value: dict[str, Any], registry: ExpertRegistry | None) -> None:
    fields = {
        "schema_version",
        "kind",
        "snapshot_id",
        "snapshot_sha256",
        "tenant_id",
        "mission_id",
        "plan_id",
        "workspace_id",
        "workspace_sha256",
        "workspace_schema_version",
        "workspace_revision",
        "workspace_status",
        "runtime_catalog_id",
        "runtime_catalog_version",
        "runtime_catalog_sha256",
        "registry_sha256",
        "target_scope_sha256",
        "authority_snapshot_sha256",
        "evidence_snapshot_sha256",
        "event_count",
        "event_head_sha256",
        "event_head_occurred_at",
        "products",
        "review_slots",
        "review_policy",
        "effects",
    }
    _exact(value, fields, "expert review snapshot")
    for field in (
        "tenant_id",
        "mission_id",
        "plan_id",
        "workspace_id",
        "runtime_catalog_id",
        "runtime_catalog_version",
    ):
        _identifier(value[field], field)
    for field in (
        "workspace_sha256",
        "runtime_catalog_sha256",
        "registry_sha256",
        "target_scope_sha256",
        "authority_snapshot_sha256",
        "evidence_snapshot_sha256",
        "event_head_sha256",
    ):
        _sha256(value[field], field)
    _integer(value["workspace_schema_version"], "workspace_schema_version", 1)
    _integer(value["workspace_revision"], "workspace_revision")
    _integer(value["event_count"], "event_count", 1)
    _integer(value["event_head_occurred_at"], "event_head_occurred_at")
    if value["workspace_status"] != "products_complete_pending_review":
        raise StoreError("Review snapshot workspace status is invalid")
    products = value["products"]
    slots = value["review_slots"]
    if not isinstance(products, list) or not products or len(products) > MAX_TEXT_ITEMS:
        raise StoreError("Review snapshot products are invalid")
    if not isinstance(slots, list) or not slots or len(slots) > MAX_REVIEW_SLOTS:
        raise StoreError("Review snapshot slots are invalid")
    product_by_work: dict[str, dict[str, Any]] = {}
    producer_by_product: dict[str, str] = {}
    for index, raw_product in enumerate(products):
        product = _mapping(raw_product, f"products[{index}]")
        _exact(
            product,
            {
                "work_id",
                "producer_profile_id",
                "command_id",
                "product_id",
                "product_sha256",
                "product_type",
                "envelope_id",
                "envelope_sha256",
                "attempt_number",
                "fencing_token",
                "review_required",
                "dependency_product_ids",
                "lineage_product_ids",
                "disagreement_sha256s",
            },
            f"products[{index}]",
        )
        work_id = _identifier(product["work_id"], "product work ID")
        producer = _profile_id(product["producer_profile_id"], "product producer")
        product_id = _identifier(product["product_id"], "product ID")
        for field in ("product_sha256", "envelope_sha256"):
            _sha256(product[field], field)
        for field in ("command_id", "product_type", "envelope_id"):
            _identifier(product[field], field)
        if registry is not None:
            producer_profile = registry.profiles_by_id.get(producer)
            if producer_profile is None:
                raise StoreError("Product producer is absent from the exact Army registry")
            producer_document = producer_profile.to_dict()
            if producer_document["command_id"] != product["command_id"]:
                raise StoreError("Product command binding is invalid")
            is_commander = producer_document["kind"] == "domain_commander"
            if (product["product_type"] == "commander_synthesis") != is_commander:
                raise StoreError("Product producer role binding is invalid")
        _integer(product["attempt_number"], "attempt_number", 1)
        _integer(product["fencing_token"], "fencing_token", 1)
        if type(product["review_required"]) is not bool:
            raise StoreError("Product review requirement is invalid")
        dependencies = _ordered_strings(product["dependency_product_ids"], "dependencies")
        lineage = _ordered_strings(product["lineage_product_ids"], "lineage")
        _ordered_hashes(product["disagreement_sha256s"], "disagreements")
        if product["product_type"] == "commander_synthesis" and dependencies != lineage:
            raise StoreError("Commander snapshot lineage is incomplete")
        if product["product_type"] != "commander_synthesis" and lineage:
            raise StoreError("Specialist snapshot product has lineage")
        if work_id in product_by_work or product_id in producer_by_product:
            raise StoreError("Review snapshot products contain duplicates")
        product_by_work[work_id] = product
        producer_by_product[product_id] = producer
    if products != sorted(products, key=lambda item: item["work_id"]):
        raise StoreError("Review snapshot products must be ordered")

    products_by_id = {item["product_id"]: item for item in product_by_work.values()}
    lineage_closures: dict[str, set[str]] = {}

    def lineage_closure(product_id: str, visiting: set[str]) -> set[str]:
        cached = lineage_closures.get(product_id)
        if cached is not None:
            return set(cached)
        if product_id in visiting:
            raise StoreError("Review snapshot product lineage contains a cycle")
        product = products_by_id.get(product_id)
        if product is None:
            raise StoreError("Review snapshot product reference is absent")
        visiting.add(product_id)
        closure: set[str] = set()
        for child_id in product["lineage_product_ids"]:
            if child_id not in producer_by_product:
                raise StoreError("Review snapshot lineage product is absent")
            closure.add(child_id)
            closure.update(lineage_closure(child_id, visiting))
        visiting.remove(product_id)
        lineage_closures[product_id] = set(closure)
        return closure

    for product in product_by_work.values():
        if any(
            dependency_id not in producer_by_product
            for dependency_id in product["dependency_product_ids"]
        ):
            raise StoreError("Review snapshot dependency product is absent")
        lineage_closure(product["product_id"], set())
    slot_keys: set[tuple[str, str]] = set()
    roles_by_work: dict[str, set[str]] = {key: set() for key in product_by_work}
    for index, raw_slot in enumerate(slots):
        slot = _mapping(raw_slot, f"review_slots[{index}]")
        _exact(
            slot,
            {
                "work_id",
                "product_id",
                "product_sha256",
                "reviewer_profile_id",
                "reviewer_role",
                "profile_sha256",
                "policy_template_id",
                "policy_template_sha256",
                "registry_sha256",
                "producer_profile_ids_excluded",
            },
            f"review_slots[{index}]",
        )
        work_id = _identifier(slot["work_id"], "slot work ID")
        product = product_by_work.get(work_id)
        if (
            product is None
            or product["product_id"] != slot["product_id"]
            or product["product_sha256"] != slot["product_sha256"]
        ):
            raise StoreError("Review slot product binding is invalid")
        reviewer = _profile_id(slot["reviewer_profile_id"], "reviewer profile ID")
        try:
            role = ReviewerRole(slot["reviewer_role"])
        except (TypeError, ValueError) as exc:
            raise StoreError("Review slot role is invalid") from exc
        excluded = _ordered_strings(
            slot["producer_profile_ids_excluded"],
            "excluded producers",
            allow_empty=False,
            profiles=True,
        )
        expected_excluded = {product["producer_profile_id"]}
        expected_excluded.update(
            producer_by_product[product_id]
            for product_id in lineage_closures[product["product_id"]]
        )
        if set(excluded) != expected_excluded or reviewer in expected_excluded:
            raise StoreError("Review slot producer separation is invalid")
        for field in (
            "product_sha256",
            "profile_sha256",
            "policy_template_sha256",
            "registry_sha256",
        ):
            _sha256(slot[field], field)
        _identifier(slot["policy_template_id"], "policy template ID")
        if slot["registry_sha256"] != value["registry_sha256"]:
            raise StoreError("Review slot registry binding is invalid")
        if registry is not None:
            expected = derive_reviewer_role(registry, reviewer)
            if any(slot[key] != expected[key] for key in expected):
                raise StoreError("Review slot role derivation is invalid")
        key = (work_id, reviewer)
        if key in slot_keys:
            raise StoreError("Review slots contain duplicates")
        slot_keys.add(key)
        roles_by_work[work_id].add(role.value)
    if slots != sorted(slots, key=lambda item: (item["work_id"], item["reviewer_profile_id"])):
        raise StoreError("Review slots must be ordered")
    for work_id, product in product_by_work.items():
        roles = roles_by_work[work_id]
        if not product["review_required"] and roles:
            raise StoreError("Optional product has mandatory review slots")
        if product["review_required"] and ReviewerRole.INDEPENDENT_ASSURANCE.value not in roles:
            raise StoreError("Required review lacks independent Assurance")
        if (
            product["review_required"]
            and product["product_type"] in {"action_proposal", "commander_synthesis"}
            and ReviewerRole.INDEPENDENT_CONTROL.value not in roles
        ):
            raise StoreError("High-impact review lacks independent Control")
    policy = _mapping(value["review_policy"], "review policy")
    expected_policy_body = {
        "all_slots_mandatory": True,
        "decision_precedence": ["rejected", "rework_required", "accepted"],
        "policy_id": "sunderkey.expert-review-policy.v1",
        "producer_and_lineage_excluded": True,
        "schema_version": 1,
    }
    expected_policy_sha = _canonical_sha256(expected_policy_body)
    if (
        policy != {**expected_policy_body, "policy_sha256": expected_policy_sha}
        or type(policy["all_slots_mandatory"]) is not bool
        or type(policy["producer_and_lineage_excluded"]) is not bool
        or type(policy["schema_version"]) is not int
    ):
        raise StoreError("Review snapshot policy is invalid")
    if registry is not None and value["registry_sha256"] != _canonical_sha256(registry.to_dict()):
        raise StoreError("Review snapshot registry substitution detected")
    _validate_addressed_record(value, "expert_review_snapshot")


def parse_expert_review_snapshot(
    raw: Any,
    registry: ExpertRegistry | None = None,
) -> ExpertReviewSnapshot:
    value = _mapping(raw, "expert review snapshot")
    _validate_snapshot(value, registry)
    return ExpertReviewSnapshot(_canonical_json(value))


def build_expert_review_snapshot(
    body: Mapping[str, Any],
    registry: ExpertRegistry,
) -> ExpertReviewSnapshot:
    value = _mapping(body, "expert review snapshot body")
    if "snapshot_id" in value or "snapshot_sha256" in value:
        raise StoreError("Expert review snapshot body is already addressed")
    return parse_expert_review_snapshot(
        _address_record("expert_review_snapshot", value),
        registry,
    )


def _submission_fields() -> set[str]:
    return {
        "schema_version",
        "kind",
        "submission_id",
        "submission_sha256",
        "snapshot_id",
        "snapshot_sha256",
        "work_id",
        "product_id",
        "product_sha256",
        "reviewer_profile_id",
        "reviewer_role",
        "decision",
        "reason_code",
        "evidence_reference_sha256s",
        "affected_work_ids",
        "required_correction_ids",
        "rationale",
        "effects",
    }


def parse_expert_review_submission(raw: Any) -> ExpertReviewSubmission:
    value = _mapping(raw, "expert review submission")
    _exact(value, _submission_fields(), "expert review submission")
    for field in ("snapshot_id", "work_id", "product_id", "reason_code"):
        _identifier(value[field], field)
    for field in ("snapshot_sha256", "product_sha256"):
        _sha256(value[field], field)
    _profile_id(value["reviewer_profile_id"], "reviewer profile ID")
    try:
        ReviewerRole(value["reviewer_role"])
        ReviewDecision(value["decision"])
    except (TypeError, ValueError) as exc:
        raise StoreError("Review submission role or decision is invalid") from exc
    _ordered_hashes(value["evidence_reference_sha256s"], "evidence references")
    _ordered_strings(value["affected_work_ids"], "affected work IDs")
    _ordered_strings(value["required_correction_ids"], "correction IDs")
    if not isinstance(value["rationale"], str) or not value["rationale"]:
        raise StoreError("Review rationale is invalid")
    _validate_addressed_record(value, "expert_review_submission")
    return ExpertReviewSubmission(_canonical_json(value))


def build_expert_review_submission(
    *,
    snapshot: ExpertReviewSnapshot,
    work_id: str,
    product_id: str,
    product_sha256: str,
    reviewer_profile_id: str,
    reviewer_role: ReviewerRole | str,
    decision: ReviewDecision | str,
    reason_code: str,
    evidence_reference_sha256s: Sequence[str] = (),
    affected_work_ids: Sequence[str] = (),
    required_correction_ids: Sequence[str] = (),
    rationale: str,
) -> ExpertReviewSubmission:
    role = ReviewerRole(reviewer_role)
    parsed_decision = ReviewDecision(decision)
    body = {
        "schema_version": 1,
        "kind": "expert_review_submission",
        "snapshot_id": snapshot.snapshot_id,
        "snapshot_sha256": snapshot.snapshot_sha256,
        "work_id": work_id,
        "product_id": product_id,
        "product_sha256": product_sha256,
        "reviewer_profile_id": reviewer_profile_id,
        "reviewer_role": role.value,
        "decision": parsed_decision.value,
        "reason_code": reason_code,
        "evidence_reference_sha256s": sorted(evidence_reference_sha256s),
        "affected_work_ids": sorted(affected_work_ids),
        "required_correction_ids": sorted(required_correction_ids),
        "rationale": rationale,
        "effects": dict(NO_EFFECTS),
    }
    return parse_expert_review_submission(_address_record("expert_review_submission", body))


def parse_authenticated_expert_review_receipt(raw: Any) -> AuthenticatedExpertReviewReceipt:
    value = _mapping(raw, "authenticated expert review receipt")
    fields = {
        "schema_version",
        "kind",
        "receipt_id",
        "receipt_sha256",
        "submission_id",
        "submission_sha256",
        "submission",
        "reviewer_subject",
        "assertion_issuer",
        "assertion_id",
        "assertion_sha256",
        "assertion_key_sha256",
        "trust_policy_sha256",
        "scope_grant_sha256",
        "operation_intent_sha256",
        "canonical_replay_key_sha256",
        "recorded_at",
        "identity_assurance",
        "effects",
    }
    _exact(value, fields, "authenticated expert review receipt")
    submission = parse_expert_review_submission(value["submission"])
    if (
        value["submission_id"] != submission.submission_id
        or value["submission_sha256"] != submission.submission_sha256
    ):
        raise StoreError("Review receipt submission binding is invalid")
    for field in ("reviewer_subject", "assertion_issuer", "assertion_id"):
        _identifier(value[field], field)
    if value["reviewer_subject"] == value["assertion_issuer"]:
        raise StoreError("Review assertion issuer and subject must differ")
    for field in (
        "assertion_sha256",
        "assertion_key_sha256",
        "trust_policy_sha256",
        "scope_grant_sha256",
        "operation_intent_sha256",
        "canonical_replay_key_sha256",
    ):
        _sha256(value[field], field)
    _integer(value["recorded_at"], "recorded_at")
    if value["identity_assurance"] != "mission_store_principal_assertion":
        raise StoreError("Review receipt identity assurance is invalid")
    _validate_addressed_record(value, "authenticated_expert_review_receipt")
    return AuthenticatedExpertReviewReceipt(_canonical_json(value))


def build_authenticated_expert_review_receipt(
    submission: ExpertReviewSubmission,
    *,
    reviewer_subject: str,
    assertion_issuer: str,
    assertion_id: str,
    assertion_sha256: str,
    assertion_key_sha256: str,
    trust_policy_sha256: str,
    scope_grant_sha256: str,
    operation_intent_sha256: str,
    canonical_replay_key_sha256: str,
    recorded_at: int,
) -> AuthenticatedExpertReviewReceipt:
    if type(submission) is not ExpertReviewSubmission:
        raise StoreError("A validated review submission is required")
    body = {
        "schema_version": 1,
        "kind": "authenticated_expert_review_receipt",
        "submission_id": submission.submission_id,
        "submission_sha256": submission.submission_sha256,
        "submission": submission.to_dict(),
        "reviewer_subject": reviewer_subject,
        "assertion_issuer": assertion_issuer,
        "assertion_id": assertion_id,
        "assertion_sha256": assertion_sha256,
        "assertion_key_sha256": assertion_key_sha256,
        "trust_policy_sha256": trust_policy_sha256,
        "scope_grant_sha256": scope_grant_sha256,
        "operation_intent_sha256": operation_intent_sha256,
        "canonical_replay_key_sha256": canonical_replay_key_sha256,
        "recorded_at": recorded_at,
        "identity_assurance": "mission_store_principal_assertion",
        "effects": dict(NO_EFFECTS),
    }
    return parse_authenticated_expert_review_receipt(
        _address_record("authenticated_expert_review_receipt", body)
    )


def parse_expert_review_closure_request(raw: Any) -> ExpertReviewClosureRequest:
    value = _mapping(raw, "expert review closure request")
    fields = {
        "schema_version",
        "kind",
        "closure_request_id",
        "closure_request_sha256",
        "snapshot_id",
        "snapshot_sha256",
        "review_receipts",
        "expected_disposition",
        "closer_profile_id",
        "requested_at",
        "effects",
    }
    _exact(value, fields, "expert review closure request")
    _identifier(value["snapshot_id"], "snapshot ID")
    _sha256(value["snapshot_sha256"], "snapshot hash")
    receipts = value["review_receipts"]
    if not isinstance(receipts, list) or not receipts or len(receipts) > MAX_REVIEW_SLOTS:
        raise StoreError("Closure request review receipts are invalid")
    keys: list[str] = []
    for index, item in enumerate(receipts):
        binding = _mapping(item, f"review_receipts[{index}]")
        _exact(binding, {"receipt_id", "receipt_sha256"}, "review receipt binding")
        keys.append(_identifier(binding["receipt_id"], "review receipt ID"))
        _sha256(binding["receipt_sha256"], "review receipt hash")
    if keys != sorted(set(keys)):
        raise StoreError("Closure review receipt bindings must be unique and ordered")
    try:
        ClosureDisposition(value["expected_disposition"])
    except (TypeError, ValueError) as exc:
        raise StoreError("Closure request disposition is invalid") from exc
    _profile_id(value["closer_profile_id"], "closer profile ID")
    _integer(value["requested_at"], "requested_at")
    _validate_addressed_record(value, "expert_review_closure_request")
    return ExpertReviewClosureRequest(_canonical_json(value))


def build_expert_review_closure_request(
    snapshot: ExpertReviewSnapshot,
    receipts: Sequence[AuthenticatedExpertReviewReceipt],
    *,
    expected_disposition: ClosureDisposition | str,
    closer_profile_id: str,
    requested_at: int,
) -> ExpertReviewClosureRequest:
    bindings = sorted(
        (
            {"receipt_id": item.receipt_id, "receipt_sha256": item.receipt_sha256}
            for item in receipts
        ),
        key=lambda item: item["receipt_id"],
    )
    body = {
        "schema_version": 1,
        "kind": "expert_review_closure_request",
        "snapshot_id": snapshot.snapshot_id,
        "snapshot_sha256": snapshot.snapshot_sha256,
        "review_receipts": bindings,
        "expected_disposition": ClosureDisposition(expected_disposition).value,
        "closer_profile_id": closer_profile_id,
        "requested_at": requested_at,
        "effects": dict(NO_EFFECTS),
    }
    return parse_expert_review_closure_request(
        _address_record("expert_review_closure_request", body)
    )


def parse_expert_review_closure_certificate(raw: Any) -> ExpertReviewClosureCertificate:
    value = _mapping(raw, "expert review closure certificate")
    fields = {
        "schema_version",
        "kind",
        "closure_id",
        "closure_sha256",
        "closure_request_id",
        "closure_request_sha256",
        "snapshot_id",
        "snapshot_sha256",
        "review_receipt_ids",
        "review_set_sha256",
        "disposition",
        "rejected_work_ids",
        "rework_work_ids",
        "required_correction_ids",
        "closer_subject",
        "closer_profile_id",
        "assertion_issuer",
        "assertion_id",
        "assertion_sha256",
        "assertion_key_sha256",
        "trust_policy_sha256",
        "scope_grant_sha256",
        "operation_intent_sha256",
        "canonical_replay_key_sha256",
        "closed_at",
        "identity_assurance",
        "effects",
    }
    _exact(value, fields, "expert review closure certificate")
    for field in (
        "closure_request_id",
        "snapshot_id",
        "closer_subject",
        "assertion_issuer",
        "assertion_id",
    ):
        _identifier(value[field], field)
    _profile_id(value["closer_profile_id"], "closer profile ID")
    for field in (
        "closure_request_sha256",
        "snapshot_sha256",
        "review_set_sha256",
        "assertion_sha256",
        "assertion_key_sha256",
        "trust_policy_sha256",
        "scope_grant_sha256",
        "operation_intent_sha256",
        "canonical_replay_key_sha256",
    ):
        _sha256(value[field], field)
    _ordered_strings(value["review_receipt_ids"], "review receipt IDs", allow_empty=False)
    _ordered_strings(value["rejected_work_ids"], "rejected work IDs")
    _ordered_strings(value["rework_work_ids"], "rework work IDs")
    _ordered_strings(value["required_correction_ids"], "required correction IDs")
    try:
        ClosureDisposition(value["disposition"])
    except (TypeError, ValueError) as exc:
        raise StoreError("Closure disposition is invalid") from exc
    if value["closer_subject"] == value["assertion_issuer"]:
        raise StoreError("Closure assertion issuer and subject must differ")
    _integer(value["closed_at"], "closed_at")
    if value["identity_assurance"] != "mission_store_principal_assertion":
        raise StoreError("Closure identity assurance is invalid")
    _validate_addressed_record(value, "expert_review_closure_certificate")
    return ExpertReviewClosureCertificate(_canonical_json(value))


def build_expert_review_closure_certificate(
    request: ExpertReviewClosureRequest,
    *,
    review_receipt_ids: Sequence[str],
    review_set_sha256: str,
    disposition: ClosureDisposition | str,
    rejected_work_ids: Sequence[str],
    rework_work_ids: Sequence[str],
    required_correction_ids: Sequence[str],
    closer_subject: str,
    closer_profile_id: str,
    assertion_issuer: str,
    assertion_id: str,
    assertion_sha256: str,
    assertion_key_sha256: str,
    trust_policy_sha256: str,
    scope_grant_sha256: str,
    operation_intent_sha256: str,
    canonical_replay_key_sha256: str,
    closed_at: int,
) -> ExpertReviewClosureCertificate:
    body = {
        "schema_version": 1,
        "kind": "expert_review_closure_certificate",
        "closure_request_id": request.closure_request_id,
        "closure_request_sha256": request.closure_request_sha256,
        "snapshot_id": request.to_dict()["snapshot_id"],
        "snapshot_sha256": request.to_dict()["snapshot_sha256"],
        "review_receipt_ids": sorted(review_receipt_ids),
        "review_set_sha256": review_set_sha256,
        "disposition": ClosureDisposition(disposition).value,
        "rejected_work_ids": sorted(rejected_work_ids),
        "rework_work_ids": sorted(rework_work_ids),
        "required_correction_ids": sorted(required_correction_ids),
        "closer_subject": closer_subject,
        "closer_profile_id": closer_profile_id,
        "assertion_issuer": assertion_issuer,
        "assertion_id": assertion_id,
        "assertion_sha256": assertion_sha256,
        "assertion_key_sha256": assertion_key_sha256,
        "trust_policy_sha256": trust_policy_sha256,
        "scope_grant_sha256": scope_grant_sha256,
        "operation_intent_sha256": operation_intent_sha256,
        "canonical_replay_key_sha256": canonical_replay_key_sha256,
        "closed_at": closed_at,
        "identity_assurance": "mission_store_principal_assertion",
        "effects": dict(NO_EFFECTS),
    }
    return parse_expert_review_closure_certificate(
        _address_record("expert_review_closure_certificate", body)
    )


def parse_expert_review_closure_revocation(raw: Any) -> ExpertReviewClosureRevocation:
    value = _mapping(raw, "expert review closure revocation")
    fields = {
        "schema_version",
        "kind",
        "revocation_id",
        "revocation_sha256",
        "closure_id",
        "closure_sha256",
        "reason_code",
        "control_subject",
        "control_profile_id",
        "assertion_issuer",
        "assertion_id",
        "assertion_sha256",
        "operation_intent_sha256",
        "canonical_replay_key_sha256",
        "revoked_at",
        "identity_assurance",
        "effects",
    }
    _exact(value, fields, "expert review closure revocation")
    for field in (
        "closure_id",
        "reason_code",
        "control_subject",
        "assertion_issuer",
        "assertion_id",
    ):
        _identifier(value[field], field)
    _profile_id(value["control_profile_id"], "control profile ID")
    for field in (
        "closure_sha256",
        "assertion_sha256",
        "operation_intent_sha256",
        "canonical_replay_key_sha256",
    ):
        _sha256(value[field], field)
    if value["control_subject"] == value["assertion_issuer"]:
        raise StoreError("Revocation issuer and subject must differ")
    _integer(value["revoked_at"], "revoked_at")
    if value["identity_assurance"] != "mission_store_principal_assertion":
        raise StoreError("Revocation identity assurance is invalid")
    _validate_addressed_record(value, "expert_review_closure_revocation")
    return ExpertReviewClosureRevocation(_canonical_json(value))


def build_expert_review_closure_revocation(
    closure: ExpertReviewClosureCertificate,
    *,
    reason_code: str,
    control_subject: str,
    control_profile_id: str,
    assertion_issuer: str,
    assertion_id: str,
    assertion_sha256: str,
    operation_intent_sha256: str,
    canonical_replay_key_sha256: str,
    revoked_at: int,
) -> ExpertReviewClosureRevocation:
    body = {
        "schema_version": 1,
        "kind": "expert_review_closure_revocation",
        "closure_id": closure.closure_id,
        "closure_sha256": closure.closure_sha256,
        "reason_code": reason_code,
        "control_subject": control_subject,
        "control_profile_id": control_profile_id,
        "assertion_issuer": assertion_issuer,
        "assertion_id": assertion_id,
        "assertion_sha256": assertion_sha256,
        "operation_intent_sha256": operation_intent_sha256,
        "canonical_replay_key_sha256": canonical_replay_key_sha256,
        "revoked_at": revoked_at,
        "identity_assurance": "mission_store_principal_assertion",
        "effects": dict(NO_EFFECTS),
    }
    return parse_expert_review_closure_revocation(
        _address_record("expert_review_closure_revocation", body)
    )


def parse_expert_workspace_closure_application(
    raw: Any,
) -> ExpertWorkspaceClosureApplication:
    value = _mapping(raw, "expert workspace closure application")
    fields = {
        "schema_version",
        "kind",
        "application_id",
        "application_sha256",
        "mission_store_id",
        "workspace_id",
        "snapshot_id",
        "snapshot_sha256",
        "closure_id",
        "closure_sha256",
        "disposition",
        "workspace_revision_before",
        "workspace_revision_after",
        "event_head_before_sha256",
        "applied_at",
        "effects",
    }
    _exact(value, fields, "expert workspace closure application")
    for field in ("mission_store_id", "workspace_id", "snapshot_id", "closure_id"):
        _identifier(value[field], field)
    for field in ("snapshot_sha256", "closure_sha256", "event_head_before_sha256"):
        _sha256(value[field], field)
    try:
        ClosureDisposition(value["disposition"])
    except (TypeError, ValueError) as exc:
        raise StoreError("Workspace closure disposition is invalid") from exc
    before = _integer(value["workspace_revision_before"], "workspace_revision_before")
    after = _integer(value["workspace_revision_after"], "workspace_revision_after", 1)
    if after != before + 1:
        raise StoreError("Workspace closure revision transition is invalid")
    _integer(value["applied_at"], "applied_at")
    _validate_addressed_record(value, "expert_workspace_closure_application")
    return ExpertWorkspaceClosureApplication(_canonical_json(value))


def build_expert_workspace_closure_application(
    *,
    mission_store_id: str,
    workspace_id: str,
    snapshot: ExpertReviewSnapshot,
    closure: ExpertReviewClosureCertificate,
    workspace_revision_before: int,
    event_head_before_sha256: str,
    applied_at: int,
) -> ExpertWorkspaceClosureApplication:
    body = {
        "schema_version": 1,
        "kind": "expert_workspace_closure_application",
        "mission_store_id": mission_store_id,
        "workspace_id": workspace_id,
        "snapshot_id": snapshot.snapshot_id,
        "snapshot_sha256": snapshot.snapshot_sha256,
        "closure_id": closure.closure_id,
        "closure_sha256": closure.closure_sha256,
        "disposition": closure.to_dict()["disposition"],
        "workspace_revision_before": workspace_revision_before,
        "workspace_revision_after": workspace_revision_before + 1,
        "event_head_before_sha256": event_head_before_sha256,
        "applied_at": applied_at,
        "effects": dict(NO_EFFECTS),
    }
    return parse_expert_workspace_closure_application(
        _address_record("expert_workspace_closure_application", body)
    )


def review_set_sha256(receipts: Sequence[AuthenticatedExpertReviewReceipt]) -> str:
    bindings = sorted(
        (
            {"receipt_id": item.receipt_id, "receipt_sha256": item.receipt_sha256}
            for item in receipts
        ),
        key=lambda item: item["receipt_id"],
    )
    return _canonical_sha256(
        {"domain": "sunderkey.expert-review-set.v1", "review_receipts": bindings}
    )


def _derived_disposition(
    receipts: Sequence[AuthenticatedExpertReviewReceipt],
) -> ClosureDisposition:
    decisions = {ReviewDecision(item.to_dict()["submission"]["decision"]) for item in receipts}
    if ReviewDecision.REJECTED in decisions:
        return ClosureDisposition.REJECTED
    if ReviewDecision.REWORK_REQUIRED in decisions:
        return ClosureDisposition.REWORK_REQUIRED
    return ClosureDisposition.ACCEPTED


def verify_expert_review_record_set(
    records: ExpertReviewRecordSet,
    registry: ExpertRegistry,
) -> ExpertReviewRecordSet:
    if type(records) is not ExpertReviewRecordSet:
        raise StoreError("An expert review record set is required")
    snapshot = parse_expert_review_snapshot(records.snapshot.to_dict(), registry)
    receipts = tuple(
        parse_authenticated_expert_review_receipt(item.to_dict()) for item in records.receipts
    )
    request = parse_expert_review_closure_request(records.closure_request.to_dict())
    closure = parse_expert_review_closure_certificate(records.closure.to_dict())
    revocation = (
        None
        if records.revocation is None
        else parse_expert_review_closure_revocation(records.revocation.to_dict())
    )
    snapshot_document = snapshot.to_dict()
    slots = {
        (item["work_id"], item["reviewer_profile_id"]): item
        for item in snapshot_document["review_slots"]
    }
    products = {item["work_id"]: item for item in snapshot_document["products"]}
    seen_slots: set[tuple[str, str]] = set()
    subjects_by_work: dict[str, set[str]] = {}
    reviewer_subjects: set[str] = set()
    assertion_identities: set[tuple[str, str, str]] = set()
    replay_keys: set[str] = set()
    rejected_work_ids: set[str] = set()
    rework_work_ids: set[str] = set()
    correction_ids: set[str] = set()
    for receipt in receipts:
        document = receipt.to_dict()
        submission = document["submission"]
        if (
            submission["snapshot_id"] != snapshot.snapshot_id
            or submission["snapshot_sha256"] != snapshot.snapshot_sha256
        ):
            raise StoreError("Review receipt snapshot binding is invalid")
        key = (submission["work_id"], submission["reviewer_profile_id"])
        slot = slots.get(key)
        if slot is None or key in seen_slots:
            raise StoreError("Review receipt slot binding is invalid")
        if any(
            submission[field] != slot[field]
            for field in ("product_id", "product_sha256", "reviewer_role")
        ):
            raise StoreError("Review receipt product or role binding is invalid")
        if not set(submission["affected_work_ids"]).issubset(products):
            raise StoreError("Review submission affects work outside the snapshot")
        if submission["decision"] == ReviewDecision.REWORK_REQUIRED.value:
            if not submission["required_correction_ids"]:
                raise StoreError("Rework review requires at least one correction")
        elif submission["affected_work_ids"] or submission["required_correction_ids"]:
            raise StoreError("Non-rework review cannot carry rework instructions")
        subject = document["reviewer_subject"]
        work_subjects = subjects_by_work.setdefault(submission["work_id"], set())
        if subject in work_subjects:
            raise StoreError("One subject cannot fill multiple slots for one product")
        work_subjects.add(subject)
        reviewer_subjects.add(subject)
        assertion_identity = (
            document["assertion_issuer"],
            document["assertion_id"],
            document["assertion_sha256"],
        )
        replay_key = document["canonical_replay_key_sha256"]
        if assertion_identity in assertion_identities or replay_key in replay_keys:
            raise StoreError("Review authority or replay identity is reused")
        assertion_identities.add(assertion_identity)
        replay_keys.add(replay_key)
        seen_slots.add(key)
        if submission["decision"] == ReviewDecision.REJECTED.value:
            rejected_work_ids.add(submission["work_id"])
        if submission["decision"] == ReviewDecision.REWORK_REQUIRED.value:
            rework_work_ids.update(submission["affected_work_ids"] or [submission["work_id"]])
            correction_ids.update(submission["required_correction_ids"])
    if seen_slots != set(slots):
        raise StoreError("Closure requires one review for every mandatory slot")
    if any(
        item.to_dict()["recorded_at"] < snapshot_document["event_head_occurred_at"]
        for item in receipts
    ):
        raise StoreError("Review receipt predates the snapshot event head")
    request_document = request.to_dict()
    if request_document["requested_at"] < max(item.to_dict()["recorded_at"] for item in receipts):
        raise StoreError("Closure request predates a review receipt")
    expected_bindings = sorted(
        (
            {"receipt_id": item.receipt_id, "receipt_sha256": item.receipt_sha256}
            for item in receipts
        ),
        key=lambda item: item["receipt_id"],
    )
    disposition = _derived_disposition(receipts)
    if (
        request_document["snapshot_id"] != snapshot.snapshot_id
        or request_document["snapshot_sha256"] != snapshot.snapshot_sha256
        or request_document["review_receipts"] != expected_bindings
        or request_document["expected_disposition"] != disposition.value
    ):
        raise StoreError("Closure request bindings are invalid")
    closer_binding = derive_reviewer_role(registry, request_document["closer_profile_id"])
    if closer_binding["reviewer_role"] != ReviewerRole.INDEPENDENT_CONTROL.value:
        raise StoreError("Closure requires an independent Control profile")
    closure_document = closure.to_dict()
    if closure_document["closed_at"] < request_document["requested_at"]:
        raise StoreError("Closure certificate predates its request")
    closure_assertion_identity = (
        closure_document["assertion_issuer"],
        closure_document["assertion_id"],
        closure_document["assertion_sha256"],
    )
    closure_replay_key = closure_document["canonical_replay_key_sha256"]
    if closure_assertion_identity in assertion_identities or closure_replay_key in replay_keys:
        raise StoreError("Closure authority or replay identity is reused")
    assertion_identities.add(closure_assertion_identity)
    replay_keys.add(closure_replay_key)
    expected_receipt_ids = sorted(item.receipt_id for item in receipts)
    if (
        closure_document["closure_request_id"] != request.closure_request_id
        or closure_document["closure_request_sha256"] != request.closure_request_sha256
        or closure_document["snapshot_id"] != snapshot.snapshot_id
        or closure_document["snapshot_sha256"] != snapshot.snapshot_sha256
        or closure_document["review_receipt_ids"] != expected_receipt_ids
        or closure_document["review_set_sha256"] != review_set_sha256(receipts)
        or closure_document["disposition"] != disposition.value
        or closure_document["rejected_work_ids"] != sorted(rejected_work_ids)
        or closure_document["rework_work_ids"] != sorted(rework_work_ids)
        or closure_document["required_correction_ids"] != sorted(correction_ids)
        or closure_document["closer_profile_id"] != request_document["closer_profile_id"]
    ):
        raise StoreError("Closure certificate bindings are invalid")
    producer_profiles = {item["producer_profile_id"] for item in products.values()}
    if closure_document["closer_subject"] in reviewer_subjects:
        raise StoreError("Closure subject must be distinct from reviewers")
    if closure_document["closer_profile_id"] in producer_profiles:
        raise StoreError("Closure profile must be distinct from producers")
    if revocation is not None:
        revocation_document = revocation.to_dict()
        if (
            revocation_document["closure_id"] != closure.closure_id
            or revocation_document["closure_sha256"] != closure.closure_sha256
        ):
            raise StoreError("Closure revocation binding is invalid")
        control = derive_reviewer_role(registry, revocation_document["control_profile_id"])
        if control["reviewer_role"] != ReviewerRole.INDEPENDENT_CONTROL.value:
            raise StoreError("Closure revocation requires independent Control")
        if revocation_document["revoked_at"] < closure_document["closed_at"]:
            raise StoreError("Closure revocation predates the closure")
        revocation_assertion_identity = (
            revocation_document["assertion_issuer"],
            revocation_document["assertion_id"],
            revocation_document["assertion_sha256"],
        )
        if (
            revocation_assertion_identity in assertion_identities
            or revocation_document["canonical_replay_key_sha256"] in replay_keys
        ):
            raise StoreError("Revocation authority or replay identity is reused")
    return ExpertReviewRecordSet(snapshot, receipts, request, closure, revocation)


def record_from_stored_json(raw: Any, kind: str) -> _PortableRecord:
    parsers = {
        "expert_review_snapshot": parse_expert_review_snapshot,
        "expert_review_submission": parse_expert_review_submission,
        "authenticated_expert_review_receipt": parse_authenticated_expert_review_receipt,
        "expert_review_closure_request": parse_expert_review_closure_request,
        "expert_review_closure_certificate": parse_expert_review_closure_certificate,
        "expert_review_closure_revocation": parse_expert_review_closure_revocation,
        "expert_workspace_closure_application": parse_expert_workspace_closure_application,
    }
    try:
        return parsers[kind](raw)
    except KeyError as exc:
        raise StoreIntegrityError("Stored expert review record kind is invalid") from exc
    except StoreError as exc:
        raise StoreIntegrityError("Stored expert review record is invalid") from exc


__all__ = [
    "APPLICATION_DOMAIN",
    "AuthenticatedExpertReviewReceipt",
    "ClosureDisposition",
    "ExpertReviewClosureCertificate",
    "ExpertReviewClosureRequest",
    "ExpertReviewClosureRevocation",
    "ExpertReviewReconciliationReport",
    "ExpertReviewRecordSet",
    "ExpertReviewSnapshot",
    "ExpertReviewSubmission",
    "ExpertWorkspaceClosureApplication",
    "NO_EFFECTS",
    "ReconciliationStatus",
    "ReviewDecision",
    "ReviewerRole",
    "build_authenticated_expert_review_receipt",
    "build_expert_review_closure_certificate",
    "build_expert_review_closure_request",
    "build_expert_review_closure_revocation",
    "build_expert_review_snapshot",
    "build_expert_review_submission",
    "build_expert_workspace_closure_application",
    "derive_reviewer_role",
    "parse_authenticated_expert_review_receipt",
    "parse_expert_review_closure_certificate",
    "parse_expert_review_closure_request",
    "parse_expert_review_closure_revocation",
    "parse_expert_review_snapshot",
    "parse_expert_review_submission",
    "parse_expert_workspace_closure_application",
    "record_from_stored_json",
    "review_set_sha256",
    "verify_expert_review_record_set",
]
