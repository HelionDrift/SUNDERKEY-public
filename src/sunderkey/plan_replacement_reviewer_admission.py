"""Signed, mission-scoped custody for replacement reviewers, not target authority."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .authenticated_collaboration import AuthenticatedCollaborationActivationService
from .authenticated_collaboration_mission_policy import (
    AuthenticatedCollaborationMissionPolicyService,
)
from .authenticated_work import AuthenticatedWorkItemLeaseService
from .collaboration_mission_policy import CollaborationMissionReconfigurationPolicy
from .errors import (
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from .events import MISSION_ID_PATTERN
from .identity import (
    PrincipalAssertion,
    PrincipalOperation,
    ScopeGrant,
    TrustKeyState,
    TrustKeyUse,
    VerifiedTrustPolicy,
    _load_json_file,
    verify_principal_assertion,
    verify_scope_grant,
)
from .registry import ExpertRegistry
from .store import (
    PLAN_REPLACEMENT_REVIEWER_ADMISSION_SCHEMA_VERSION,
    MissionStore,
    StoredMission,
    canonical_json,
    format_timestamp,
    parse_timestamp,
    sha256_text,
)
from .types import ProfileKind

ADMISSION_DOMAIN = "sunderkey.collaboration.plan-replacement.reviewer-admission.v1"
ADMISSION_ID_PATTERN = re.compile(r"RVA-[0-9A-F]{32}\Z")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
REVIEWER_OPERATIONS = MappingProxyType(
    {
        "independent_control": PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_CONTROL_APPROVE,
        "second_control": PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_SECOND_CONTROL_APPROVE,
        "independent_assurance": (
            PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_ASSURANCE_APPROVE
        ),
    }
)
_APPROVAL_OPERATIONS = MappingProxyType(
    {
        "mission_owner": PrincipalOperation.COLLABORATION_REPLACEMENT_REVIEWER_OWNER_AUTHORIZE,
        "independent_control": (
            PrincipalOperation.COLLABORATION_REPLACEMENT_REVIEWER_CONTROL_APPROVE
        ),
    }
)
_FIELDS = {
    "schema_version",
    "admission_id",
    "admission_sha256",
    "store_id",
    "audience",
    "mission_id",
    "mission_context_sha256",
    "active_plan_id",
    "active_plan_content_sha256",
    "active_plan_version",
    "mission_policy_id",
    "mission_policy_sha256",
    "admission_sequence",
    "previous_admission_sha256",
    "principal_ledger",
    "reviewer",
    "issued_at",
    "not_before",
    "expires_at",
    "review_only",
    "target_authority",
}


def _fail(message: str) -> PrincipalAuthenticationError:
    return PrincipalAuthenticationError(message)


def _object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if (
        type(value) is not dict
        or len(value) != len(fields)
        or any(type(key) is not str for key in value)
        or set(value) != fields
    ):
        raise _fail(f"{label} must have exactly its declared fields")
    return value


def _native_json(value: Any) -> None:
    if value is None or type(value) in {str, int, bool}:
        return
    if type(value) is list:
        for item in value:
            _native_json(item)
        return
    if type(value) is dict and all(type(key) is str for key in value):
        for item in value.values():
            _native_json(item)
        return
    raise _fail("Reviewer admission requires exact JSON primitives")


def _text(value: Any, label: str) -> str:
    if type(value) is not str or not value or value.strip() != value:
        raise _fail(f"{label} must be nonblank text")
    return value


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise _fail(f"{label} must be a SHA-256 digest")
    return value


def _integer(value: Any, label: str, minimum: int) -> int:
    if type(value) is not int or value < minimum:
        raise _fail(f"{label} must be an integer at least {minimum}")
    return value


def _time(value: Any, label: str) -> datetime:
    text = _text(value, label)
    parsed = parse_timestamp(text, label)
    if format_timestamp(parsed) != text:
        raise _fail(f"{label} must use canonical UTC timestamp text")
    return parsed


def _request_digest(document: dict[str, Any]) -> str:
    body = {key: value for key, value in document.items() if key != "admission_sha256"}
    return sha256_text(canonical_json({"domain": ADMISSION_DOMAIN, "admission": body}))


def _parse_request(raw: Any) -> dict[str, Any]:
    value = _object(raw, _FIELDS, "Reviewer admission")
    _native_json(value)
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise _fail("Reviewer admission schema_version must be integer 1")
    if (
        type(value["admission_id"]) is not str
        or ADMISSION_ID_PATTERN.fullmatch(value["admission_id"]) is None
    ):
        raise _fail("Reviewer admission identity is invalid")
    if (
        type(value["mission_id"]) is not str
        or MISSION_ID_PATTERN.fullmatch(value["mission_id"]) is None
    ):
        raise _fail("Reviewer admission mission identity is invalid")
    for field in ("store_id", "audience", "mission_policy_id"):
        _text(value[field], field)
    if (
        type(value["active_plan_id"]) is not str
        or re.fullmatch(r"CLP-[0-9A-F]{24}", value["active_plan_id"]) is None
    ):
        raise _fail("Reviewer admission active plan identity is invalid")
    for field in (
        "admission_sha256",
        "mission_context_sha256",
        "active_plan_content_sha256",
        "mission_policy_sha256",
    ):
        _digest(value[field], field)
    _integer(value["active_plan_version"], "active_plan_version", 1)
    sequence = _integer(value["admission_sequence"], "admission_sequence", 1)
    previous = value["previous_admission_sha256"]
    if sequence == 1:
        if previous is not None:
            raise _fail("Initial reviewer admission cannot have a predecessor")
    else:
        _digest(previous, "previous_admission_sha256")
    ledger = _object(
        value["principal_ledger"],
        {"assertion_count", "effect_count", "head_sha256"},
        "principal_ledger",
    )
    _integer(ledger["assertion_count"], "assertion_count", 0)
    _integer(ledger["effect_count"], "effect_count", 0)
    _digest(ledger["head_sha256"], "head_sha256")
    reviewer = _object(
        value["reviewer"],
        {"issuer", "subject", "profile_id", "role", "scope_grant", "scope_grant_sha256"},
        "reviewer",
    )
    for field in ("issuer", "subject", "profile_id", "role"):
        _text(reviewer[field], "reviewer." + field)
    operation = REVIEWER_OPERATIONS.get(reviewer["role"])
    if operation is None:
        raise _fail("Reviewer admission role is invalid")
    grant = ScopeGrant.from_dict(reviewer["scope_grant"])
    if canonical_json(grant.to_dict()) != canonical_json(reviewer["scope_grant"]):
        raise _fail("Reviewer scope grant is not exact canonical contract data")
    if grant.operations != (operation,):
        raise _fail("Reviewer scope grant must contain only its role-specific review operation")
    if (
        grant.subject != reviewer["subject"]
        or grant.profile_id != reviewer["profile_id"]
        or grant.content_sha256 != _digest(reviewer["scope_grant_sha256"], "scope_grant_sha256")
        or grant.mission_id != value["mission_id"]
        or grant.store_id != value["store_id"]
        or grant.audience != value["audience"]
        or grant.mission_context_hash != value["mission_context_sha256"]
    ):
        raise _fail("Reviewer admission scope and prospective principal binding do not match")
    issued = _time(value["issued_at"], "issued_at")
    start = _time(value["not_before"], "not_before")
    end = _time(value["expires_at"], "expires_at")
    if (
        not issued <= start < end
        or not _time(grant.not_before, "grant.not_before")
        <= start
        < end
        <= _time(grant.expires_at, "grant.expires_at")
        or _time(grant.issued_at, "grant.issued_at") > issued
    ):
        raise _fail("Reviewer admission validity must be contained in its scope grant")
    if value["review_only"] is not True or value["target_authority"] != "none":
        raise _fail("Reviewer admission is review-only with no target authority")
    if value["admission_sha256"] != _request_digest(value):
        raise _fail("Reviewer admission content digest is invalid")
    return value


@dataclass(frozen=True)
class PlanReplacementReviewerAdmissionRequest:
    """Owned closed request awaiting two independently authenticated approvals."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self.document_json) is not str:
            raise _fail("Reviewer admission document must be canonical JSON text")
        value = _parse_request(json.loads(self.document_json))
        if canonical_json(value) != self.document_json:
            raise _fail("Reviewer admission document is not canonical JSON")

    @classmethod
    def from_dict(cls, raw: Any) -> PlanReplacementReviewerAdmissionRequest:
        return cls(canonical_json(_parse_request(raw)))

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @property
    def admission_id(self) -> str:
        return self.to_dict()["admission_id"]

    @property
    def admission_sha256(self) -> str:
        return self.to_dict()["admission_sha256"]

    @property
    def content_sha256(self) -> str:
        return self.admission_sha256

    @property
    def mission_id(self) -> str:
        return self.to_dict()["mission_id"]

    @property
    def scope_grant(self) -> ScopeGrant:
        return ScopeGrant.from_dict(self.to_dict()["reviewer"]["scope_grant"])


def reviewer_admission_operation_intent(
    request: PlanReplacementReviewerAdmissionRequest, *, principal_profile_id: str, role: str
) -> dict[str, str]:
    if role not in _APPROVAL_OPERATIONS:
        raise _fail("Reviewer admission approval role is invalid")
    document = PlanReplacementReviewerAdmissionRequest.from_dict(request.to_dict()).to_dict()
    return {
        "mission_id": document["mission_id"],
        "mission_context_sha256": document["mission_context_sha256"],
        "admission_id": document["admission_id"],
        "admission_sha256": document["admission_sha256"],
        "principal_profile_id": _text(principal_profile_id, "principal_profile_id"),
        "role": role,
    }


def load_plan_replacement_reviewer_admission_request(
    path: str | Path,
) -> PlanReplacementReviewerAdmissionRequest:
    """Read a bounded strict request file without authenticating or admitting it."""

    try:
        return PlanReplacementReviewerAdmissionRequest.from_dict(
            _load_json_file(path, "plan replacement reviewer admission request")
        )
    except RecursionError as exc:
        raise _fail("Reviewer admission request nesting is invalid") from exc


def _require_reviewer_profile(
    registry: ExpertRegistry, request: PlanReplacementReviewerAdmissionRequest
) -> None:
    reviewer = request.to_dict()["reviewer"]
    profile = registry.profile(reviewer["profile_id"])
    category = (
        "independent assurance"
        if reviewer["role"] == "independent_assurance"
        else "independent control"
    )
    tag = (
        "independent-assurance"
        if reviewer["role"] == "independent_assurance"
        else "independent-control"
    )
    if (
        profile.kind is not ProfileKind.SHARED
        or profile.status not in {"defined", "qualified"}
        or profile.category != category
        or tag not in profile.tags
    ):
        raise _fail("Reviewer profile is not an eligible independent review profile")


def _row_request(row: sqlite3.Row) -> PlanReplacementReviewerAdmissionRequest:
    try:
        request = PlanReplacementReviewerAdmissionRequest.from_dict(
            json.loads(row["admission_json"])
        )
        document = request.to_dict()
        if (
            request.document_json != row["admission_json"]
            or any(
                document[field] != row[field]
                for field in (
                    "admission_id",
                    "mission_id",
                    "admission_sequence",
                    "previous_admission_sha256",
                    "admission_sha256",
                )
            )
            or document["reviewer"]["scope_grant_sha256"] != row["reviewer_scope_grant_sha256"]
        ):
            raise _fail("Reviewer admission row binding is invalid")
        return request
    except (ValueError, TypeError, StoreError, PrincipalAuthenticationError) as exc:
        raise StoreIntegrityError("Stored reviewer admission is invalid") from exc


def _use(connection: sqlite3.Connection, row: sqlite3.Row, role: str) -> sqlite3.Row:
    prefix = "owner" if role == "mission_owner" else "control"
    use = connection.execute(
        "SELECT * FROM principal_assertion_uses WHERE issuer=? AND assertion_id=?",
        (row[prefix + "_issuer"], row[prefix + "_assertion_id"]),
    ).fetchone()
    if use is None:
        raise StoreIntegrityError("Reviewer admission approval provenance is missing")
    return use


def _require_approver_separation(
    mission: StoredMission,
    request: PlanReplacementReviewerAdmissionRequest,
    owner: Any,
    control: Any,
    *,
    owner_profile_id: str,
) -> None:
    reviewer = request.to_dict()["reviewer"]

    def profile(item: Any) -> str:
        return item["principal_profile_id"] if isinstance(item, sqlite3.Row) else item.profile_id

    def subject(item: Any) -> str:
        return item["subject"] if isinstance(item, sqlite3.Row) else item.subject

    if (
        profile(owner) != owner_profile_id
        or profile(owner) not in mission.allowed_profile_ids
        or profile(control) not in mission.control_profile_ids
    ):
        raise _fail(
            "Reviewer admission approvals require the current owner and already-assigned Control"
        )
    if (
        len({profile(owner), profile(control), reviewer["profile_id"]}) != 3
        or len({subject(owner), subject(control), reviewer["subject"]}) != 3
    ):
        raise _fail(
            "Reviewer and admission approvers require distinct profiles and authenticated subjects"
        )


def _reviewer_admission_for_scope(
    connection: sqlite3.Connection,
    *,
    mission: StoredMission,
    grant: ScopeGrant,
    registry: ExpertRegistry,
) -> bool:
    """Check structural admission linkage before the ordinary principal ledger verifier.

    This is not a signature verifier or a current-use authority decision. Full
    reconciliation must follow within the same verified store snapshot.
    """
    row = connection.execute(
        "SELECT * FROM plan_replacement_reviewer_admissions "
        "WHERE mission_id=? AND reviewer_scope_grant_sha256=?",
        (mission.mission.mission_id, grant.content_sha256),
    ).fetchone()
    if row is None:
        return False
    request = _row_request(row)
    _require_reviewer_profile(registry, request)
    document = request.to_dict()
    if document["mission_context_sha256"] != mission.context_hash or canonical_json(
        grant.to_dict()
    ) != canonical_json(request.scope_grant.to_dict()):
        return False
    owner = _use(connection, row, "mission_owner")
    control = _use(connection, row, "independent_control")
    plan = connection.execute(
        "SELECT readiness_owner_profile_id FROM collaboration_plan_activations "
        "WHERE plan_id=? AND mission_id=?",
        (document["active_plan_id"], request.mission_id),
    ).fetchone()
    if plan is None:
        return False
    _require_approver_separation(
        mission, request, owner, control, owner_profile_id=plan["readiness_owner_profile_id"]
    )
    return all(
        use["mission_id"] == request.mission_id
        and use["operation"] == _APPROVAL_OPERATIONS[role].value
        and use["scope_grant_hash"] != grant.content_sha256
        for role, use in (("mission_owner", owner), ("independent_control", control))
    )


def _effect(
    request: PlanReplacementReviewerAdmissionRequest, role: str, committed_at: str
) -> dict[str, Any]:
    document = request.to_dict()
    return {
        "schema_version": 1,
        "effect_id": request.admission_id,
        "effect_kind": _APPROVAL_OPERATIONS[role].value,
        "recorded_at": committed_at,
        "payload": {
            "admission_sha256": request.admission_sha256,
            "mission_context_sha256": document["mission_context_sha256"],
            "store_id": document["store_id"],
            "reviewer_scope_grant_sha256": document["reviewer"]["scope_grant_sha256"],
            "reviewer_issuer": document["reviewer"]["issuer"],
            "reviewer_subject": document["reviewer"]["subject"],
            "reviewer_profile_id": document["reviewer"]["profile_id"],
            "reviewer_role": document["reviewer"]["role"],
            "approval_role": role,
            "review_only": True,
            "target_authority": "none",
        },
    }


def _assertion_material(
    request: PlanReplacementReviewerAdmissionRequest, assertion: PrincipalAssertion, role: str
) -> dict[str, str]:
    intent = reviewer_admission_operation_intent(
        request, principal_profile_id=assertion.profile_id, role=role
    )
    material = AuthenticatedCollaborationMissionPolicyService._assertion_material(
        assertion, _APPROVAL_OPERATIONS[role], intent
    )
    return material


def _historical_plan(
    connection: sqlite3.Connection, mission_id: str, before_sequence: int
) -> sqlite3.Row:
    rows = connection.execute(
        """
        SELECT activation.*, initial_use.use_sequence AS initial_sequence,
          (SELECT MAX(replacement_use.use_sequence)
           FROM collaboration_plan_replacement_commits AS replacement
           JOIN collaboration_plan_replacement_authority_consumptions AS consumption
             ON consumption.preflight_id = replacement.preflight_id
           JOIN principal_assertion_uses AS replacement_use
             ON replacement_use.issuer = consumption.issuer
            AND replacement_use.assertion_id = consumption.assertion_id
           WHERE replacement.replacement_commit_id = activation.replacement_commit_id)
          AS replacement_sequence
        FROM collaboration_plan_activations AS activation
        LEFT JOIN principal_assertion_uses AS initial_use
          ON initial_use.issuer = activation.issuer
         AND initial_use.assertion_id = activation.assertion_id
        WHERE activation.mission_id = ? ORDER BY activation.plan_version
    """,
        (mission_id,),
    ).fetchall()
    eligible = [
        row
        for row in rows
        if (
            sequence := row["initial_sequence"]
            if row["activation_kind"] == "initial"
            else row["replacement_sequence"]
        )
        is not None
        and sequence < before_sequence
    ]
    if not eligible:
        raise StoreIntegrityError("Reviewer admission has no prior authenticated active plan")
    return eligible[-1]


def _verify_plan_replacement_reviewer_admission_state(
    connection: sqlite3.Connection,
    *,
    store: MissionStore,
    mission: StoredMission,
    registry: ExpertRegistry,
    trust_policies: dict[str, VerifiedTrustPolicy],
    scope_grants: dict[str, Any],
) -> int:
    """Reconcile append-only admissions with already-verified ordinary custody."""
    rows = connection.execute(
        "SELECT * FROM plan_replacement_reviewer_admissions "
        "WHERE mission_id=? ORDER BY admission_sequence",
        (mission.mission.mission_id,),
    ).fetchall()
    previous = None
    linked_uses: set[tuple[str, str]] = set()
    previous_control_sequence = 0
    previous_time = None
    for sequence, row in enumerate(rows, start=1):
        request = _row_request(row)
        document = request.to_dict()
        _require_reviewer_profile(registry, request)
        committed = _time(row["committed_at"], "reviewer admission committed_at")
        if (
            document["admission_sequence"] != sequence
            or document["previous_admission_sha256"] != previous
            or (previous_time is not None and committed < previous_time)
        ):
            raise StoreIntegrityError("Reviewer admission chain is invalid")
        if (
            not _time(document["issued_at"], "issued_at")
            <= _time(document["not_before"], "not_before")
            <= committed
            < _time(document["expires_at"], "expires_at")
        ):
            raise StoreIntegrityError("Reviewer admission commit is outside its validity window")
        identity = connection.execute(
            "SELECT * FROM store_identity WHERE singleton_id=1"
        ).fetchone()
        if (
            identity is None
            or document["store_id"] != identity["store_id"]
            or document["audience"] != identity["audience"]
            or document["mission_context_sha256"] != mission.context_hash
        ):
            raise StoreIntegrityError("Reviewer admission mission or store context differs")
        entry = scope_grants.get(document["reviewer"]["scope_grant_sha256"])
        if (
            entry is None
            or canonical_json(entry[1].to_dict()) != canonical_json(request.scope_grant.to_dict())
            or entry[0]["accepted_at"] != row["committed_at"]
        ):
            raise StoreIntegrityError("Reviewer admission scope custody is missing or different")
        owner = _use(connection, row, "mission_owner")
        control = _use(connection, row, "independent_control")
        fence = document["principal_ledger"]
        if (
            owner["use_sequence"] != fence["assertion_count"] + 1
            or control["use_sequence"] != owner["use_sequence"] + 1
            or owner["previous_hash"] != fence["head_sha256"]
            or control["previous_hash"] != owner["entry_hash"]
            or owner["use_sequence"] <= previous_control_sequence
        ):
            raise StoreIntegrityError("Reviewer admission principal sequence fence is invalid")
        prior_effects = connection.execute(
            "SELECT COUNT(*) FROM principal_assertion_effects AS effect "
            "JOIN principal_assertion_uses AS use ON use.issuer=effect.issuer "
            "AND use.assertion_id=effect.assertion_id "
            "WHERE use.mission_id=? AND use.use_sequence<?",
            (request.mission_id, owner["use_sequence"]),
        ).fetchone()[0]
        if prior_effects != fence["effect_count"]:
            raise StoreIntegrityError("Reviewer admission effect fence is invalid")
        activation = _historical_plan(connection, request.mission_id, owner["use_sequence"])
        if (
            activation["plan_id"] != document["active_plan_id"]
            or activation["plan_content_sha256"] != document["active_plan_content_sha256"]
            or activation["plan_version"] != document["active_plan_version"]
            or _time(activation["activated_at"], "activated_at") > committed
        ):
            raise StoreIntegrityError("Reviewer admission active plan fence is invalid")
        policy_row = connection.execute(
            """SELECT policy.* FROM collaboration_mission_policy_commits AS policy
            JOIN principal_assertion_uses AS control_use
              ON control_use.issuer=policy.control_issuer
             AND control_use.assertion_id=policy.control_assertion_id
            WHERE policy.mission_id=? AND control_use.use_sequence<?
            ORDER BY policy.policy_version DESC LIMIT 1""",
            (request.mission_id, owner["use_sequence"]),
        ).fetchone()
        if (
            policy_row is None
            or policy_row["policy_id"] != document["mission_policy_id"]
            or policy_row["policy_sha256"] != document["mission_policy_sha256"]
            or policy_row["plan_id"] != activation["plan_id"]
            or policy_row["plan_content_sha256"] != activation["plan_content_sha256"]
            or _time(policy_row["committed_at"], "policy committed_at") > committed
        ):
            raise StoreIntegrityError("Reviewer admission mission policy fence is invalid")
        policy = CollaborationMissionReconfigurationPolicy.from_dict(
            json.loads(policy_row["policy_json"])
        ).to_dict()
        if (
            not _time(policy["effective_at"], "policy effective_at")
            <= committed
            < _time(policy["expires_at"], "policy expires_at")
        ):
            raise StoreIntegrityError("Reviewer admission policy was not active at commitment")
        _require_approver_separation(
            mission,
            request,
            owner,
            control,
            owner_profile_id=activation["readiness_owner_profile_id"],
        )
        high_water = store._trust_policy_high_water_at(trust_policies, committed)
        _verify_candidate_scope(request, mission, high_water, committed)
        for role, use in (("mission_owner", owner), ("independent_control", control)):
            assertion = PrincipalAssertion.from_dict(json.loads(use["assertion_json"]))
            material = _assertion_material(request, assertion, role)
            if (
                use["mission_id"] != request.mission_id
                or use["operation"] != _APPROVAL_OPERATIONS[role].value
                or use["consumed_at"] != row["committed_at"]
                or use["trust_policy_hash"] != high_water.policy_sha256
                or use["idempotency_key_hash"] is not None
                or any(
                    use[column] != material[key]
                    for column, key in (
                        ("assertion_json", "assertion_json"),
                        ("assertion_hash", "assertion_hash"),
                        ("operation_intent_json", "intent_json"),
                        ("signed_intent_hash", "signed_hash"),
                        ("domain_request_hash", "domain_hash"),
                    )
                )
            ):
                raise StoreIntegrityError("Reviewer admission signed approval binding is invalid")
            effects = connection.execute(
                "SELECT * FROM principal_assertion_effects "
                "WHERE issuer=? AND assertion_id=? ORDER BY effect_index",
                (use["issuer"], use["assertion_id"]),
            ).fetchall()
            expected = _effect(request, role, row["committed_at"])
            if (
                len(effects) != 1
                or effects[0]["effect_index"] != 1
                or effects[0]["mission_id"] != request.mission_id
                or effects[0]["effect_kind"] != _APPROVAL_OPERATIONS[role].value
                or effects[0]["effect_id"] != request.admission_id
                or effects[0]["recorded_at"] != row["committed_at"]
                or effects[0]["effect_json"] != canonical_json(expected)
                or effects[0]["effect_hash"] != sha256_text(canonical_json(expected))
            ):
                raise StoreIntegrityError("Reviewer admission approval effect is invalid")
            linked_uses.add((use["issuer"], use["assertion_id"]))
        previous = request.admission_sha256
        previous_control_sequence = control["use_sequence"]
        previous_time = committed
    actual = {
        (row["issuer"], row["assertion_id"])
        for row in connection.execute(
            "SELECT issuer,assertion_id FROM principal_assertion_uses "
            "WHERE mission_id=? AND operation IN (?,?)",
            (
                mission.mission.mission_id,
                *[operation.value for operation in _APPROVAL_OPERATIONS.values()],
            ),
        )
    }
    if actual != linked_uses:
        raise StoreIntegrityError("Reviewer admission approval custody is orphaned")
    return len(rows)


def _verify_candidate_scope(
    request: PlanReplacementReviewerAdmissionRequest,
    mission: StoredMission,
    policy: VerifiedTrustPolicy,
    at: datetime,
) -> Any:
    grant = request.scope_grant
    reviewer = request.to_dict()["reviewer"]
    operation = REVIEWER_OPERATIONS[reviewer["role"]]
    # A scope issuer is not necessarily the issuer of the prospective assertion.
    # Admission must name a principal issuer that current trust independently allows.
    if not any(
        key.key_use is TrustKeyUse.PRINCIPAL_ASSERTION
        and key.state is not TrustKeyState.REVOKED
        and key.issuer == reviewer["issuer"]
        and reviewer["profile_id"] in key.allowed_profiles
        and reviewer["subject"] in key.allowed_subjects
        and operation in key.allowed_operations
        and _time(key.not_before, "reviewer key not_before")
        <= at
        < _time(key.not_after, "reviewer key not_after")
        and (key.retire_at is None or at < _time(key.retire_at, "reviewer key retire_at"))
        for key in policy.policy.keys
    ):
        raise _fail(
            "Prospective reviewer assertion issuer is not independently allowed by current trust"
        )
    return verify_scope_grant(
        grant,
        policy,
        expected_audience=request.to_dict()["audience"],
        expected_store_id=request.to_dict()["store_id"],
        expected_mission_id=mission.mission.mission_id,
        expected_mission_context_hash=mission.context_hash,
        expected_scope_reference=mission.mission.scope_reference,
        expected_scope_document_hash=mission.mission.scope_document_hash,
        expected_environment=mission.mission.environment,
        expected_max_action_tier=mission.mission.max_action_tier,
        expected_constraints_hash=sha256_text(
            canonical_json(mission.mission.to_dict()["constraints"])
        ),
        expected_operation=operation,
        clock=lambda: at,
    )


def verify_plan_replacement_reviewer_admission_for_use(
    connection: sqlite3.Connection,
    *,
    store: MissionStore,
    mission: StoredMission,
    registry: ExpertRegistry,
    trust_policies: dict[str, VerifiedTrustPolicy],
    scope_grants: dict[str, Any],
    grant: ScopeGrant,
    role: str,
    at: datetime,
) -> PlanReplacementReviewerAdmissionRequest:
    """Require exact admitted reviewer custody and current review-only authority."""
    if (
        connection.execute("PRAGMA user_version").fetchone()[0]
        < PLAN_REPLACEMENT_REVIEWER_ADMISSION_SCHEMA_VERSION
    ):
        raise _fail("Replacement reviewer admission requires schema 38")
    store._require_mission_active(connection, mission.mission.mission_id)
    owned = ScopeGrant.from_dict(grant.to_dict())
    operation = REVIEWER_OPERATIONS.get(role)
    if operation is None or owned.operations != (operation,):
        raise _fail("Replacement reviewer role and narrow scope do not agree")
    row = connection.execute(
        "SELECT * FROM plan_replacement_reviewer_admissions "
        "WHERE mission_id=? AND reviewer_scope_grant_sha256=?",
        (mission.mission.mission_id, owned.content_sha256),
    ).fetchone()
    if row is None:
        raise _fail("Replacement reviewer has no signed mission-scoped admission")
    request = _row_request(row)
    document = request.to_dict()
    if (
        document["reviewer"]["role"] != role
        or canonical_json(owned.to_dict()) != canonical_json(request.scope_grant.to_dict())
        or not _reviewer_admission_for_scope(
            connection, mission=mission, grant=owned, registry=registry
        )
    ):
        raise _fail("Replacement reviewer admission principal or role binding differs")
    now = parse_timestamp(format_timestamp(at), "reviewer admission use time")
    if _time(row["committed_at"], "committed_at") > now or not _time(
        document["not_before"], "not_before"
    ) <= now < _time(document["expires_at"], "expires_at"):
        raise _fail("Replacement reviewer admission is not currently active")
    entry = scope_grants.get(owned.content_sha256)
    if (
        entry is None
        or canonical_json(entry[1].to_dict()) != canonical_json(owned.to_dict())
        or _time(entry[0]["accepted_at"], "accepted_at") > now
        or store._effective_scope_grant_revocation(connection, entry[0]) is not None
    ):
        raise _fail("Replacement reviewer scope is absent, stale or revoked")
    identity = connection.execute(
        "SELECT trust_policy_hash FROM store_identity WHERE singleton_id=1"
    ).fetchone()
    high_water = store._trust_policy_high_water_at(trust_policies, now)
    if identity is None or identity["trust_policy_hash"] != high_water.policy_sha256:
        raise _fail("Runtime clock precedes current trust policy")
    _verify_candidate_scope(request, mission, high_water, now)
    return request


@dataclass(frozen=True)
class PlanReplacementReviewerAdmissionReceipt:
    request: PlanReplacementReviewerAdmissionRequest
    committed_at: str
    owner_assertion_sha256: str
    owner_ledger_entry_sha256: str
    control_assertion_sha256: str
    control_ledger_entry_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "admission": self.request.to_dict(),
            "committed_at": self.committed_at,
            "mission_owner": {
                "assertion_sha256": self.owner_assertion_sha256,
                "ledger_entry_sha256": self.owner_ledger_entry_sha256,
            },
            "independent_control": {
                "assertion_sha256": self.control_assertion_sha256,
                "ledger_entry_sha256": self.control_ledger_entry_sha256,
            },
            "review_only": True,
            "target_authority": "none",
        }


class AuthenticatedPlanReplacementReviewerAdmissionService:
    """Atomically consume owner and assigned Control approvals for one reviewer."""

    def __init__(
        self,
        store: MissionStore,
        registry: ExpertRegistry,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(store, MissionStore) or not isinstance(registry, ExpertRegistry):
            raise TypeError("Reviewer admission requires MissionStore and ExpertRegistry")
        registry.validate()
        self._store = store
        self._registry = registry
        self._clock = clock or store._clock
        self._activation = AuthenticatedCollaborationActivationService(
            store, registry, clock=self._clock
        )
        self._work = AuthenticatedWorkItemLeaseService(store, registry, clock=self._clock)
        self._policy = AuthenticatedCollaborationMissionPolicyService(
            store, registry, clock=self._clock
        )

    def prepare(
        self,
        mission_id: str,
        *,
        admission_id: str,
        reviewer_scope_grant: ScopeGrant,
        reviewer_issuer: str,
        reviewer_subject: str,
        role: str,
        issued_at: str,
        not_before: str,
        expires_at: str,
    ) -> PlanReplacementReviewerAdmissionRequest:
        """Capture current immutable context and fences without accepting a grant."""
        if not isinstance(reviewer_scope_grant, ScopeGrant):
            raise TypeError("reviewer_scope_grant must be a ScopeGrant")
        grant = ScopeGrant.from_dict(reviewer_scope_grant.to_dict())
        with self._store._read_connection() as connection:
            identity, _, mission, _, ledger = self._activation._verified_mission_state(
                connection, mission_id
            )
            activation, plan = self._work._load_activation(connection, mission_id)
            policy = self._latest_policy(connection, mission_id)
            head = connection.execute(
                "SELECT * FROM plan_replacement_reviewer_admissions "
                "WHERE mission_id=? ORDER BY admission_sequence DESC LIMIT 1",
                (mission_id,),
            ).fetchone()
            body = {
                "schema_version": 1,
                "admission_id": admission_id,
                "store_id": identity["store_id"],
                "audience": identity["audience"],
                "mission_id": mission_id,
                "mission_context_sha256": mission.context_hash,
                "active_plan_id": plan.plan_id,
                "active_plan_content_sha256": plan.content_sha256,
                "active_plan_version": activation["plan_version"],
                "mission_policy_id": policy["policy_id"],
                "mission_policy_sha256": policy["policy_sha256"],
                "admission_sequence": 1 if head is None else head["admission_sequence"] + 1,
                "previous_admission_sha256": None if head is None else head["admission_sha256"],
                "principal_ledger": {
                    "assertion_count": ledger["assertion_count"],
                    "effect_count": ledger["effect_count"],
                    "head_sha256": ledger["head_hash"],
                },
                "reviewer": {
                    "issuer": reviewer_issuer,
                    "subject": reviewer_subject,
                    "profile_id": grant.profile_id,
                    "role": role,
                    "scope_grant": grant.to_dict(),
                    "scope_grant_sha256": grant.content_sha256,
                },
                "issued_at": issued_at,
                "not_before": not_before,
                "expires_at": expires_at,
                "review_only": True,
                "target_authority": "none",
            }
            request = PlanReplacementReviewerAdmissionRequest.from_dict(
                {**body, "admission_sha256": _request_digest(body)}
            )
            _require_reviewer_profile(self._registry, request)
            return request

    @staticmethod
    def _latest_policy(connection: sqlite3.Connection, mission_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM collaboration_mission_policy_commits "
            "WHERE mission_id=? ORDER BY policy_version DESC LIMIT 1",
            (mission_id,),
        ).fetchone()
        if row is None:
            raise StoreConflictError("Reviewer admission requires a durable mission policy")
        return row

    def get(self, mission_id: str, admission_id: str) -> PlanReplacementReviewerAdmissionReceipt:
        """Inspect historical custody; this result is not a current-use grant."""
        with self._store._read_connection() as connection:
            self._activation._verified_mission_state(connection, mission_id)
            row = connection.execute(
                "SELECT * FROM plan_replacement_reviewer_admissions "
                "WHERE mission_id=? AND admission_id=?",
                (mission_id, admission_id),
            ).fetchone()
            if row is None:
                raise StoreConflictError("Reviewer admission does not exist")
            return self._receipt(connection, row)

    @staticmethod
    def _receipt(
        connection: sqlite3.Connection, row: sqlite3.Row
    ) -> PlanReplacementReviewerAdmissionReceipt:
        owner = _use(connection, row, "mission_owner")
        control = _use(connection, row, "independent_control")
        return PlanReplacementReviewerAdmissionReceipt(
            _row_request(row),
            row["committed_at"],
            owner["assertion_hash"],
            owner["entry_hash"],
            control["assertion_hash"],
            control["entry_hash"],
        )

    def admit(
        self,
        request: PlanReplacementReviewerAdmissionRequest,
        *,
        mission_owner_assertion: PrincipalAssertion,
        independent_control_assertion: PrincipalAssertion,
    ) -> PlanReplacementReviewerAdmissionReceipt:
        """Commit one exact request; retries recheck current reviewer eligibility."""
        if not isinstance(request, PlanReplacementReviewerAdmissionRequest):
            raise TypeError("request must be a PlanReplacementReviewerAdmissionRequest")
        request = PlanReplacementReviewerAdmissionRequest.from_dict(request.to_dict())
        document = request.to_dict()
        assertions = {
            "mission_owner": self._policy._assertion(
                mission_owner_assertion, "mission_owner_assertion"
            ),
            "independent_control": self._policy._assertion(
                independent_control_assertion, "independent_control_assertion"
            ),
        }
        materials = {
            role: _assertion_material(request, assertion, role)
            for role, assertion in assertions.items()
        }
        try:
            with self._store._write_connection() as connection:
                identity, trust_policies, mission, scopes, ledger = (
                    self._activation._verified_mission_state(connection, request.mission_id)
                )
                # Admission custody was reconciled through principal-ledger verification
                # inside _verified_mission_state on this same connection.
                row = connection.execute(
                    "SELECT * FROM plan_replacement_reviewer_admissions WHERE admission_id=?",
                    (request.admission_id,),
                ).fetchone()
                uses = {
                    role: self._policy._existing_use(connection, assertion)
                    for role, assertion in assertions.items()
                }
                now = self._clock()
                if row is not None or any(use is not None for use in uses.values()):
                    if (
                        row is None
                        or row["admission_json"] != request.document_json
                        or any(use is None for use in uses.values())
                        or any(
                            (
                                row[
                                    ("owner" if role == "mission_owner" else "control") + "_issuer"
                                ],
                                row[
                                    ("owner" if role == "mission_owner" else "control")
                                    + "_assertion_id"
                                ],
                            )
                            != (assertion.issuer, assertion.assertion_id)
                            for role, assertion in assertions.items()
                        )
                    ):
                        raise StoreConflictError(
                            "Reviewer admission replay has different or incomplete custody"
                        )
                    for role, assertion in assertions.items():
                        self._policy._require_exact_replay(
                            uses[role],
                            assertion=assertion,
                            mission_id=request.mission_id,
                            operation=_APPROVAL_OPERATIONS[role],
                            material=materials[role],
                        )
                    verify_plan_replacement_reviewer_admission_for_use(
                        connection,
                        store=self._store,
                        mission=mission,
                        registry=self._registry,
                        trust_policies=trust_policies,
                        scope_grants=scopes,
                        grant=request.scope_grant,
                        role=document["reviewer"]["role"],
                        at=now,
                    )
                    return self._receipt(connection, row)
                self._store._require_mission_active(connection, request.mission_id)
                committed_at = format_timestamp(now)
                committed = parse_timestamp(committed_at, "reviewer admission committed_at")
                self._activation._require_runtime_not_before_state(
                    connection, mission, ledger, committed
                )
                self._require_fences(connection, request, identity, mission, ledger, committed)
                if (
                    not _time(document["not_before"], "not_before")
                    <= committed
                    < _time(document["expires_at"], "expires_at")
                ):
                    raise _fail("Reviewer admission is outside its validity window")
                _require_reviewer_profile(self._registry, request)
                _, plan = self._work._load_activation(connection, request.mission_id)
                _require_approver_separation(
                    mission,
                    request,
                    assertions["mission_owner"],
                    assertions["independent_control"],
                    owner_profile_id=self._activation._readiness_owner(plan),
                )
                principals = {}
                policies = {}
                for role, assertion in assertions.items():
                    policy, scope = self._policy._verified_scope(
                        connection,
                        assertion=assertion,
                        operation=_APPROVAL_OPERATIONS[role],
                        mission=mission,
                        identity=identity,
                        trust_policies=trust_policies,
                        scope_grants=scopes,
                        now=now,
                        consumed_time=committed,
                    )
                    policies[role] = policy
                    principals[role] = verify_principal_assertion(
                        assertion,
                        policy,
                        scope,
                        expected_audience=document["audience"],
                        expected_store_id=document["store_id"],
                        expected_mission_id=request.mission_id,
                        expected_operation=_APPROVAL_OPERATIONS[role],
                        expected_operation_intent_sha256=materials[role]["signed_hash"],
                        clock=lambda: now,
                    )
                if (
                    policies["mission_owner"].policy_sha256
                    != policies["independent_control"].policy_sha256
                ):
                    raise _fail("Reviewer admission approvals use different current trust policies")
                candidate = _verify_candidate_scope(
                    request, mission, policies["mission_owner"], now
                )
                if (
                    connection.execute(
                        "SELECT 1 FROM mission_scope_grants "
                        "WHERE grant_hash=? OR (issuer=? AND grant_id=?)",
                        (
                            request.scope_grant.content_sha256,
                            request.scope_grant.issuer,
                            request.scope_grant.grant_id,
                        ),
                    ).fetchone()
                    is not None
                ):
                    raise StoreConflictError(
                        "Reviewer scope grant already has different durable custody"
                    )
                for role, assertion in assertions.items():
                    self._policy._record_assertion(
                        connection,
                        principal=principals[role],
                        assertion=assertion,
                        mission_id=request.mission_id,
                        operation=_APPROVAL_OPERATIONS[role],
                        material=materials[role],
                        effect=_effect(request, role, committed_at),
                        ledger=ledger,
                        consumed_at=committed_at,
                    )
                    ledger = connection.execute(
                        "SELECT * FROM mission_principal_ledgers WHERE mission_id=?",
                        (request.mission_id,),
                    ).fetchone()
                    if ledger is None:
                        raise StoreIntegrityError("Reviewer admission principal ledger disappeared")
                self._insert_scope(connection, request.scope_grant, candidate, committed_at)
                connection.execute(
                    """INSERT INTO plan_replacement_reviewer_admissions(
                    admission_id,mission_id,admission_sequence,previous_admission_sha256,
                    admission_json,admission_sha256,reviewer_scope_grant_sha256,committed_at,
                    owner_issuer,owner_assertion_id,control_issuer,control_assertion_id)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        request.admission_id,
                        request.mission_id,
                        document["admission_sequence"],
                        document["previous_admission_sha256"],
                        request.document_json,
                        request.admission_sha256,
                        request.scope_grant.content_sha256,
                        committed_at,
                        assertions["mission_owner"].issuer,
                        assertions["mission_owner"].assertion_id,
                        assertions["independent_control"].issuer,
                        assertions["independent_control"].assertion_id,
                    ),
                )
                self._activation._verified_mission_state(connection, request.mission_id)
                row = connection.execute(
                    "SELECT * FROM plan_replacement_reviewer_admissions WHERE admission_id=?",
                    (request.admission_id,),
                ).fetchone()
                if row is None:
                    raise StoreIntegrityError("Reviewer admission disappeared after insertion")
                return self._receipt(connection, row)
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError("Could not atomically commit reviewer admission") from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not persist reviewer admission") from exc

    def _require_fences(
        self,
        connection: sqlite3.Connection,
        request: PlanReplacementReviewerAdmissionRequest,
        identity: sqlite3.Row,
        mission: StoredMission,
        ledger: sqlite3.Row,
        now: datetime,
    ) -> None:
        document = request.to_dict()
        activation, plan = self._work._load_activation(connection, request.mission_id)
        policy = self._latest_policy(connection, request.mission_id)
        head = connection.execute(
            "SELECT * FROM plan_replacement_reviewer_admissions "
            "WHERE mission_id=? ORDER BY admission_sequence DESC LIMIT 1",
            (request.mission_id,),
        ).fetchone()
        expected_ledger = {
            "assertion_count": ledger["assertion_count"],
            "effect_count": ledger["effect_count"],
            "head_sha256": ledger["head_hash"],
        }
        if (
            document["store_id"] != identity["store_id"]
            or document["audience"] != identity["audience"]
            or document["mission_context_sha256"] != mission.context_hash
            or document["active_plan_id"] != plan.plan_id
            or document["active_plan_content_sha256"] != plan.content_sha256
            or document["active_plan_version"] != activation["plan_version"]
            or document["mission_policy_id"] != policy["policy_id"]
            or document["mission_policy_sha256"] != policy["policy_sha256"]
            or policy["plan_id"] != plan.plan_id
            or policy["plan_content_sha256"] != plan.content_sha256
            or canonical_json(document["principal_ledger"]) != canonical_json(expected_ledger)
            or document["admission_sequence"]
            != (1 if head is None else head["admission_sequence"] + 1)
            or document["previous_admission_sha256"]
            != (None if head is None else head["admission_sha256"])
        ):
            raise StoreConflictError(
                "Reviewer admission current-source fence is stale or different"
            )
        policy_document = CollaborationMissionReconfigurationPolicy.from_dict(
            json.loads(policy["policy_json"])
        ).to_dict()
        if (
            _time(activation["activated_at"], "activated_at") > now
            or _time(policy["committed_at"], "policy committed_at") > now
            or not _time(policy_document["effective_at"], "policy effective_at")
            <= now
            < _time(policy_document["expires_at"], "policy expires_at")
        ):
            raise _fail("Reviewer admission sources are not currently active")

    @staticmethod
    def _insert_scope(
        connection: sqlite3.Connection, grant: ScopeGrant, verified: Any, committed_at: str
    ) -> None:
        connection.execute(
            """INSERT INTO mission_scope_grants(
            grant_hash,grant_id,grant_json,issuer,key_id,key_hash,audience,store_id,mission_id,
            mission_context_hash,scope_document_hash,environment,max_action_tier,constraints_hash,
            issued_at,not_before,expires_at,accepted_at,revoked_at,revocation_reason,
            trust_policy_id,trust_policy_version,trust_policy_hash)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL,?,?,?)""",
            (
                verified.grant_sha256,
                grant.grant_id,
                canonical_json(grant.to_dict()),
                grant.issuer,
                grant.key_id,
                verified.key_sha256,
                grant.audience,
                grant.store_id,
                grant.mission_id,
                grant.mission_context_hash,
                grant.scope_document_hash,
                grant.environment.value,
                grant.max_action_tier.value,
                grant.constraints_hash,
                grant.issued_at,
                grant.not_before,
                grant.expires_at,
                committed_at,
                grant.policy_id,
                grant.policy_version,
                verified.policy_sha256,
            ),
        )
