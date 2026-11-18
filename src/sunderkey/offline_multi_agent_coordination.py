"""Inert projection of supplied multi-agent relay and approval declarations."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "multi_agent_supplied_coordination_trust"
PROFILE_ID = "AOE-GD-D20-S20"
CAPABILITY_ID = "army.gd.d20.s20"
VECTOR_ID = "AV-GD-D20-S20-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D20-S20"
WAVE_ID = "IW2-002"
COMMANDER_ID = "AOE-GD-D20-CMD"
GROUP_OWNER_ID = "AOE-HQ-06"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-35"
BLUEPRINT_SHA256 = "sha256:ef243b8fd3caf7870d3f9e981e55a266fc03b3c98a63fa9bd091aa1ebfaf89f9"
DOMAIN = "sunderkey.offline-multi-agent-coordination.v1"
SCHEMA_VERSION = "v1"
MAX_SOURCE_BYTES = 131_072
MAX_REPORT_BYTES = 262_144
MAX_NODES = 20_000
MAX_DEPTH = 14
MAX_TEXT_BYTES = 256
MAX_AGENTS = 64
MAX_APPROVALS = 256
MAX_MESSAGES = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_EFFECTS = {
    key: "none"
    for key in (
        "authority",
        "target",
        "execution",
        "routing",
        "qualification",
        "deployment",
        "network",
        "process",
        "credentials",
        "provider_requests",
        "agent_messaging",
    )
}
_FLAGS = {
    "offline_only": True,
    "agents_authenticated": False,
    "approvals_authenticated": False,
    "messages_observed_live": False,
    "agent_action_executed": False,
    "finding_claimed": False,
    "positive_use_approved": False,
    "qualification_claimed": False,
}
_LIMITATIONS = [
    "Agents, trust labels, approvals, relay links and dispositions are supplied assertions.",
    "An accepted label does not establish delivery, attention, compliance or execution.",
    "The relay model carries one exact action label and has no natural-language semantics.",
    "Unknown trust or acceptance prevents a positive coordination candidate.",
    "A candidate is a declared unapproved relay, not observed rogue behavior.",
    "No agent message, network call, credential, process or target action occurs.",
]
_ASSESSMENTS = {
    "candidate_unapproved_privileged_relay",
    "declared_approved_or_trusted",
    "declared_blocked",
    "declared_nonprivileged_relay",
    "unknown",
}
_BASES = {
    "incomplete_facts",
    "incomplete_approvals",
    "rejected_message",
    "inconsistent_relay_dispositions",
    "unknown_message_disposition",
    "unknown_agent_trust",
    "nonprivileged_receiver",
    "untrusted_privileged_receiver",
    "unapproved_untrusted_participant",
    "approved_or_trusted_chain",
}


class MultiAgentCoordinationError(ValueError):
    """Closed model, resource bound or source replay validation failed."""


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields or any(type(k) is not str for k in value):
        raise MultiAgentCoordinationError(f"{label} fields are invalid")
    return value


def _id(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise MultiAgentCoordinationError(f"{label} must be bounded native ASCII text")
    return value


def _optional_id(value: Any, label: str) -> str | None:
    return None if value is None else _id(value, label)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MultiAgentCoordinationError("duplicate JSON key")
        result[key] = value
    return result


def _json_integer(token: str) -> int:
    if len(token) > 20 or len(token.lstrip("-")) > 19:
        raise MultiAgentCoordinationError("JSON integer exceeds signed64 bound")
    value = int(token)
    if not -(1 << 63) <= value < (1 << 63):
        raise MultiAgentCoordinationError("JSON integer exceeds signed64 bound")
    return value


def _unsupported_number(_token: str) -> None:
    raise MultiAgentCoordinationError("floating and nonfinite numbers are unsupported")


def _validate_tree(value: Any, *, maximum: int) -> None:
    stack = [(value, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise MultiAgentCoordinationError("JSON node or depth bound exceeded")
        kind = type(item)
        if kind is dict:
            if nodes + len(stack) + 2 * len(item) > MAX_NODES:
                raise MultiAgentCoordinationError("JSON node bound exceeded")
            for key, child in item.items():
                if type(key) is not str:
                    raise MultiAgentCoordinationError("JSON keys must be native text")
                stack.append((child, depth + 1))
                stack.append((key, depth + 1))
        elif kind is list:
            if nodes + len(stack) + len(item) > MAX_NODES:
                raise MultiAgentCoordinationError("JSON node bound exceeded")
            stack.extend((child, depth + 1) for child in item)
        elif kind is str:
            if len(item.encode("utf-8", errors="surrogatepass")) > MAX_TEXT_BYTES or any(
                0xD800 <= ord(char) <= 0xDFFF for char in item
            ):
                raise MultiAgentCoordinationError("JSON string is unsupported or too long")
        elif kind is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise MultiAgentCoordinationError("JSON integer exceeds signed64 bound")
        elif kind not in (bool, type(None)):
            raise MultiAgentCoordinationError("unsupported JSON value family")
    if len(_canonical(value).encode("ascii")) > maximum:
        raise MultiAgentCoordinationError("canonical JSON byte bound exceeded")


def _decode(content: bytes, *, maximum: int) -> Any:
    if type(content) is not bytes or not content or len(content) > maximum:
        raise MultiAgentCoordinationError("source must be bounded nonempty native bytes")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MultiAgentCoordinationError("source must be UTF-8") from exc
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise MultiAgentCoordinationError("pre-decoder depth bound exceeded")
        elif char in "]}":
            depth -= 1
            if depth < 0:
                raise MultiAgentCoordinationError("malformed JSON nesting")
    if depth or quoted:
        raise MultiAgentCoordinationError("malformed JSON nesting")
    try:
        result = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_json_integer,
            parse_float=_unsupported_number,
            parse_constant=_unsupported_number,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, MultiAgentCoordinationError):
            raise
        raise MultiAgentCoordinationError("malformed JSON source") from exc
    _validate_tree(result, maximum=maximum)
    return result


def _model(document: Any) -> tuple[bool, bool, dict, set, dict]:
    model = _exact(
        document,
        {
            "schema_version",
            "facts_complete",
            "approvals_complete",
            "agents",
            "approvals",
            "messages",
        },
        "model",
    )
    if type(model["schema_version"]) is not str or model["schema_version"] != SCHEMA_VERSION:
        raise MultiAgentCoordinationError("unsupported model version")
    if type(model["facts_complete"]) is not bool or type(model["approvals_complete"]) is not bool:
        raise MultiAgentCoordinationError("completeness must be native Booleans")
    for name, maximum in (
        ("agents", MAX_AGENTS),
        ("approvals", MAX_APPROVALS),
        ("messages", MAX_MESSAGES),
    ):
        values = model[name]
        if type(values) is not list or len(values) > maximum:
            raise MultiAgentCoordinationError(f"{name} must be a bounded native array")
    agents = {}
    for raw in model["agents"]:
        entry = _exact(raw, {"agent_id", "trust_state", "privileged_actions"}, "agent")
        identity = _id(entry["agent_id"], "agent ID")
        if identity in agents:
            raise MultiAgentCoordinationError("duplicate agent ID")
        trust = entry["trust_state"]
        if type(trust) is not str or trust not in ("trusted", "untrusted", "unknown"):
            raise MultiAgentCoordinationError("trust state is unsupported")
        actions = entry["privileged_actions"]
        if type(actions) is not list or len(actions) > 64:
            raise MultiAgentCoordinationError("privileged actions must be bounded native array")
        checked = [_id(action, "action ID") for action in actions]
        if len(checked) != len(set(checked)):
            raise MultiAgentCoordinationError("duplicate privileged action")
        agents[identity] = {"trust": trust, "privileged_actions": frozenset(checked)}
    approvals = set()
    for raw in model["approvals"]:
        entry = _exact(raw, {"receiver_agent_id", "action_id", "participant_agent_id"}, "approval")
        receiver = _id(entry["receiver_agent_id"], "receiver agent ID")
        participant = _id(entry["participant_agent_id"], "participant agent ID")
        action = _id(entry["action_id"], "action ID")
        if receiver not in agents or participant not in agents:
            raise MultiAgentCoordinationError("approval refers to unknown agent")
        key = (receiver, action, participant)
        if key in approvals:
            raise MultiAgentCoordinationError("duplicate approval")
        approvals.add(key)
    messages = {}
    for raw in model["messages"]:
        entry = _exact(
            raw,
            {
                "message_id",
                "parent_message_id",
                "sender_agent_id",
                "receiver_agent_id",
                "action_id",
                "disposition",
            },
            "message",
        )
        identity = _id(entry["message_id"], "message ID")
        if identity in messages:
            raise MultiAgentCoordinationError("duplicate message ID")
        sender = _id(entry["sender_agent_id"], "sender agent ID")
        receiver = _id(entry["receiver_agent_id"], "receiver agent ID")
        if sender not in agents or receiver not in agents or sender == receiver:
            raise MultiAgentCoordinationError("message endpoints are invalid")
        disposition = entry["disposition"]
        if type(disposition) is not str or disposition not in ("accepted", "rejected", "unknown"):
            raise MultiAgentCoordinationError("message disposition is unsupported")
        messages[identity] = {
            "message_id": identity,
            "parent_message_id": _optional_id(entry["parent_message_id"], "parent message ID"),
            "sender_agent_id": sender,
            "receiver_agent_id": receiver,
            "action_id": _id(entry["action_id"], "action ID"),
            "disposition": disposition,
        }
    for identity, message in messages.items():
        parent_id = message["parent_message_id"]
        if parent_id is None:
            continue
        parent = messages.get(parent_id)
        if (
            parent is None
            or parent["receiver_agent_id"] != message["sender_agent_id"]
            or parent["action_id"] != message["action_id"]
        ):
            raise MultiAgentCoordinationError("parent relay relation is invalid")
    for identity, message in messages.items():
        seen = {identity}
        parent_id = message["parent_message_id"]
        current = parent_id
        while current is not None:
            if current in seen:
                raise MultiAgentCoordinationError("message relay cycle")
            seen.add(current)
            current = messages[current]["parent_message_id"]
    return model["facts_complete"], model["approvals_complete"], agents, approvals, messages


def _project(
    facts_complete: bool, approvals_complete: bool, agents: dict, approvals: set, messages: dict
) -> list:
    projections = []
    for identity in sorted(messages):
        chain = []
        current = identity
        while current is not None:
            chain.append(messages[current])
            current = messages[current]["parent_message_id"]
        chain.reverse()
        sink = chain[-1]["receiver_agent_id"]
        action = chain[-1]["action_id"]
        participants = sorted({item["sender_agent_id"] for item in chain})
        uncertain_agents = [
            agent_id for agent_id in {*participants, sink} if agents[agent_id]["trust"] == "unknown"
        ]
        unapproved = [
            agent_id
            for agent_id in participants
            if agents[agent_id]["trust"] == "untrusted"
            and (sink, action, agent_id) not in approvals
        ]
        if not facts_complete:
            assessment, basis = "unknown", "incomplete_facts"
        elif not approvals_complete:
            assessment, basis = "unknown", "incomplete_approvals"
        elif (
            any(item["disposition"] == "rejected" for item in chain[:-1])
            and chain[-1]["disposition"] != "rejected"
        ):
            assessment, basis = "unknown", "inconsistent_relay_dispositions"
        elif chain[-1]["disposition"] == "rejected":
            assessment, basis = "declared_blocked", "rejected_message"
        elif any(item["disposition"] == "unknown" for item in chain):
            assessment, basis = "unknown", "unknown_message_disposition"
        elif uncertain_agents:
            assessment, basis = "unknown", "unknown_agent_trust"
        elif action not in agents[sink]["privileged_actions"]:
            assessment, basis = "declared_nonprivileged_relay", "nonprivileged_receiver"
        elif agents[sink]["trust"] == "untrusted":
            assessment, basis = "unknown", "untrusted_privileged_receiver"
        elif unapproved:
            assessment, basis = (
                "candidate_unapproved_privileged_relay",
                "unapproved_untrusted_participant",
            )
        else:
            assessment, basis = "declared_approved_or_trusted", "approved_or_trusted_chain"
        projections.append(
            {
                "message_id": identity,
                "action_id": action,
                "receiver_agent_id": sink,
                "relay_message_ids": [item["message_id"] for item in chain],
                "participant_agent_ids": participants,
                "unapproved_untrusted_agent_ids": unapproved
                if assessment == "candidate_unapproved_privileged_relay"
                else [],
                "assessment": assessment,
                "basis": basis,
            }
        )
    return projections


@dataclass(frozen=True, slots=True)
class MultiAgentCoordinationReport:
    """Canonical supplied-data projection requiring original-source replay."""

    _json: str

    def __post_init__(self) -> None:
        if type(self) is not MultiAgentCoordinationReport or self._json != _checked_report_json(
            self._json
        ):
            raise MultiAgentCoordinationError("canonical exact report is required")

    def to_json(self) -> str:
        if type(self) is not MultiAgentCoordinationReport or self._json != _checked_report_json(
            self._json
        ):
            raise MultiAgentCoordinationError("canonical exact report is required")
        return self._json

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.to_json())

    @classmethod
    def from_json(cls, content: str) -> MultiAgentCoordinationReport:
        if cls is not MultiAgentCoordinationReport:
            raise MultiAgentCoordinationError("report must be the exact report family")
        return cls(_checked_report_json(content))


def _checked_report_json(content: Any) -> str:
    if type(content) is not str:
        raise MultiAgentCoordinationError("report must be native JSON text")
    try:
        raw = content.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise MultiAgentCoordinationError("report must be UTF-8 JSON text") from exc
    document = _decode(raw, maximum=MAX_REPORT_BYTES)
    _validate_report(document)
    return _canonical(document)


def _validate_report(document: Any) -> None:
    item = _exact(
        document,
        {
            "schema_version",
            "component_id",
            "profile_id",
            "capability_id",
            "vector_id",
            "work_package_id",
            "wave_id",
            "commander_id",
            "group_owner_id",
            "independent_validator_id",
            "blueprint_sha256",
            "domain",
            "source",
            "facts_complete",
            "approvals_complete",
            "projections",
            "summary",
            "effects",
            "limitations",
            "report_id",
            "report_sha256",
            *_FLAGS,
        },
        "report",
    )
    for key, expected in {
        "schema_version": SCHEMA_VERSION,
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
        "domain": DOMAIN,
        "effects": _EFFECTS,
        "limitations": _LIMITATIONS,
        **_FLAGS,
    }.items():
        if type(item[key]) is not type(expected) or item[key] != expected:
            raise MultiAgentCoordinationError(f"report {key} is invalid")
    source = _exact(item["source"], {"source_id", "sha256", "byte_count"}, "source")
    _id(source["source_id"], "source ID")
    if type(source["sha256"]) is not str or _DIGEST.fullmatch(source["sha256"]) is None:
        raise MultiAgentCoordinationError("source digest is invalid")
    if type(source["byte_count"]) is not int or not 1 <= source["byte_count"] <= MAX_SOURCE_BYTES:
        raise MultiAgentCoordinationError("source byte count is invalid")
    for key in ("facts_complete", "approvals_complete"):
        if type(item[key]) is not bool:
            raise MultiAgentCoordinationError("report completeness is invalid")
    projections = item["projections"]
    if type(projections) is not list or len(projections) > MAX_MESSAGES:
        raise MultiAgentCoordinationError("report projections are invalid")
    ids = []
    counts = {assessment: 0 for assessment in sorted(_ASSESSMENTS)}
    for raw in projections:
        projection = _exact(
            raw,
            {
                "message_id",
                "action_id",
                "receiver_agent_id",
                "relay_message_ids",
                "participant_agent_ids",
                "unapproved_untrusted_agent_ids",
                "assessment",
                "basis",
            },
            "projection",
        )
        ids.append(_id(projection["message_id"], "message ID"))
        _id(projection["action_id"], "action ID")
        _id(projection["receiver_agent_id"], "receiver agent ID")
        for key in ("relay_message_ids", "participant_agent_ids", "unapproved_untrusted_agent_ids"):
            names = projection[key]
            if type(names) is not list or len(names) > MAX_MESSAGES:
                raise MultiAgentCoordinationError("report references are invalid")
            checked = [_id(name, key) for name in names]
            if len(set(checked)) != len(checked):
                raise MultiAgentCoordinationError("report references must be unique")
            if key != "relay_message_ids" and checked != sorted(checked):
                raise MultiAgentCoordinationError("report participants must be sorted")
        if (
            type(projection["assessment"]) is not str
            or projection["assessment"] not in _ASSESSMENTS
        ):
            raise MultiAgentCoordinationError("report assessment is invalid")
        if type(projection["basis"]) is not str or projection["basis"] not in _BASES:
            raise MultiAgentCoordinationError("report basis is invalid")
        counts[projection["assessment"]] += 1
    if ids != sorted(set(ids)):
        raise MultiAgentCoordinationError("report message IDs must be sorted unique")
    summary = _exact(item["summary"], {"message_count", *counts}, "summary")
    if summary != {"message_count": len(projections), **counts} or any(
        type(value) is not int for value in summary.values()
    ):
        raise MultiAgentCoordinationError("report summary is invalid")
    body = {key: value for key, value in item.items() if key not in ("report_id", "report_sha256")}
    digest = _digest(_canonical({"domain": DOMAIN, "analysis": body}).encode("ascii"))
    if item["report_sha256"] != digest or item["report_id"] != "MAC-" + digest[7:39].upper():
        raise MultiAgentCoordinationError("report address is invalid")


def analyze_multi_agent_coordination(
    *,
    source_content: bytes,
    source_id: str,
) -> MultiAgentCoordinationReport:
    """Project supplied relay declarations without sending any message."""
    identity = _id(source_id, "source ID")
    source = _decode(source_content, maximum=MAX_SOURCE_BYTES)
    facts_complete, approvals_complete, agents, approvals, messages = _model(source)
    projections = _project(facts_complete, approvals_complete, agents, approvals, messages)
    counts = {
        assessment: sum(p["assessment"] == assessment for p in projections)
        for assessment in sorted(_ASSESSMENTS)
    }
    document = {
        "schema_version": SCHEMA_VERSION,
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
        "domain": DOMAIN,
        "source": {
            "source_id": identity,
            "sha256": _digest(source_content),
            "byte_count": len(source_content),
        },
        "facts_complete": facts_complete,
        "approvals_complete": approvals_complete,
        "projections": projections,
        "summary": {"message_count": len(projections), **counts},
        **_FLAGS,
        "effects": _EFFECTS,
        "limitations": _LIMITATIONS,
    }
    digest = _digest(_canonical({"domain": DOMAIN, "analysis": document}).encode("ascii"))
    document["report_id"] = "MAC-" + digest[7:39].upper()
    document["report_sha256"] = digest
    _validate_tree(document, maximum=MAX_REPORT_BYTES)
    _validate_report(document)
    return MultiAgentCoordinationReport(_canonical(document))


def analyze_supplied_multi_agent_coordination(
    model: dict[str, Any],
) -> MultiAgentCoordinationReport:
    """Canonicalize an exact native source-backed component model."""
    _validate_tree(model, maximum=MAX_SOURCE_BYTES)
    item = _exact(model, {"source_id", "source"}, "component model")
    source_id = _id(item["source_id"], "source ID")
    _model(item["source"])
    return analyze_multi_agent_coordination(
        source_content=_canonical(item["source"]).encode("ascii"),
        source_id=source_id,
    )


def verify_multi_agent_coordination(
    report: MultiAgentCoordinationReport,
    *,
    source_content: bytes,
    source_id: str,
) -> MultiAgentCoordinationReport:
    """Rebuild a detached report from exact original supplied source bytes."""
    if type(report) is not MultiAgentCoordinationReport:
        raise MultiAgentCoordinationError("report must be the exact report family")
    loaded = MultiAgentCoordinationReport.from_json(report.to_json())
    expected = analyze_multi_agent_coordination(source_content=source_content, source_id=source_id)
    if loaded.to_json() != expected.to_json():
        raise MultiAgentCoordinationError("report does not replay from supplied source")
    return expected


def component_fixture() -> dict[str, Any]:
    """Return fresh synthetic agent, approval and relay declarations."""
    return {
        "schema_version": SCHEMA_VERSION,
        "facts_complete": True,
        "approvals_complete": True,
        "agents": [
            {"agent_id": "rogue", "trust_state": "untrusted", "privileged_actions": []},
            {"agent_id": "relay", "trust_state": "trusted", "privileged_actions": []},
            {"agent_id": "executor", "trust_state": "trusted", "privileged_actions": ["publish"]},
        ],
        "approvals": [],
        "messages": [
            {
                "message_id": "m1",
                "parent_message_id": None,
                "sender_agent_id": "rogue",
                "receiver_agent_id": "relay",
                "action_id": "publish",
                "disposition": "accepted",
            },
            {
                "message_id": "m2",
                "parent_message_id": "m1",
                "sender_agent_id": "relay",
                "receiver_agent_id": "executor",
                "action_id": "publish",
                "disposition": "accepted",
            },
        ],
    }


__all__ = [
    "MultiAgentCoordinationError",
    "MultiAgentCoordinationReport",
    "analyze_multi_agent_coordination",
    "analyze_supplied_multi_agent_coordination",
    "verify_multi_agent_coordination",
    "component_fixture",
]
