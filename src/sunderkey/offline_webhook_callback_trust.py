"""Offline projection of supplied webhook receiver and delivery assertions."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

PROFILE_ID = "AOE-GB-D06-S06"
CAPABILITY_ID = "army.gb.d06.s06"
VECTOR_ID = "AV-GB-D06-S06-01"
WAVE_ID = "IW2-001"
DOMAIN = "sunderkey.offline-webhook-callback-trust.v1"
SCHEMA_VERSION = "v1"
MAX_SOURCE_BYTES = 262_144
MAX_REPORT_BYTES = 524_288
MAX_NODES = 40_000
MAX_DEPTH = 16
MAX_TEXT_BYTES = 512
MAX_RECEIVERS = 256
MAX_PRODUCERS_PER_RECEIVER = 128
MAX_PRIOR_ACCEPTANCES = 2_048
MAX_DELIVERIES = 2_048
MAX_AGE_SECONDS = 86_400
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
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
    )
}
_FLAGS = {
    "offline_only": True,
    "facts_authenticated": False,
    "policy_authenticated": False,
    "signature_verified_live": False,
    "receiver_outcomes_authenticated": False,
    "callback_performed": False,
    "finding_claimed": False,
    "positive_use_approved": False,
    "qualification_claimed": False,
}
_LIMITATIONS = [
    "Receiver policy, producers, prior acceptances, ages and outcomes are supplied assertions.",
    "A verified signature disposition is a label; no signature or secret is processed.",
    "Age is supplied arithmetic, not a trusted clock or actual delivery timestamp.",
    "Prior acceptance is supplied context, not a read from a receiver or storage service.",
    "A supplied contradiction is a candidate, not a verified webhook weakness.",
    "No URL, HTTP request, callback, credential, process or network operation occurs.",
]
_ASSESSMENTS = {"candidate_policy_contradiction", "declared_consistent", "unknown"}
_BASES = {
    "incomplete_facts",
    "incomplete_policy",
    "no_receiver_policy",
    "producer_not_allowed",
    "signature_not_verified",
    "replay_event_id",
    "replay_idempotency_key",
    "stale_event",
    "unknown_signature",
    "missing_idempotency_key",
    "unknown_age",
    "all_declared_checks_pass",
}


class WebhookCallbackTrustError(ValueError):
    """Closed input, resource bound or source replay validation failed."""


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields or any(type(k) is not str for k in value):
        raise WebhookCallbackTrustError(f"{label} fields are invalid")
    return value


def _id(value: Any, label: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise WebhookCallbackTrustError(f"{label} must be bounded native ASCII text")
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
            raise WebhookCallbackTrustError("duplicate JSON key")
        result[key] = value
    return result


def _json_integer(token: str) -> int:
    if len(token) > 20 or len(token.lstrip("-")) > 19:
        raise WebhookCallbackTrustError("JSON integer exceeds signed64 bound")
    value = int(token)
    if not -(1 << 63) <= value < (1 << 63):
        raise WebhookCallbackTrustError("JSON integer exceeds signed64 bound")
    return value


def _unsupported_number(_token: str) -> None:
    raise WebhookCallbackTrustError("floating and nonfinite numbers are unsupported")


def _validate_tree(value: Any, *, maximum: int) -> None:
    stack = [(value, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise WebhookCallbackTrustError("JSON node or depth bound exceeded")
        kind = type(item)
        if kind is dict:
            if nodes + len(stack) + 2 * len(item) > MAX_NODES:
                raise WebhookCallbackTrustError("JSON node bound exceeded")
            for key, child in item.items():
                if type(key) is not str:
                    raise WebhookCallbackTrustError("JSON keys must be native text")
                stack.append((child, depth + 1))
                stack.append((key, depth + 1))
        elif kind is list:
            if nodes + len(stack) + len(item) > MAX_NODES:
                raise WebhookCallbackTrustError("JSON node bound exceeded")
            stack.extend((child, depth + 1) for child in item)
        elif kind is str:
            if len(item.encode("utf-8", errors="surrogatepass")) > MAX_TEXT_BYTES or any(
                0xD800 <= ord(char) <= 0xDFFF for char in item
            ):
                raise WebhookCallbackTrustError("JSON string is unsupported or too long")
        elif kind is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise WebhookCallbackTrustError("JSON integer exceeds signed64 bound")
        elif kind not in (bool, type(None)):
            raise WebhookCallbackTrustError("unsupported JSON value family")
    if len(_canonical(value).encode("ascii")) > maximum:
        raise WebhookCallbackTrustError("canonical JSON byte bound exceeded")


def _decode(content: bytes, *, maximum: int) -> Any:
    if type(content) is not bytes or not content or len(content) > maximum:
        raise WebhookCallbackTrustError("source must be bounded nonempty native bytes")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WebhookCallbackTrustError("source must be UTF-8") from exc
    nesting = 0
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
            nesting += 1
            if nesting > MAX_DEPTH:
                raise WebhookCallbackTrustError("pre-decoder depth bound exceeded")
        elif char in "]}":
            nesting -= 1
            if nesting < 0:
                raise WebhookCallbackTrustError("malformed JSON nesting")
    if nesting or quoted:
        raise WebhookCallbackTrustError("malformed JSON nesting")
    try:
        result = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_json_integer,
            parse_float=_unsupported_number,
            parse_constant=_unsupported_number,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, WebhookCallbackTrustError):
            raise
        raise WebhookCallbackTrustError("malformed JSON source") from exc
    _validate_tree(result, maximum=maximum)
    return result


def _optional_age(value: Any, label: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int or not 0 <= value <= MAX_AGE_SECONDS:
        raise WebhookCallbackTrustError(f"{label} must be a bounded native integer")
    return value


def _model(document: Any) -> tuple[bool, bool, dict, dict, list]:
    model = _exact(
        document,
        {
            "schema_version",
            "facts_complete",
            "policy_complete",
            "receivers",
            "prior_acceptances",
            "deliveries",
        },
        "model",
    )
    if type(model["schema_version"]) is not str or model["schema_version"] != SCHEMA_VERSION:
        raise WebhookCallbackTrustError("unsupported model version")
    if type(model["facts_complete"]) is not bool or type(model["policy_complete"]) is not bool:
        raise WebhookCallbackTrustError("completeness must be native Booleans")
    for name, maximum in (
        ("receivers", MAX_RECEIVERS),
        ("prior_acceptances", MAX_PRIOR_ACCEPTANCES),
        ("deliveries", MAX_DELIVERIES),
    ):
        values = model[name]
        if type(values) is not list or len(values) > maximum:
            raise WebhookCallbackTrustError(f"{name} must be a bounded native array")
    receivers = {}
    for raw in model["receivers"]:
        entry = _exact(
            raw,
            {
                "receiver_id",
                "allowed_producer_ids",
                "signature_required",
                "replay_key",
                "max_age_seconds",
            },
            "receiver",
        )
        receiver_id = _id(entry["receiver_id"], "receiver ID")
        if receiver_id in receivers:
            raise WebhookCallbackTrustError("duplicate receiver ID")
        producers = entry["allowed_producer_ids"]
        if type(producers) is not list or len(producers) > MAX_PRODUCERS_PER_RECEIVER:
            raise WebhookCallbackTrustError("allowed producers must be a bounded native array")
        checked = [_id(producer, "producer ID") for producer in producers]
        if len(checked) != len(set(checked)):
            raise WebhookCallbackTrustError("duplicate allowed producer ID")
        if type(entry["signature_required"]) is not bool:
            raise WebhookCallbackTrustError("signature requirement must be native Boolean")
        replay_key = entry["replay_key"]
        if type(replay_key) is not str or replay_key not in ("none", "event_id", "idempotency_key"):
            raise WebhookCallbackTrustError("replay key is unsupported")
        receivers[receiver_id] = {
            "allowed_producers": frozenset(checked),
            "signature_required": entry["signature_required"],
            "replay_key": replay_key,
            "max_age_seconds": _optional_age(entry["max_age_seconds"], "maximum age"),
        }
    prior = {}
    for raw in model["prior_acceptances"]:
        entry = _exact(raw, {"receiver_id", "event_id", "idempotency_key_id"}, "prior acceptance")
        receiver_id = _id(entry["receiver_id"], "receiver ID")
        event_id = _id(entry["event_id"], "event ID")
        key_id = _optional_id(entry["idempotency_key_id"], "idempotency key ID")
        record = prior.setdefault(receiver_id, {"events": set(), "keys": set()})
        if event_id in record["events"] or (key_id is not None and key_id in record["keys"]):
            raise WebhookCallbackTrustError("duplicate prior event or idempotency key")
        record["events"].add(event_id)
        if key_id is not None:
            record["keys"].add(key_id)
    deliveries = []
    seen = set()
    for raw in model["deliveries"]:
        entry = _exact(
            raw,
            {
                "delivery_id",
                "receiver_id",
                "producer_id",
                "event_id",
                "idempotency_key_id",
                "signature_disposition",
                "age_seconds",
                "receiver_outcome",
            },
            "delivery",
        )
        delivery_id = _id(entry["delivery_id"], "delivery ID")
        if delivery_id in seen:
            raise WebhookCallbackTrustError("duplicate delivery ID")
        seen.add(delivery_id)
        signature = entry["signature_disposition"]
        outcome = entry["receiver_outcome"]
        if type(signature) is not str or signature not in (
            "verified",
            "failed",
            "not_checked",
            "unknown",
        ):
            raise WebhookCallbackTrustError("signature disposition is unsupported")
        if type(outcome) is not str or outcome not in ("accepted", "rejected", "unknown"):
            raise WebhookCallbackTrustError("receiver outcome is unsupported")
        deliveries.append(
            {
                "delivery_id": delivery_id,
                "receiver_id": _id(entry["receiver_id"], "receiver ID"),
                "producer_id": _id(entry["producer_id"], "producer ID"),
                "event_id": _id(entry["event_id"], "event ID"),
                "idempotency_key_id": _optional_id(
                    entry["idempotency_key_id"], "idempotency key ID"
                ),
                "signature_disposition": signature,
                "age_seconds": _optional_age(entry["age_seconds"], "event age"),
                "receiver_outcome": outcome,
            }
        )
    return model["facts_complete"], model["policy_complete"], receivers, prior, deliveries


def _project(
    facts_complete: bool, policy_complete: bool, receivers: dict, prior: dict, deliveries: list
) -> list:
    projections = []
    for delivery in sorted(deliveries, key=lambda item: item["delivery_id"]):
        receiver_id = delivery["receiver_id"]
        policy = receivers.get(receiver_id)
        prior_at_receiver = prior.get(receiver_id, {"events": set(), "keys": set()})
        expected = "unknown"
        if not facts_complete:
            basis = "incomplete_facts"
        elif not policy_complete:
            basis = "incomplete_policy"
        elif policy is None:
            expected, basis = "reject", "no_receiver_policy"
        elif delivery["producer_id"] not in policy["allowed_producers"]:
            expected, basis = "reject", "producer_not_allowed"
        elif policy["signature_required"] and delivery["signature_disposition"] in (
            "failed",
            "not_checked",
        ):
            expected, basis = "reject", "signature_not_verified"
        elif (
            policy["replay_key"] == "event_id"
            and delivery["event_id"] in prior_at_receiver["events"]
        ):
            expected, basis = "reject", "replay_event_id"
        elif (
            policy["replay_key"] == "idempotency_key"
            and delivery["idempotency_key_id"] is not None
            and delivery["idempotency_key_id"] in prior_at_receiver["keys"]
        ):
            expected, basis = "reject", "replay_idempotency_key"
        elif (
            policy["max_age_seconds"] is not None
            and delivery["age_seconds"] is not None
            and delivery["age_seconds"] > policy["max_age_seconds"]
        ):
            expected, basis = "reject", "stale_event"
        elif policy["signature_required"] and delivery["signature_disposition"] == "unknown":
            basis = "unknown_signature"
        elif policy["replay_key"] == "idempotency_key" and delivery["idempotency_key_id"] is None:
            basis = "missing_idempotency_key"
        elif policy["max_age_seconds"] is not None and delivery["age_seconds"] is None:
            basis = "unknown_age"
        else:
            expected, basis = "accept", "all_declared_checks_pass"
        outcome = delivery["receiver_outcome"]
        if expected == "unknown" or outcome == "unknown":
            assessment = "unknown"
        elif (expected == "accept") == (outcome == "accepted"):
            assessment = "declared_consistent"
        else:
            assessment = "candidate_policy_contradiction"
        projections.append(
            {
                **delivery,
                "expected_decision": expected,
                "basis": basis,
                "assessment": assessment,
            }
        )
    return projections


@dataclass(frozen=True, slots=True)
class WebhookCallbackTrustReport:
    """Canonical report whose derivation requires exact original-source replay."""

    _json: str

    def __post_init__(self) -> None:
        if type(self) is not WebhookCallbackTrustReport or self._json != _checked_report_json(
            self._json
        ):
            raise WebhookCallbackTrustError("canonical exact report is required")

    def to_json(self) -> str:
        if type(self) is not WebhookCallbackTrustReport or self._json != _checked_report_json(
            self._json
        ):
            raise WebhookCallbackTrustError("canonical exact report is required")
        return self._json

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.to_json())

    @classmethod
    def from_json(cls, content: str) -> WebhookCallbackTrustReport:
        if cls is not WebhookCallbackTrustReport:
            raise WebhookCallbackTrustError("report must be the exact report family")
        return cls(_checked_report_json(content))


def _checked_report_json(content: Any) -> str:
    if type(content) is not str:
        raise WebhookCallbackTrustError("report must be native JSON text")
    try:
        raw = content.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise WebhookCallbackTrustError("report must be UTF-8 JSON text") from exc
    document = _decode(raw, maximum=MAX_REPORT_BYTES)
    _validate_report(document)
    return _canonical(document)


def _validate_report(document: Any) -> None:
    item = _exact(
        document,
        {
            "schema_version",
            "profile_id",
            "capability_id",
            "vector_id",
            "wave_id",
            "domain",
            "source",
            "facts_complete",
            "policy_complete",
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
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "wave_id": WAVE_ID,
        "domain": DOMAIN,
        "effects": _EFFECTS,
        "limitations": _LIMITATIONS,
        **_FLAGS,
    }.items():
        if type(item[key]) is not type(expected) or item[key] != expected:
            raise WebhookCallbackTrustError(f"report {key} is invalid")
    source = _exact(item["source"], {"source_id", "sha256", "byte_count"}, "source")
    _id(source["source_id"], "source ID")
    if type(source["sha256"]) is not str or _DIGEST.fullmatch(source["sha256"]) is None:
        raise WebhookCallbackTrustError("source digest is invalid")
    if type(source["byte_count"]) is not int or not 1 <= source["byte_count"] <= MAX_SOURCE_BYTES:
        raise WebhookCallbackTrustError("source byte count is invalid")
    if type(item["facts_complete"]) is not bool or type(item["policy_complete"]) is not bool:
        raise WebhookCallbackTrustError("report completeness is invalid")
    projections = item["projections"]
    if type(projections) is not list or len(projections) > MAX_DELIVERIES:
        raise WebhookCallbackTrustError("report projections are invalid")
    ids = []
    counts = {assessment: 0 for assessment in sorted(_ASSESSMENTS)}
    for raw in projections:
        projection = _exact(
            raw,
            {
                "delivery_id",
                "receiver_id",
                "producer_id",
                "event_id",
                "idempotency_key_id",
                "signature_disposition",
                "age_seconds",
                "receiver_outcome",
                "expected_decision",
                "basis",
                "assessment",
            },
            "projection",
        )
        ids.append(_id(projection["delivery_id"], "delivery ID"))
        for key in ("receiver_id", "producer_id", "event_id"):
            _id(projection[key], key)
        _optional_id(projection["idempotency_key_id"], "idempotency key ID")
        _optional_age(projection["age_seconds"], "event age")
        for key, options in (
            ("signature_disposition", ("verified", "failed", "not_checked", "unknown")),
            ("receiver_outcome", ("accepted", "rejected", "unknown")),
            ("expected_decision", ("accept", "reject", "unknown")),
            ("basis", _BASES),
            ("assessment", _ASSESSMENTS),
        ):
            if type(projection[key]) is not str or projection[key] not in options:
                raise WebhookCallbackTrustError(f"report {key} is invalid")
        counts[projection["assessment"]] += 1
    if ids != sorted(set(ids)):
        raise WebhookCallbackTrustError("report delivery IDs must be sorted unique")
    summary = _exact(item["summary"], {"delivery_count", *counts}, "summary")
    if summary != {"delivery_count": len(projections), **counts} or any(
        type(value) is not int for value in summary.values()
    ):
        raise WebhookCallbackTrustError("report summary is invalid")
    body = {key: value for key, value in item.items() if key not in ("report_id", "report_sha256")}
    digest = _digest(_canonical({"domain": DOMAIN, "analysis": body}).encode("ascii"))
    if item["report_sha256"] != digest or item["report_id"] != "WCT-" + digest[7:39].upper():
        raise WebhookCallbackTrustError("report address is invalid")


def analyze_webhook_callback_trust(
    *,
    source_content: bytes,
    source_id: str,
) -> WebhookCallbackTrustReport:
    """Compare supplied receiver outcomes against declared callback policy."""
    identity = _id(source_id, "source ID")
    source = _decode(source_content, maximum=MAX_SOURCE_BYTES)
    facts_complete, policy_complete, receivers, prior, deliveries = _model(source)
    projections = _project(facts_complete, policy_complete, receivers, prior, deliveries)
    counts = {
        assessment: sum(p["assessment"] == assessment for p in projections)
        for assessment in sorted(_ASSESSMENTS)
    }
    document = {
        "schema_version": SCHEMA_VERSION,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "wave_id": WAVE_ID,
        "domain": DOMAIN,
        "source": {
            "source_id": identity,
            "sha256": _digest(source_content),
            "byte_count": len(source_content),
        },
        "facts_complete": facts_complete,
        "policy_complete": policy_complete,
        "projections": projections,
        "summary": {"delivery_count": len(projections), **counts},
        **_FLAGS,
        "effects": _EFFECTS,
        "limitations": _LIMITATIONS,
    }
    digest = _digest(_canonical({"domain": DOMAIN, "analysis": document}).encode("ascii"))
    document["report_id"] = "WCT-" + digest[7:39].upper()
    document["report_sha256"] = digest
    _validate_tree(document, maximum=MAX_REPORT_BYTES)
    _validate_report(document)
    return WebhookCallbackTrustReport(_canonical(document))


def analyze_supplied_webhook_callback_trust(model: dict[str, Any]) -> WebhookCallbackTrustReport:
    """Canonicalize an exact native source-backed component model."""
    _validate_tree(model, maximum=MAX_SOURCE_BYTES)
    item = _exact(model, {"source_id", "source"}, "component model")
    source_id = _id(item["source_id"], "source ID")
    _model(item["source"])
    return analyze_webhook_callback_trust(
        source_content=_canonical(item["source"]).encode("ascii"),
        source_id=source_id,
    )


def verify_webhook_callback_trust(
    report: WebhookCallbackTrustReport,
    *,
    source_content: bytes,
    source_id: str,
) -> WebhookCallbackTrustReport:
    """Rebuild a detached report from exact original supplied source bytes."""
    if type(report) is not WebhookCallbackTrustReport:
        raise WebhookCallbackTrustError("report must be the exact report family")
    loaded = WebhookCallbackTrustReport.from_json(report.to_json())
    expected = analyze_webhook_callback_trust(source_content=source_content, source_id=source_id)
    if loaded.to_json() != expected.to_json():
        raise WebhookCallbackTrustError("report does not replay from supplied source")
    return expected


def component_fixture() -> dict[str, Any]:
    """Return fresh inert receiver, prior acceptance and delivery assertions."""
    return {
        "schema_version": SCHEMA_VERSION,
        "facts_complete": True,
        "policy_complete": True,
        "receivers": [
            {
                "receiver_id": "billing-hook",
                "allowed_producer_ids": ["billing-service"],
                "signature_required": True,
                "replay_key": "event_id",
                "max_age_seconds": 300,
            }
        ],
        "prior_acceptances": [
            {"receiver_id": "billing-hook", "event_id": "evt-old", "idempotency_key_id": "key-old"}
        ],
        "deliveries": [
            {
                "delivery_id": "delivery-fresh",
                "receiver_id": "billing-hook",
                "producer_id": "billing-service",
                "event_id": "evt-new",
                "idempotency_key_id": "key-new",
                "signature_disposition": "verified",
                "age_seconds": 30,
                "receiver_outcome": "accepted",
            },
            {
                "delivery_id": "delivery-replay",
                "receiver_id": "billing-hook",
                "producer_id": "billing-service",
                "event_id": "evt-old",
                "idempotency_key_id": "key-old",
                "signature_disposition": "verified",
                "age_seconds": 60,
                "receiver_outcome": "accepted",
            },
        ],
    }


__all__ = [
    "WebhookCallbackTrustError",
    "WebhookCallbackTrustReport",
    "analyze_webhook_callback_trust",
    "analyze_supplied_webhook_callback_trust",
    "verify_webhook_callback_trust",
    "component_fixture",
]
