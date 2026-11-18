"""Review one supplied synthetic SMS URI without composing or sending it."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from . import offline_framework_declaration_core as core

COMPONENT_ID = "social_supplied_sms_uri_review"
PROFILE_ID = "AOE-GA-D02-S03"
CAPABILITY_ID = "army.ga.d02.s03"
VECTOR_ID = "AV-GA-D02-S03-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D02-S03"
WAVE_ID = "IW2-004"
COMMANDER_ID = "AOE-GA-D02-CMD"
GROUP_OWNER_ID = "AOE-HQ-03"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:57f15f63ea1a670b69a2bc876010fa2cef1d02df4202915c01702871b7745295"
DOMAIN = "sunderkey.offline-sms-uri-review.v1"
MAX_MODEL_BYTES = 8_192
MAX_REPORT_BYTES = 32_768
SYNTHETIC_RECIPIENT = re.compile(r"\+120255501[0-9]{2}\Z")
PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class SmsUriReviewError(ValueError):
    """A synthetic SMS URI declaration or replay is invalid."""


def _canonical(value: Any) -> str:
    try:
        result = json.dumps(
            value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise SmsUriReviewError("Model must be bounded native JSON") from exc
    if len(result) > MAX_MODEL_BYTES:
        raise SmsUriReviewError("Model exceeds byte bound")
    return result


def _hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _recipients(value: Any) -> list[str]:
    if (type(value) is not list or not 1 <= len(value) <= 4
            or any(type(item) is not str or SYNTHETIC_RECIPIENT.fullmatch(item) is None
                   for item in value)
            or len(set(value)) != len(value)):
        raise SmsUriReviewError("One to four distinct synthetic recipients required")
    return value


def _derive(value: Any) -> dict:
    model_text = _canonical(value)
    model = core.exact(
        json.loads(model_text),
        {"schema_version", "source_id", "synthetic_fixture", "sms_uri",
         "expected_recipients"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise SmsUriReviewError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise SmsUriReviewError("Only synthetic fixtures are accepted")
    expected = _recipients(model["expected_recipients"])
    uri = model["sms_uri"]
    if (type(uri) is not str or not 1 <= len(uri) <= 1_024
            or not uri.isascii() or any(ord(char) < 33 for char in uri)
            or PERCENT_ESCAPE.search(uri)):
        raise SmsUriReviewError("Bounded ASCII SMS URI required")
    parsed = urlsplit(uri)
    if parsed.scheme != "sms" or parsed.netloc or parsed.fragment:
        raise SmsUriReviewError("SMS URI scheme without authority required")
    recipients = _recipients(parsed.path.split(","))
    if parsed.query:
        if PERCENT_ESCAPE.search(parsed.query):
            raise SmsUriReviewError("Malformed body escape")
        try:
            fields = parse_qsl(
                parsed.query, keep_blank_values=True, strict_parsing=True,
                errors="strict",
            )
        except (ValueError, UnicodeDecodeError) as exc:
            raise SmsUriReviewError("Malformed SMS URI query") from exc
        if len(fields) != 1 or fields[0][0] != "body":
            raise SmsUriReviewError("Only one optional body field is modeled")
        body = fields[0][1]
        if len(body) > 160 or any(ord(char) < 32 for char in body):
            raise SmsUriReviewError("Bounded body without controls required")
    else:
        body = None
    matches = recipients == expected
    report_body = {
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
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "synthetic_fixture_asserted": True,
        "sms_uri_sha256": _hash(uri),
        "recipient_count": len(recipients),
        "recipients_match_supplied_expectation": matches,
        "recipient_sha256": [_hash(item) for item in recipients],
        "body_present": body is not None,
        "body_sha256": _hash(body) if body is not None else None,
        "message_composed": False,
        "message_delivered": False,
        "recipient_validated": False,
        "candidate_count": 0,
        "uncertainty": [
            "recipient_assertions_unverified",
            "message_composition_and_delivery_unobserved",
            "carrier_behavior_unverified",
        ],
        "unknown_count": 3,
        "disposition": "unknown",
        "source_authenticated": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Only a constrained RFC 5724 SMS URI subset is parsed from synthetic data.",
            "Numbers must be reserved synthetic examples, not real recipients.",
            "A URI does not prove recipient reachability, message composition, or delivery.",
            "No SMS client or provider is invoked and no message is sent.",
        ],
    }
    report_id, report_sha256 = core.report_address(
        report_body, domain=DOMAIN, prefix="SMR-"
    )
    report = {**report_body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class SmsUriReviewReport:
    """Unsigned SMS URI projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise SmsUriReviewError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> SmsUriReviewReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_sms_uri(model: Any) -> SmsUriReviewReport:
    return SmsUriReviewReport._owned(_derive(model))


def verify_supplied_sms_uri(report: Any, *, model: Any) -> SmsUriReviewReport:
    if type(report) is not SmsUriReviewReport:
        raise SmsUriReviewError("Exact SMS URI wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise SmsUriReviewError("Report differs from separate original model")
    return SmsUriReviewReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-sms-uri",
        "synthetic_fixture": True,
        "sms_uri": "sms:+12025550101,+12025550102?body=Exercise%20metadata",
        "expected_recipients": ["+12025550101", "+12025550102"],
    }
