"""Parse one supplied synthetic Authentication-Results header without mail I/O."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "social_supplied_email_auth_results_review"
PROFILE_ID = "AOE-GA-D02-S01"
CAPABILITY_ID = "army.ga.d02.s01"
VECTOR_ID = "AV-GA-D02-S01-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D02-S01"
WAVE_ID = "IW2-002"
COMMANDER_ID = "AOE-GA-D02-CMD"
GROUP_OWNER_ID = "AOE-HQ-03"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:5a5d2754ad2061f91da4298f0a127e863a0466063761ca00a3969d449329e285"
DOMAIN = "sunderkey.offline-email-auth-results-review.v1"
MAX_MODEL_BYTES = 8_192
MAX_REPORT_BYTES = 32_768
METHOD_RESULT = re.compile(
    r"(spf|dkim|dmarc)=(pass|fail|neutral|none|temperror|permerror)"
    r" (smtp\.mailfrom|header\.d|header\.from)=([a-z0-9.-]+)"
)
PROPERTY_FOR = {
    "spf": "smtp.mailfrom",
    "dkim": "header.d",
    "dmarc": "header.from",
}
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class EmailAuthResultsReviewError(ValueError):
    """A synthetic Authentication-Results declaration or replay is invalid."""


def _canonical(value: Any) -> str:
    try:
        result = json.dumps(
            value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise EmailAuthResultsReviewError("Model must be bounded native JSON") from exc
    if len(result) > MAX_MODEL_BYTES:
        raise EmailAuthResultsReviewError("Model exceeds byte bound")
    return result


def _hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _synthetic_domain(value: Any) -> str:
    if (type(value) is not str or not 1 <= len(value) <= 128
            or not value.endswith(".synthetic.example")
            or any(not label or len(label) > 63
                   or re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", label) is None
                   for label in value.split("."))):
        raise EmailAuthResultsReviewError("Synthetic .example domain required")
    return value


def _derive(value: Any) -> dict:
    model_text = _canonical(value)
    model = core.exact(
        json.loads(model_text),
        {"schema_version", "source_id", "synthetic_fixture",
         "authentication_results_header", "expected_authserv_id",
         "expected_origin_domain"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise EmailAuthResultsReviewError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise EmailAuthResultsReviewError("Only synthetic fixtures are accepted")
    expected_authserv = _synthetic_domain(model["expected_authserv_id"])
    expected_origin = _synthetic_domain(model["expected_origin_domain"])
    header = model["authentication_results_header"]
    if (type(header) is not str or not 1 <= len(header) <= 1_024
            or not header.isascii() or any(ord(char) < 32 for char in header)):
        raise EmailAuthResultsReviewError("Bounded single-line ASCII header required")
    prefix = "Authentication-Results: "
    if not header.startswith(prefix):
        raise EmailAuthResultsReviewError("Authentication-Results field required")
    parts = header[len(prefix):].split("; ")
    if not 2 <= len(parts) <= 4:
        raise EmailAuthResultsReviewError("One to three method results required")
    authserv = _synthetic_domain(parts[0])
    seen = set()
    results = []
    for part in parts[1:]:
        match = METHOD_RESULT.fullmatch(part)
        if match is None:
            raise EmailAuthResultsReviewError("Unsupported method-result subset")
        method, result, prop, declared_domain = match.groups()
        _synthetic_domain(declared_domain)
        if method in seen or prop != PROPERTY_FOR[method]:
            raise EmailAuthResultsReviewError("Distinct method-property pairing required")
        seen.add(method)
        results.append({
            "method": method,
            "declared_result": result,
            "property": prop,
            "declared_domain_sha256": _hash(declared_domain),
            "domain_matches_supplied_expectation": declared_domain == expected_origin,
        })
    body = {
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
        "header_sha256": _hash(header),
        "authserv_matches_supplied_expectation": authserv == expected_authserv,
        "method_result_count": len(results),
        "declared_results": results,
        "mail_authentication_verified": False,
        "header_trust_verified": False,
        "message_delivered": False,
        "candidate_count": 0,
        "uncertainty": [
            "header_origin_and_trust_unverified",
            "authentication_results_not_independently_recomputed",
            "message_delivery_and_recipient_behavior_unobserved",
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
            "Only a constrained RFC 8601 field subset is parsed from synthetic data.",
            "Header contents are untrusted claims, not independently checked SPF, DKIM or DMARC.",
            "Expected origin and authserv are caller assertions, not authenticated identities.",
            "No message is built, sent, delivered, or opened.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="EAR-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class EmailAuthResultsReviewReport:
    """Unsigned header projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise EmailAuthResultsReviewError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> EmailAuthResultsReviewReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_email_auth_results(model: Any) -> EmailAuthResultsReviewReport:
    return EmailAuthResultsReviewReport._owned(_derive(model))


def verify_supplied_email_auth_results(
    report: Any, *, model: Any
) -> EmailAuthResultsReviewReport:
    if type(report) is not EmailAuthResultsReviewReport:
        raise EmailAuthResultsReviewError("Exact header wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise EmailAuthResultsReviewError("Report differs from separate original model")
    return EmailAuthResultsReviewReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-email-auth-results",
        "synthetic_fixture": True,
        "authentication_results_header": (
            "Authentication-Results: mx.synthetic.example; "
            "spf=pass smtp.mailfrom=sender.synthetic.example; "
            "dkim=pass header.d=sender.synthetic.example; "
            "dmarc=pass header.from=sender.synthetic.example"
        ),
        "expected_authserv_id": "mx.synthetic.example",
        "expected_origin_domain": "sender.synthetic.example",
    }
