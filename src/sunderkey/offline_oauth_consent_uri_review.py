"""Review a supplied synthetic Entra consent-request URI without opening it."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from . import offline_framework_declaration_core as core

COMPONENT_ID = "social_supplied_oauth_consent_uri_review"
PROFILE_ID = "AOE-GA-D02-S06"
CAPABILITY_ID = "army.ga.d02.s06"
VECTOR_ID = "AV-GA-D02-S06-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D02-S06"
WAVE_ID = "IW2-007"
COMMANDER_ID = "AOE-GA-D02-CMD"
GROUP_OWNER_ID = "AOE-HQ-03"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:6a82c96dbe64cdb5e0ec0aecf85e6855f393a974cec95bdac19f370772f2dacd"
DOMAIN = "sunderkey.offline-oauth-consent-uri-review.v1"
MAX_MODEL_BYTES = 8_192
MAX_REPORT_BYTES = 32_768
GUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
SCOPE = re.compile(r"[A-Za-z0-9_./:-]{1,128}\Z")
STATE = re.compile(r"[A-Za-z0-9._-]{8,128}\Z")
PARAMETERS = {"client_id", "response_type", "redirect_uri", "scope", "state", "prompt"}
REQUIRED = {"client_id", "response_type", "redirect_uri", "scope", "state"}
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class OAuthConsentUriReviewError(ValueError):
    """A supplied consent-request model or replay is invalid."""


def _canonical(value: Any) -> str:
    try:
        result = json.dumps(
            value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise OAuthConsentUriReviewError("Model must be bounded native JSON") from exc
    if len(result) > MAX_MODEL_BYTES:
        raise OAuthConsentUriReviewError("Model exceeds byte bound")
    return result


def _hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _synthetic_redirect(value: Any) -> str:
    if type(value) is not str or len(value) > 512:
        raise OAuthConsentUriReviewError("Bounded redirect URI required")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise OAuthConsentUriReviewError("Malformed redirect URI") from exc
    if (parsed.scheme != "https" or parsed.hostname is None
            or not parsed.hostname.endswith(".example")
            or parsed.username is not None or parsed.password is not None
            or port is not None or parsed.query or parsed.fragment):
        raise OAuthConsentUriReviewError("Only an HTTPS .example redirect is accepted")
    return value


def _derive(value: Any) -> dict:
    model_text = _canonical(value)
    model = core.exact(
        json.loads(model_text),
        {
            "schema_version", "source_id", "synthetic_fixture", "authorization_uri",
            "expected_tenant_id", "expected_client_id", "expected_redirect_uri",
            "allowed_scopes",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise OAuthConsentUriReviewError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise OAuthConsentUriReviewError("Only synthetic fixtures are accepted")
    tenant = model["expected_tenant_id"]
    client = model["expected_client_id"]
    if type(tenant) is not str or GUID.fullmatch(tenant) is None:
        raise OAuthConsentUriReviewError("Synthetic tenant GUID required")
    if type(client) is not str or GUID.fullmatch(client) is None:
        raise OAuthConsentUriReviewError("Synthetic client GUID required")
    expected_redirect = _synthetic_redirect(model["expected_redirect_uri"])
    allowed = model["allowed_scopes"]
    if (type(allowed) is not list or not 1 <= len(allowed) <= 16
            or any(type(item) is not str or SCOPE.fullmatch(item) is None for item in allowed)
            or len(set(allowed)) != len(allowed)):
        raise OAuthConsentUriReviewError("Distinct bounded allowed scopes required")
    uri = model["authorization_uri"]
    if (type(uri) is not str or not 1 <= len(uri) <= 2_048
            or not uri.isascii() or any(ord(char) < 33 for char in uri)):
        raise OAuthConsentUriReviewError("Bounded printable authorization URI required")
    parsed = urlsplit(uri)
    if (parsed.scheme != "https" or parsed.netloc != "login.microsoftonline.com"
            or parsed.path != f"/{tenant}/oauth2/v2.0/authorize" or parsed.fragment):
        raise OAuthConsentUriReviewError("Synthetic Entra authorization path required")
    try:
        pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError as exc:
        raise OAuthConsentUriReviewError("Malformed authorization query") from exc
    if (len(pairs) > 6 or {key for key, _ in pairs} != REQUIRED | (
            {"prompt"} if any(key == "prompt" for key, _ in pairs) else set()
        ) or len({key for key, _ in pairs}) != len(pairs)
            or any(key not in PARAMETERS for key, _ in pairs)):
        raise OAuthConsentUriReviewError("Closed unique authorization parameters required")
    params = dict(pairs)
    if params["response_type"] != "code" or STATE.fullmatch(params["state"]) is None:
        raise OAuthConsentUriReviewError("Code flow and bounded state required")
    if "prompt" in params and params["prompt"] != "consent":
        raise OAuthConsentUriReviewError("Only optional consent prompt is accepted")
    requested = params["scope"].split(" ")
    if (not 1 <= len(requested) <= 16 or len(set(requested)) != len(requested)
            or any(SCOPE.fullmatch(item) is None for item in requested)):
        raise OAuthConsentUriReviewError("Distinct bounded requested scopes required")
    if any(item.endswith("/.default") for item in requested) and len(requested) != 1:
        raise OAuthConsentUriReviewError("Static .default cannot mix with dynamic scopes")
    redirect = _synthetic_redirect(params["redirect_uri"])
    client_match = params["client_id"] == client
    redirect_match = redirect == expected_redirect
    unlisted = sorted(set(requested) - set(allowed))
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
        "authorization_uri_sha256": _hash(uri),
        "client_id_matches_supplied_expectation": client_match,
        "redirect_uri_matches_supplied_expectation": redirect_match,
        "requested_scope_count": len(requested),
        "unlisted_scope_count": len(unlisted),
        "unlisted_scope_sha256": [_hash(item) for item in unlisted],
        "static_default_scope": requested[0].endswith("/.default"),
        "explicit_consent_prompt": params.get("prompt") == "consent",
        "syntax_and_declared_expectations_match": (
            client_match and redirect_match and not unlisted
        ),
        "tenant_policy_verified": False,
        "application_identity_verified": False,
        "consent_granted": False,
        "lure_delivered": False,
        "candidate_count": 0,
        "uncertainty": [
            "caller_declared_expectations_unverified",
            "tenant_policy_and_application_identity_unverified",
            "consent_and_delivery_unobserved",
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
            "Only one synthetic supplied Entra code-flow URI is parsed locally.",
            "Expected client, redirect and scopes are caller assertions, not tenant policy.",
            "Syntax consistency does not prove application identity or a consent grant.",
            "No URL is opened and no lure, message, or consent request is delivered.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="OCR-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class OAuthConsentUriReviewReport:
    """Unsigned consent URI projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise OAuthConsentUriReviewError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> OAuthConsentUriReviewReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_oauth_consent_uri(model: Any) -> OAuthConsentUriReviewReport:
    return OAuthConsentUriReviewReport._owned(_derive(model))


def verify_supplied_oauth_consent_uri(
    report: Any, *, model: Any
) -> OAuthConsentUriReviewReport:
    if type(report) is not OAuthConsentUriReviewReport:
        raise OAuthConsentUriReviewError("Exact consent URI wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise OAuthConsentUriReviewError("Report differs from separate original model")
    return OAuthConsentUriReviewReport._owned(expected)


def component_fixture() -> dict:
    tenant = "11111111-1111-1111-1111-111111111111"
    client = "22222222-2222-2222-2222-222222222222"
    redirect = "https://app.synthetic.example/callback"
    return {
        "schema_version": 1,
        "source_id": "synthetic-oauth-consent-uri",
        "synthetic_fixture": True,
        "authorization_uri": (
            f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
            f"?client_id={client}&response_type=code"
            "&redirect_uri=https%3A%2F%2Fapp.synthetic.example%2Fcallback"
            "&scope=User.Read%20offline_access&state=synthetic-state-1&prompt=consent"
        ),
        "expected_tenant_id": tenant,
        "expected_client_id": client,
        "expected_redirect_uri": redirect,
        "allowed_scopes": ["User.Read", "offline_access"],
    }
