"""Compare supplied parser views of inert token-payload JSON bytes."""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "crypto_supplied_token_payload_views"
PROFILE_ID = "AOE-GE-D22-S11"
CAPABILITY_ID = "army.ge.d22.s11"
VECTOR_ID = "AV-GE-D22-S11-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D22-S11"
WAVE_ID = "IW2-024"
COMMANDER_ID = "AOE-GE-D22-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:21d77925dd2facb7949c188ecf501375a569a9a85aaa713f9e85c80afed262d2"
DOMAIN = "sunderkey.offline-token-payload-views.v1"
MAX_PAYLOAD_BYTES = 8192
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_VIEWS = 8
B64URL = re.compile(r"[A-Za-z0-9_-]{1,10923}\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process",
        "provider", "credentials", "target_interaction",
        "finding_publication", "qualification",
    )
}


class TokenPayloadViewsError(ValueError):
    """The inert payload model or original-model replay is invalid."""


def _payload(value: Any) -> bytes:
    if type(value) is not str or B64URL.fullmatch(value) is None:
        raise TokenPayloadViewsError("Payload must be bounded unpadded base64url")
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise TokenPayloadViewsError("Payload base64url is invalid") from exc
    if not raw or len(raw) > MAX_PAYLOAD_BYTES or (
        base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value
    ):
        raise TokenPayloadViewsError("Payload base64url is not canonical or bounded")
    return raw


def _model(value: Any) -> tuple[dict, bytes, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "payload_b64url", "views_complete", "parser_views"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise TokenPayloadViewsError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    raw = _payload(model["payload_b64url"])
    core.boolean(model["views_complete"], "view completeness")
    seen: set[str] = set()
    for item in core.bounded_list(model["parser_views"], MAX_VIEWS, "parser views"):
        row = core.exact(item, {"parser_id", "claims"}, "parser view")
        parser_id = core.identifier(row["parser_id"], "parser ID")
        if parser_id in seen:
            raise TokenPayloadViewsError("Duplicate parser ID")
        seen.add(parser_id)
        if type(row["claims"]) is not dict:
            raise TokenPayloadViewsError("Parser claims must be an object")
        core.validate_tree(row["claims"], maximum=MAX_PAYLOAD_BYTES)
    return model, raw, core.canonical(model)


def _derive(value: Any) -> dict:
    model, raw, source_text = _model(value)
    try:
        strict_claims = core.decode(raw, maximum=MAX_PAYLOAD_BYTES)
        strict_accepted = type(strict_claims) is dict
    except core.FrameworkDeclarationError:
        strict_claims = None
        strict_accepted = False
    strict_digest = (
        core.digest(core.canonical(strict_claims).encode("ascii"))
        if strict_accepted else None
    )
    views = sorted(
        (
            {
                "parser_id": row["parser_id"],
                "claims_sha256": core.digest(core.canonical(row["claims"]).encode("ascii")),
            }
            for row in model["parser_views"]
        ),
        key=lambda row: row["parser_id"],
    )
    signals: list[str] = []
    uncertainty: list[str] = []
    if not strict_accepted and views:
        signals.append("strict_json_rejected_but_parser_claims_declared")
    elif not strict_accepted:
        uncertainty.append("strict_json_rejected_without_parser_view")
    if len({row["claims_sha256"] for row in views}) > 1:
        signals.append("declared_parser_view_disagreement")
    if strict_digest is not None and any(
        row["claims_sha256"] != strict_digest for row in views
    ):
        signals.append("declared_view_differs_from_strict_decode")
    if not model["views_complete"]:
        uncertainty.append("parser_view_inventory_incomplete")
    if not views:
        uncertainty.append("no_parser_views_supplied")
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
        "source_model_sha256": core.digest(source_text.encode("ascii")),
        "payload_sha256": core.digest(raw),
        "strict_local_decode_accepted": strict_accepted,
        "strict_local_claims_sha256": strict_digest,
        "views_complete_asserted": model["views_complete"],
        "parser_views": views,
        "signals": sorted(signals),
        "uncertainty": sorted(uncertainty),
        "candidate_count": len(signals),
        "unknown_count": len(uncertainty),
        "disposition": (
            "candidate_declared_token_view_review" if signals else
            "unknown" if uncertainty else "no_declared_token_view_difference"
        ),
        "source_authenticated": False,
        "parser_execution_verified": False,
        "signature_verified": False,
        "token_accepted_by_target": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Payload bytes and parser views are supplied inert inputs.",
            "The local strict JSON policy is not an application parser oracle.",
            "No signature, token acceptance or authorization decision is verified.",
            "A difference is a review question, not an exploit or finding.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="TPV-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class TokenPayloadViewsReport:
    """Unsigned comparison requiring the original payload and model."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise TokenPayloadViewsError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> TokenPayloadViewsReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_token_payload_views(model: Any) -> TokenPayloadViewsReport:
    return TokenPayloadViewsReport._owned(_derive(model))


def verify_supplied_token_payload_views(
    report: Any, *, model: Any
) -> TokenPayloadViewsReport:
    if type(report) is not TokenPayloadViewsReport:
        raise TokenPayloadViewsError("Exact token-view wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise TokenPayloadViewsError("Report differs from separate original model")
    return TokenPayloadViewsReport._owned(expected)


def component_fixture() -> dict:
    raw = b'{"sub":"reader","sub":"admin"}'
    return {
        "schema_version": 1,
        "source_id": "synthetic-token-payload",
        "payload_b64url": base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
        "views_complete": True,
        "parser_views": [
            {"parser_id": "first_wins", "claims": {"sub": "reader"}},
            {"parser_id": "last_wins", "claims": {"sub": "admin"}},
        ],
    }
