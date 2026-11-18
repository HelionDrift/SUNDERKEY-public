"""Compare identifiers in one supplied synthetic ActivityStreams Create record."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from . import offline_framework_declaration_core as core

COMPONENT_ID = "social_supplied_activitystreams_create_review"
PROFILE_ID = "AOE-GA-D02-S04"
CAPABILITY_ID = "army.ga.d02.s04"
VECTOR_ID = "AV-GA-D02-S04-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D02-S04"
WAVE_ID = "IW2-005"
COMMANDER_ID = "AOE-GA-D02-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:75f9550852ca9b11262453ae5c002e05da0e63af9039dddeb4220df3b9df757d"
DOMAIN = "sunderkey.offline-activitystreams-create-review.v1"
MAX_MODEL_BYTES = 16_384
MAX_REPORT_BYTES = 32_768
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class ActivityStreamsCreateReviewError(ValueError):
    """A synthetic Create record or original-model replay is invalid."""


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or len(value) > 512 or any(ord(ch) < 33 for ch in value):
        raise ActivityStreamsCreateReviewError(f"Bounded {label} URL required")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ActivityStreamsCreateReviewError(f"HTTPS {label} URL required")
    return value


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "synthetic_fixture", "expected_actor_id", "activity"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ActivityStreamsCreateReviewError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise ActivityStreamsCreateReviewError("Only synthetic fixtures are accepted")
    expected_actor = _identifier(model["expected_actor_id"], "expected actor")
    activity = core.exact(
        model["activity"], {"@context", "id", "type", "actor", "object"},
        "activity",
    )
    if activity["@context"] != "https://www.w3.org/ns/activitystreams":
        raise ActivityStreamsCreateReviewError("ActivityStreams context required")
    if activity["type"] != "Create":
        raise ActivityStreamsCreateReviewError("Create activity required")
    activity_id = _identifier(activity["id"], "activity")
    actor_id = _identifier(activity["actor"], "actor")
    obj = core.exact(activity["object"], {"id", "type", "attributedTo"}, "object")
    if obj["type"] != "Note":
        raise ActivityStreamsCreateReviewError("Note object required")
    object_id = _identifier(obj["id"], "object")
    attributed_id = _identifier(obj["attributedTo"], "attribution")
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_id": COMMANDER_ID,
        "independent_validator_id": INDEPENDENT_VALIDATOR_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "synthetic_fixture_asserted": True,
        "activity_sha256": _digest(core.canonical(activity)),
        "activity_id_sha256": _digest(activity_id),
        "actor_id_sha256": _digest(actor_id),
        "object_id_sha256": _digest(object_id),
        "attributed_id_sha256": _digest(attributed_id),
        "actor_matches_supplied_expectation": actor_id == expected_actor,
        "actor_matches_object_attribution": actor_id == attributed_id,
        "candidate_count": 0,
        "uncertainty": [
            "record_origin_and_delivery_unverified",
            "actor_identity_and_object_authorship_unverified",
            "attribution_difference_is_not_proof_of_impersonation",
        ],
        "unknown_count": 3,
        "disposition": "unknown",
        "source_authenticated": False,
        "social_account_control_verified": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Only one supplied synthetic ActivityStreams Create/Note subset is compared.",
            "The format permits actor and attributedTo to differ; this is a review cue only.",
            "No actor URL, object URL, social account, or recruiting site is fetched.",
            "No post is created and no account or human identity is authenticated.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="ACR-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class ActivityStreamsCreateReviewReport:
    """Unsigned identifier projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise ActivityStreamsCreateReviewError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> ActivityStreamsCreateReviewReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_activitystreams_create(model: Any) -> ActivityStreamsCreateReviewReport:
    return ActivityStreamsCreateReviewReport._owned(_derive(model))


def verify_supplied_activitystreams_create(
    report: Any, *, model: Any
) -> ActivityStreamsCreateReviewReport:
    if type(report) is not ActivityStreamsCreateReviewReport:
        raise ActivityStreamsCreateReviewError("Exact ActivityStreams wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise ActivityStreamsCreateReviewError("Report differs from separate original model")
    return ActivityStreamsCreateReviewReport._owned(expected)


def component_fixture() -> dict:
    actor = "https://social.example.test/actors/alex"
    return {
        "schema_version": 1,
        "source_id": "synthetic-activitystreams-create",
        "synthetic_fixture": True,
        "expected_actor_id": actor,
        "activity": {
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "https://social.example.test/activities/one",
            "type": "Create",
            "actor": actor,
            "object": {
                "id": "https://social.example.test/notes/one",
                "type": "Note",
                "attributedTo": actor,
            },
        },
    }
