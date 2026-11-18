"""Inspect synthetic OOXML relationship declarations without opening targets."""

from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from . import offline_framework_declaration_core as core

COMPONENT_ID = "social_supplied_ooxml_relationship_review"
PROFILE_ID = "AOE-GA-D02-S08"
CAPABILITY_ID = "army.ga.d02.s08"
VECTOR_ID = "AV-GA-D02-S08-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D02-S08"
WAVE_ID = "IW2-009"
COMMANDER_ID = "AOE-GA-D02-CMD"
GROUP_OWNER_ID = "AOE-HQ-03"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:54eb81c5059f03781724eeb84f5c15a2392805341532aab198d290c321608039"
DOMAIN = "sunderkey.offline-ooxml-relationship-review.v1"
NAMESPACE = "http://schemas.openxmlformats.org/package/2006/relationships"
ROOT_TAG = f"{{{NAMESPACE}}}Relationships"
RELATIONSHIP_TAG = f"{{{NAMESPACE}}}Relationship"
RELATIONSHIP_ID = re.compile(r"rId[1-9][0-9]{0,3}\Z")
MAX_MODEL_BYTES = 8_192
MAX_REPORT_BYTES = 32_768
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class OoxmlRelationshipReviewError(ValueError):
    """A synthetic relationship declaration or replay is invalid."""


def _canonical(value: Any) -> str:
    try:
        result = json.dumps(
            value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise OoxmlRelationshipReviewError("Model must be bounded native JSON") from exc
    if len(result) > MAX_MODEL_BYTES:
        raise OoxmlRelationshipReviewError("Model exceeds byte bound")
    return result


def _hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _derive(value: Any) -> dict:
    model_text = _canonical(value)
    model = core.exact(
        json.loads(model_text),
        {"schema_version", "source_id", "synthetic_fixture", "relationships_xml"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise OoxmlRelationshipReviewError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise OoxmlRelationshipReviewError("Only synthetic fixtures are accepted")
    xml = model["relationships_xml"]
    if (type(xml) is not str or not 1 <= len(xml) <= 4_096
            or not xml.isascii() or "<!" in xml or "<?" in xml):
        raise OoxmlRelationshipReviewError("Bounded ASCII XML without DTD required")
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise OoxmlRelationshipReviewError("Malformed relationship XML") from exc
    if root.tag != ROOT_TAG or root.attrib or (root.text or "").strip():
        raise OoxmlRelationshipReviewError("OOXML Relationships root required")
    children = list(root)
    if not 1 <= len(children) <= 16:
        raise OoxmlRelationshipReviewError("One to sixteen relationships required")
    seen_ids = set()
    externals = []
    internal_count = 0
    for child in children:
        if (child.tag != RELATIONSHIP_TAG or len(child) or (child.text or "").strip()
                or (child.tail or "").strip()
                or not {"Id", "Type", "Target"} <= child.attrib.keys()
                or not child.attrib.keys() <= {"Id", "Type", "Target", "TargetMode"}):
            raise OoxmlRelationshipReviewError("Closed flat Relationship elements required")
        identifier = child.attrib["Id"]
        if RELATIONSHIP_ID.fullmatch(identifier) is None or identifier in seen_ids:
            raise OoxmlRelationshipReviewError("Distinct bounded relationship IDs required")
        seen_ids.add(identifier)
        relation_type = child.attrib["Type"]
        target = child.attrib["Target"]
        mode = child.attrib.get("TargetMode", "Internal")
        if (len(relation_type) > 256 or not relation_type.startswith(
                "http://schemas.openxmlformats.org/")
                or not 1 <= len(target) <= 512
                or any(ord(char) < 33 for char in target)
                or mode not in {"External", "Internal"}):
            raise OoxmlRelationshipReviewError("Bounded relationship fields required")
        try:
            target_uri = urlsplit(target)
        except ValueError as exc:
            raise OoxmlRelationshipReviewError("Malformed target URI") from exc
        if mode == "Internal":
            if target_uri.scheme or target_uri.netloc or target.startswith("//"):
                raise OoxmlRelationshipReviewError("Internal target must be package-relative")
            internal_count += 1
        else:
            if target.startswith("//") or (
                target_uri.scheme and target_uri.scheme not in {"http", "https"}
            ) or (
                target_uri.scheme in {"http", "https"} and not target_uri.netloc
            ):
                raise OoxmlRelationshipReviewError("Only HTTP(S) external URI schemes modeled")
            externals.append({
                "relationship_id_sha256": _hash(identifier),
                "target_sha256": _hash(target),
                "target_is_relative": not bool(target_uri.scheme),
                "target_scheme": target_uri.scheme or "relative",
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
        "relationship_count": len(children),
        "internal_relationship_count": internal_count,
        "external_relationship_count": len(externals),
        "external_relationships": externals,
        "external_target_reachable": False,
        "document_delivered": False,
        "document_opened": False,
        "browser_navigation_observed": False,
        "candidate_count": 0,
        "uncertainty": [
            "package_and_relationship_source_unverified",
            "external_target_reachability_unverified",
            "document_delivery_and_open_behavior_unobserved",
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
            "Only one synthetic supplied OOXML .rels declaration is parsed locally.",
            "External TargetMode identifies a declared reference, not a fetched resource.",
            "No document package, macro, linked content, or browser behavior is interpreted.",
            "No relationship target is opened and no document or lure is delivered.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="OXR-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class OoxmlRelationshipReviewReport:
    """Unsigned declaration projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise OoxmlRelationshipReviewError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> OoxmlRelationshipReviewReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_ooxml_relationships(model: Any) -> OoxmlRelationshipReviewReport:
    return OoxmlRelationshipReviewReport._owned(_derive(model))


def verify_supplied_ooxml_relationships(
    report: Any, *, model: Any
) -> OoxmlRelationshipReviewReport:
    if type(report) is not OoxmlRelationshipReviewReport:
        raise OoxmlRelationshipReviewError("Exact OOXML wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise OoxmlRelationshipReviewError("Report differs from separate original model")
    return OoxmlRelationshipReviewReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-ooxml-relationships",
        "synthetic_fixture": True,
        "relationships_xml": (
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/'
            'officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/'
            'officeDocument/2006/relationships/hyperlink" '
            'Target="https://resource.synthetic.example/info" TargetMode="External"/>'
            '</Relationships>'
        ),
    }
