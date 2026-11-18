"""Inert projection of supplied source, build, release and GitOps lineage."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "cd_supplied_release_provenance"
PROFILE_ID = "AOE-GC-D17-S03"
CAPABILITY_ID = "army.gc.d17.s03"
VECTOR_ID = "AV-GC-D17-S03-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D17-S03"
WAVE_ID = "IW2-015"
COMMANDER_ID = "AOE-GC-D17-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:483814709e77586357ceebf367068da0c5d21455fe37f32b6a29be6f5246a5a8"
DOMAIN = "sunderkey.offline-cd-release-provenance.v1"
SCHEMA_VERSION = "v1"
MAX_SOURCE_BYTES = 131_072
MAX_REPORT_BYTES = 262_144
MAX_NODES = 20_000
MAX_DEPTH = 14
MAX_TEXT_BYTES = 256
MAX_REVISIONS = 128
MAX_BUILDS = 128
MAX_RELEASES = 128
MAX_DECLARATIONS = 256
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
        "git_write",
    )
}
_FLAGS = {
    "offline_only": True,
    "source_authenticated": False,
    "build_observed_live": False,
    "provenance_verified_cryptographically": False,
    "release_approval_authenticated": False,
    "gitops_state_observed_live": False,
    "deployment_performed": False,
    "finding_claimed": False,
    "positive_use_approved": False,
    "qualification_claimed": False,
}
_LIMITATIONS = [
    "Revisions, builds, artifact digests, approvals and GitOps state are supplied assertions.",
    "A verified provenance label is not cryptographic attestation validation.",
    "An approved release label is not authenticated change approval.",
    "Observed artifact digests are supplied, not read from any cluster or service.",
    "A mismatch is a declared inconsistency, not proof of supply-chain compromise.",
    "No repository, CI provider, artifact registry, GitOps controller or target is accessed.",
]
_ASSESSMENTS = {
    "candidate_declared_lineage_conflict",
    "candidate_release_gate_conflict",
    "candidate_observed_artifact_mismatch",
    "declared_consistent",
    "declared_blocked",
    "declared_not_observed",
    "unknown",
}
_BASES = {
    "incomplete_facts",
    "incomplete_lineage",
    "missing_release",
    "missing_build",
    "missing_revision",
    "build_source_digest_mismatch",
    "release_build_digest_mismatch",
    "desired_release_digest_mismatch",
    "approved_without_provenance",
    "provenance_or_approval_unknown",
    "provenance_or_approval_blocked",
    "observed_state_unknown",
    "not_observed",
    "observed_desired_digest_mismatch",
    "all_declared_links_match",
}


class CdReleaseProvenanceError(ValueError):
    """Closed model, resource bound or original-source replay failed."""


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields or any(type(k) is not str for k in value):
        raise CdReleaseProvenanceError(f"{label} fields are invalid")
    return value


def _id(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise CdReleaseProvenanceError(f"{label} must be bounded native ASCII text")
    return value


def _sha(value: Any, label: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise CdReleaseProvenanceError(f"{label} must be a canonical SHA-256 address")
    return value


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CdReleaseProvenanceError("duplicate JSON key")
        result[key] = value
    return result


def _json_integer(token: str) -> int:
    if len(token) > 20 or len(token.lstrip("-")) > 19:
        raise CdReleaseProvenanceError("JSON integer exceeds signed64 bound")
    value = int(token)
    if not -(1 << 63) <= value < (1 << 63):
        raise CdReleaseProvenanceError("JSON integer exceeds signed64 bound")
    return value


def _unsupported_number(_token: str) -> None:
    raise CdReleaseProvenanceError("floating and nonfinite numbers are unsupported")


def _validate_tree(value: Any, *, maximum: int) -> None:
    stack = [(value, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise CdReleaseProvenanceError("JSON node or depth bound exceeded")
        kind = type(item)
        if kind is dict:
            if nodes + len(stack) + 2 * len(item) > MAX_NODES:
                raise CdReleaseProvenanceError("JSON node bound exceeded")
            for key, child in item.items():
                if type(key) is not str:
                    raise CdReleaseProvenanceError("JSON keys must be native text")
                stack.append((child, depth + 1))
                stack.append((key, depth + 1))
        elif kind is list:
            if nodes + len(stack) + len(item) > MAX_NODES:
                raise CdReleaseProvenanceError("JSON node bound exceeded")
            stack.extend((child, depth + 1) for child in item)
        elif kind is str:
            if len(item.encode("utf-8", errors="surrogatepass")) > MAX_TEXT_BYTES or any(
                0xD800 <= ord(char) <= 0xDFFF for char in item
            ):
                raise CdReleaseProvenanceError("JSON string is unsupported or too long")
        elif kind is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise CdReleaseProvenanceError("JSON integer exceeds signed64 bound")
        elif kind not in (bool, type(None)):
            raise CdReleaseProvenanceError("unsupported JSON value family")
    if len(_canonical(value).encode("ascii")) > maximum:
        raise CdReleaseProvenanceError("canonical JSON byte bound exceeded")


def _decode(content: bytes, *, maximum: int) -> Any:
    if type(content) is not bytes or not content or len(content) > maximum:
        raise CdReleaseProvenanceError("source must be bounded nonempty native bytes")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CdReleaseProvenanceError("source must be UTF-8") from exc
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
                raise CdReleaseProvenanceError("pre-decoder depth bound exceeded")
        elif char in "]}":
            depth -= 1
            if depth < 0:
                raise CdReleaseProvenanceError("malformed JSON nesting")
    if depth or quoted:
        raise CdReleaseProvenanceError("malformed JSON nesting")
    try:
        result = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_json_integer,
            parse_float=_unsupported_number,
            parse_constant=_unsupported_number,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, CdReleaseProvenanceError):
            raise
        raise CdReleaseProvenanceError("malformed JSON source") from exc
    _validate_tree(result, maximum=maximum)
    return result


def _records(values: Any, name: str, maximum: int, fields: set[str]) -> list[dict]:
    if type(values) is not list or len(values) > maximum:
        raise CdReleaseProvenanceError(f"{name} must be a bounded native array")
    return [_exact(value, fields, name) for value in values]


def _model(document: Any) -> tuple[bool, bool, dict, dict, dict, list]:
    model = _exact(
        document,
        {
            "schema_version",
            "facts_complete",
            "lineage_complete",
            "source_revisions",
            "builds",
            "releases",
            "gitops_declarations",
        },
        "model",
    )
    if type(model["schema_version"]) is not str or model["schema_version"] != SCHEMA_VERSION:
        raise CdReleaseProvenanceError("unsupported model version")
    if type(model["facts_complete"]) is not bool or type(model["lineage_complete"]) is not bool:
        raise CdReleaseProvenanceError("completeness must be native Booleans")
    revisions = {}
    for item in _records(
        model["source_revisions"],
        "source revision",
        MAX_REVISIONS,
        {"revision_id", "commit_sha256"},
    ):
        identity = _id(item["revision_id"], "revision ID")
        if identity in revisions:
            raise CdReleaseProvenanceError("duplicate revision ID")
        revisions[identity] = _sha(item["commit_sha256"], "commit digest")
    builds = {}
    for item in _records(
        model["builds"],
        "build",
        MAX_BUILDS,
        {"build_id", "revision_id", "input_sha256", "artifact_sha256", "provenance_disposition"},
    ):
        identity = _id(item["build_id"], "build ID")
        if identity in builds:
            raise CdReleaseProvenanceError("duplicate build ID")
        disposition = item["provenance_disposition"]
        if type(disposition) is not str or disposition not in ("verified", "failed", "unknown"):
            raise CdReleaseProvenanceError("provenance disposition is unsupported")
        builds[identity] = {
            "revision_id": _id(item["revision_id"], "revision ID"),
            "input_sha256": _sha(item["input_sha256"], "build input digest"),
            "artifact_sha256": _sha(item["artifact_sha256"], "build artifact digest"),
            "provenance_disposition": disposition,
        }
    releases = {}
    for item in _records(
        model["releases"],
        "release",
        MAX_RELEASES,
        {"release_id", "build_id", "artifact_sha256", "approval_disposition"},
    ):
        identity = _id(item["release_id"], "release ID")
        if identity in releases:
            raise CdReleaseProvenanceError("duplicate release ID")
        approval = item["approval_disposition"]
        if type(approval) is not str or approval not in ("approved", "denied", "unknown"):
            raise CdReleaseProvenanceError("release approval is unsupported")
        releases[identity] = {
            "build_id": _id(item["build_id"], "build ID"),
            "artifact_sha256": _sha(item["artifact_sha256"], "release artifact digest"),
            "approval_disposition": approval,
        }
    declarations = []
    seen = set()
    for item in _records(
        model["gitops_declarations"],
        "GitOps declaration",
        MAX_DECLARATIONS,
        {
            "declaration_id",
            "release_id",
            "desired_artifact_sha256",
            "observed_status",
            "observed_artifact_sha256",
        },
    ):
        identity = _id(item["declaration_id"], "declaration ID")
        if identity in seen:
            raise CdReleaseProvenanceError("duplicate declaration ID")
        seen.add(identity)
        status = item["observed_status"]
        if type(status) is not str or status not in ("present", "absent", "unknown"):
            raise CdReleaseProvenanceError("observed status is unsupported")
        observed = item["observed_artifact_sha256"]
        if (status == "present") != (observed is not None):
            raise CdReleaseProvenanceError("observed artifact must match present status")
        if observed is not None:
            _sha(observed, "observed artifact digest")
        declarations.append(
            {
                "declaration_id": identity,
                "release_id": _id(item["release_id"], "release ID"),
                "desired_artifact_sha256": _sha(
                    item["desired_artifact_sha256"], "desired artifact digest"
                ),
                "observed_status": status,
                "observed_artifact_sha256": observed,
            }
        )
    return (
        model["facts_complete"],
        model["lineage_complete"],
        revisions,
        builds,
        releases,
        declarations,
    )


def _project(
    facts_complete: bool,
    lineage_complete: bool,
    revisions: dict,
    builds: dict,
    releases: dict,
    declarations: list,
) -> list:
    projections = []
    for declaration in sorted(declarations, key=lambda item: item["declaration_id"]):
        release = releases.get(declaration["release_id"])
        build = builds.get(release["build_id"]) if release is not None else None
        revision = revisions.get(build["revision_id"]) if build is not None else None
        if not facts_complete:
            assessment, basis = "unknown", "incomplete_facts"
        elif not lineage_complete:
            assessment, basis = "unknown", "incomplete_lineage"
        elif release is None:
            assessment, basis = "unknown", "missing_release"
        elif build is None:
            assessment, basis = "unknown", "missing_build"
        elif revision is None:
            assessment, basis = "unknown", "missing_revision"
        elif build["input_sha256"] != revision:
            assessment, basis = (
                "candidate_declared_lineage_conflict",
                "build_source_digest_mismatch",
            )
        elif release["artifact_sha256"] != build["artifact_sha256"]:
            assessment, basis = (
                "candidate_declared_lineage_conflict",
                "release_build_digest_mismatch",
            )
        elif declaration["desired_artifact_sha256"] != release["artifact_sha256"]:
            assessment, basis = (
                "candidate_declared_lineage_conflict",
                "desired_release_digest_mismatch",
            )
        elif (
            build["provenance_disposition"] == "failed"
            and release["approval_disposition"] == "approved"
        ):
            assessment, basis = "candidate_release_gate_conflict", "approved_without_provenance"
        elif (
            build["provenance_disposition"] == "unknown"
            or release["approval_disposition"] == "unknown"
        ):
            assessment, basis = "unknown", "provenance_or_approval_unknown"
        elif (
            build["provenance_disposition"] == "failed"
            or release["approval_disposition"] == "denied"
        ):
            assessment, basis = "declared_blocked", "provenance_or_approval_blocked"
        elif declaration["observed_status"] == "unknown":
            assessment, basis = "unknown", "observed_state_unknown"
        elif declaration["observed_status"] == "absent":
            assessment, basis = "declared_not_observed", "not_observed"
        elif declaration["observed_artifact_sha256"] != declaration["desired_artifact_sha256"]:
            assessment, basis = (
                "candidate_observed_artifact_mismatch",
                "observed_desired_digest_mismatch",
            )
        else:
            assessment, basis = "declared_consistent", "all_declared_links_match"
        projections.append(
            {
                **declaration,
                "build_id": None if release is None else release["build_id"],
                "revision_id": None if build is None else build["revision_id"],
                "assessment": assessment,
                "basis": basis,
            }
        )
    return projections


@dataclass(frozen=True, slots=True)
class CdReleaseProvenanceReport:
    """Canonical supplied-data projection requiring original-source replay."""

    _json: str

    def __post_init__(self) -> None:
        if type(self) is not CdReleaseProvenanceReport or self._json != _checked_report_json(
            self._json
        ):
            raise CdReleaseProvenanceError("canonical exact report is required")

    def to_json(self) -> str:
        if type(self) is not CdReleaseProvenanceReport or self._json != _checked_report_json(
            self._json
        ):
            raise CdReleaseProvenanceError("canonical exact report is required")
        return self._json

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.to_json())

    @classmethod
    def from_json(cls, content: str) -> CdReleaseProvenanceReport:
        if cls is not CdReleaseProvenanceReport:
            raise CdReleaseProvenanceError("report must be the exact report family")
        return cls(_checked_report_json(content))


def _checked_report_json(content: Any) -> str:
    if type(content) is not str:
        raise CdReleaseProvenanceError("report must be native JSON text")
    try:
        raw = content.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CdReleaseProvenanceError("report must be UTF-8 JSON text") from exc
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
            "lineage_complete",
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
            raise CdReleaseProvenanceError(f"report {key} is invalid")
    source = _exact(item["source"], {"source_id", "sha256", "byte_count"}, "source")
    _id(source["source_id"], "source ID")
    _sha(source["sha256"], "source digest")
    if type(source["byte_count"]) is not int or not 1 <= source["byte_count"] <= MAX_SOURCE_BYTES:
        raise CdReleaseProvenanceError("source byte count is invalid")
    for key in ("facts_complete", "lineage_complete"):
        if type(item[key]) is not bool:
            raise CdReleaseProvenanceError("report completeness is invalid")
    projections = item["projections"]
    if type(projections) is not list or len(projections) > MAX_DECLARATIONS:
        raise CdReleaseProvenanceError("report projections are invalid")
    ids = []
    counts = {assessment: 0 for assessment in sorted(_ASSESSMENTS)}
    for raw in projections:
        projection = _exact(
            raw,
            {
                "declaration_id",
                "release_id",
                "desired_artifact_sha256",
                "observed_status",
                "observed_artifact_sha256",
                "build_id",
                "revision_id",
                "assessment",
                "basis",
            },
            "projection",
        )
        ids.append(_id(projection["declaration_id"], "declaration ID"))
        _id(projection["release_id"], "release ID")
        _sha(projection["desired_artifact_sha256"], "desired artifact digest")
        for key in ("build_id", "revision_id"):
            if projection[key] is not None:
                _id(projection[key], key)
        if projection["observed_artifact_sha256"] is not None:
            _sha(projection["observed_artifact_sha256"], "observed artifact digest")
        status = projection["observed_status"]
        if type(status) is not str or status not in ("present", "absent", "unknown"):
            raise CdReleaseProvenanceError("report observed status is invalid")
        if (status == "present") != (projection["observed_artifact_sha256"] is not None):
            raise CdReleaseProvenanceError("report observed artifact is invalid")
        if (
            type(projection["assessment"]) is not str
            or projection["assessment"] not in _ASSESSMENTS
        ):
            raise CdReleaseProvenanceError("report assessment is invalid")
        if type(projection["basis"]) is not str or projection["basis"] not in _BASES:
            raise CdReleaseProvenanceError("report basis is invalid")
        counts[projection["assessment"]] += 1
    if ids != sorted(set(ids)):
        raise CdReleaseProvenanceError("report declaration IDs must be sorted unique")
    summary = _exact(item["summary"], {"declaration_count", *counts}, "summary")
    if summary != {"declaration_count": len(projections), **counts} or any(
        type(value) is not int for value in summary.values()
    ):
        raise CdReleaseProvenanceError("report summary is invalid")
    body = {key: value for key, value in item.items() if key not in ("report_id", "report_sha256")}
    digest = _digest(_canonical({"domain": DOMAIN, "analysis": body}).encode("ascii"))
    if item["report_sha256"] != digest or item["report_id"] != "CDP-" + digest[7:39].upper():
        raise CdReleaseProvenanceError("report address is invalid")


def analyze_cd_release_provenance(
    *,
    source_content: bytes,
    source_id: str,
) -> CdReleaseProvenanceReport:
    """Project supplied source/build/release/GitOps links without provider access."""
    identity = _id(source_id, "source ID")
    source = _decode(source_content, maximum=MAX_SOURCE_BYTES)
    facts_complete, lineage_complete, revisions, builds, releases, declarations = _model(source)
    projections = _project(
        facts_complete, lineage_complete, revisions, builds, releases, declarations
    )
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
        "lineage_complete": lineage_complete,
        "projections": projections,
        "summary": {"declaration_count": len(projections), **counts},
        **_FLAGS,
        "effects": _EFFECTS,
        "limitations": _LIMITATIONS,
    }
    digest = _digest(_canonical({"domain": DOMAIN, "analysis": document}).encode("ascii"))
    document["report_id"] = "CDP-" + digest[7:39].upper()
    document["report_sha256"] = digest
    _validate_tree(document, maximum=MAX_REPORT_BYTES)
    _validate_report(document)
    return CdReleaseProvenanceReport(_canonical(document))


def analyze_supplied_cd_release_provenance(model: dict[str, Any]) -> CdReleaseProvenanceReport:
    """Canonicalize an exact native source-backed component model."""
    _validate_tree(model, maximum=MAX_SOURCE_BYTES)
    item = _exact(model, {"source_id", "source"}, "component model")
    source_id = _id(item["source_id"], "source ID")
    _model(item["source"])
    return analyze_cd_release_provenance(
        source_content=_canonical(item["source"]).encode("ascii"),
        source_id=source_id,
    )


def verify_cd_release_provenance(
    report: CdReleaseProvenanceReport,
    *,
    source_content: bytes,
    source_id: str,
) -> CdReleaseProvenanceReport:
    """Rebuild a detached report from exact original supplied source bytes."""
    if type(report) is not CdReleaseProvenanceReport:
        raise CdReleaseProvenanceError("report must be the exact report family")
    loaded = CdReleaseProvenanceReport.from_json(report.to_json())
    expected = analyze_cd_release_provenance(source_content=source_content, source_id=source_id)
    if loaded.to_json() != expected.to_json():
        raise CdReleaseProvenanceError("report does not replay from supplied source")
    return expected


def component_fixture() -> dict[str, Any]:
    """Return fresh synthetic source, build, release and desired-state facts."""
    source_digest = "sha256:" + "1" * 64
    artifact_digest = "sha256:" + "2" * 64
    other_digest = "sha256:" + "3" * 64
    return {
        "schema_version": SCHEMA_VERSION,
        "facts_complete": True,
        "lineage_complete": True,
        "source_revisions": [{"revision_id": "rev-a", "commit_sha256": source_digest}],
        "builds": [
            {
                "build_id": "build-a",
                "revision_id": "rev-a",
                "input_sha256": source_digest,
                "artifact_sha256": artifact_digest,
                "provenance_disposition": "verified",
            }
        ],
        "releases": [
            {
                "release_id": "release-a",
                "build_id": "build-a",
                "artifact_sha256": artifact_digest,
                "approval_disposition": "approved",
            }
        ],
        "gitops_declarations": [
            {
                "declaration_id": "env-consistent",
                "release_id": "release-a",
                "desired_artifact_sha256": artifact_digest,
                "observed_status": "present",
                "observed_artifact_sha256": artifact_digest,
            },
            {
                "declaration_id": "env-mismatch",
                "release_id": "release-a",
                "desired_artifact_sha256": artifact_digest,
                "observed_status": "present",
                "observed_artifact_sha256": other_digest,
            },
        ],
    }


__all__ = [
    "CdReleaseProvenanceError",
    "CdReleaseProvenanceReport",
    "analyze_cd_release_provenance",
    "analyze_supplied_cd_release_provenance",
    "verify_cd_release_provenance",
    "component_fixture",
]
