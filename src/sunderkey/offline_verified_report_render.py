"""Bounded, local-only report rendering after finding-origin comparison."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .assessment_report_rendering import (
    render_assessment_report_html,
    render_assessment_report_text,
)
from .assessment_reporting import AssessmentReportBundle, AssessmentReportingError
from .finding_lifecycle import FindingLifecycleError, FindingSnapshot
from .offline_report_finding_origins import (
    OfflineReportFindingOriginsError,
    verify_report_finding_origins,
)

SCHEMA_VERSION = 1
MANIFEST_KIND = "sunderkey.offline-report-finding-origins.v1"
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_FINDINGS = 200
MAX_SNAPSHOTS = 4096
MAX_EMBEDDED_EVENTS = 2048
_NOTICE = (
    "Finding Origins: Matched Local Originals Only. Live currentness, authenticated "
    "review, publication approval, and authority are not established."
)


class OfflineVerifiedReportRenderError(ValueError):
    """Raised when the local verified-render boundary fails closed."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OfflineVerifiedReportRenderError("origin manifest has duplicate keys")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise OfflineVerifiedReportRenderError(f"origin manifest has invalid constant {value}")


def parse_canonical_origin_manifest(
    document: bytes,
) -> tuple[dict[str, tuple[FindingSnapshot, ...]], str]:
    """Parse exact canonical bytes into bounded, complete supplied histories."""

    if type(document) is not bytes or not 0 < len(document) <= MAX_MANIFEST_BYTES:
        raise OfflineVerifiedReportRenderError("origin manifest byte limit is invalid")
    try:
        raw = json.loads(
            document.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        canonical = json.dumps(
            raw, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError, RecursionError) as exc:
        raise OfflineVerifiedReportRenderError("origin manifest is invalid JSON") from exc
    if canonical != document:
        raise OfflineVerifiedReportRenderError("origin manifest is not canonical JSON")
    if (
        type(raw) is not dict
        or set(raw) != {"histories", "kind", "schema_version"}
        or raw["kind"] != MANIFEST_KIND
        or type(raw["schema_version"]) is not int
        or raw["schema_version"] != SCHEMA_VERSION
        or type(raw["histories"]) is not list
        or len(raw["histories"]) > MAX_FINDINGS
    ):
        raise OfflineVerifiedReportRenderError("origin manifest fields are invalid")

    histories: dict[str, tuple[FindingSnapshot, ...]] = {}
    previous_id: str | None = None
    snapshot_count = 0
    event_count = 0
    for item in raw["histories"]:
        if type(item) is not dict or set(item) != {"finding_id", "snapshots"}:
            raise OfflineVerifiedReportRenderError("origin history fields are invalid")
        finding_id, snapshots = item["finding_id"], item["snapshots"]
        if (
            type(finding_id) is not str
            or not finding_id
            or (previous_id is not None and finding_id <= previous_id)
            or type(snapshots) is not list
            or not snapshots
        ):
            raise OfflineVerifiedReportRenderError("origin history order is invalid")
        previous_id = finding_id
        snapshot_count += len(snapshots)
        if snapshot_count > MAX_SNAPSHOTS:
            raise OfflineVerifiedReportRenderError("origin snapshot count exceeds limit")
        parsed: list[FindingSnapshot] = []
        for source in snapshots:
            if type(source) is not dict or type(source.get("events")) is not list:
                raise OfflineVerifiedReportRenderError("origin snapshot shape is invalid")
            event_count += len(source["events"])
            if event_count > MAX_EMBEDDED_EVENTS:
                raise OfflineVerifiedReportRenderError("origin event count exceeds limit")
            try:
                parsed.append(FindingSnapshot.from_dict(source))
            except (FindingLifecycleError, TypeError, ValueError, KeyError) as exc:
                raise OfflineVerifiedReportRenderError("origin snapshot is invalid") from exc
        histories[finding_id] = tuple(parsed)
    return histories, "sha256:" + hashlib.sha256(document).hexdigest()


def render_verified_assessment_report(
    *,
    bundle: AssessmentReportBundle,
    origin_manifest: bytes,
    format: str,
) -> tuple[bytes, dict[str, Any]]:
    """Render only after the report matches exact supplied local origins."""

    if type(bundle) is not AssessmentReportBundle:
        raise OfflineVerifiedReportRenderError("bundle must be an AssessmentReportBundle")
    if type(format) is not str or format not in {"html", "text"}:
        raise OfflineVerifiedReportRenderError("format is invalid")
    try:
        owned = AssessmentReportBundle.from_json(bundle.to_json())
    except (AssessmentReportingError, TypeError, ValueError, RecursionError) as exc:
        raise OfflineVerifiedReportRenderError("bundle original is invalid") from exc
    histories, manifest_sha256 = parse_canonical_origin_manifest(origin_manifest)
    try:
        matched = verify_report_finding_origins(report=owned.report, snapshot_histories=histories)
    except OfflineReportFindingOriginsError as exc:
        raise OfflineVerifiedReportRenderError("report origins do not match") from exc
    if matched["status"] != "matched_local_originals":
        raise OfflineVerifiedReportRenderError("report origins were not matched")

    if format == "html":
        rendered = render_assessment_report_html(owned)
        if rendered.count("<main>") != 1:
            raise OfflineVerifiedReportRenderError("report HTML structure is invalid")
        rendered = rendered.replace(
            "<main>",
            (
                '<main>\n<section aria-label="Finding Origin Review"><p>'
                + _NOTICE
                + "</p></section>"
            ),
            1,
        )
    else:
        rendered = _NOTICE + "\n\n" + render_assessment_report_text(owned)
    return rendered.encode("utf-8"), {
        "schema_version": SCHEMA_VERSION,
        "status": "origins_matched_local_only",
        "bundle_id": owned.bundle_id,
        "bundle_sha256": owned.bundle_sha256,
        "report_sha256": owned.report.report_sha256,
        "origin_manifest_sha256": manifest_sha256,
        "finding_count": matched["finding_count"],
        "format": format,
        "live_source_currentness": "not_proven",
        "authenticated_review": "not_proven",
        "publication_approved": False,
        "authorization_effect": "none",
        "qualification_effect": "none",
        "target_effect": "none",
    }


__all__ = [
    "OfflineVerifiedReportRenderError",
    "parse_canonical_origin_manifest",
    "render_verified_assessment_report",
]
