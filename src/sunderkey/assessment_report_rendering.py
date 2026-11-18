"""Pure, deterministic human-readable views of existing assessment bundles."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from html import escape
from typing import Any

from .assessment_reporting import AssessmentReportBundle, AssessmentReportingError

_NOTICE = (
    "Offline presentation of a content-addressed assessment record. This view does not "
    "establish a signature, publication, reviewer acceptance, current authority, "
    "compliance certification or product qualification."
)
_COVERAGE_NOTICE = (
    "Coverage labels describe recorded outcomes, not overall security assurance. "
    "A complete coverage partition does not establish complete security."
)
_EMPTY = "None recorded in this bundle."
_STYLE = """\
:root {
  --text-primary: #111827;
  --text-secondary: #374151;
  --bg-surface: #ffffff;
  --bg-header: #f3f4f6;
  --border-default: #9ca3af;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 1rem;
  color: var(--text-primary);
  background: var(--bg-surface);
  font-family: system-ui, sans-serif;
  line-height: 1.5;
}
main { max-width: 72rem; margin: 0 auto; }
h1 { font-size: 2rem; line-height: 1.25; }
h2 { margin-top: 2rem; font-size: 1.5rem; }
h3 { margin-top: 1.5rem; font-size: 1.25rem; }
h4 { margin-top: 1rem; font-size: 1rem; }
h1, h2, h3, h4 { overflow-wrap: anywhere; }
p, li, th, td { overflow-wrap: anywhere; white-space: pre-wrap; }
p { margin: 0.75rem 0; }
table { width: 100%; border-collapse: collapse; table-layout: fixed; margin: 1rem 0; }
caption { text-align: left; font-weight: 600; padding-bottom: 0.5rem; }
th, td { border: 1px solid var(--border-default); padding: 0.5rem; vertical-align: top; }
th { text-align: left; background: var(--bg-header); }
thead th { color: var(--text-secondary); }
ul, ol { padding-left: 1.5rem; }
@media print {
  body { padding: 0; }
  main { max-width: none; }
  h1, h2, h3, h4, caption { break-after: avoid; }
  tr { break-inside: avoid; }
  thead { display: table-header-group; }
}
"""


def _value(value: Any) -> str:
    if value is None:
        return "Not supplied"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


class _Writer:
    """Small static-format writer; every content insertion is treated as text."""

    def __init__(self, *, html: bool) -> None:
        self.html = html
        self.lines: list[str] = []
        if html:
            self.lines.extend(
                (
                    "<!DOCTYPE html>",
                    '<html lang="en">',
                    "<head>",
                    '<meta charset="utf-8">',
                    '<meta name="viewport" content="width=device-width, initial-scale=1">',
                    '<meta name="referrer" content="no-referrer">',
                    '<meta http-equiv="Content-Security-Policy" '
                    "content=\"default-src 'none'; style-src 'unsafe-inline'; "
                    "base-uri 'none'; form-action 'none'\">",
                    "<title>Assessment report</title>",
                    "<style>",
                    _STYLE.rstrip("\n"),
                    "</style>",
                    "</head>",
                    "<body>",
                    "<main>",
                )
            )

    def heading(self, level: int, title: str) -> None:
        if self.html:
            self.lines.append(f"<h{level}>{escape(title, quote=True)}</h{level}>")
        else:
            self.lines.extend(("", title.replace("\n", "\n  ")))
            self.lines.append(("=" if level == 1 else "-") * min(len(title), 80))

    def paragraph(self, text: str) -> None:
        if self.html:
            self.lines.append(f"<p>{escape(text, quote=True)}</p>")
        else:
            self.lines.append(text.replace("\n", "\n  "))

    def table(self, caption: str, headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> None:
        if self.html:
            self.lines.extend(("<table>", f"<caption>{escape(caption, quote=True)}</caption>"))
            self.lines.append("<thead><tr>")
            self.lines.extend(f'<th scope="col">{escape(text)}</th>' for text in headers)
            self.lines.extend(("</tr></thead>", "<tbody>"))
            for row in rows:
                self.lines.append("<tr>")
                for index, value in enumerate(row):
                    text = escape(_value(value), quote=True)
                    self.lines.append(
                        f'<th scope="row">{text}</th>' if index == 0 else f"<td>{text}</td>"
                    )
                self.lines.append("</tr>")
            self.lines.extend(("</tbody>", "</table>"))
        else:
            self.lines.extend(("", caption, "  " + " | ".join(headers)))
            for row in rows:
                text = " | ".join(_value(value) for value in row)
                self.lines.append("  " + text.replace("\n", "\n    "))

    def fields(self, caption: str, record: dict[str, Any], names: Sequence[str]) -> None:
        self.table(caption, ("Field", "Recorded value"), ((name, record[name]) for name in names))

    def items(
        self, title: str, values: Sequence[str], *, ordered: bool = False, level: int = 3
    ) -> None:
        self.heading(level, title)
        if not values:
            self.paragraph(_EMPTY)
        elif self.html:
            tag = "ol" if ordered else "ul"
            self.lines.append(f"<{tag}>")
            self.lines.extend(f"<li>{escape(value, quote=True)}</li>" for value in values)
            self.lines.append(f"</{tag}>")
        else:
            for index, value in enumerate(values, start=1):
                prefix = f"{index}. " if ordered else "- "
                self.lines.append("  " + prefix + value.replace("\n", "\n    "))

    def finish(self) -> str:
        if self.html:
            self.lines.extend(("</main>", "</body>", "</html>"))
        return "\n".join(self.lines).lstrip("\n") + "\n"


def _checked_document(bundle: AssessmentReportBundle) -> dict[str, Any]:
    if type(bundle) is not AssessmentReportBundle:
        raise AssessmentReportingError("bundle must be an exact AssessmentReportBundle")
    # The full canonical parser checks all addresses and captures JSON-owned values.
    owned = AssessmentReportBundle.from_json(bundle.to_json())
    return owned.to_dict()


def _render(document: dict[str, Any], *, html: bool) -> str:
    writer = _Writer(html=html)
    report = document["report"]
    assessment = report["assessment"]
    summary = report["executive_summary"]
    attestation = document["attestation"]
    writer.heading(1, "Assessment report")
    writer.paragraph(_NOTICE)
    writer.paragraph(_COVERAGE_NOTICE)

    writer.heading(2, "Record identity and source binding")
    writer.fields("Bundle identity", document, ("bundle_id", "bundle_sha256"))
    writer.fields("Report identity", report, ("report_id", "report_sha256"))
    writer.fields(
        "Assessment source and timing",
        assessment,
        (
            "assessment_id",
            "assessment_sha256",
            "signed_scope_sha256",
            "world_snapshot_sha256",
            "schedule_sha256",
            "started_at",
            "ended_at",
            "source_observed_at",
            "generated_at",
            "max_source_age_seconds",
        ),
    )
    writer.paragraph(
        "Content addresses and recorded freshness are checked against the supplied bundle. "
        "The source objects, signatures and live currentness are not independently verified "
        "by this renderer."
    )

    writer.heading(2, "Executive summary and coverage limitations")
    writer.fields(
        "Summary identity and recorded state",
        summary,
        (
            "executive_summary_id",
            "executive_summary_sha256",
            "completeness",
            "residual_risk_rating",
            "residual_risk",
            "restoration_status",
        ),
    )
    writer.table(
        "Coverage metrics, including zero counts",
        ("Metric", "Recorded value"),
        summary["coverage_metrics"].items(),
    )
    writer.table(
        "Finding severity counts, including zero counts",
        ("Severity", "Count"),
        ((item["severity"], item["count"]) for item in summary["severity_counts"]),
    )
    writer.table(
        "Finding lifecycle counts, including zero counts",
        ("Status", "Count"),
        ((item["status"], item["count"]) for item in summary["status_counts"]),
    )
    for title, name in (
        ("Negative result tasks", "negative_result_task_ids"),
        ("Abstained tasks", "abstained_task_ids"),
        ("Blocked areas", "blocked_areas"),
        ("Untested areas", "untested_areas"),
        ("Blind spots", "blind_spots"),
        ("Scope limits", "scope_limits"),
        ("Incomplete restoration tasks", "incomplete_restoration_task_ids"),
    ):
        writer.items(title, summary[name])
    writer.items("Not determined areas", assessment["not_determined_areas"])

    writer.heading(2, "Scoped assets")
    for asset in assessment["assets"]:
        writer.heading(3, asset["display_name"])
        writer.fields(
            "Asset identity and scope",
            asset,
            ("asset_id", "asset_type", "asset_record_id", "asset_sha256", "signed_scope_sha256"),
        )
        writer.items("Scoped operations", asset["operation_ids"], level=4)
        writer.items("Asset evidence digests", asset["evidence_digests"], level=4)

    writer.heading(2, "Task outcomes and restoration")
    for task in assessment["task_transcripts"]:
        writer.heading(3, task["task_id"])
        writer.fields(
            "Recorded task outcome and lineage",
            task,
            (
                "coverage_area_id",
                "status",
                "blocker_code",
                "technique_id",
                "profile_id",
                "started_at",
                "ended_at",
                "restoration_required",
                "restoration_status",
                "transcript_sha256",
                "transcript_record_sha256",
                "signed_scope_sha256",
                "world_snapshot_sha256",
                "schedule_sha256",
            ),
        )
        writer.items("Task evidence digests", task["evidence_digests"], level=4)

    writer.heading(2, "Technical findings")
    if not report["findings"]:
        writer.paragraph(
            "No finding reports are present in this bundle. This is not a statement that "
            "the assessed assets are free of vulnerabilities."
        )
    for finding in report["findings"]:
        writer.heading(3, f"{finding['finding_id']}: {finding['title']}")
        writer.fields(
            "Finding identity, classification and retest",
            finding,
            (
                "finding_id",
                "finding_report_id",
                "finding_report_sha256",
                "affected_asset_id",
                "affected_operation_id",
                "vulnerability_class",
                "cwe_ref",
                "severity",
                "confidence",
                "status",
                "cvss_vector",
                "cvss_score",
                "validation_status",
                "validation_result_sha256",
                "retest_status",
                "lifecycle_snapshot_sha256",
            ),
        )
        writer.heading(4, "Impact")
        writer.paragraph(finding["impact_description"])
        writer.items(
            "High-level reproduction summary",
            finding["reproduction_summary"],
            ordered=True,
            level=4,
        )
        writer.heading(4, "Remediation guidance")
        writer.paragraph(finding["remediation_guidance"])
        writer.items("Finding evidence digests", finding["evidence_digests"], level=4)

    writer.heading(2, "Validation and lifecycle source references")
    if not assessment["validator_results"]:
        writer.paragraph("No validator result references are recorded in this bundle.")
    for result in assessment["validator_results"]:
        writer.heading(3, result["validator_id"])
        writer.fields("Validator result binding", result, ("task_id", "outcome", "result_sha256"))
        writer.items("Validator evidence digests", result["evidence_digests"], level=4)
    if not assessment["finding_lifecycle"]:
        writer.paragraph("No finding lifecycle references are recorded in this bundle.")
    for lifecycle in assessment["finding_lifecycle"]:
        writer.fields(
            "Finding lifecycle binding",
            lifecycle,
            ("finding_id", "state", "snapshot_sha256", "updated_at"),
        )

    writer.heading(2, "Evidence-only attestation and compliance limitations")
    writer.fields(
        "Recorded attestation",
        attestation,
        (
            "attestation_id",
            "attestation_sha256",
            "report_id",
            "report_sha256",
            "assessment_id",
            "assessment_sha256",
            "attested_at",
            "compliance_claim",
            "conclusion",
            "restoration_status",
        ),
    )
    writer.paragraph(
        "Compliance is not assessed. This evidence-only attestation is not a compliance "
        "certification or proof of authenticated reviewer acceptance."
    )
    for title, name in (
        ("Tested areas", "tested_areas"),
        ("Not tested areas", "not_tested_areas"),
        ("Not determined areas in the attestation", "not_determined_areas"),
        ("Attestation scope limits", "scope_limits"),
    ):
        writer.items(title, attestation[name])

    writer.heading(2, "Declared reviewer roles")
    writer.paragraph(
        "These are declared identities and roles in the checked record. Structural role "
        "separation is not signature verification, enrollment or independent acceptance."
    )
    writer.table(
        "Declared report reviewers",
        ("Role", "Reviewer identifier"),
        ((item["role"], item["reviewer_id"]) for item in report["reviewer_roles"]),
    )
    writer.table(
        "Declared attestation reviewers",
        ("Role", "Reviewer identifier"),
        ((item["role"], item["reviewer_id"]) for item in attestation["reviewer_roles"]),
    )
    writer.heading(2, "Unchanged operational effects")
    writer.table("Bundle effects", ("Effect", "Recorded status"), document["effects"].items())
    writer.paragraph(
        "Rendering performs no file write, target action, network request, signing, "
        "publication, API mutation or store mutation. The caller remains responsible "
        "for separately authorized handling of the returned text."
    )
    return writer.finish()


def render_assessment_report_html(bundle: AssessmentReportBundle) -> str:
    """Return static, escaped HTML after exact full-bundle reconstruction."""

    return _render(_checked_document(bundle), html=True)


def render_assessment_report_text(bundle: AssessmentReportBundle) -> str:
    """Return deterministic plain text after exact full-bundle reconstruction."""

    return _render(_checked_document(bundle), html=False)


__all__ = ["render_assessment_report_html", "render_assessment_report_text"]
