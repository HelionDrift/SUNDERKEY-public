"""Pure assessment presentation preserves checked records and inert semantics."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace
from html import escape
from html.parser import HTMLParser
from unittest.mock import patch

from sunderkey.assessment_report_rendering import (
    render_assessment_report_html,
    render_assessment_report_text,
)
from sunderkey.assessment_reporting import (
    FINDING_STATUSES,
    NO_EFFECTS,
    SEVERITIES,
    AssessmentReportBundle,
    AssessmentReportingError,
    build_assessment_report_bundle,
)
from tests.agents import test_assessment_reporting_phase161 as report_fixtures

_RENDERERS = (render_assessment_report_html, render_assessment_report_text)
_ALLOWED_TAGS = {
    "html",
    "head",
    "meta",
    "title",
    "style",
    "body",
    "main",
    "h1",
    "h2",
    "h3",
    "h4",
    "p",
    "table",
    "caption",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
    "ul",
    "ol",
    "li",
}


class _HtmlProbe(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elements: list[tuple[str, dict[str, str | None]]] = []
        self.data: list[str] = []
        self.headings: list[int] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.elements.append((tag, dict(attrs)))
        if tag in {"h1", "h2", "h3", "h4"}:
            self.headings.append(int(tag[1:]))

    def handle_data(self, data: str) -> None:
        self.data.append(data)


class AssessmentReportRenderingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = report_fixtures.AssessmentReportingPhase161Tests("runTest")
        self.bundle = self.fixture.bundle()

    def _assemble(self, assessment, findings) -> AssessmentReportBundle:
        report_reviewers, attestation_reviewers = self.fixture.reviewers()
        return build_assessment_report_bundle(
            assessment,
            findings,
            report_reviewers=report_reviewers,
            attestation_reviewers=attestation_reviewers,
            attested_at="2026-09-20T03:22:00Z",
        )

    def _probe(self, bundle: AssessmentReportBundle) -> _HtmlProbe:
        probe = _HtmlProbe()
        probe.feed(render_assessment_report_html(bundle))
        probe.close()
        return probe

    def test_deterministic_round_trips_preserve_all_source_identities(self) -> None:
        before = self.bundle.to_json()
        restored = AssessmentReportBundle.from_json(before)
        for renderer in _RENDERERS:
            with self.subTest(renderer=renderer.__name__):
                first = renderer(self.bundle)
                self.assertEqual(first, renderer(self.bundle))
                self.assertEqual(first, renderer(restored))
                self.assertTrue(first.endswith("\n"))
                for record in (
                    self.bundle,
                    self.bundle.report,
                    self.bundle.report.assessment,
                    self.bundle.report.executive_summary,
                    self.bundle.attestation,
                    *self.bundle.report.findings,
                    *self.bundle.report.assessment.assets,
                ):
                    for key, value in record.to_dict().items():
                        if key.endswith("_sha256") or key.endswith("_id"):
                            self.assertIn(value, first, key)
        self.assertEqual(self.bundle.to_json(), before)

    def test_full_technical_details_and_ordered_reproduction_are_visible(self) -> None:
        finding = self.bundle.report.findings[0]
        for renderer in _RENDERERS:
            with self.subTest(renderer=renderer.__name__):
                result = renderer(self.bundle)
                for value in (
                    finding.title,
                    finding.affected_asset_id,
                    finding.affected_operation_id,
                    finding.vulnerability_class,
                    finding.cwe_ref,
                    finding.severity,
                    finding.confidence,
                    finding.status,
                    finding.impact_description,
                    finding.remediation_guidance,
                    finding.validation_status,
                    finding.validation_result_sha256,
                    finding.retest_status,
                    finding.cvss_vector,
                    str(finding.cvss_score),
                    *finding.evidence_digests,
                    *finding.reproduction_summary,
                ):
                    self.assertIn(value, result)
                steps = finding.reproduction_summary
                self.assertLess(result.index(steps[0]), result.index(steps[1]))
        self.assertIn("<ol>", render_assessment_report_html(self.bundle))
        self.assertIn(
            "  1. " + finding.reproduction_summary[0], render_assessment_report_text(self.bundle)
        )

    def test_all_adverse_outcomes_and_zero_counts_are_retained(self) -> None:
        bundle = self.fixture.bundle(
            ("tested", "negative", "abstained", "blocked", "untested", "not_determined"),
            restoration_status="incomplete",
        )
        for renderer in _RENDERERS:
            with self.subTest(renderer=renderer.__name__):
                result = renderer(bundle)
                for value in (
                    "partial",
                    "negative",
                    "abstained",
                    "blocked",
                    "untested",
                    "not_determined",
                    "dependency_unavailable",
                    "incomplete",
                    "task.op0",
                    "task.op1",
                    "task.op2",
                    "asset.api::op3",
                    "asset.api::op4",
                    "asset.api::op5",
                    "3333",
                    bundle.report.assessment.residual_risk,
                    *bundle.report.assessment.scope_limits,
                    *SEVERITIES,
                    *FINDING_STATUSES,
                ):
                    self.assertIn(value, result)
        html = render_assessment_report_html(bundle)
        self.assertIn('<th scope="row">low</th>\n<td>0</td>', html)
        self.assertIn('<th scope="row">resolved</th>\n<td>0</td>', html)

    def test_empty_findings_have_explicit_non_assurance_state(self) -> None:
        assessment = replace(self.fixture.assessment(("negative",)), finding_lifecycle=())
        bundle = self._assemble(assessment, ())
        for renderer in _RENDERERS:
            result = renderer(bundle)
            self.assertIn("No finding reports are present in this bundle.", result)
            self.assertIn("not a statement that", result)
            self.assertIn("No finding lifecycle references are recorded", result)
            self.assertIn("None recorded in this bundle.", result)
            self.assertIn("negative", result)
            for severity in SEVERITIES:
                self.assertIn(severity, result)
        html = render_assessment_report_html(bundle)
        self.assertIn('<th scope="row">critical</th>\n<td>0</td>', html)

    def test_blocked_only_bundle_has_no_invented_validator_or_finding(self) -> None:
        assessment = replace(self.fixture.assessment(("blocked",)), finding_lifecycle=())
        bundle = self._assemble(assessment, ())
        for renderer in _RENDERERS:
            result = renderer(bundle)
            self.assertIn("No validator result references are recorded", result)
            self.assertIn("dependency_unavailable", result)
            self.assertIn("partial", result)
        self.assertEqual(bundle.report.executive_summary.coverage_metrics.coverage_basis_points, 0)

    def test_optional_cvss_is_never_invented(self) -> None:
        assessment = self.bundle.report.assessment
        finding = replace(
            self.bundle.report.findings[0], cvss_vector=None, cvss_score=None, severity="unrated"
        )
        bundle = self._assemble(assessment, (finding,))
        for renderer in _RENDERERS:
            result = renderer(bundle)
            self.assertIn("Not supplied", result)
            self.assertIn("unrated", result)
            self.assertNotIn("CVSS:3.1", result)
            self.assertNotIn("9.8", result)

    def test_native_hostile_text_is_escaped_and_never_an_active_element(self) -> None:
        name = '<script>alert("asset")</script> & <link href="https://untrusted.invalid/a">'
        risk = 'Remaining <iframe src="https://untrusted.invalid/b"></iframe> risk.'
        limit = 'Only named <object data="https://untrusted.invalid/c">areas</object>.'
        impact = 'Observed <img src="https://untrusted.invalid/d" onerror="alert(1)">.'
        title = 'An <svg onload="alert(2)">example</svg> & "quoted" title'
        remediation = 'Use <a href="javascript:alert(3)">authorization checks</a>.'
        steps = ("Compare <b>labels</b> & literal text.", "Retest the named operation.")
        asset = replace(self.bundle.report.assessment.assets[0], display_name=name)
        assessment = replace(
            self.bundle.report.assessment,
            assets=(asset,),
            residual_risk=risk,
            scope_limits=(limit,),
        )
        finding = replace(
            self.bundle.report.findings[0],
            title=title,
            impact_description=impact,
            remediation_guidance=remediation,
            reproduction_summary=steps,
        )
        bundle = self._assemble(assessment, (finding,))
        html = render_assessment_report_html(bundle)
        plain = render_assessment_report_text(bundle)
        probe = self._probe(bundle)
        for value in (name, risk, limit, impact, title, remediation, *steps):
            self.assertIn(escape(value, quote=True), html)
            self.assertIn(value, plain)
            self.assertTrue(any(value in data for data in probe.data), value)
        self.assertLessEqual({tag for tag, _ in probe.elements}, _ALLOWED_TAGS)
        for _, attrs in probe.elements:
            self.assertFalse(set(attrs) & {"href", "src", "srcset", "action", "data"})
            self.assertFalse(any(name.startswith("on") for name in attrs))

    def test_unicode_and_multiline_text_are_data_not_new_sections(self) -> None:
        text = "Recorded Caf\u00e9 comparison\nSecond line\tand literal & value."
        finding = replace(self.bundle.report.findings[0], impact_description=text)
        bundle = self._assemble(self.bundle.report.assessment, (finding,))
        self.assertIn(escape(text), render_assessment_report_html(bundle))
        self.assertIn(text.replace("\n", "\n  "), render_assessment_report_text(bundle))

    def test_late_source_mutation_cannot_reuse_addressed_bundle(self) -> None:
        for target, field, value in (
            ("bundle", "bundle_sha256", report_fixtures.DIGESTS[15]),
            ("finding", "title", "A different title"),
            ("assessment", "residual_risk", "A different residual risk."),
            ("attestation", "compliance_claim", "compliant"),
        ):
            for renderer in _RENDERERS:
                with self.subTest(target=target, field=field, renderer=renderer.__name__):
                    bundle = copy.deepcopy(self.bundle)
                    targets = {
                        "bundle": bundle,
                        "finding": bundle.report.findings[0],
                        "assessment": bundle.report.assessment,
                        "attestation": bundle.attestation,
                    }
                    object.__setattr__(targets[target], field, value)
                    before = bundle.to_json()
                    with self.assertRaises(AssessmentReportingError):
                        renderer(bundle)
                    self.assertEqual(bundle.to_json(), before)

    def test_python_equal_wire_types_cannot_be_normalized_under_old_identity(self) -> None:
        for target, field, value in (
            ("coverage", "coverage_basis_points", 10000.0),
            ("coverage", "total_areas", 2.0),
            ("coverage", "tested", True),
            ("assessment", "max_source_age_seconds", 300.0),
        ):
            for renderer in _RENDERERS:
                with self.subTest(
                    target=target, field=field, value=value, renderer=renderer.__name__
                ):
                    bundle = copy.deepcopy(self.bundle)
                    selected = (
                        bundle.report.executive_summary.coverage_metrics
                        if target == "coverage"
                        else bundle.report.assessment
                    )
                    object.__setattr__(selected, field, value)
                    old_hash = bundle.bundle_sha256
                    with self.assertRaises(AssessmentReportingError):
                        renderer(bundle)
                    self.assertEqual(bundle.bundle_sha256, old_hash)
                    self.assertIs(type(getattr(selected, field)), type(value))

    def test_only_exact_bundle_class_is_accepted(self) -> None:
        class DerivedBundle(AssessmentReportBundle):
            pass

        derived = DerivedBundle(self.bundle.report, self.bundle.attestation)
        for value in (None, self.bundle.to_dict(), self.bundle.to_json(), derived):
            for renderer in _RENDERERS:
                with (
                    self.subTest(type=type(value).__name__, renderer=renderer.__name__),
                    self.assertRaisesRegex(
                        AssessmentReportingError, "exact AssessmentReportBundle"
                    ),
                ):
                    renderer(value)

    def test_semantic_headings_tables_and_mobile_print_styles_are_present(self) -> None:
        html = render_assessment_report_html(self.bundle)
        probe = self._probe(self.bundle)
        tags = [tag for tag, _ in probe.elements]
        self.assertEqual(tags.count("h1"), 1)
        self.assertEqual(tags.count("main"), 1)
        self.assertEqual(tags.count("table"), tags.count("caption"))
        self.assertGreater(tags.count("table"), 0)
        for previous, current in zip(probe.headings, probe.headings[1:]):
            self.assertLessEqual(current, previous + 1)
        for tag, attrs in probe.elements:
            if tag == "th":
                self.assertIn(attrs.get("scope"), {"row", "col"})
        self.assertIn(("html", {"lang": "en"}), probe.elements)
        self.assertIn("width=device-width, initial-scale=1", html)
        for style in (
            "width: 100%",
            "overflow-wrap: anywhere",
            "@media print",
            "break-after: avoid",
            "table-header-group",
        ):
            self.assertIn(style, html)

    def test_neutral_text_colors_have_normal_text_contrast(self) -> None:
        def luminance(color: str) -> float:
            components = [int(color[index : index + 2], 16) / 255 for index in (1, 3, 5)]
            linear = [
                value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4
                for value in components
            ]
            return sum(value * weight for value, weight in zip(linear, (0.2126, 0.7152, 0.0722)))

        html = render_assessment_report_html(self.bundle)
        for foreground, background in (
            ("#111827", "#ffffff"),
            ("#111827", "#f3f4f6"),
            ("#374151", "#f3f4f6"),
        ):
            self.assertIn(foreground, html)
            self.assertIn(background, html)
            ratio = (luminance(background) + 0.05) / (luminance(foreground) + 0.05)
            self.assertGreaterEqual(ratio, 4.5)

    def test_static_html_has_no_resource_links_forms_or_active_content(self) -> None:
        probe = self._probe(self.bundle)
        self.assertLessEqual({tag for tag, _ in probe.elements}, _ALLOWED_TAGS)
        for _, attrs in probe.elements:
            self.assertFalse(
                set(attrs)
                & {
                    "href",
                    "src",
                    "srcset",
                    "action",
                    "formaction",
                    "poster",
                    "data",
                }
            )
            self.assertFalse(any(name.startswith("on") for name in attrs))
        html = render_assessment_report_html(self.bundle)
        for forbidden in ("url(", "@import", "gradient", "https://", "http://"):
            self.assertNotIn(forbidden, html)
        self.assertIn("default-src 'none'", html)

    def test_effects_and_review_compliance_qualification_boundaries_remain_none(self) -> None:
        before = self.bundle.to_dict()
        for renderer in _RENDERERS:
            result = renderer(self.bundle)
            for value in (
                "not_assessed",
                "evidence_only_no_compliance_determination",
                "not a compliance certification",
                "Declared reviewer roles",
                "not signature verification",
                "product qualification",
                "current authority",
                "qualification",
                "target_authority",
                "none",
            ):
                self.assertIn(value, result)
        self.assertEqual(self.bundle.to_dict(), before)
        self.assertEqual(before["effects"], NO_EFFECTS)
        self.assertEqual(
            json.loads(self.bundle.to_json())["attestation"]["compliance_claim"], "not_assessed"
        )

    def test_rendering_performs_no_file_or_socket_io(self) -> None:
        with (
            patch("builtins.open", side_effect=AssertionError("file access")),
            patch("socket.socket", side_effect=AssertionError("network access")),
        ):
            for renderer in _RENDERERS:
                self.assertIsInstance(renderer(self.bundle), str)


if __name__ == "__main__":
    unittest.main()
