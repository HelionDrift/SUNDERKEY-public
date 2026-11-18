"""Phase 171 deterministic evidence-aware asset risk scoring coverage."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from dataclasses import replace
from pathlib import Path

from jsonschema import Draft202012Validator

import sunderkey
from sunderkey.asset_risk_scoring import (
    NO_EFFECTS,
    AssetCriticalityExposureBinding,
    AssetRiskPortfolio,
    AssetRiskScoringError,
    AttackPathEvidence,
    DefenderDetectionCoverage,
    ExceptionState,
    FindingRecordState,
    FindingValidationState,
    OpenFindingRecord,
    ReachabilityState,
    RemediationState,
    RiskScoringPolicy,
    Severity,
    build_asset_risk_portfolio,
    verify_asset_risk_portfolio,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "registry" / "schemas" / "asset-risk-scorecard-v1.schema.json"


def _sha(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("ascii")).hexdigest()


def _policy(**changes: object) -> RiskScoringPolicy:
    values: dict[str, object] = {
        "policy_version": "1.0.0",
        "maximum_evidence_age_seconds": 3_600,
        "minimum_evidence_coverage_bps": 7_500,
    }
    values.update(changes)
    return RiskScoringPolicy(**values)  # type: ignore[arg-type]


def _asset(suffix: str = "a", **changes: object) -> AssetCriticalityExposureBinding:
    values: dict[str, object] = {
        "tenant_ref": "tenantref:acme",
        "context_ref": "contextref:assessment-171",
        "scope_sha256": _sha("scope"),
        "asset_ref": f"assetref:service-{suffix}",
        "asset_sha256": _sha(f"asset-{suffix}"),
        "criticality_bps": 8_000,
        "exposure_bps": 6_000,
        "evidence_coverage_bps": 9_000,
        "uncertainty_bps": 1_000,
        "evidence_sha256": _sha(f"asset-evidence-{suffix}"),
        "observed_at": "2026-09-20T12:00:00Z",
    }
    values.update(changes)
    return AssetCriticalityExposureBinding(**values)  # type: ignore[arg-type]


def _finding(
    asset: AssetCriticalityExposureBinding,
    suffix: str = "a",
    **changes: object,
) -> OpenFindingRecord:
    values: dict[str, object] = {
        "tenant_ref": asset.tenant_ref,
        "context_ref": asset.context_ref,
        "scope_sha256": asset.scope_sha256,
        "asset_ref": asset.asset_ref,
        "asset_sha256": asset.asset_sha256,
        "finding_ref": f"findingref:finding-{suffix}",
        "finding_sha256": _sha(f"finding-{suffix}"),
        "severity": Severity.MEDIUM,
        "confidence_bps": 8_000,
        "validation_state": FindingValidationState.VERIFIED,
        "record_state": FindingRecordState.ACTIVE,
        "remediation_state": RemediationState.OPEN_UNADDRESSED,
        "exception_state": ExceptionState.NONE,
        "evidence_coverage_bps": 9_000,
        "evidence_sha256": _sha(f"finding-evidence-{suffix}"),
        "observed_at": "2026-09-20T12:00:00Z",
    }
    values.update(changes)
    return OpenFindingRecord(**values)  # type: ignore[arg-type]


def _path(
    asset: AssetCriticalityExposureBinding,
    **changes: object,
) -> AttackPathEvidence:
    values: dict[str, object] = {
        "tenant_ref": asset.tenant_ref,
        "context_ref": asset.context_ref,
        "scope_sha256": asset.scope_sha256,
        "asset_ref": asset.asset_ref,
        "asset_sha256": asset.asset_sha256,
        "reachability_state": ReachabilityState.CONFIRMED,
        "depth": 2,
        "evidence_coverage_bps": 9_000,
        "uncertainty_bps": 1_000,
        "evidence_sha256": _sha(f"path-{asset.asset_ref}"),
        "observed_at": "2026-09-20T12:00:00Z",
    }
    values.update(changes)
    return AttackPathEvidence(**values)  # type: ignore[arg-type]


def _defender(
    asset: AssetCriticalityExposureBinding,
    **changes: object,
) -> DefenderDetectionCoverage:
    values: dict[str, object] = {
        "tenant_ref": asset.tenant_ref,
        "context_ref": asset.context_ref,
        "scope_sha256": asset.scope_sha256,
        "asset_ref": asset.asset_ref,
        "asset_sha256": asset.asset_sha256,
        "detection_coverage_bps": 5_000,
        "evidence_coverage_bps": 9_000,
        "uncertainty_bps": 1_000,
        "evidence_sha256": _sha(f"defender-{asset.asset_ref}"),
        "observed_at": "2026-09-20T12:00:00Z",
    }
    values.update(changes)
    return DefenderDetectionCoverage(**values)  # type: ignore[arg-type]


def _portfolio(
    *,
    asset_bindings: tuple[AssetCriticalityExposureBinding, ...] | None = None,
    finding_records: tuple[OpenFindingRecord, ...] | None = None,
    attack_path_bindings: tuple[AttackPathEvidence, ...] | None = None,
    defender_bindings: tuple[DefenderDetectionCoverage, ...] | None = None,
    calculated_at: str = "2026-09-20T12:10:00Z",
    policy: RiskScoringPolicy | None = None,
) -> AssetRiskPortfolio:
    asset = _asset()
    assets = asset_bindings if asset_bindings is not None else (asset,)
    findings = finding_records if finding_records is not None else (_finding(asset),)
    paths = attack_path_bindings if attack_path_bindings is not None else (_path(asset),)
    defenders = defender_bindings if defender_bindings is not None else (_defender(asset),)
    return build_asset_risk_portfolio(
        calculated_at=calculated_at,
        policy=policy or _policy(),
        asset_bindings=assets,
        finding_records=findings,
        attack_path_bindings=paths,
        defender_bindings=defenders,
    )


class AssetRiskScoringPhase171Tests(unittest.TestCase):
    def test_public_exports_keep_identity(self) -> None:
        self.assertIs(sunderkey.AssetRiskPortfolio, AssetRiskPortfolio)
        self.assertIs(sunderkey.AssetRiskScoringError, AssetRiskScoringError)
        self.assertIs(sunderkey.RiskScoringPolicy, RiskScoringPolicy)
        self.assertIs(sunderkey.build_asset_risk_portfolio, build_asset_risk_portfolio)
        self.assertIs(sunderkey.verify_asset_risk_portfolio, verify_asset_risk_portfolio)

    def test_complete_portfolio_is_deterministic_schema_valid_and_effect_free(self) -> None:
        first = _portfolio()
        second = _portfolio()
        self.assertEqual(first, second)
        self.assertEqual(first, AssetRiskPortfolio.from_json(first.document_json))
        verify_asset_risk_portfolio(first)

        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(first.to_dict())
        self.assertEqual(first.to_dict()["effects"], dict(NO_EFFECTS))
        self.assertEqual(first.scorecards[0].evidence_state.value, "complete")
        self.assertEqual(first.scorecards[0].disposition, "manual_review_required")

    def test_exact_baseline_and_composite_formulas_are_disclosed(self) -> None:
        score = _portfolio().scorecards[0]
        contribution = score.finding_contributions[0]
        self.assertEqual(score.baseline_score_bps, 3_000)
        self.assertEqual(contribution.severity_component_bps, 4_500)
        self.assertEqual(contribution.validation_bonus_bps, 500)
        self.assertEqual(contribution.confidence_uncertainty_bonus_bps, 400)
        self.assertEqual(contribution.remediation_bonus_bps, 750)
        self.assertEqual(contribution.composite_contribution_bps, 6_150)
        self.assertEqual(
            score.composite_breakdown.to_dict(),
            {
                "asset_context_floor_bps": 7_200,
                "asset_uncertainty_bonus_bps": 100,
                "attack_path_bonus_bps": 2_300,
                "attack_path_uncertainty_bonus_bps": 200,
                "baseline_floor_bps": 3_000,
                "calculated_score_bps": 9_000,
                "defender_detection_reduction_bps": 1_000,
                "defender_uncertainty_bonus_bps": 200,
                "finding_aggregate_bps": 6_150,
                "inherent_floor_bps": 7_200,
                "pre_control_score_bps": 10_000,
            },
        )
        self.assertEqual(score.composite_score_bps, 9_000)
        self.assertFalse(score.fail_closed_floor_applied)

    def test_uncertainty_never_silently_lowers_finding_risk(self) -> None:
        asset = _asset()
        high_confidence = _finding(asset, confidence_bps=8_000)
        low_confidence = _finding(asset, confidence_bps=4_000)
        high = _portfolio(
            asset_bindings=(asset,),
            finding_records=(high_confidence,),
            attack_path_bindings=(_path(asset),),
            defender_bindings=(_defender(asset),),
        ).scorecards[0]
        low = _portfolio(
            asset_bindings=(asset,),
            finding_records=(low_confidence,),
            attack_path_bindings=(_path(asset),),
            defender_bindings=(_defender(asset),),
        ).scorecards[0]
        self.assertGreater(
            low.finding_contributions[0].confidence_uncertainty_bonus_bps,
            high.finding_contributions[0].confidence_uncertainty_bonus_bps,
        )
        self.assertGreaterEqual(
            low.finding_contributions[0].composite_contribution_bps,
            high.finding_contributions[0].composite_contribution_bps,
        )

    def test_defender_coverage_reduction_is_bounded_and_visible(self) -> None:
        asset = _asset()
        no_coverage = _portfolio(
            asset_bindings=(asset,),
            finding_records=(_finding(asset),),
            attack_path_bindings=(_path(asset),),
            defender_bindings=(_defender(asset, detection_coverage_bps=0),),
        ).scorecards[0]
        coverage = _portfolio(
            asset_bindings=(asset,),
            finding_records=(_finding(asset),),
            attack_path_bindings=(_path(asset),),
            defender_bindings=(_defender(asset),),
        ).scorecards[0]
        self.assertEqual(no_coverage.composite_breakdown.defender_detection_reduction_bps, 0)
        self.assertEqual(no_coverage.composite_score_bps, 10_000)
        self.assertEqual(coverage.composite_breakdown.defender_detection_reduction_bps, 1_000)
        self.assertGreaterEqual(
            coverage.composite_score_bps,
            coverage.composite_breakdown.inherent_floor_bps,
        )

    def test_stale_evidence_publishes_stale_state_and_maximum_fail_closed_score(self) -> None:
        asset = _asset(observed_at="2026-09-20T10:00:00Z")
        portfolio = _portfolio(
            asset_bindings=(asset,),
            finding_records=(_finding(asset),),
            attack_path_bindings=(_path(asset),),
            defender_bindings=(_defender(asset),),
        )
        score = portfolio.scorecards[0]
        self.assertEqual(score.evidence_state.value, "stale")
        self.assertEqual(score.disposition, "blocked_stale")
        self.assertEqual(score.composite_score_bps, 10_000)
        self.assertTrue(score.fail_closed_floor_applied)
        self.assertIn("evidence.stale", score.reason_codes)

    def test_missing_and_low_coverage_evidence_are_insufficient_and_not_low_risk(self) -> None:
        asset = _asset()
        missing = _portfolio(
            asset_bindings=(asset,),
            finding_records=(),
            attack_path_bindings=(),
            defender_bindings=(),
        ).scorecards[0]
        self.assertEqual(missing.evidence_state.value, "insufficient")
        self.assertEqual(missing.composite_score_bps, 10_000)
        self.assertEqual(missing.coverage_bps, 0)
        self.assertIn("evidence.missing_open_findings", missing.reason_codes)
        self.assertIn("evidence.missing_attack_path", missing.reason_codes)
        self.assertIn("evidence.missing_defender_coverage", missing.reason_codes)

        low = _portfolio(
            asset_bindings=(asset,),
            finding_records=(_finding(asset, evidence_coverage_bps=7_000),),
            attack_path_bindings=(_path(asset),),
            defender_bindings=(_defender(asset),),
        ).scorecards[0]
        self.assertEqual(low.evidence_state.value, "insufficient")
        self.assertEqual(low.composite_score_bps, 10_000)
        self.assertIn("evidence.coverage_below_minimum", low.reason_codes)

    def test_invalid_finding_is_preserved_as_invalid_and_maximum_risk(self) -> None:
        asset = _asset()
        invalid = _finding(asset, validation_state=FindingValidationState.INVALID)
        score = _portfolio(
            asset_bindings=(asset,),
            finding_records=(invalid,),
            attack_path_bindings=(_path(asset),),
            defender_bindings=(_defender(asset),),
        ).scorecards[0]
        self.assertEqual(score.evidence_state.value, "invalid")
        self.assertEqual(score.disposition, "blocked_invalid")
        self.assertEqual(score.composite_score_bps, 10_000)
        self.assertEqual(score.finding_count, 1)
        self.assertIn("evidence.invalid_finding", score.reason_codes)

    def test_reported_remediation_and_exceptions_do_not_remove_findings(self) -> None:
        asset = _asset()
        finding = _finding(
            asset,
            remediation_state=RemediationState.REPORTED_REMEDIATED,
            exception_state=ExceptionState.APPROVED,
        )
        score = _portfolio(
            asset_bindings=(asset,),
            finding_records=(finding,),
            attack_path_bindings=(_path(asset),),
            defender_bindings=(_defender(asset),),
        ).scorecards[0]
        self.assertEqual(score.finding_count, 1)
        self.assertEqual(score.finding_contributions[0].exception_bonus_bps, 750)
        self.assertIn("risk.exception_retained", score.reason_codes)
        self.assertIn("risk.reported_remediation_unverified", score.reason_codes)

    def test_cross_tenant_context_scope_and_asset_bindings_fail_closed(self) -> None:
        asset = _asset()
        cases = (
            _finding(asset, tenant_ref="tenantref:other"),
            _finding(asset, context_ref="contextref:other"),
            _finding(asset, scope_sha256=_sha("other-scope")),
            _finding(asset, asset_sha256=_sha("other-asset")),
        )
        for finding in cases:
            with (
                self.subTest(finding=finding.finding_ref),
                self.assertRaisesRegex(AssetRiskScoringError, "crosses"),
            ):
                _portfolio(
                    asset_bindings=(asset,),
                    finding_records=(finding,),
                    attack_path_bindings=(_path(asset),),
                    defender_bindings=(_defender(asset),),
                )

    def test_duplicate_and_merged_away_finding_misuse_fails_closed(self) -> None:
        asset = _asset()
        finding = _finding(asset)
        with self.assertRaisesRegex(AssetRiskScoringError, "duplicate finding reference"):
            _portfolio(
                asset_bindings=(asset,),
                finding_records=(finding, finding),
                attack_path_bindings=(_path(asset),),
                defender_bindings=(_defender(asset),),
            )
        with self.assertRaisesRegex(AssetRiskScoringError, "merged-away"):
            _portfolio(
                asset_bindings=(asset,),
                finding_records=(replace(finding, record_state=FindingRecordState.MERGED_AWAY),),
                attack_path_bindings=(_path(asset),),
                defender_bindings=(_defender(asset),),
            )

    def test_invalid_ranges_paths_future_evidence_and_secrets_fail_closed(self) -> None:
        asset = _asset()
        with self.assertRaises(AssetRiskScoringError):
            _asset(criticality_bps=10_001)
        with self.assertRaisesRegex(AssetRiskScoringError, "positive depth"):
            _path(asset, depth=0)
        with self.assertRaisesRegex(AssetRiskScoringError, "cannot claim"):
            _path(asset, reachability_state=ReachabilityState.UNKNOWN, depth=2)
        with self.assertRaisesRegex(AssetRiskScoringError, "future"):
            _portfolio(
                asset_bindings=(replace(asset, observed_at="2026-09-20T12:11:00Z"),),
                finding_records=(),
                attack_path_bindings=(),
                defender_bindings=(),
            )
        with self.assertRaisesRegex(AssetRiskScoringError, "safe identifier"):
            _asset(asset_ref="assetref:authorization=unsafe")

    def test_ranking_and_input_order_are_deterministic(self) -> None:
        first = _asset("a")
        second = _asset("b", criticality_bps=10_000, exposure_bps=10_000)
        first_finding = _finding(first, "a")
        second_finding = _finding(second, "b", severity=Severity.CRITICAL)
        assets = (first, second)
        findings = (first_finding, second_finding)
        paths = (_path(first), _path(second))
        defenders = (_defender(first), _defender(second))
        ordered = _portfolio(
            asset_bindings=assets,
            finding_records=findings,
            attack_path_bindings=paths,
            defender_bindings=defenders,
        )
        reversed_inputs = _portfolio(
            asset_bindings=tuple(reversed(assets)),
            finding_records=tuple(reversed(findings)),
            attack_path_bindings=tuple(reversed(paths)),
            defender_bindings=tuple(reversed(defenders)),
        )
        self.assertEqual(ordered, reversed_inputs)
        self.assertEqual(ordered.scorecards[0].asset_ref, second.asset_ref)
        self.assertEqual([item.rank for item in ordered.scorecards], [1, 2])

    def test_tampering_with_inputs_scores_ranks_and_identity_is_rejected(self) -> None:
        raw = _portfolio().to_dict()
        cases: list[tuple[dict[str, object], str]] = []
        changed_score = copy.deepcopy(raw)
        changed_score["scorecards"][0]["composite"]["score_bps"] = 1  # type: ignore[index]
        cases.append((changed_score, "content address"))
        changed_rank = copy.deepcopy(raw)
        changed_rank["scorecards"][0]["rank"] = 2  # type: ignore[index]
        cases.append((changed_rank, "content address"))
        changed_asset = copy.deepcopy(raw)
        changed_asset["asset_bindings"][0]["criticality_bps"] = 1  # type: ignore[index]
        cases.append((changed_asset, "asset binding content address"))
        changed_identity = copy.deepcopy(raw)
        changed_identity["portfolio_sha256"] = _sha("tampered")
        cases.append((changed_identity, "content address"))
        for value, pattern in cases:
            with (
                self.subTest(pattern=pattern),
                self.assertRaisesRegex(AssetRiskScoringError, pattern),
            ):
                AssetRiskPortfolio.from_dict(value)


if __name__ == "__main__":
    unittest.main()
