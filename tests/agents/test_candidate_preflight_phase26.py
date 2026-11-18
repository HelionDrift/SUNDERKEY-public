"""Phase 26 unsigned candidate evaluation preflight contracts."""

from __future__ import annotations

import ast
import hashlib
import json
import unittest
from pathlib import Path
from typing import Any

from scripts.build_candidate_evaluation_submission import build_submission
from sunderkey.candidate_blueprints import load_candidate_blueprint_catalog
from sunderkey.candidate_components import (
    CandidateComponentCatalog,
    CandidateOnboardingReport,
    assess_candidate_onboarding,
    load_candidate_component_catalog,
)
from sunderkey.candidate_inventory import load_candidate_implementation_catalog
from sunderkey.candidate_preflight import (
    CandidateEvaluationPreflightReport,
    CandidateEvaluationSubmission,
    assess_candidate_evaluation_preflight,
    compute_candidate_evaluation_submission_sha256,
    load_candidate_evaluation_submission,
    load_candidate_onboarding_report,
)
from sunderkey.errors import QualificationError
from sunderkey.qualification import (
    load_qualification_plan_catalog,
    load_qualification_standard,
)
from sunderkey.qualification_evaluation import (
    load_qualification_evaluation_suite,
)
from sunderkey.registry import load_registry
from sunderkey.routing import load_capability_catalog

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "registry" / "army-v1.json"
CAPABILITY_PATH = ROOT / "registry" / "capabilities-army-v1.json"
STANDARD_PATH = ROOT / "registry" / "qualification-standard-v1.json"
PLANS_PATH = ROOT / "registry" / "qualification-plans-army-v1.json"
BLUEPRINTS_PATH = ROOT / "registry" / "candidate-blueprints-army-v1.json"
COMPONENTS_PATH = ROOT / "registry" / "candidate-components-v1.json"
CANDIDATES_PATH = ROOT / "registry" / "candidate-implementations-v1.json"
ONBOARDING_PATH = (
    ROOT / "examples" / "qualification" / "passive-osint-onboarding.json"
)
SUITE_PATH = (
    ROOT / "examples" / "qualification" / "passive-osint-suite.json"
)
SUBMISSION_PATH = (
    ROOT / "examples" / "qualification" / "passive-osint-submission.json"
)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"Expected an object in {path}")
    return value


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def rebind_submission(document: dict[str, Any]) -> None:
    body = {
        key: value
        for key, value in document.items()
        if key != "submission_sha256"
    }
    document["submission_sha256"] = (
        compute_candidate_evaluation_submission_sha256(body)
    )


def rebind_onboarding(document: dict[str, Any]) -> None:
    body = {
        key: value
        for key, value in document.items()
        if key not in {"report_id", "report_sha256"}
    }
    report_hash = canonical_sha256(
        {"domain": "sunderkey.candidate-onboarding-report.v1", "report": body}
    )
    document["report_sha256"] = report_hash
    document["report_id"] = (
        "ONR-" + report_hash.removeprefix("sha256:")[:32].upper()
    )


class CandidatePreflightPhase26Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)
        cls.capabilities = load_capability_catalog(
            CAPABILITY_PATH, cls.registry
        )
        cls.standard = load_qualification_standard(
            STANDARD_PATH, cls.registry, cls.capabilities
        )
        cls.plans = load_qualification_plan_catalog(
            PLANS_PATH,
            cls.registry,
            cls.capabilities,
            cls.standard,
        )
        cls.blueprints = load_candidate_blueprint_catalog(
            BLUEPRINTS_PATH,
            cls.registry,
            cls.capabilities,
            cls.standard,
            cls.plans,
        )
        cls.components = load_candidate_component_catalog(
            COMPONENTS_PATH, cls.blueprints
        )
        cls.candidates = load_candidate_implementation_catalog(
            CANDIDATES_PATH,
            cls.registry,
            cls.capabilities,
            cls.standard,
            cls.plans,
            cls.blueprints,
        )
        cls.onboarding = load_candidate_onboarding_report(ONBOARDING_PATH)
        cls.suite = load_qualification_evaluation_suite(
            SUITE_PATH,
            cls.registry,
            cls.capabilities,
            cls.standard,
            cls.plans,
        )
        cls.submission = load_candidate_evaluation_submission(
            SUBMISSION_PATH
        )

    def submission_from(
        self, raw: dict[str, Any]
    ) -> CandidateEvaluationSubmission:
        return CandidateEvaluationSubmission.from_dict(raw)

    def assess(
        self,
        *,
        components: CandidateComponentCatalog | None = None,
        onboarding: CandidateOnboardingReport | None = None,
        submission: CandidateEvaluationSubmission | None = None,
    ) -> CandidateEvaluationPreflightReport:
        return assess_candidate_evaluation_preflight(
            self.registry,
            self.capabilities,
            self.standard,
            self.plans,
            self.blueprints,
            components or self.components,
            self.candidates,
            onboarding or self.onboarding,
            self.suite,
            submission or self.submission,
        )

    def test_checked_in_artifacts_match_deterministic_builder(self) -> None:
        expected_onboarding = assess_candidate_onboarding(
            self.registry,
            self.capabilities,
            self.standard,
            self.plans,
            self.blueprints,
            self.components,
            self.candidates,
        )
        expected_submission = build_submission(
            self.standard,
            self.plans,
            self.blueprints,
            self.components,
            self.candidates,
            expected_onboarding,
            self.suite,
        )
        self.assertEqual(
            ONBOARDING_PATH.read_text(encoding="utf-8"),
            json.dumps(
                expected_onboarding.to_dict(),
                ensure_ascii=True,
                indent=2,
            )
            + "\n",
        )
        self.assertEqual(
            SUBMISSION_PATH.read_text(encoding="utf-8"),
            json.dumps(expected_submission, ensure_ascii=True, indent=2)
            + "\n",
        )

    def test_submission_binds_complete_fixture_chain(self) -> None:
        document = self.submission.to_dict()
        self.assertEqual(
            document["submission_sha256"],
            "sha256:ef9c4d7e13fadd8f4f4c62b785878653"
            "d7fa2b26254fb5ce23813fbed793dc98",
        )
        self.assertEqual(
            document["candidate_onboarding_report"]["report_id"],
            self.onboarding.report_id,
        )
        self.assertEqual(
            document["qualification_suite"]["sha256"],
            self.suite.canonical_sha256,
        )
        self.assertEqual(len(document["requested_gate_ids"]), 8)
        self.assertEqual(
            document["review_requirements"],
            self.standard.decision_policy.to_dict(),
        )

    def test_report_is_deterministic_and_explicitly_non_authoritative(
        self,
    ) -> None:
        first = self.assess()
        second = self.assess()
        document = first.to_dict()
        self.assertEqual(first, second)
        self.assertEqual(
            CandidateEvaluationPreflightReport.from_dict(document), first
        )
        self.assertEqual(
            document["report_id"],
            "PFR-FF19E981BC6ED8C733C5BA16399BACFE",
        )
        self.assertEqual(
            document["report_sha256"],
            "sha256:ff19e981bc6ed8c733c5ba16399bacfe"
            "6962d54e5bafe784eb9b24cd63377157",
        )
        self.assertEqual(
            document["status"], "synthetic_fixture_preflight_complete"
        )
        self.assertEqual(document["preflight_effect"], "none")
        self.assertFalse(document["authoritative_evaluation_eligible"])
        self.assertEqual(document["summary"]["requested_gate_count"], 8)
        self.assertEqual(document["summary"]["suite_case_count"], 29)
        self.assertEqual(document["summary"]["component_artifact_count"], 5)
        self.assertEqual(
            document["summary"]["authoritative_evaluation_blocker_count"],
            6,
        )
        self.assertIn(
            "qualification_decision_authority_pending_d008",
            document["authoritative_evaluation_blockers"],
        )

    def test_submission_hash_tampering_fails_closed(self) -> None:
        raw = self.submission.to_dict()
        raw["submission_version"] = "changed"
        with self.assertRaisesRegex(QualificationError, "hash is invalid"):
            self.submission_from(raw)

    def test_rehashed_candidate_substitution_fails_closed(self) -> None:
        raw = self.submission.to_dict()
        raw["candidate"]["candidate_artifact_sha256"] = (
            "sha256:" + ("0" * 64)
        )
        rebind_submission(raw)
        with self.assertRaisesRegex(
            QualificationError, "candidate binding is invalid"
        ):
            self.assess(submission=self.submission_from(raw))

    def test_rehashed_component_catalog_substitution_fails_closed(self) -> None:
        raw = self.submission.to_dict()
        raw["candidate_component_catalog"]["sha256"] = (
            "sha256:" + ("0" * 64)
        )
        rebind_submission(raw)
        with self.assertRaisesRegex(
            QualificationError, "Candidate component catalog binding"
        ):
            self.assess(submission=self.submission_from(raw))

    def test_rehashed_suite_substitution_fails_closed(self) -> None:
        raw = self.submission.to_dict()
        raw["qualification_suite"]["sha256"] = "sha256:" + ("0" * 64)
        rebind_submission(raw)
        with self.assertRaisesRegex(
            QualificationError, "Qualification suite binding"
        ):
            self.assess(submission=self.submission_from(raw))

    def test_rehashed_gate_omission_fails_closed(self) -> None:
        raw = self.submission.to_dict()
        raw["requested_gate_ids"].pop()
        rebind_submission(raw)
        with self.assertRaisesRegex(
            QualificationError, "requested gate binding is invalid"
        ):
            self.assess(submission=self.submission_from(raw))

    def test_rehashed_review_weakening_fails_closed(self) -> None:
        raw = self.submission.to_dict()
        raw["review_requirements"]["allow_self_attestation"] = True
        rebind_submission(raw)
        with self.assertRaisesRegex(
            QualificationError, "review requirements are invalid"
        ):
            self.assess(submission=self.submission_from(raw))

    def test_stale_but_self_identifying_onboarding_fails_closed(self) -> None:
        raw = self.onboarding.to_dict()
        raw["limitations"][0] = "Changed limitation"
        rebind_onboarding(raw)
        stale = CandidateOnboardingReport.from_dict(raw)
        with self.assertRaisesRegex(
            QualificationError, "does not match current artifacts"
        ):
            self.assess(onboarding=stale)

    def test_incomplete_component_chain_fails_closed(self) -> None:
        component_raw = self.components.to_dict()
        component_raw["components"].pop()
        components = CandidateComponentCatalog.from_dict(
            component_raw, self.blueprints
        )
        onboarding = assess_candidate_onboarding(
            self.registry,
            self.capabilities,
            self.standard,
            self.plans,
            self.blueprints,
            components,
            self.candidates,
        )
        raw = self.submission.to_dict()
        raw["candidate_component_catalog"]["sha256"] = (
            components.canonical_sha256
        )
        raw["candidate_onboarding_report"] = {
            "report_id": onboarding.report_id,
            "sha256": onboarding.report_sha256,
        }
        rebind_submission(raw)
        with self.assertRaisesRegex(
            QualificationError, "component binding is incomplete"
        ):
            self.assess(
                components=components,
                onboarding=onboarding,
                submission=self.submission_from(raw),
            )

    def test_fixture_mode_cannot_claim_authoritative_inputs(self) -> None:
        for field, value, message in (
            ("advisory_only", False, "must be advisory_only"),
            (
                "reviewer_assignment_state",
                "complete",
                "must be not_performed",
            ),
            (
                "evidence_manifest_state",
                "provided",
                "must be not_provided",
            ),
        ):
            with self.subTest(field=field):
                raw = self.submission.to_dict()
                raw[field] = value
                rebind_submission(raw)
                with self.assertRaisesRegex(QualificationError, message):
                    self.submission_from(raw)

    def test_report_rejects_tampering(self) -> None:
        document = self.assess().to_dict()
        document["authoritative_evaluation_eligible"] = True
        with self.assertRaisesRegex(QualificationError, "hash is invalid"):
            CandidateEvaluationPreflightReport.from_dict(document)

    def test_preflight_does_not_mutate_inputs(self) -> None:
        before_registry = self.registry.to_dict()
        before_submission = self.submission.to_dict()
        before_onboarding = self.onboarding.to_dict()
        self.assess()
        self.assertEqual(self.registry.to_dict(), before_registry)
        self.assertEqual(self.submission.to_dict(), before_submission)
        self.assertEqual(self.onboarding.to_dict(), before_onboarding)

    def test_modules_have_no_network_or_execution_dependencies(self) -> None:
        for path in (
            ROOT / "src" / "sunderkey" / "candidate_preflight.py",
            ROOT / "scripts" / "build_candidate_evaluation_submission.py",
        ):
            with self.subTest(path=path.name):
                tree = ast.parse(path.read_text(encoding="utf-8"))
                imported = {
                    alias.name.split(".")[0]
                    for node in ast.walk(tree)
                    if isinstance(node, ast.Import)
                    for alias in node.names
                }
                imported.update(
                    node.module.split(".")[0]
                    for node in ast.walk(tree)
                    if isinstance(node, ast.ImportFrom)
                    and node.module is not None
                    and not node.level
                )
                self.assertTrue(
                    {
                        "http",
                        "requests",
                        "socket",
                        "subprocess",
                        "urllib",
                    }.isdisjoint(imported)
                )


if __name__ == "__main__":
    unittest.main()
