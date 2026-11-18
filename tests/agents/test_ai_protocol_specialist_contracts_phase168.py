import ast
import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover
    Draft202012Validator = None

from sunderkey.ai_protocol_specialist_contracts import (
    AdapterDisposition,
    AIProtocolSpecialistContractError,
    AssessmentBudget,
    AssessmentOutcome,
    AssessmentScenario,
    ReceiptStatus,
    SafeSyntheticFixture,
    SpecialistAssessmentContext,
    SpecialistAssessmentObservation,
    SpecialistAssessmentRequest,
    SpecialistFamily,
    canonical_json,
    canonical_sha256,
    dispatch_specialist_assessment,
    parse_contract,
    recommended_capability_declarations,
)

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "src" / "sunderkey" / "ai_protocol_specialist_contracts.py"
SCHEMA = ROOT / "registry" / "schemas" / "ai-protocol-specialist-contract-v1.schema.json"
DOC = ROOT / "docs" / "ai-protocol-specialist-contracts.md"
FILES = (MODULE, SCHEMA, DOC, Path(__file__))


def digest(label: str) -> str:
    return canonical_sha256({"label": label})


def context(*, context_ref: str = "contextref:primary") -> SpecialistAssessmentContext:
    return SpecialistAssessmentContext(
        tenant_ref="tenantref:example",
        context_ref=context_ref,
        context_binding_sha256=digest("context"),
        scope_ref="scoperef:approved",
        scope_sha256=digest("scope"),
        model_ref="modelref:synthetic-model-manifest",
        model_sha256=digest("model"),
        tool_policy_ref="toolref:no-execution-policy",
        tool_policy_sha256=digest("tool-policy"),
        corpus_ref="corpusref:synthetic-corpus",
        corpus_sha256=digest("corpus"),
        session_ref="sessionref:assessment",
        agent_identity_ref="agentref:specialist",
        agent_identity_sha256=digest("agent"),
        delegation_ref="delegationref:approved-chain",
        delegation_sha256=digest("delegation"),
        protocol_ref="protocolref:synthetic-state-machine",
        protocol_state_sha256=digest("protocol-state"),
        evidence_plan_ref="evidenceref:digest-only",
        evidence_plan_sha256=digest("evidence-plan"),
        action_admission_ref="admissionref:repository-only",
        action_admission_sha256=digest("admission"),
        budget=AssessmentBudget(
            budget_ref="budgetref:synthetic",
            maximum_adapter_requests=8,
            maximum_observed_bytes=4096,
            maximum_observed_tokens=1024,
            maximum_duration_seconds=60,
        ),
    )


def request(
    *,
    family: SpecialistFamily = SpecialistFamily.AI_APPLICATION,
    scenario: AssessmentScenario = AssessmentScenario.PROMPT_CONTEXT_BOUNDARY,
    selected_context: SpecialistAssessmentContext | None = None,
) -> SpecialistAssessmentRequest:
    declaration = next(
        item for item in recommended_capability_declarations() if item.family is family
    )
    return SpecialistAssessmentRequest(
        declaration_id=declaration.declaration_id,
        declaration_sha256=declaration.declaration_sha256,
        family=family,
        capability_ref=declaration.capability_ref,
        scenario=scenario,
        context=selected_context or context(),
        fixture=SafeSyntheticFixture(
            fixture_ref="fixtureref:boundary-case-001",
            fixture_manifest_sha256=digest("fixture-manifest"),
        ),
        expected_control_sha256=digest("expected-control"),
        estimated_adapter_requests=2,
        estimated_observed_bytes=2048,
        estimated_observed_tokens=512,
        estimated_duration_seconds=30,
        idempotency_sha256=digest("idempotency"),
        issued_at="2026-09-20T10:00:00Z",
        expires_at="2026-09-20T10:10:00Z",
    )


def observation(
    selected_request: SpecialistAssessmentRequest,
    *,
    outcome: AssessmentOutcome = AssessmentOutcome.PASS,
) -> SpecialistAssessmentObservation:
    return SpecialistAssessmentObservation(
        request_id=selected_request.request_id,
        request_sha256=selected_request.request_sha256,
        assessment_context_sha256=selected_request.context.assessment_context_sha256,
        fixture_sha256=selected_request.fixture.fixture_sha256,
        disposition=AdapterDisposition.COMPLETED,
        outcome=outcome,
        evidence_sha256=digest("evidence"),
        actual_adapter_requests=1,
        actual_observed_bytes=1024,
        actual_observed_tokens=256,
        actual_duration_seconds=10,
        network_call_performed=False,
        provider_call_performed=False,
        model_execution_performed=False,
        tool_execution_performed=False,
        raw_secret_observed=False,
        live_target_data_observed=False,
        started_at="2026-09-20T10:01:00Z",
        completed_at="2026-09-20T10:01:10Z",
    )


class RecordingAdapter:
    def __init__(self, selected_observation: SpecialistAssessmentObservation):
        self.selected_observation = selected_observation
        self.calls: list[SpecialistAssessmentRequest] = []

    def assess(self, selected_request: SpecialistAssessmentRequest):
        self.calls.append(selected_request)
        return self.selected_observation


class AIProtocolSpecialistContractsPhase168Tests(unittest.TestCase):
    def test_recommended_declarations_cover_all_families_and_scenarios(self):
        declarations = recommended_capability_declarations()
        self.assertEqual({item.family for item in declarations}, set(SpecialistFamily))
        covered = {scenario for item in declarations for scenario in item.scenarios}
        self.assertEqual(covered, set(AssessmentScenario))
        self.assertEqual(len(declarations), 6)

    def test_records_are_deterministic_and_parseable(self):
        selected_request = request()
        declaration = recommended_capability_declarations()[0]
        self.assertEqual(request().to_dict(), selected_request.to_dict())
        self.assertEqual(parse_contract(declaration.to_dict()), declaration.to_dict())
        self.assertEqual(parse_contract(selected_request.to_dict()), selected_request.to_dict())

    def test_safe_fixture_rejects_real_or_harmful_material_flags(self):
        for changes in (
            {"synthetic": False},
            {"contains_real_credentials": True},
            {"contains_live_target_data": True},
            {"contains_harmful_payload_body": True},
        ):
            with (
                self.subTest(changes=changes),
                self.assertRaises(AIProtocolSpecialistContractError),
            ):
                SafeSyntheticFixture(
                    fixture_ref="fixtureref:unsafe",
                    fixture_manifest_sha256=digest("fixture"),
                    **changes,
                )

    def test_raw_secret_patterns_are_rejected(self):
        with self.assertRaises(AIProtocolSpecialistContractError):
            canonical_json({"credential": "password=not-allowed"})

    def test_cross_context_fails_before_adapter_invocation(self):
        selected_request = request()
        adapter = RecordingAdapter(observation(selected_request))
        with self.assertRaises(AIProtocolSpecialistContractError):
            dispatch_specialist_assessment(
                selected_request,
                recommended_capability_declarations()[0],
                context(context_ref="contextref:foreign"),
                adapter,
                evaluated_at=datetime(2026, 9, 20, 10, 1, tzinfo=UTC),
            )
        self.assertEqual(adapter.calls, [])

    def test_stale_future_and_replay_requests_fail_before_adapter(self):
        selected_request = request()
        declaration = recommended_capability_declarations()[0]
        scenarios = (
            {"evaluated_at": datetime(2026, 9, 20, 9, 59, tzinfo=UTC)},
            {"evaluated_at": datetime(2026, 9, 20, 10, 11, tzinfo=UTC)},
            {
                "evaluated_at": datetime(2026, 9, 20, 10, 1, tzinfo=UTC),
                "seen_request_ids": (selected_request.request_id,),
            },
            {
                "evaluated_at": datetime(2026, 9, 20, 10, 1, tzinfo=UTC),
                "seen_idempotency_sha256": (selected_request.idempotency_sha256,),
            },
        )
        for values in scenarios:
            adapter = RecordingAdapter(observation(selected_request))
            with self.subTest(values=values), self.assertRaises(AIProtocolSpecialistContractError):
                dispatch_specialist_assessment(
                    selected_request,
                    declaration,
                    selected_request.context,
                    adapter,
                    **values,
                )
            self.assertEqual(adapter.calls, [])

    def test_wrong_declaration_fails_before_adapter(self):
        selected_request = request()
        adapter = RecordingAdapter(observation(selected_request))
        with self.assertRaises(AIProtocolSpecialistContractError):
            dispatch_specialist_assessment(
                selected_request,
                recommended_capability_declarations()[1],
                selected_request.context,
                adapter,
                evaluated_at=datetime(2026, 9, 20, 10, 1, tzinfo=UTC),
            )
        self.assertEqual(adapter.calls, [])

    def test_cross_family_scenario_is_rejected(self):
        with self.assertRaises(AIProtocolSpecialistContractError):
            request(
                family=SpecialistFamily.MODEL_SUPPLY_CHAIN,
                scenario=AssessmentScenario.TOOL_AUTHORIZATION,
            )

    def test_adapter_observation_must_match_all_bindings(self):
        selected_request = request()
        wrong = replace(observation(selected_request), evidence_sha256=digest("other"))
        wrong = replace(wrong, fixture_sha256=digest("wrong-fixture"))
        adapter = RecordingAdapter(wrong)
        with self.assertRaises(AIProtocolSpecialistContractError):
            dispatch_specialist_assessment(
                selected_request,
                recommended_capability_declarations()[0],
                selected_request.context,
                adapter,
                evaluated_at=datetime(2026, 9, 20, 10, 1, tzinfo=UTC),
            )
        self.assertEqual(len(adapter.calls), 1)

    def test_adapter_boundary_effects_fail_closed(self):
        selected_request = request()
        for field_name in (
            "network_call_performed",
            "provider_call_performed",
            "model_execution_performed",
            "tool_execution_performed",
            "raw_secret_observed",
            "live_target_data_observed",
        ):
            with (
                self.subTest(field_name=field_name),
                self.assertRaises(AIProtocolSpecialistContractError),
            ):
                replace(observation(selected_request), **{field_name: True})

    def test_adapter_cannot_exceed_estimate_or_budget(self):
        selected_request = request()
        adapter = RecordingAdapter(
            replace(observation(selected_request), actual_observed_tokens=513)
        )
        with self.assertRaises(AIProtocolSpecialistContractError):
            dispatch_specialist_assessment(
                selected_request,
                recommended_capability_declarations()[0],
                selected_request.context,
                adapter,
                evaluated_at=datetime(2026, 9, 20, 10, 1, tzinfo=UTC),
            )

    def test_control_gap_is_a_completed_nonqualifying_receipt(self):
        selected_request = request()
        receipt = dispatch_specialist_assessment(
            selected_request,
            recommended_capability_declarations()[0],
            selected_request.context,
            RecordingAdapter(observation(selected_request, outcome=AssessmentOutcome.CONTROL_GAP)),
            evaluated_at=datetime(2026, 9, 20, 10, 1, tzinfo=UTC),
        )
        self.assertEqual(receipt.status, ReceiptStatus.COMPLETED)
        self.assertEqual(receipt.observation.outcome, AssessmentOutcome.CONTROL_GAP)
        self.assertEqual(receipt.to_dict()["qualification_effect"], "none")

    def test_tampering_is_rejected_by_parser(self):
        record = request().to_dict()
        record["estimated_observed_tokens"] = 511
        with self.assertRaises(AIProtocolSpecialistContractError):
            parse_contract(record)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_schema_accepts_all_wire_records(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        declaration = recommended_capability_declarations()[0]
        selected_request = request()
        receipt = dispatch_specialist_assessment(
            selected_request,
            declaration,
            selected_request.context,
            RecordingAdapter(observation(selected_request)),
            evaluated_at=datetime(2026, 9, 20, 10, 1, tzinfo=UTC),
        )
        for record in (declaration.to_dict(), selected_request.to_dict(), receipt.to_dict()):
            errors = list(validator.iter_errors(record))
            self.assertEqual(errors, [], errors)

    def test_module_has_no_execution_or_network_imports(self):
        tree = ast.parse(MODULE.read_text(encoding="utf-8"))
        imports = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports.update(
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        )
        self.assertTrue(
            imports.isdisjoint({"requests", "httpx", "urllib", "socket", "subprocess", "openai"})
        )

    def test_increment_has_no_forbidden_unicode(self):
        for path in FILES:
            content = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2013", content, path)
            self.assertNotIn("\u2014", content, path)

    def test_public_package_exports_specialist_boundary(self):
        import sunderkey

        self.assertIs(sunderkey.AiProtocolAssessmentRequest, SpecialistAssessmentRequest)
        self.assertIs(
            sunderkey.dispatch_ai_protocol_specialist_assessment,
            dispatch_specialist_assessment,
        )
        self.assertIs(sunderkey.parse_ai_protocol_specialist_contract, parse_contract)
        self.assertIs(
            sunderkey.ai_protocol_specialist_capabilities,
            recommended_capability_declarations,
        )


if __name__ == "__main__":
    unittest.main()
