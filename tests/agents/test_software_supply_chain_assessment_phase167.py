from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover
    Draft202012Validator = None

from sunderkey.software_supply_chain_assessment import (
    NO_EFFECTS,
    ActionTier,
    AdapterRequest,
    AdapterSpec,
    AssessmentBudgets,
    AssessmentContext,
    AssessmentReport,
    EvidenceKind,
    FindingKind,
    GraphEdge,
    GraphNode,
    NodeKind,
    RelationKind,
    SupplyChainAssessmentError,
    analyze_supply_chain,
    build_adapter_result,
    build_assessment_plan,
    build_evidence_record,
    canonical_json,
    import_evidence,
    parse_assessment_report,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "registry" / "schemas" / "software-supply-chain-assessment-v1.schema.json"
SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
SHA_C = "sha256:" + "c" * 64
SHA_D = "sha256:" + "d" * 64
SHA_E = "sha256:" + "e" * 64
SHA_F = "sha256:" + "f" * 64


class FakeAdapter:
    def __init__(self, factory):
        self.factory = factory
        self.calls: list[AdapterRequest] = []

    def collect(self, request: AdapterRequest):
        self.calls.append(request)
        return self.factory(request)


def context(tenant: str = "tenant:one", context_id: str = "context:assessment"):
    return AssessmentContext(
        tenant_id=tenant,
        context_id=context_id,
        repository_ref="repository:sunderkey",
        revision_sha256=SHA_A,
        build_ref="build:2026-09-20",
        scope_binding_sha256=SHA_B,
    )


def spec(
    adapter_id: str = "adapter:manifest",
    kinds: tuple[EvidenceKind, ...] = tuple(EvidenceKind),
    limit: int = 20,
):
    return AdapterSpec(
        adapter_id=adapter_id,
        adapter_version="v1",
        evidence_source_ref="evidence:approved-export",
        evidence_kinds=kinds,
        record_limit=limit,
    )


def plan(*specs: AdapterSpec, tenant_context=None, budgets=None, key: str = SHA_C):
    return build_assessment_plan(
        tenant_context or context(),
        specs or (spec(),),
        planned_at="2026-09-20T10:00:00Z",
        valid_until="2026-09-20T14:00:00Z",
        idempotency_key_sha256=key,
        budgets=budgets,
    )


def node(
    key: str,
    kind: NodeKind,
    subject: str,
    *,
    boundary: str = "boundary:build",
    exposure: str = "internal",
    integrity: str | None = SHA_D,
):
    return GraphNode(
        node_key_sha256=key,
        node_kind=kind,
        subject_ref=subject,
        trust_boundary_ref=boundary,
        exposure=exposure,
        integrity_sha256=integrity,
    )


def record(
    request: AdapterRequest,
    *,
    sequence: int = 0,
    kind: EvidenceKind = EvidenceKind.SBOM,
    nodes=(),
    edges=(),
    fresh_until: str = "2026-09-21T10:00:00Z",
):
    return build_evidence_record(
        request,
        sequence=sequence,
        evidence_kind=kind,
        evidence_ref=f"evidence:record-{sequence}",
        content_sha256=SHA_E,
        observed_at="2026-09-20T10:05:00Z",
        fresh_until=fresh_until,
        nodes=nodes,
        edges=edges,
    )


def import_batch(assessment_plan, factory, *, seen=()):
    adapters = {item.adapter_id: FakeAdapter(factory) for item in assessment_plan.adapters}
    batch = import_evidence(
        assessment_plan,
        adapters,
        imported_at="2026-09-20T10:30:00Z",
        seen_record_sha256s=seen,
    )
    return batch, adapters


class SoftwareSupplyChainAssessmentTests(unittest.TestCase):
    def test_plan_is_canonical_bounded_r0_and_effect_free(self) -> None:
        first = spec("adapter:source", (EvidenceKind.SOURCE_MANIFEST,), 3)
        second = spec("adapter:provenance", (EvidenceKind.BUILD_PROVENANCE,), 4)
        left = plan(first, second)
        right = plan(second, first)
        self.assertEqual(left.plan_sha256, right.plan_sha256)
        self.assertEqual(dict(left.no_effects), NO_EFFECTS)
        self.assertTrue(all(item.required_action_tier is ActionTier.R0 for item in left.adapters))
        self.assertEqual(left.qualification_effect, "none")

        with self.assertRaisesRegex(SupplyChainAssessmentError, "max_records"):
            plan(
                spec("adapter:a", (EvidenceKind.SBOM,), 2),
                spec("adapter:b", (EvidenceKind.SBOM,), 2),
                budgets=AssessmentBudgets(max_records=3),
            )
        with self.assertRaisesRegex(SupplyChainAssessmentError, "require R0"):
            replace(first, required_action_tier=ActionTier.R1)

    def test_all_evidence_families_are_admitted_by_reference_only(self) -> None:
        assessment_plan = plan()

        def factory(request):
            records = []
            for sequence, kind in enumerate(EvidenceKind):
                graph_node = node(
                    f"sha256:{sequence + 1:064x}",
                    NodeKind.SOURCE,
                    f"subject:item-{sequence}",
                )
                records.append(record(request, sequence=sequence, kind=kind, nodes=(graph_node,)))
            return build_adapter_result(request, records)

        batch, adapters = import_batch(assessment_plan, factory)
        self.assertEqual({item.evidence_kind for item in batch.records}, set(EvidenceKind))
        self.assertEqual(len(adapters["adapter:manifest"].calls), 1)
        self.assertEqual(batch.evidence_level, "repository_only")
        self.assertEqual(batch.operational_status, "nonqualified")
        self.assertEqual(batch.qualification_effect, "none")

    def test_dependency_provenance_boundaries_exposure_and_proposals(self) -> None:
        assessment_plan = plan()

        source = node(SHA_A, NodeKind.SOURCE, "subject:source", boundary="boundary:source")
        dependency = node(
            SHA_B,
            NodeKind.DEPENDENCY,
            "subject:dependency",
            boundary="boundary:external",
            integrity=None,
        )
        pipeline = node(
            SHA_C,
            NodeKind.PIPELINE,
            "subject:pipeline",
            exposure="public",
            integrity=None,
        )
        image = node(SHA_D, NodeKind.IMAGE, "subject:image")
        provenance = node(SHA_E, NodeKind.PROVENANCE, "subject:provenance", integrity=None)
        artifact = node(SHA_F, NodeKind.ARTIFACT, "subject:artifact")
        edges = (
            GraphEdge(SHA_A, SHA_B, RelationKind.DEPENDS_ON),
            GraphEdge(SHA_C, SHA_D, RelationKind.PRODUCES),
            GraphEdge(SHA_E, SHA_D, RelationKind.DERIVED_FROM),
        )

        def factory(request):
            evidence = record(
                request,
                nodes=(source, dependency, pipeline, image, provenance, artifact),
                edges=edges,
            )
            return build_adapter_result(request, (evidence,))

        batch, _ = import_batch(assessment_plan, factory)
        report = analyze_supply_chain(batch, generated_at="2026-09-20T11:00:00Z")
        kinds = {item.finding_kind for item in report.findings}
        self.assertTrue(
            {
                FindingKind.UNPINNED_DEPENDENCY,
                FindingKind.UNVERIFIED_BUILD_PROVENANCE,
                FindingKind.MISSING_ARTIFACT_PROVENANCE,
                FindingKind.CROSS_BOUNDARY_FLOW,
                FindingKind.PUBLIC_BUILD_EXPOSURE,
            }.issubset(kinds)
        )
        self.assertEqual(
            [item.priority for item in report.findings],
            sorted(item.priority for item in report.findings),
        )
        self.assertTrue(all(item.status == "proposal_only" for item in report.candidate_plans))
        self.assertTrue(
            all(item.minimum_action_tier is ActionTier.R1 for item in report.candidate_plans)
        )
        self.assertTrue(all(item.separate_admission_required for item in report.candidate_plans))
        self.assertTrue(
            all(
                not item.network_access_permitted
                and not item.command_execution_permitted
                and not item.repository_mutation_permitted
                and not item.registry_contact_permitted
                for item in report.candidate_plans
            )
        )

    def test_freshness_creates_r0_refresh_proposal(self) -> None:
        assessment_plan = plan()

        def factory(request):
            stale = record(
                request,
                nodes=(node(SHA_A, NodeKind.SOURCE, "subject:source"),),
                fresh_until="2026-09-20T10:20:00Z",
            )
            return build_adapter_result(request, (stale,))

        batch, _ = import_batch(assessment_plan, factory)
        report = analyze_supply_chain(batch, generated_at="2026-09-20T11:00:00Z")
        stale = next(
            item for item in report.findings if item.finding_kind is FindingKind.STALE_EVIDENCE
        )
        proposal = next(
            item for item in report.candidate_plans if item.finding_id == stale.finding_id
        )
        self.assertEqual(proposal.minimum_action_tier, ActionTier.R0)
        self.assertEqual(proposal.plan_kind, "refresh_passive_evidence")

    def test_cross_tenant_context_revision_build_and_scope_results_are_rejected(self) -> None:
        assessment_plan = plan()

        def valid_result(request):
            evidence = record(request, nodes=(node(SHA_A, NodeKind.SOURCE, "subject:source"),))
            return build_adapter_result(request, (evidence,))

        valid = valid_result(assessment_plan.request_for("adapter:manifest"))
        substitutions = {
            "tenant_id": "tenant:other",
            "context_id": "context:other",
            "repository_ref": "repository:other",
            "revision_sha256": SHA_F,
            "build_ref": "build:other",
            "scope_binding_sha256": SHA_F,
        }
        for field, value in substitutions.items():
            with self.subTest(field=field):
                injected = FakeAdapter(lambda _request, f=field, v=value: replace(valid, **{f: v}))
                with self.assertRaisesRegex(SupplyChainAssessmentError, "binding mismatch"):
                    import_evidence(
                        assessment_plan,
                        {"adapter:manifest": injected},
                        imported_at="2026-09-20T10:30:00Z",
                    )
                self.assertEqual(len(injected.calls), 1)

    def test_replay_tamper_and_conflicting_node_claims_fail_closed(self) -> None:
        assessment_plan = plan()

        def factory(request):
            evidence = record(request, nodes=(node(SHA_A, NodeKind.SOURCE, "subject:source"),))
            return build_adapter_result(request, (evidence,))

        first, _ = import_batch(assessment_plan, factory)
        with self.assertRaisesRegex(SupplyChainAssessmentError, "replayed evidence"):
            import_batch(assessment_plan, factory, seen=(first.records[0].record_sha256,))
        with self.assertRaisesRegex(SupplyChainAssessmentError, "record identity"):
            replace(first.records[0], content_sha256=SHA_F)

        conflicting_plan = plan(
            spec("adapter:a", (EvidenceKind.SBOM,)),
            spec("adapter:b", (EvidenceKind.SBOM,)),
            key=SHA_D,
        )

        def conflict_factory(request):
            boundary = "boundary:a" if request.adapter.adapter_id == "adapter:a" else "boundary:b"
            evidence = record(
                request,
                nodes=(node(SHA_A, NodeKind.SOURCE, "subject:source", boundary=boundary),),
            )
            return build_adapter_result(request, (evidence,))

        batch, _ = import_batch(conflicting_plan, conflict_factory)
        with self.assertRaisesRegex(SupplyChainAssessmentError, "conflicting node claims"):
            analyze_supply_chain(batch, generated_at="2026-09-20T11:00:00Z")

    def test_effect_attestations_and_secret_bearing_references_are_rejected(self) -> None:
        assessment_plan = plan()
        request = assessment_plan.request_for("adapter:manifest")
        valid = build_adapter_result(request, ())
        for field in (
            "network_call_performed",
            "command_execution_performed",
            "repository_mutation_performed",
            "registry_contact_performed",
            "secret_material_returned",
        ):
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(SupplyChainAssessmentError, "must be false"),
            ):
                replace(valid, **{field: True})
        with self.assertRaisesRegex(SupplyChainAssessmentError, "secret-safe"):
            replace(spec(), evidence_source_ref="evidence:password-export")

    def test_idempotent_import_and_analysis_are_byte_stable(self) -> None:
        assessment_plan = plan()

        def factory(request):
            evidence = record(request, nodes=(node(SHA_A, NodeKind.SOURCE, "subject:source"),))
            return build_adapter_result(request, (evidence,))

        left, _ = import_batch(assessment_plan, factory)
        right, _ = import_batch(assessment_plan, factory)
        self.assertEqual(left.batch_sha256, right.batch_sha256)
        left_report = analyze_supply_chain(left, generated_at="2026-09-20T11:00:00Z")
        right_report = analyze_supply_chain(right, generated_at="2026-09-20T11:00:00Z")
        self.assertEqual(
            canonical_json(left_report.to_dict()), canonical_json(right_report.to_dict())
        )

    def test_graph_and_report_budgets_fail_closed(self) -> None:
        assessment_plan = plan(budgets=AssessmentBudgets(max_nodes=1, max_edges=1))

        def factory(request):
            evidence = record(
                request,
                nodes=(
                    node(SHA_A, NodeKind.SOURCE, "subject:source"),
                    node(SHA_B, NodeKind.DEPENDENCY, "subject:dependency"),
                ),
                edges=(GraphEdge(SHA_A, SHA_B, RelationKind.DEPENDS_ON),),
            )
            return build_adapter_result(request, (evidence,))

        batch, _ = import_batch(assessment_plan, factory)
        with self.assertRaisesRegex(SupplyChainAssessmentError, "graph exceeds"):
            analyze_supply_chain(batch, generated_at="2026-09-20T11:00:00Z")

    def test_closed_round_trip_schema_and_tamper_rejection(self) -> None:
        assessment_plan = plan()

        def factory(request):
            evidence = record(request, nodes=(node(SHA_A, NodeKind.SOURCE, "subject:source"),))
            return build_adapter_result(request, (evidence,))

        batch, _ = import_batch(assessment_plan, factory)
        report = analyze_supply_chain(batch, generated_at="2026-09-20T11:00:00Z")
        raw = report.to_dict()
        parsed = parse_assessment_report(canonical_json(raw))
        self.assertIsInstance(parsed, AssessmentReport)
        self.assertEqual(parsed.report_sha256, report.report_sha256)

        unknown = copy.deepcopy(raw)
        unknown["unexpected"] = True
        with self.assertRaisesRegex(SupplyChainAssessmentError, "fields are not exact"):
            parse_assessment_report(unknown)
        tampered = copy.deepcopy(raw)
        tampered["generated_at"] = "2026-09-20T11:01:00Z"
        with self.assertRaisesRegex(SupplyChainAssessmentError, "report identity"):
            parse_assessment_report(tampered)

        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        if Draft202012Validator is not None:
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(raw)
            self.assertTrue(list(Draft202012Validator(schema).iter_errors(unknown)))

    def test_public_package_exports_assessment_boundary(self) -> None:
        import sunderkey

        self.assertIs(sunderkey.SupplyChainAssessmentReport, AssessmentReport)
        self.assertIs(sunderkey.analyze_supply_chain, analyze_supply_chain)
        self.assertIs(
            sunderkey.build_supply_chain_assessment_plan,
            build_assessment_plan,
        )
        self.assertIs(
            sunderkey.parse_supply_chain_assessment_report,
            parse_assessment_report,
        )


if __name__ == "__main__":
    unittest.main()
