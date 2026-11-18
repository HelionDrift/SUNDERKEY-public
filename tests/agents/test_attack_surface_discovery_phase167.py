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

from sunderkey.attack_surface_discovery import (
    NO_EFFECTS,
    AttackSurfaceDiscoveryError,
    CollectorRequest,
    CollectorSpec,
    DiscoveryContext,
    DiscoveryLimits,
    DiscoveryReport,
    EntityState,
    GapKind,
    SurfaceKind,
    TemporalChange,
    build_collector_observation,
    build_collector_result,
    build_discovery_plan,
    canonical_json,
    correlate_attack_surface,
    execute_discovery_plan,
    parse_discovery_report,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "registry" / "schemas" / "attack-surface-discovery-report-v1.schema.json"
SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
SHA_C = "sha256:" + "c" * 64
SHA_D = "sha256:" + "d" * 64
SHA_E = "sha256:" + "e" * 64


class FakeCollector:
    def __init__(self, factory):
        self.factory = factory
        self.calls: list[CollectorRequest] = []

    def collect(self, request: CollectorRequest):
        self.calls.append(request)
        return self.factory(request)


def context(tenant: str = "tenant:one", context_id: str = "context:alpha"):
    return DiscoveryContext(
        tenant_id=tenant,
        context_id=context_id,
        scope_binding_sha256=SHA_A,
        owner_refs=("owner:security",),
        scope_refs=("scope:authorized",),
    )


def spec(
    collector_id: str = "collector:inventory",
    kinds: tuple[SurfaceKind, ...] = tuple(SurfaceKind),
    limit: int = 100,
):
    return CollectorSpec(
        collector_id=collector_id,
        collector_version="v1",
        evidence_source_ref="evidence:approved-export",
        surface_kinds=kinds,
        record_limit=limit,
    )


def plan(
    *specs: CollectorSpec,
    tenant_context: DiscoveryContext | None = None,
    nonce: str = SHA_B,
    limits: DiscoveryLimits | None = None,
):
    return build_discovery_plan(
        tenant_context or context(),
        specs or (spec(),),
        planned_at="2026-09-20T10:00:00Z",
        valid_until="2026-09-20T14:00:00Z",
        run_nonce_sha256=nonce,
        limits=limits,
    )


def observation(
    request: CollectorRequest,
    sequence: int,
    kind: SurfaceKind,
    *,
    native: str | None = None,
    asset: str | None = None,
    service: str | None = SHA_C,
    endpoint: str | None = SHA_D,
    content: str = SHA_E,
    provenance: str = SHA_A,
    observed_at: str = "2026-09-20T10:15:00Z",
    expires_at: str = "2026-09-21T10:15:00Z",
    confidence: int = 80,
    owners: tuple[str, ...] = ("owner:application",),
    scopes: tuple[str, ...] = ("scope:authorized",),
):
    return build_collector_observation(
        request,
        sequence=sequence,
        surface_kind=kind,
        native_key_sha256=native or f"sha256:{sequence + 1:064x}",
        asset_key_sha256=asset or f"sha256:{sequence + 101:064x}",
        service_key_sha256=service,
        endpoint_key_sha256=endpoint,
        content_sha256=content,
        provenance_sha256=provenance,
        observed_at=observed_at,
        freshness_expires_at=expires_at,
        confidence=confidence,
        owner_refs=owners,
        scope_refs=scopes,
    )


def run_plan(discovery_plan, factory, collected_at="2026-09-20T10:30:00Z"):
    collectors = {item.collector_id: FakeCollector(factory) for item in discovery_plan.collectors}
    return execute_discovery_plan(
        discovery_plan,
        collectors,
        collected_at=collected_at,
    )


class AttackSurfaceDiscoveryTests(unittest.TestCase):
    def test_plan_is_canonical_bounded_and_effect_free(self) -> None:
        second = spec("collector:code", (SurfaceKind.CODE,), 5)
        first = spec("collector:web", (SurfaceKind.WEB,), 5)
        left = plan(first, second)
        right = plan(second, first)
        self.assertEqual(left.plan_sha256, right.plan_sha256)
        self.assertEqual(dict(left.no_effects), NO_EFFECTS)
        self.assertEqual(left.qualification_effect, "none")
        self.assertTrue(all(item.passive_only for item in left.collectors))

        with self.assertRaisesRegex(AttackSurfaceDiscoveryError, "max_observations"):
            plan(
                spec("collector:a", (SurfaceKind.API,), 2),
                spec("collector:b", (SurfaceKind.WEB,), 2),
                limits=DiscoveryLimits(max_observations=3),
            )

    def test_all_surface_families_resolve_to_assets_services_and_endpoints(self) -> None:
        discovery_plan = plan()

        def factory(request):
            values = []
            for sequence, kind in enumerate(SurfaceKind):
                values.append(observation(request, sequence, kind))
            return build_collector_result(request, values)

        batch = run_plan(discovery_plan, factory)
        report = correlate_attack_surface(batch, generated_at="2026-09-20T11:00:00Z")
        self.assertEqual(
            {kind for asset in report.assets for kind in asset.surface_kinds},
            set(SurfaceKind),
        )
        self.assertEqual(len(report.assets), 7)
        self.assertEqual(len(report.services), 7)
        self.assertEqual(len(report.endpoints), 7)
        self.assertEqual(report.evidence_level, "repository_only")
        self.assertEqual(report.operational_status, "nonqualified")
        self.assertEqual(report.qualification_effect, "none")

    def test_import_is_content_addressed_and_collector_order_independent(self) -> None:
        specs = (
            spec("collector:web", (SurfaceKind.WEB,), 3),
            spec("collector:api", (SurfaceKind.API,), 3),
        )
        discovery_plan = plan(*specs)

        def factory(request):
            kind = request.collector.surface_kinds[0]
            item = observation(
                request,
                0,
                kind,
                asset=SHA_B if kind is SurfaceKind.API else SHA_C,
            )
            return build_collector_result(request, (item,))

        collectors = {item.collector_id: FakeCollector(factory) for item in reversed(specs)}
        first = execute_discovery_plan(
            discovery_plan,
            collectors,
            collected_at="2026-09-20T10:30:00Z",
        )
        second = execute_discovery_plan(
            discovery_plan,
            {item.collector_id: FakeCollector(factory) for item in specs},
            collected_at="2026-09-20T10:30:00Z",
        )
        self.assertEqual(first.batch_sha256, second.batch_sha256)
        self.assertEqual(canonical_json(first.to_dict()), canonical_json(second.to_dict()))

    def test_cross_tenant_context_and_request_substitution_are_rejected(self) -> None:
        primary = plan()
        foreign = plan(tenant_context=context("tenant:two", "context:beta"), nonce=SHA_C)
        foreign_request = foreign.request_for("collector:inventory")
        foreign_result = build_collector_result(
            foreign_request,
            (observation(foreign_request, 0, SurfaceKind.WEB),),
        )
        injected = FakeCollector(lambda _request: foreign_result)
        with self.assertRaisesRegex(AttackSurfaceDiscoveryError, "binding mismatch"):
            execute_discovery_plan(
                primary,
                {"collector:inventory": injected},
                collected_at="2026-09-20T10:30:00Z",
            )
        self.assertEqual(len(injected.calls), 1)

    def test_replayed_observations_and_results_fail_closed(self) -> None:
        discovery_plan = plan()

        def factory(request):
            item = observation(request, 0, SurfaceKind.API)
            return build_collector_result(request, (item,))

        batch = run_plan(discovery_plan, factory)
        with self.assertRaisesRegex(AttackSurfaceDiscoveryError, "replayed observation"):
            execute_discovery_plan(
                discovery_plan,
                {"collector:inventory": FakeCollector(factory)},
                collected_at="2026-09-20T10:31:00Z",
                seen_observation_sha256s=(batch.observations[0].observation_sha256,),
            )
        result = factory(discovery_plan.request_for("collector:inventory"))
        with self.assertRaisesRegex(AttackSurfaceDiscoveryError, "sequences|replayed observation"):
            replace(result, observations=(result.observations[0], result.observations[0]))

    def test_active_network_or_credential_attestations_are_rejected(self) -> None:
        discovery_plan = plan()
        request = discovery_plan.request_for("collector:inventory")
        result = build_collector_result(
            request,
            (observation(request, 0, SurfaceKind.NETWORK),),
        )
        for field in (
            "network_call_performed",
            "active_scan_performed",
            "credential_material_returned",
        ):
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(AttackSurfaceDiscoveryError, "must be false"),
            ):
                replace(result, **{field: True})

    def test_stale_low_confidence_and_missing_associations_create_gaps(self) -> None:
        discovery_plan = plan()

        def factory(request):
            stale = observation(
                request,
                0,
                SurfaceKind.WEB,
                expires_at="2026-09-20T10:20:00Z",
                confidence=25,
                owners=(),
                scopes=(),
            )
            return build_collector_result(request, (stale,))

        report = correlate_attack_surface(
            run_plan(discovery_plan, factory),
            generated_at="2026-09-20T11:00:00Z",
        )
        self.assertEqual(report.assets[0].state, EntityState.STALE)
        gap_kinds = {item.gap_kind for item in report.gaps}
        self.assertTrue(
            {
                GapKind.STALE_EVIDENCE,
                GapKind.LOW_CONFIDENCE,
                GapKind.MISSING_OWNERSHIP,
                GapKind.MISSING_SCOPE,
            }.issubset(gap_kinds)
        )
        self.assertEqual(
            [item.priority for item in report.gaps],
            sorted(item.priority for item in report.gaps),
        )
        self.assertTrue(
            all(
                item.status == "proposal_only"
                and not item.active_scan_permitted
                and not item.network_access_permitted
                for item in report.revalidation_plans
            )
        )

    def test_conflicting_identity_ownership_and_scope_claims_are_preserved(self) -> None:
        discovery_plan = plan()

        def factory(request):
            first = observation(
                request,
                0,
                SurfaceKind.CLOUD,
                native=SHA_A,
                asset=SHA_B,
                confidence=90,
                owners=("owner:a",),
                scopes=("scope:a",),
            )
            second = observation(
                request,
                1,
                SurfaceKind.IDENTITY,
                native=SHA_A,
                asset=SHA_C,
                confidence=40,
                owners=("owner:b",),
                scopes=("scope:b",),
            )
            third = observation(
                request,
                2,
                SurfaceKind.CLOUD,
                native=SHA_D,
                asset=SHA_B,
                confidence=60,
                owners=("owner:c",),
                scopes=("scope:c",),
            )
            return build_collector_result(request, (first, second, third))

        report = correlate_attack_surface(
            run_plan(discovery_plan, factory),
            generated_at="2026-09-20T11:00:00Z",
        )
        conflict_kinds = {item.conflict_kind for item in report.conflicts}
        self.assertIn("native_key_multiple_assets", conflict_kinds)
        self.assertIn("ownership_claim_conflict", conflict_kinds)
        self.assertIn("scope_claim_conflict", conflict_kinds)
        self.assertTrue(any(item.state is EntityState.CONFLICTED for item in report.assets))
        self.assertIn(GapKind.IDENTITY_CONFLICT, {item.gap_kind for item in report.gaps})

    def test_temporal_links_capture_changes_and_missing_entities(self) -> None:
        first_plan = plan(nonce=SHA_B)

        def initial(request):
            return build_collector_result(
                request,
                (
                    observation(request, 0, SurfaceKind.API, asset=SHA_B, content=SHA_C),
                    observation(request, 1, SurfaceKind.CODE, asset=SHA_D, content=SHA_C),
                ),
            )

        first_report = correlate_attack_surface(
            run_plan(first_plan, initial),
            generated_at="2026-09-20T11:00:00Z",
        )
        second_plan = plan(nonce=SHA_C)

        def updated(request):
            return build_collector_result(
                request,
                (observation(request, 0, SurfaceKind.API, asset=SHA_B, content=SHA_D),),
            )

        second_report = correlate_attack_surface(
            run_plan(second_plan, updated, "2026-09-20T12:00:00Z"),
            generated_at="2026-09-20T12:30:00Z",
            prior_report=first_report,
        )
        changes = {item.change for item in second_report.temporal_links}
        self.assertIn(TemporalChange.CHANGED, changes)
        self.assertIn(TemporalChange.MISSING, changes)
        self.assertIn(GapKind.TEMPORAL_MISSING, {item.gap_kind for item in second_report.gaps})

        with self.assertRaisesRegex(AttackSurfaceDiscoveryError, "replay"):
            correlate_attack_surface(
                run_plan(first_plan, initial),
                generated_at="2026-09-20T13:00:00Z",
                prior_report=first_report,
            )

    def test_record_and_entity_limits_fail_closed(self) -> None:
        limited_plan = plan(spec(limit=1))

        def too_many(request):
            return build_collector_result(
                request,
                (
                    observation(request, 0, SurfaceKind.WEB),
                    observation(request, 1, SurfaceKind.API),
                ),
            )

        with self.assertRaisesRegex(AttackSurfaceDiscoveryError, "record limit"):
            run_plan(limited_plan, too_many)

        asset_limited = plan(
            spec(limit=5),
            limits=DiscoveryLimits(max_assets=1, max_observations=5),
        )
        batch = run_plan(asset_limited, too_many)
        with self.assertRaisesRegex(AttackSurfaceDiscoveryError, "max_assets"):
            correlate_attack_surface(batch, generated_at="2026-09-20T11:00:00Z")

    def test_serialization_rejects_tamper_and_unknown_fields(self) -> None:
        discovery_plan = plan()

        def factory(request):
            return build_collector_result(
                request,
                (observation(request, 0, SurfaceKind.THIRD_PARTY),),
            )

        report = correlate_attack_surface(
            run_plan(discovery_plan, factory),
            generated_at="2026-09-20T11:00:00Z",
        )
        restored = parse_discovery_report(report.to_dict())
        self.assertEqual(restored.report_sha256, report.report_sha256)
        tampered = copy.deepcopy(report.to_dict())
        tampered["assets"][0]["confidence"] = 1
        with self.assertRaisesRegex(AttackSurfaceDiscoveryError, "identity"):
            DiscoveryReport.from_dict(tampered)
        unknown = copy.deepcopy(report.to_dict())
        unknown["unexpected"] = True
        with self.assertRaisesRegex(AttackSurfaceDiscoveryError, "fields"):
            parse_discovery_report(unknown)

    def test_schema_and_source_confirm_closed_offline_contract(self) -> None:
        if Draft202012Validator is None:
            self.skipTest("jsonschema is not installed")
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        discovery_plan = plan()

        def factory(request):
            return build_collector_result(
                request,
                (observation(request, 0, SurfaceKind.API),),
            )

        report = correlate_attack_surface(
            run_plan(discovery_plan, factory),
            generated_at="2026-09-20T11:00:00Z",
        )
        Draft202012Validator(schema).validate(report.to_dict())
        invalid = report.to_dict()
        invalid["network_client"] = "forbidden"
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(invalid)))

        source = (ROOT / "src" / "sunderkey" / "attack_surface_discovery.py").read_text(
            encoding="utf-8"
        )
        for forbidden_import in (
            "import socket",
            "import requests",
            "import subprocess",
            "from urllib",
            "import boto3",
        ):
            self.assertNotIn(forbidden_import, source)

    def test_public_package_exports_discovery_boundary(self) -> None:
        import sunderkey

        self.assertIs(sunderkey.AttackSurfaceDiscoveryReport, DiscoveryReport)
        self.assertIs(
            sunderkey.build_attack_surface_discovery_plan,
            build_discovery_plan,
        )
        self.assertIs(sunderkey.correlate_attack_surface, correlate_attack_surface)
        self.assertIs(
            sunderkey.parse_attack_surface_discovery_report,
            parse_discovery_report,
        )


if __name__ == "__main__":
    unittest.main()
