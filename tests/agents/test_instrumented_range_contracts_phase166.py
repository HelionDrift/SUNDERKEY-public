from __future__ import annotations

import copy
import json
import re
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import sunderkey
from sunderkey.instrumented_range_contracts import (
    NO_EFFECTS,
    GroundTruthVulnerability,
    HealthProbe,
    ImageBinding,
    InstrumentedRangeContractError,
    NegativeControl,
    NetworkBoundary,
    OpaqueReference,
    RangeReadinessAssessment,
    RangeReadinessObservation,
    RangeScenarioManifest,
    ResetManifest,
    ResourceQuota,
    RestorationCheck,
    SeededDataSet,
    SnapshotManifest,
    SyntheticApplicationManifest,
    TelemetryChannel,
    assess_range_readiness,
    parse_application_manifest,
    parse_readiness_assessment,
    parse_readiness_observation,
    parse_scenario_manifest,
)

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "src" / "sunderkey" / "instrumented_range_contracts.py"
SCHEMA = ROOT / "registry" / "schemas" / "instrumented-range-contract-v1.schema.json"
DOC = ROOT / "docs" / "instrumented-range-contracts.md"


def digest(character: str) -> str:
    return "sha256:" + character * 64


class InstrumentedRangeContractsPhase166Tests(unittest.TestCase):
    def test_public_package_exports_are_available(self) -> None:
        self.assertIs(sunderkey.assess_range_readiness, assess_range_readiness)
        self.assertIs(
            sunderkey.parse_instrumented_range_application,
            parse_application_manifest,
        )
        self.assertIs(
            sunderkey.parse_instrumented_range_scenario,
            parse_scenario_manifest,
        )

    def application(
        self, *, application_id: str = "application.synthetic.1"
    ) -> SyntheticApplicationManifest:
        return SyntheticApplicationManifest(
            application_id=application_id,
            source_sha256=digest("1"),
            build_sha256=digest("2"),
            images=(
                ImageBinding(
                    component_id="component.api",
                    image_reference="registry.example/range/api@" + digest("3"),
                    build_sha256=digest("4"),
                    source_sha256=digest("5"),
                ),
            ),
            ground_truth_vulnerabilities=(
                GroundTruthVulnerability(
                    vulnerability_id="vulnerability.authz.1",
                    component_id="component.api",
                    weakness_id="CWE-639",
                    disposition="exploitable",
                    ground_truth_sha256=digest("6"),
                ),
            ),
            negative_controls=(
                NegativeControl(
                    control_id="negative.authz.1",
                    component_id="component.api",
                    claim_sha256=digest("7"),
                ),
            ),
            seeded_data_sets=(
                SeededDataSet(
                    data_set_id="fixture.customers.1",
                    fixture_sha256=digest("8"),
                    record_count=32,
                ),
            ),
            opaque_references=(
                OpaqueReference(
                    reference_id="reference.vault.seed.1",
                    kind="seeded_secret",
                    provider_id="provider.vault.test",
                    version_id="version.17",
                ),
                OpaqueReference(
                    reference_id="reference.canary.1",
                    kind="canary",
                    provider_id="provider.canary.test",
                    version_id="version.4",
                ),
            ),
            network_boundaries=(
                NetworkBoundary(
                    boundary_id="boundary.ingress.1",
                    direction="ingress",
                    source_zone="zone.executor",
                    destination_zone="zone.application",
                    policy_sha256=digest("9"),
                ),
                NetworkBoundary(
                    boundary_id="boundary.egress.1",
                    direction="egress",
                    source_zone="zone.application",
                    destination_zone="zone.sink",
                    policy_sha256=digest("a"),
                ),
            ),
            resource_quota=ResourceQuota(
                cpu_millicores=2000,
                memory_mebibytes=4096,
                storage_mebibytes=16384,
                process_limit=512,
            ),
            telemetry_channels=(
                TelemetryChannel(
                    channel_id="telemetry.application.1",
                    kind="application",
                    collector_id="collector.otel.1",
                    correlation_fields=("assessment_id", "scenario_id", "action_id"),
                    schema_sha256=digest("b"),
                ),
                TelemetryChannel(
                    channel_id="telemetry.network.1",
                    kind="network",
                    collector_id="collector.flow.1",
                    correlation_fields=("assessment_id", "scenario_id", "flow_id"),
                    schema_sha256=digest("c"),
                ),
            ),
            health_probes=(
                HealthProbe(
                    probe_id="probe.api.1",
                    component_id="component.api",
                    probe_kind="http_contract",
                    expectation_sha256=digest("d"),
                ),
            ),
            baseline_snapshot=SnapshotManifest(
                snapshot_id="snapshot.baseline.1",
                snapshot_sha256=digest("e"),
                application_state_sha256=digest("f"),
                data_state_sha256=digest("0"),
            ),
        )

    def scenario(
        self, application: SyntheticApplicationManifest | None = None
    ) -> RangeScenarioManifest:
        app = application or self.application()
        return RangeScenarioManifest(
            scenario_id="scenario.authz.1",
            application_id=app.application_id,
            application_manifest_sha256=app.manifest_sha256,
            expected_vulnerability_ids=("vulnerability.authz.1",),
            expected_negative_control_ids=("negative.authz.1",),
            required_telemetry_channel_ids=(
                "telemetry.application.1",
                "telemetry.network.1",
            ),
            required_health_probe_ids=("probe.api.1",),
            reset_manifest=ResetManifest(
                reset_id="reset.authz.1",
                procedure_sha256=digest("1"),
                baseline_snapshot_id=app.baseline_snapshot.snapshot_id,
                baseline_snapshot_sha256=app.baseline_snapshot.snapshot_sha256,
                required_restoration_check_ids=("check.database.1",),
            ),
            scenario_source_sha256=digest("2"),
        )

    def observation(
        self,
        application: SyntheticApplicationManifest | None = None,
        scenario: RangeScenarioManifest | None = None,
        **changes: object,
    ) -> RangeReadinessObservation:
        app = application or self.application()
        selected_scenario = scenario or self.scenario(app)
        values: dict[str, object] = {
            "scenario_id": selected_scenario.scenario_id,
            "scenario_manifest_sha256": selected_scenario.manifest_sha256,
            "application_id": app.application_id,
            "application_manifest_sha256": app.manifest_sha256,
            "observed_at": "2026-09-20T10:00:00Z",
            "reset_id": selected_scenario.reset_manifest.reset_id,
            "reset_completed_at": "2026-09-20T09:59:30Z",
            "observed_snapshot_id": app.baseline_snapshot.snapshot_id,
            "observed_snapshot_sha256": app.baseline_snapshot.snapshot_sha256,
            "contamination_detected": False,
            "health_probe_results": (("probe.api.1", True),),
            "telemetry_channel_results": (
                ("telemetry.application.1", True),
                ("telemetry.network.1", True),
            ),
            "restoration_checks": (
                RestorationCheck(
                    check_id="check.database.1",
                    expected_sha256=digest("3"),
                    observed_sha256=digest("3"),
                    matched=True,
                ),
            ),
            "evidence_sha256": digest("4"),
        }
        values.update(changes)
        return RangeReadinessObservation(**values)

    def test_ready_assessment_and_all_documents_round_trip_deterministically(self) -> None:
        app = self.application()
        scenario = self.scenario(app)
        observation = self.observation(app, scenario)
        assessment = assess_range_readiness(
            app,
            scenario,
            observation,
            evaluated_at="2026-09-20T10:05:00Z",
        )
        self.assertEqual(assessment.status, "ready")
        self.assertEqual(assessment.reason_codes, ())
        round_trips = (
            (app, parse_application_manifest),
            (scenario, parse_scenario_manifest),
            (observation, parse_readiness_observation),
            (assessment, parse_readiness_assessment),
        )
        for original, parser in round_trips:
            rebuilt = parser(json.loads(json.dumps(original.to_dict())))
            self.assertEqual(rebuilt, original)
            self.assertEqual(rebuilt.to_dict(), original.to_dict())

    def test_contracts_are_immutable_and_content_addressed(self) -> None:
        app = self.application()
        with self.assertRaises(FrozenInstanceError):
            app.application_id = "application.changed"  # type: ignore[misc]
        tampered = app.to_dict()
        tampered["build_sha256"] = digest("a")
        with self.assertRaisesRegex(InstrumentedRangeContractError, "content address"):
            parse_application_manifest(tampered)
        scenario = self.scenario(app)
        tampered = scenario.to_dict()
        tampered["scenario_source_sha256"] = digest("b")
        with self.assertRaisesRegex(InstrumentedRangeContractError, "content address"):
            parse_scenario_manifest(tampered)

    def test_exact_image_build_source_and_opaque_reference_boundaries(self) -> None:
        with self.assertRaisesRegex(InstrumentedRangeContractError, "exact image digest"):
            replace(self.application().images[0], image_reference="registry.example/api:latest")
        with self.assertRaisesRegex(InstrumentedRangeContractError, "sha256"):
            replace(self.application().images[0], build_sha256="latest")
        with self.assertRaisesRegex(InstrumentedRangeContractError, "secret material"):
            OpaqueReference(
                reference_id="authorization:raw-value",
                kind="seeded_secret",
                provider_id="provider.test",
                version_id="version.1",
            )

    def test_component_and_duplicate_references_fail_closed(self) -> None:
        app = self.application()
        with self.assertRaisesRegex(InstrumentedRangeContractError, "outside"):
            replace(
                app,
                health_probes=(replace(app.health_probes[0], component_id="component.missing"),),
            )
        with self.assertRaisesRegex(InstrumentedRangeContractError, "unique"):
            replace(app, images=(app.images[0], app.images[0]))

    def test_stale_and_future_observations_fail_readiness(self) -> None:
        app = self.application()
        scenario = self.scenario(app)
        observation = self.observation(app, scenario)
        stale = assess_range_readiness(
            app,
            scenario,
            observation,
            evaluated_at="2026-09-20T10:20:00Z",
            maximum_observation_age_seconds=300,
        )
        self.assertEqual(stale.status, "not_ready")
        self.assertIn("stale_observation", stale.reason_codes)
        future = assess_range_readiness(
            app,
            scenario,
            observation,
            evaluated_at="2026-09-20T09:59:59Z",
        )
        self.assertIn("stale_observation", future.reason_codes)

    def test_cross_context_manifest_and_observation_mismatch_fail_closed(self) -> None:
        app = self.application()
        other = self.application(application_id="application.synthetic.2")
        scenario = self.scenario(app)
        observation = self.observation(app, scenario)
        result = assess_range_readiness(
            other,
            scenario,
            observation,
            evaluated_at="2026-09-20T10:05:00Z",
        )
        self.assertEqual(result.status, "not_ready")
        self.assertIn("scenario_application_mismatch", result.reason_codes)
        self.assertIn("observation_application_hash_mismatch", result.reason_codes)

    def test_incomplete_ground_truth_and_negative_controls_fail_closed(self) -> None:
        app = self.application()
        scenario = replace(
            self.scenario(app),
            expected_vulnerability_ids=("vulnerability.other",),
            expected_negative_control_ids=("negative.other",),
        )
        observation = self.observation(app, scenario)
        result = assess_range_readiness(
            app,
            scenario,
            observation,
            evaluated_at="2026-09-20T10:05:00Z",
        )
        self.assertIn("ground_truth_incomplete", result.reason_codes)
        self.assertIn("negative_controls_incomplete", result.reason_codes)

    def test_contaminated_unreset_and_baseline_mismatch_fail_closed(self) -> None:
        app = self.application()
        scenario = self.scenario(app)
        observation = self.observation(
            app,
            scenario,
            contamination_detected=True,
            reset_id="reset.wrong",
            observed_snapshot_sha256=digest("f"),
        )
        result = assess_range_readiness(
            app,
            scenario,
            observation,
            evaluated_at="2026-09-20T10:05:00Z",
        )
        self.assertIn("range_contaminated", result.reason_codes)
        self.assertIn("range_unreset", result.reason_codes)
        self.assertIn("baseline_not_restored", result.reason_codes)

    def test_unhealthy_and_incomplete_health_evidence_fail_closed(self) -> None:
        app = self.application()
        scenario = self.scenario(app)
        unhealthy = self.observation(
            app,
            scenario,
            health_probe_results=(("probe.api.1", False),),
        )
        result = assess_range_readiness(
            app, scenario, unhealthy, evaluated_at="2026-09-20T10:05:00Z"
        )
        self.assertIn("range_unhealthy", result.reason_codes)
        extra = self.observation(
            app,
            scenario,
            health_probe_results=(("probe.api.1", True), ("probe.extra", True)),
        )
        result = assess_range_readiness(app, scenario, extra, evaluated_at="2026-09-20T10:05:00Z")
        self.assertIn("health_evidence_incomplete", result.reason_codes)

    def test_telemetry_blind_and_incomplete_evidence_fail_closed(self) -> None:
        app = self.application()
        scenario = self.scenario(app)
        blind = self.observation(
            app,
            scenario,
            telemetry_channel_results=(
                ("telemetry.application.1", True),
                ("telemetry.network.1", False),
            ),
        )
        result = assess_range_readiness(app, scenario, blind, evaluated_at="2026-09-20T10:05:00Z")
        self.assertIn("telemetry_blind", result.reason_codes)
        incomplete = self.observation(
            app,
            scenario,
            telemetry_channel_results=(("telemetry.application.1", True),),
        )
        result = assess_range_readiness(
            app, scenario, incomplete, evaluated_at="2026-09-20T10:05:00Z"
        )
        self.assertIn("telemetry_evidence_incomplete", result.reason_codes)
        self.assertIn("telemetry_blind", result.reason_codes)

    def test_restoration_failure_and_missing_check_fail_closed(self) -> None:
        app = self.application()
        scenario = self.scenario(app)
        failed = self.observation(
            app,
            scenario,
            restoration_checks=(
                RestorationCheck(
                    check_id="check.database.1",
                    expected_sha256=digest("1"),
                    observed_sha256=digest("2"),
                    matched=False,
                ),
            ),
        )
        result = assess_range_readiness(app, scenario, failed, evaluated_at="2026-09-20T10:05:00Z")
        self.assertIn("restoration_check_failed", result.reason_codes)
        wrong = self.observation(
            app,
            scenario,
            restoration_checks=(
                RestorationCheck(
                    check_id="check.wrong",
                    expected_sha256=digest("1"),
                    observed_sha256=digest("1"),
                    matched=True,
                ),
            ),
        )
        result = assess_range_readiness(app, scenario, wrong, evaluated_at="2026-09-20T10:05:00Z")
        self.assertIn("restoration_evidence_incomplete", result.reason_codes)

    def test_observation_and_assessment_tamper_are_rejected(self) -> None:
        app = self.application()
        scenario = self.scenario(app)
        observation = self.observation(app, scenario)
        tampered = observation.to_dict()
        tampered["contamination_detected"] = True
        with self.assertRaisesRegex(InstrumentedRangeContractError, "content address"):
            parse_readiness_observation(tampered)
        assessment = assess_range_readiness(
            app, scenario, observation, evaluated_at="2026-09-20T10:05:00Z"
        )
        tampered = assessment.to_dict()
        tampered["status"] = "not_ready"
        with self.assertRaises(InstrumentedRangeContractError):
            RangeReadinessAssessment.from_dict(tampered)

    def test_unknown_fields_and_no_effects_tamper_are_rejected(self) -> None:
        document = self.application().to_dict()
        document["unexpected"] = True
        with self.assertRaisesRegex(InstrumentedRangeContractError, "fields"):
            parse_application_manifest(document)
        document = self.application().to_dict()
        document["effects"]["network"] = "performed"
        with self.assertRaisesRegex(InstrumentedRangeContractError, "effects"):
            parse_application_manifest(document)

    def test_schema_accepts_all_contract_documents_and_rejects_unknown_fields(self) -> None:
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is not installed")
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(schema)
        app = self.application()
        scenario = self.scenario(app)
        observation = self.observation(app, scenario)
        assessment = assess_range_readiness(
            app, scenario, observation, evaluated_at="2026-09-20T10:05:00Z"
        )
        for value in (app, scenario, observation, assessment):
            validator.validate(value.to_dict())
        document = copy.deepcopy(app.to_dict())
        document["unexpected"] = True
        with self.assertRaises(jsonschema.ValidationError):
            validator.validate(document)

    def test_no_effects_and_repository_text_hygiene(self) -> None:
        self.assertEqual(
            dict(NO_EFFECTS),
            {
                "container_start": "none",
                "exploit_execution": "none",
                "live_readiness_claim": "none",
                "network": "none",
                "secret_resolution": "none",
                "state_change": "none",
            },
        )
        marker_terms = (
            "generated" + " by",
            "written" + " by (?:an )?ai",
            "as" + " an ai",
            "chat" + "gpt",
            "co" + "dex",
            "clau" + "de",
            "gem" + "ini",
            "co-authored" + "-by",
        )
        marker = re.compile("|".join(marker_terms), re.IGNORECASE)
        for path in (MODULE, SCHEMA, DOC, Path(__file__)):
            text = path.read_text(encoding="utf-8")
            self.assertIsNone(marker.search(text), path)
            self.assertNotRegex(text, "[\u2013\u2014]")


if __name__ == "__main__":
    unittest.main()
