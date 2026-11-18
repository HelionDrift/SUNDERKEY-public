"""Phase 167 defender telemetry adapter contract coverage."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.defender_telemetry_adapters import (
    NO_BUILTIN_NETWORK,
    NO_EFFECTS,
    DefenderTelemetryAdapterError,
    FreshnessPolicy,
    NormalizationProjection,
    NormalizedAttribute,
    ReplayMarker,
    TelemetryDomain,
    TelemetryEnvelopeReference,
    TelemetrySourceBinding,
    canonical_json,
    normalize_import_batch,
    parse_contract,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "defender-telemetry-adapter-contract-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "defender_telemetry_adapters.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "defender-telemetry-adapters.md",
)
ZERO = "sha256:" + "0" * 64
ONE = "sha256:" + "1" * 64
TWO = "sha256:" + "2" * 64
THREE = "sha256:" + "3" * 64


class FakeNormalizer:
    def __init__(self, *, mapping_sha256: str = TWO) -> None:
        self.mapping_sha256 = mapping_sha256
        self.calls: list[tuple[str, str]] = []

    def normalize(self, *, binding, envelope) -> NormalizationProjection:
        self.calls.append((binding.binding_id, envelope.envelope_id))
        return NormalizationProjection(
            source_event_ref=envelope.source_event_ref,
            raw_event_sha256=envelope.raw_event_sha256,
            mapping_sha256=self.mapping_sha256,
            event_category="security_alert",
            operation_code="detector.alert",
            outcome="blocked",
            severity="high",
            actor_ref="entityref:principal-001",
            subject_ref="entityref:session-001",
            resource_ref="entityref:resource-001",
            attributes=(NormalizedAttribute("rule_ref", "ruleref:detector-001"),),
        )


class DefenderTelemetryAdaptersPhase167Tests(unittest.TestCase):
    def binding(self, domain: str = "network", **changes: object) -> TelemetrySourceBinding:
        values: dict[str, object] = {
            "tenant_ref": "tenantref:acme",
            "engagement_ref": "engagementref:assessment-001",
            "scope_sha256": ZERO,
            "source_ref": f"sourceref:{domain}-primary",
            "telemetry_domain": domain,
            "adapter_ref": f"adapterref:{domain}-v1",
            "adapter_version": "1.2.0",
            "source_schema_sha256": ONE,
            "mapping_sha256": TWO,
            "custody_policy_sha256": THREE,
            "processing_region": "us-west-2",
            "freshness_policy": FreshnessPolicy(
                maximum_event_age_seconds=3600,
                maximum_ingest_delay_seconds=600,
                maximum_future_skew_seconds=30,
                replay_window_seconds=7200,
            ),
            "effective_at": "2026-09-20T11:00:00Z",
            "expires_at": "2026-09-20T14:00:00Z",
        }
        values.update(changes)
        return TelemetrySourceBinding(**values)

    def envelope(
        self,
        binding: TelemetrySourceBinding | None = None,
        sequence: int = 1,
        **changes: object,
    ) -> TelemetryEnvelopeReference:
        active = binding or self.binding()
        values: dict[str, object] = {
            "binding_id": active.binding_id,
            "binding_sha256": active.binding_sha256,
            "tenant_ref": active.tenant_ref,
            "engagement_ref": active.engagement_ref,
            "scope_sha256": active.scope_sha256,
            "source_ref": active.source_ref,
            "telemetry_domain": active.telemetry_domain,
            "source_event_ref": f"eventref:event-{sequence:03d}",
            "source_sequence": sequence,
            "occurred_at": "2026-09-20T12:00:00Z",
            "received_at": "2026-09-20T12:00:05Z",
            "raw_event_sha256": "sha256:" + f"{sequence:x}" * 64,
            "artifact_ref": f"artifactref:telemetry-{sequence:03d}",
            "custody_sha256": THREE,
        }
        values.update(changes)
        return TelemetryEnvelopeReference(**values)

    def batch(self, domain: str = "network"):
        binding = self.binding(domain)
        envelope = self.envelope(binding)
        normalizer = FakeNormalizer()
        batch = normalize_import_batch(
            binding,
            (envelope,),
            normalizer,
            imported_at="2026-09-20T12:01:00Z",
        )
        return binding, envelope, normalizer, batch

    def test_all_required_domains_normalize_to_one_common_contract(self) -> None:
        domains = (
            "network",
            "identity",
            "cloud",
            "application_api",
            "endpoint",
            "siem",
        )
        for domain in domains:
            with self.subTest(domain=domain):
                binding, envelope, normalizer, batch = self.batch(domain)
                self.assertEqual(batch.events[0].telemetry_domain, TelemetryDomain(domain))
                self.assertEqual(batch.events[0].source_event_ref, envelope.source_event_ref)
                self.assertEqual(batch.to_dict()["effects"], dict(NO_EFFECTS))
                self.assertEqual(normalizer.calls, [(binding.binding_id, envelope.envelope_id)])
                self.assertTrue(batch.batch_id.startswith("TIB-"))
        self.assertTrue(NO_BUILTIN_NETWORK)

    def test_import_is_deterministic_and_content_addressed(self) -> None:
        binding = self.binding()
        envelopes = (self.envelope(binding, 2), self.envelope(binding, 1))
        first = normalize_import_batch(
            binding,
            envelopes,
            FakeNormalizer(),
            imported_at="2026-09-20T12:01:00Z",
        )
        second = normalize_import_batch(
            binding,
            tuple(reversed(envelopes)),
            FakeNormalizer(),
            imported_at="2026-09-20T12:01:00Z",
        )
        self.assertEqual(first, second)
        self.assertEqual([item.source_sequence for item in first.events], [1, 2])
        self.assertEqual(json.loads(canonical_json(first.to_dict())), first.to_dict())

    def test_supported_contracts_round_trip_and_tamper_fails(self) -> None:
        binding, envelope, _, batch = self.batch()
        for record in (binding, envelope, batch.events[0], batch):
            with self.subTest(kind=record.to_dict()["kind"]):
                document = record.to_dict()
                parsed = parse_contract(canonical_json(document))
                self.assertEqual(parsed.to_dict(), document)
                tampered = copy.deepcopy(document)
                digest_field = next(key for key in tampered if key.endswith("_sha256"))
                tampered[digest_field] = ONE if tampered[digest_field] != ONE else ZERO
                with self.assertRaises(DefenderTelemetryAdapterError):
                    parse_contract(tampered)

    def test_stale_and_clock_skewed_envelopes_fail_before_normalization(self) -> None:
        binding = self.binding()
        cases = (
            self.envelope(binding, occurred_at="2026-09-20T10:00:00Z"),
            self.envelope(binding, received_at="2026-09-20T11:40:00Z"),
            self.envelope(
                binding,
                occurred_at="2026-09-20T12:02:00Z",
                received_at="2026-09-20T12:00:00Z",
            ),
        )
        for envelope in cases:
            normalizer = FakeNormalizer()
            with (
                self.subTest(envelope=envelope.envelope_id),
                self.assertRaises(DefenderTelemetryAdapterError),
            ):
                normalize_import_batch(
                    binding,
                    (envelope,),
                    normalizer,
                    imported_at="2026-09-20T12:01:00Z",
                )
            self.assertEqual(normalizer.calls, [])

    def test_cross_context_envelopes_fail_before_normalization(self) -> None:
        binding = self.binding()
        base = self.envelope(binding)
        cases = (
            replace(base, tenant_ref="tenantref:other"),
            replace(base, scope_sha256=ONE),
            replace(base, engagement_ref="engagementref:other"),
            replace(base, source_ref="sourceref:other"),
            replace(base, telemetry_domain="identity"),
        )
        for envelope in cases:
            normalizer = FakeNormalizer()
            with (
                self.subTest(envelope=envelope.envelope_id),
                self.assertRaisesRegex(DefenderTelemetryAdapterError, "bound context"),
            ):
                normalize_import_batch(
                    binding,
                    (envelope,),
                    normalizer,
                    imported_at="2026-09-20T12:01:00Z",
                )
            self.assertEqual(normalizer.calls, [])

    def test_active_replay_and_duplicate_payload_are_rejected(self) -> None:
        binding, envelope, _, batch = self.batch()
        for repeated in (
            envelope,
            replace(envelope, source_event_ref="eventref:different"),
        ):
            with (
                self.subTest(source=repeated.source_event_ref),
                self.assertRaisesRegex(DefenderTelemetryAdapterError, "replay"),
            ):
                normalize_import_batch(
                    binding,
                    (repeated,),
                    FakeNormalizer(),
                    imported_at="2026-09-20T12:02:00Z",
                    prior_replay_markers=batch.replay_markers,
                )

    def test_expired_replay_marker_allows_reimport_but_cross_context_state_fails(self) -> None:
        binding = self.binding()
        envelope = self.envelope(binding)
        expired = ReplayMarker(
            binding_id=binding.binding_id,
            binding_sha256=binding.binding_sha256,
            tenant_ref=binding.tenant_ref,
            engagement_ref=binding.engagement_ref,
            scope_sha256=binding.scope_sha256,
            source_event_ref=envelope.source_event_ref,
            raw_event_sha256=envelope.raw_event_sha256,
            accepted_at="2026-09-20T11:00:00Z",
            expires_at="2026-09-20T12:00:00Z",
        )
        accepted = normalize_import_batch(
            binding,
            (envelope,),
            FakeNormalizer(),
            imported_at="2026-09-20T12:01:00Z",
            prior_replay_markers=(expired,),
        )
        self.assertEqual(len(accepted.events), 1)
        crossed = replace(expired, tenant_ref="tenantref:other")
        with self.assertRaisesRegex(DefenderTelemetryAdapterError, "replay state"):
            normalize_import_batch(
                binding,
                (envelope,),
                FakeNormalizer(),
                imported_at="2026-09-20T12:01:00Z",
                prior_replay_markers=(crossed,),
            )

    def test_projection_must_bind_exact_input_and_mapping(self) -> None:
        binding = self.binding()
        envelope = self.envelope(binding)
        for projection_change in (
            {"mapping_sha256": ONE},
            {"raw_event_sha256": ZERO},
            {"source_event_ref": "eventref:other"},
        ):

            class CrossingNormalizer(FakeNormalizer):
                def normalize(self, *, binding, envelope, change=projection_change):
                    projection = super().normalize(binding=binding, envelope=envelope)
                    return replace(projection, **change)

            with (
                self.subTest(change=projection_change),
                self.assertRaisesRegex(DefenderTelemetryAdapterError, "projection crosses"),
            ):
                normalize_import_batch(
                    binding,
                    (envelope,),
                    CrossingNormalizer(),
                    imported_at="2026-09-20T12:01:00Z",
                )

    def test_custody_redaction_and_secret_material_fail_closed(self) -> None:
        binding = self.binding()
        with self.assertRaisesRegex(DefenderTelemetryAdapterError, "custody"):
            self.envelope(binding, custody_status="unverified")
        with self.assertRaisesRegex(DefenderTelemetryAdapterError, "redacted"):
            self.envelope(binding, redacted=False)
        with self.assertRaisesRegex(DefenderTelemetryAdapterError, "opaque reference"):
            self.envelope(binding, artifact_ref="artifactref:authorization=secret-value")

    def test_binding_requires_exact_versions_regions_and_active_window(self) -> None:
        for changes in (
            {"adapter_version": "latest"},
            {"processing_region": "US West"},
            {"expires_at": "2026-09-20T10:00:00Z"},
            {"telemetry_domain": "database"},
        ):
            with self.subTest(changes=changes), self.assertRaises(DefenderTelemetryAdapterError):
                self.binding(**changes)
        inactive = self.binding(effective_at="2026-09-20T13:00:00Z")
        with self.assertRaisesRegex(DefenderTelemetryAdapterError, "not active"):
            normalize_import_batch(
                inactive,
                (self.envelope(inactive),),
                FakeNormalizer(),
                imported_at="2026-09-20T12:01:00Z",
            )

    def test_duplicate_reference_digest_and_sequence_fail_closed(self) -> None:
        binding = self.binding()
        first = self.envelope(binding, 1)
        cases = (
            (first, replace(first, source_sequence=2)),
            (first, replace(first, source_event_ref="eventref:other", source_sequence=2)),
            (
                first,
                replace(
                    first,
                    source_event_ref="eventref:other",
                    raw_event_sha256=ONE,
                ),
            ),
        )
        for envelopes in cases:
            with (
                self.subTest(envelopes=envelopes),
                self.assertRaises(DefenderTelemetryAdapterError),
            ):
                normalize_import_batch(
                    binding,
                    envelopes,
                    FakeNormalizer(),
                    imported_at="2026-09-20T12:01:00Z",
                )

    def test_batch_effect_and_identity_tampering_fail_closed(self) -> None:
        _, _, _, batch = self.batch()
        effect_tamper = copy.deepcopy(batch.to_dict())
        effect_tamper["effects"]["network"] = "performed"
        with self.assertRaisesRegex(DefenderTelemetryAdapterError, "effect escalation"):
            parse_contract(effect_tamper)
        identity_tamper = copy.deepcopy(batch.to_dict())
        identity_tamper["events"][0]["tenant_ref"] = "tenantref:other"
        with self.assertRaises(DefenderTelemetryAdapterError):
            parse_contract(identity_tamper)

    def test_contracts_are_immutable(self) -> None:
        binding, _, _, batch = self.batch()
        with self.assertRaises(FrozenInstanceError):
            binding.source_ref = "sourceref:other"  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            batch.imported_at = "2026-09-20T12:02:00Z"  # type: ignore[misc]

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_schema_accepts_all_top_level_contracts_and_rejects_unknown_fields(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        binding, envelope, _, batch = self.batch()
        for record in (binding, envelope, batch.events[0], batch):
            with self.subTest(kind=record.to_dict()["kind"]):
                self.assertEqual(list(validator.iter_errors(record.to_dict())), [])
        unknown = binding.to_dict()
        unknown["network_client"] = "enabled"
        self.assertNotEqual(list(validator.iter_errors(unknown)), [])

    def test_files_contain_no_forbidden_markers_or_dash_characters(self) -> None:
        forbidden = (
            "generated" + " by",
            "written" + " by ai",
            "as" + " an ai",
            "chat" + "gpt",
            "code" + "x",
            "clau" + "de",
            "gemi" + "ni",
            "co-authored" + "-by",
        )
        for path in FILES:
            text = path.read_text(encoding="utf-8")
            lowered = text.lower()
            self.assertNotIn("\u2013", text, path.name)
            self.assertNotIn("\u2014", text, path.name)
            for marker in forbidden:
                self.assertNotIn(marker, lowered, f"{marker} in {path.name}")

    def test_public_package_exports_telemetry_boundary(self) -> None:
        import sunderkey

        self.assertIs(sunderkey.DefenderTelemetryDomain, TelemetryDomain)
        self.assertIs(
            sunderkey.DefenderTelemetrySourceBinding,
            TelemetrySourceBinding,
        )
        self.assertIs(
            sunderkey.normalize_defender_telemetry_batch,
            normalize_import_batch,
        )
        self.assertIs(sunderkey.parse_defender_telemetry_contract, parse_contract)


if __name__ == "__main__":
    unittest.main()
