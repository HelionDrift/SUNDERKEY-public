import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from sunderkey.durable_artifact_recorder import (
    MAX_ARTIFACT_BYTES,
    ArtifactCommitObservation,
    ArtifactMetadata,
    ArtifactRecordingPlan,
    ArtifactRecordingReceipt,
    ArtifactRecordingRequest,
    CommitDisposition,
    DurableArtifactRecorderError,
    OutboxEventMetadata,
    ReceiptStatus,
    RetentionClass,
    custody_entry_sha256,
    parse_record,
    plan_artifact_recording,
    record_artifact,
)

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "src" / "sunderkey" / "durable_artifact_recorder.py"
SCHEMA = ROOT / "registry" / "schemas" / "durable-artifact-recorder-v1.schema.json"
DOC = ROOT / "docs" / "durable-artifact-recorder.md"
FILES = (MODULE, Path(__file__), SCHEMA, DOC)

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
NOW = "2026-09-20T12:00:00Z"


def request(*, prior: str | None = DIGEST_B, outbox: bool = True) -> ArtifactRecordingRequest:
    return ArtifactRecordingRequest(
        tenant_ref="tenantref:tenant-a",
        assessment_ref="assessmentref:assessment-42",
        scope_ref="scoperef:scope-admitted-42",
        artifact=ArtifactMetadata(
            artifact_ref="artifactref:evidence-42",
            content_sha256=DIGEST_A,
            media_type="application/json",
            size_bytes=4096,
            retention_class=RetentionClass.ASSESSMENT_1_YEAR,
            custody_ref="custodyref:evidence-42.entry-7",
            prior_custody_sha256=prior,
        ),
        expected_artifact_version=6,
        expected_custody_version=6,
        fence_resource_ref="resourceref:artifact-store.tenant-a",
        fence_token="fence:artifact-store-00000042",
        fence_epoch=42,
        idempotency_key="idem:artifact-evidence-42-00000001",
        recorded_at=NOW,
        outbox_event=(
            OutboxEventMetadata(
                outbox_event_ref="outboxref:artifact-recorded-42",
                event_type="artifact.recorded",
                content_sha256=DIGEST_C,
                expected_version=0,
            )
            if outbox
            else None
        ),
    )


def observation(
    plan: ArtifactRecordingPlan,
    *,
    disposition: CommitDisposition = CommitDisposition.COMMITTED,
    **overrides,
) -> ArtifactCommitObservation:
    item = plan.request
    values = {
        "adapter_ref": "adapterref:test.persistence",
        "batch_id": plan.transaction_batch.batch_id,
        "batch_sha256": plan.transaction_batch.batch_sha256,
        "tenant_ref": item.tenant_ref,
        "assessment_ref": item.assessment_ref,
        "scope_ref": item.scope_ref,
        "idempotency_key": item.idempotency_key,
        "artifact_ref": item.artifact.artifact_ref,
        "stored_content_sha256": item.artifact.content_sha256,
        "custody_ref": item.artifact.custody_ref,
        "prior_custody_sha256": item.artifact.prior_custody_sha256,
        "custody_entry_sha256": custody_entry_sha256(item),
        "expected_artifact_version": item.expected_artifact_version,
        "observed_artifact_version": item.expected_artifact_version + 1,
        "expected_custody_version": item.expected_custody_version,
        "observed_custody_version": item.expected_custody_version + 1,
        "fence_resource_ref": item.fence_resource_ref,
        "fence_token": item.fence_token,
        "fence_epoch": item.fence_epoch,
        "outbox_event_ref": (
            None if item.outbox_event is None else item.outbox_event.outbox_event_ref
        ),
        "disposition": disposition,
        "observed_at": "2026-09-20T12:00:01Z",
    }
    values.update(overrides)
    return ArtifactCommitObservation(**values)


class BoundAdapter:
    def __init__(self, result: ArtifactCommitObservation) -> None:
        self.result = result
        self.calls: list[ArtifactRecordingPlan] = []

    def commit_artifact(self, plan: ArtifactRecordingPlan) -> ArtifactCommitObservation:
        self.calls.append(plan)
        return self.result


class DurableArtifactRecorderPhase169Tests(unittest.TestCase):
    def test_plan_is_deterministic_and_binds_all_transaction_controls(self) -> None:
        first = plan_artifact_recording(request())
        second = plan_artifact_recording(request())
        self.assertEqual(first, second)
        self.assertEqual(first, ArtifactRecordingPlan.from_json(first.to_json()))
        self.assertEqual(first, parse_record(first.to_dict()))
        batch = first.transaction_batch
        self.assertEqual(batch.tenant_ref, "tenantref:tenant-a")
        self.assertEqual(batch.assessment_ref, "assessmentref:assessment-42")
        self.assertEqual(batch.scope_ref, "scoperef:scope-admitted-42")
        self.assertEqual(batch.idempotency_key, "idem:artifact-evidence-42-00000001")
        self.assertEqual(batch.isolation_level.value, "serializable")
        self.assertEqual(len(batch.operations), 3)
        self.assertEqual(
            [item.kind.value for item in batch.operations],
            ["append", "append", "outbox_enqueue"],
        )
        self.assertEqual(len(batch.version_bindings), 3)
        self.assertEqual(batch.fence_bindings[0].fence_epoch, 42)
        self.assertEqual(batch.outbox_event_refs, ("outboxref:artifact-recorded-42",))
        self.assertEqual(first.to_dict()["effects"]["persistence"], "none")

    def test_optional_outbox_is_absent_as_one_atomic_unit(self) -> None:
        plan = plan_artifact_recording(request(outbox=False))
        self.assertEqual(len(plan.transaction_batch.operations), 2)
        self.assertEqual(len(plan.transaction_batch.version_bindings), 2)
        self.assertEqual(plan.transaction_batch.outbox_event_refs, ())

    def test_first_custody_entry_and_linked_entry_have_different_addresses(self) -> None:
        first = request(prior=None)
        linked = request(prior=DIGEST_B)
        self.assertNotEqual(custody_entry_sha256(first), custody_entry_sha256(linked))
        self.assertEqual(
            custody_entry_sha256(linked),
            custody_entry_sha256(request(prior=DIGEST_B)),
        )

    def test_metadata_rejects_non_content_addresses_media_types_and_size_limits(self) -> None:
        base = request().artifact.to_dict()
        for field_name, value, message in (
            ("content_sha256", "C:\\evidence\\artifact.json", "content address"),
            ("media_type", "Application/JSON", "normalized media type"),
            ("size_bytes", MAX_ARTIFACT_BYTES + 1, "between"),
        ):
            with self.subTest(field=field_name):
                changed = dict(base)
                changed[field_name] = value
                with self.assertRaisesRegex(DurableArtifactRecorderError, message):
                    ArtifactMetadata.from_dict(changed)

    def test_exact_field_parsing_and_plan_tamper_fail_closed(self) -> None:
        plan = plan_artifact_recording(request())
        changed = copy.deepcopy(plan.to_dict())
        changed["unexpected"] = True
        with self.assertRaisesRegex(DurableArtifactRecorderError, "fields"):
            ArtifactRecordingPlan.from_dict(changed)
        changed = copy.deepcopy(plan.to_dict())
        changed["request"]["artifact"]["retention_class"] = "archive_7_years"
        with self.assertRaisesRegex(DurableArtifactRecorderError, "content address"):
            ArtifactRecordingPlan.from_dict(changed)
        with self.assertRaisesRegex(DurableArtifactRecorderError, "canonical"):
            ArtifactRecordingPlan.from_json(plan.to_json() + "\n")

    def test_injected_adapter_observation_produces_nonqualifying_receipt(self) -> None:
        plan = plan_artifact_recording(request())
        observed = observation(plan)
        adapter = BoundAdapter(observed)
        receipt = record_artifact(plan, adapter)
        self.assertEqual(adapter.calls, [plan])
        self.assertEqual(receipt.status, ReceiptStatus.OBSERVED_COMMIT)
        self.assertEqual(receipt, ArtifactRecordingReceipt.from_json(receipt.to_json()))
        self.assertEqual(receipt, parse_record(receipt.to_dict()))
        self.assertEqual(observed, ArtifactCommitObservation.from_json(observed.to_json()))
        self.assertEqual(observed, parse_record(observed.to_dict()))
        self.assertEqual(receipt.to_dict()["qualification_effect"], "none")
        self.assertEqual(receipt.to_dict()["effects"]["durability"], "adapter_observation_only")

    def test_replay_is_explicit_and_deterministic(self) -> None:
        plan = plan_artifact_recording(request())
        observed = observation(plan, disposition=CommitDisposition.REPLAYED)
        first = record_artifact(plan, BoundAdapter(observed))
        second = record_artifact(plan, BoundAdapter(observed))
        self.assertEqual(first, second)
        self.assertEqual(first.status, ReceiptStatus.OBSERVED_REPLAY)
        self.assertEqual(first.batch_id, plan.transaction_batch.batch_id)

    def test_optimistic_concurrency_is_validated_by_observation_type(self) -> None:
        plan = plan_artifact_recording(request())
        with self.assertRaisesRegex(DurableArtifactRecorderError, "artifact optimistic"):
            observation(plan, observed_artifact_version=9)
        with self.assertRaisesRegex(DurableArtifactRecorderError, "custody optimistic"):
            observation(plan, observed_custody_version=9)

    def test_adapter_substitution_of_identity_digest_fence_or_custody_is_rejected(self) -> None:
        plan = plan_artifact_recording(request())
        cases = (
            {"tenant_ref": "tenantref:tenant-b"},
            {"stored_content_sha256": DIGEST_C},
            {"fence_token": "fence:artifact-store-00000043"},
            {"fence_epoch": 43},
            {"prior_custody_sha256": DIGEST_C},
            {"custody_entry_sha256": DIGEST_C},
            {"batch_sha256": DIGEST_C},
            {"idempotency_key": "idem:artifact-evidence-42-00000002"},
        )
        for changes in cases:
            with (
                self.subTest(changes=changes),
                self.assertRaisesRegex(DurableArtifactRecorderError, "does not match"),
            ):
                record_artifact(plan, BoundAdapter(observation(plan, **changes)))

    def test_invalid_adapter_result_and_missing_adapter_method_fail_closed(self) -> None:
        plan = plan_artifact_recording(request())

        class InvalidAdapter:
            def commit_artifact(self, plan):
                return {"status": "committed"}

        with self.assertRaisesRegex(DurableArtifactRecorderError, "invalid commit observation"):
            record_artifact(plan, InvalidAdapter())
        with self.assertRaisesRegex(DurableArtifactRecorderError, "provide commit_artifact"):
            record_artifact(plan, object())

    def test_observation_and_receipt_tamper_rejection(self) -> None:
        plan = plan_artifact_recording(request())
        observed = observation(plan)
        changed = observed.to_dict()
        changed["stored_content_sha256"] = DIGEST_C
        with self.assertRaisesRegex(DurableArtifactRecorderError, "content address"):
            ArtifactCommitObservation.from_dict(changed)
        receipt = record_artifact(plan, BoundAdapter(observed))
        changed = receipt.to_dict()
        changed["status"] = "observed_replay"
        with self.assertRaisesRegex(DurableArtifactRecorderError, "content address"):
            ArtifactRecordingReceipt.from_dict(changed)

    def test_schema_accepts_all_records_and_rejects_unknown_fields(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        plan = plan_artifact_recording(request())
        observed = observation(plan)
        receipt = record_artifact(plan, BoundAdapter(observed))
        for item in (plan, observed, receipt):
            with self.subTest(kind=item.KIND):
                validator.validate(item.to_dict())
                changed = copy.deepcopy(item.to_dict())
                changed["unexpected"] = True
                self.assertTrue(list(validator.iter_errors(changed)))

    def test_unsupported_record_kind_fails_closed(self) -> None:
        with self.assertRaisesRegex(DurableArtifactRecorderError, "unsupported"):
            parse_record({"kind": "sunderkey.unknown.v1"})

    def test_module_has_no_direct_effect_clients_or_byte_and_path_fields(self) -> None:
        source = MODULE.read_text(encoding="utf-8")
        forbidden = (
            "import " + "sqlite3",
            "import " + "psycopg",
            "import " + "sqlalchemy",
            "import " + "socket",
            "import " + "requests",
            "import " + "urllib",
            "sub" + "process",
            "artifact_" + "bytes:",
            "file" + "system_path:",
        )
        for marker in forbidden:
            self.assertNotIn(marker, source)

    def test_increment_has_no_unicode_dashes_or_authorship_markers(self) -> None:
        marker_fragments = (
            "generated " + "by",
            "written " + "by " + "an " + "ai",
            "as " + "an " + "ai",
            "chat" + "gpt",
            "co-authored" + "-by",
        )
        for path in FILES:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2013", text, path)
            self.assertNotIn("\u2014", text, path)
            lowered = text.lower()
            for marker in marker_fragments:
                self.assertNotIn(marker, lowered, path)

    def test_public_package_exports_recorder_boundary(self) -> None:
        import sunderkey

        self.assertIs(sunderkey.DurableArtifactRecordingPlan, ArtifactRecordingPlan)
        self.assertIs(sunderkey.DurableArtifactRecordingReceipt, ArtifactRecordingReceipt)
        self.assertIs(sunderkey.plan_artifact_recording, plan_artifact_recording)
        self.assertIs(sunderkey.record_artifact, record_artifact)
        self.assertIs(sunderkey.parse_durable_artifact_record, parse_record)


if __name__ == "__main__":
    unittest.main()
