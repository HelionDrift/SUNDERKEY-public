"""Focused checks for bounded, source-replayed planning previews."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import MappingProxyType
from unittest.mock import patch

import sunderkey.offline_verified_planning_preview as preview_module
import tests.agents.test_offline_api_planning_bundle as planning_fixture
from sunderkey.offline_api_planning_bundle import (
    build_offline_api_planning_bundle,
    inspect_offline_api_planning_integrity,
)
from sunderkey.offline_planning_preview import PlanningBundleRecord
from sunderkey.offline_planning_preview_store import (
    MAX_BUNDLE_BYTES,
    SQLitePlanningBundleStore,
)
from sunderkey.offline_verified_planning_preview import (
    OfflineVerifiedPlanningPreviewError,
    build_offline_verified_planning_preview,
)


class Reader:
    def __init__(self, record: PlanningBundleRecord) -> None:
        self.record = record
        self.calls: list[tuple[str, str, str]] = []

    def get(
        self, tenant_id: str, context_id: str, bundle_sha256: str
    ) -> PlanningBundleRecord | None:
        self.calls.append((tenant_id, context_id, bundle_sha256))
        if (
            tenant_id,
            context_id,
            bundle_sha256,
        ) == (
            self.record.tenant_id,
            self.record.context_id,
            self.record.bundle_sha256,
        ):
            return self.record
        return None


class OfflineVerifiedPlanningPreviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        planning_fixture.OfflineApiPlanningBundleTests.setUpClass()

    def setUp(self) -> None:
        fixture = planning_fixture.OfflineApiPlanningBundleTests(
            "test_synthetic_signal_reaches_bound_rehearsal_only"
        )
        fixture.setUp()
        self.fixture = fixture
        self.inputs = fixture.options()
        self.bundle = build_offline_api_planning_bundle(**self.inputs)
        self.reader = Reader(
            PlanningBundleRecord(
                "tenant.synthetic.001",
                "context.synthetic.001",
                self.bundle["bundle_sha256"],
                self.bundle,
            )
        )

    def options(self, **changes: object) -> dict:
        return {
            "reader": self.reader,
            "expected_tenant_id": "tenant.synthetic.001",
            "expected_context_id": "context.synthetic.001",
            "expected_bundle_sha256": self.bundle["bundle_sha256"],
            "expected_scope_sha256": self.bundle["scope_sha256"],
            "planning_inputs": self.inputs,
            **changes,
        }

    def test_exact_archived_bundle_replays_without_authority_or_raw_sources(self) -> None:
        preview = build_offline_verified_planning_preview(**self.options())
        self.assertEqual(preview, build_offline_verified_planning_preview(**self.options()))
        self.assertTrue(preview["source_replay_performed"])
        self.assertEqual(preview["bundle_sha256"], self.bundle["bundle_sha256"])
        self.assertEqual(preview["scope_sha256"], self.fixture.scope.content_sha256)
        self.assertFalse(preview["external_source_custody_verified"])
        self.assertFalse(preview["live_currentness_verified"])
        self.assertFalse(preview["caller_authorization_verified"])
        self.assertFalse(preview["positive_use_approved"])
        self.assertEqual(preview["effects"]["module_direct_network"], "none")
        self.assertEqual(
            preview["effects"]["injected_reader_and_analyzer_effects"],
            "not_verified",
        )
        rendered = json.dumps(preview)
        self.assertNotIn(self.fixture.source.case_id, rendered)
        self.assertNotIn("tenant.synthetic.001", rendered)
        self.assertNotIn("context.synthetic.001", rendered)
        self.assertEqual(
            self.reader.calls[0],
            (
                "tenant.synthetic.001",
                "context.synthetic.001",
                self.bundle["bundle_sha256"],
            ),
        )

    def test_self_consistent_forged_archive_fails_exact_source_replay(self) -> None:
        changed_inputs = {
            **self.inputs,
            "specialist_capacity": {self.fixture.profile_id: 2},
        }
        forged = build_offline_api_planning_bundle(**changed_inputs)
        self.assertNotEqual(forged["bundle_sha256"], self.bundle["bundle_sha256"])
        self.assertEqual(
            inspect_offline_api_planning_integrity(bundle=forged, registry=self.fixture.registry)[
                "status"
            ],
            "valid_historical_integrity",
        )
        self.reader.record = PlanningBundleRecord(
            "tenant.synthetic.001", "context.synthetic.001", forged["bundle_sha256"], forged
        )
        with self.assertRaisesRegex(
            OfflineVerifiedPlanningPreviewError, "source binding is invalid"
        ):
            build_offline_verified_planning_preview(
                **self.options(expected_bundle_sha256=forged["bundle_sha256"])
            )

    def test_changed_original_planning_inputs_and_cases_fail_closed(self) -> None:
        changed_inputs = {
            **self.inputs,
            "capability_availability": copy.deepcopy(self.inputs["capability_availability"]),
        }
        changed_inputs["capability_availability"]["safe_probe"]["available"] = False
        with self.assertRaises(OfflineVerifiedPlanningPreviewError):
            build_offline_verified_planning_preview(**self.options(planning_inputs=changed_inputs))
        with self.assertRaises(OfflineVerifiedPlanningPreviewError):
            build_offline_verified_planning_preview(
                **self.options(planning_inputs={**self.inputs, "sources": ()})
            )

    def test_reader_cannot_rebind_entry_sources_to_forged_archive(self) -> None:
        forged_inputs = {
            **self.inputs,
            "specialist_capacity": {self.fixture.profile_id: 2},
        }
        forged = build_offline_api_planning_bundle(**forged_inputs)

        class MutatingReader:
            def get(reader_self, tenant_id, context_id, bundle_sha256):
                self.inputs["specialist_capacity"][self.fixture.profile_id] = 2
                return PlanningBundleRecord(tenant_id, context_id, bundle_sha256, forged)

        with self.assertRaises(OfflineVerifiedPlanningPreviewError):
            build_offline_verified_planning_preview(
                **self.options(
                    reader=MutatingReader(),
                    expected_bundle_sha256=forged["bundle_sha256"],
                )
            )
        self.assertEqual(self.inputs["specialist_capacity"][self.fixture.profile_id], 1)

        calls = []

        class DriftingReader:
            def get(reader_self, tenant_id, context_id, bundle_sha256):
                calls.append(bundle_sha256)
                self.inputs["specialist_capacity"][self.fixture.profile_id] = 2
                return PlanningBundleRecord(tenant_id, context_id, bundle_sha256, self.bundle)

        with self.assertRaises(OfflineVerifiedPlanningPreviewError):
            build_offline_verified_planning_preview(**self.options(reader=DriftingReader()))
        self.assertEqual(calls, [self.bundle["bundle_sha256"]])

    def test_oversized_generic_reader_result_is_rejected_before_serialization(self) -> None:
        oversized = copy.deepcopy(self.bundle)
        oversized["extra"] = "x" * (MAX_BUNDLE_BYTES + 1)
        self.reader.record = PlanningBundleRecord(
            "tenant.synthetic.001",
            "context.synthetic.001",
            self.bundle["bundle_sha256"],
            oversized,
        )
        with (
            patch.object(
                preview_module, "_canonical", wraps=preview_module._canonical
            ) as canonical,
            self.assertRaisesRegex(OfflineVerifiedPlanningPreviewError, "size limit"),
        ):
            build_offline_verified_planning_preview(**self.options())
        self.assertFalse(any(call.args[0] is oversized for call in canonical.call_args_list))
        self.assertFalse(
            any(call.args[0] is oversized["extra"] for call in canonical.call_args_list)
        )

    def test_deep_generic_reader_result_is_rejected_before_serialization(self) -> None:
        nested: list = []
        for _ in range(preview_module.MAX_ARCHIVE_DEPTH + 2):
            nested = [nested]
        malformed = copy.deepcopy(self.bundle)
        malformed["extra"] = nested
        self.reader.record = PlanningBundleRecord(
            "tenant.synthetic.001",
            "context.synthetic.001",
            self.bundle["bundle_sha256"],
            malformed,
        )
        with self.assertRaisesRegex(OfflineVerifiedPlanningPreviewError, "structure limit"):
            build_offline_verified_planning_preview(**self.options())

    def test_wrong_tenant_context_scope_and_record_binding_fail_closed(self) -> None:
        for changed in (
            {"expected_tenant_id": "tenant.other"},
            {"expected_context_id": "context.other"},
            {"expected_scope_sha256": "sha256:" + "a" * 64},
            {"expected_bundle_sha256": "sha256:" + "b" * 64},
        ):
            with (
                self.subTest(changed=changed),
                self.assertRaises(OfflineVerifiedPlanningPreviewError),
            ):
                build_offline_verified_planning_preview(**self.options(**changed))
        self.reader.get = lambda *_: PlanningBundleRecord(
            "tenant.other", "context.synthetic.001", self.bundle["bundle_sha256"], self.bundle
        )
        with self.assertRaisesRegex(OfflineVerifiedPlanningPreviewError, "binding"):
            build_offline_verified_planning_preview(**self.options())

    def test_replay_inputs_must_be_exact_and_typed(self) -> None:
        with self.assertRaisesRegex(OfflineVerifiedPlanningPreviewError, "fields"):
            build_offline_verified_planning_preview(
                **self.options(planning_inputs=MappingProxyType(self.inputs))
            )
        with self.assertRaisesRegex(OfflineVerifiedPlanningPreviewError, "fields"):
            build_offline_verified_planning_preview(
                **self.options(planning_inputs={**self.inputs, "unrecognized": 1})
            )
        with self.assertRaisesRegex(OfflineVerifiedPlanningPreviewError, "fields"):
            build_offline_verified_planning_preview(
                **self.options(planning_inputs={"scope": self.fixture.scope})
            )

    def test_sqlite_archive_is_replayed_without_modifying_the_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SQLitePlanningBundleStore(
                Path(directory) / "planning.sqlite3", self.fixture.registry
            )
            store.put(self.reader.record)
            before = store.path.read_bytes()
            preview = build_offline_verified_planning_preview(**self.options(reader=store))
            self.assertEqual(preview["bundle_sha256"], self.bundle["bundle_sha256"])
            self.assertEqual(store.path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
