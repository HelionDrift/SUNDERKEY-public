"""Three offline API and candidate-history composition regressions."""

from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from sunderkey.api_release_delta_review import (
    ApiReleaseDeltaError,
    compare_api_release_inventories,
    verify_api_release_delta_from_sources,
)
from sunderkey.api_release_role_response_review import (
    ApiReleaseRoleResponseReviewError,
    compare_api_release_role_responses,
    verify_api_release_role_response_review,
)
from sunderkey.api_role_response_matrix import (
    ApiRoleResponseError,
    build_api_role_response_matrix,
    verify_api_role_response_matrix_from_sources,
)
from sunderkey.event_assessment_history import (
    EventAssessmentHistoryError,
    OfflineEventAssessmentHistoryStore,
)
from sunderkey.event_assessment_planning import (
    CandidateDisposition,
    EventAssessmentError,
    EventKind,
    event_from_evidence,
)
from sunderkey.traffic_derived_api_inventory import (
    SanitizedApiTrafficObservation,
    TrafficApiInventoryError,
    build_traffic_api_inventory,
    load_traffic_api_inventory_json,
    verify_traffic_api_inventory_from_sources,
)

TEMP_PARENT = Path(tempfile.gettempdir())
CONTEXT_SHA = "sha256:" + "c" * 64
SCOPE_SHA = "sha256:" + "d" * 64
SOURCE_SHA = "sha256:" + "e" * 64
RELEASE_SHA = "sha256:" + "f" * 64
RELEASE_AT = "2026-09-23T12:00:00Z"
AGE = 7 * 24 * 60 * 60
SNAPSHOTS = {"before": "2026-09-23T11:59:00Z", "after": "2026-09-23T12:10:00Z"}
OBSERVED = {"before": "2026-09-23T11:55:00Z", "after": "2026-09-23T12:05:00Z"}


class EqualText(str):
    def __eq__(self, other):
        return True

    __hash__ = str.__hash__


class NativeAge(int):
    def __int__(self):
        raise AssertionError("custom conversion must not execute")


def observation(event_id, *, side="before", role="role:reader", status=200, **changes):
    values = {
        "event_id": event_id,
        "tenant_id": "tenant:one",
        "context_id": "context:one",
        "context_sha256": CONTEXT_SHA,
        "scope_id": "scope:one",
        "scope_sha256": SCOPE_SHA,
        "collector_id": "collector:metadata",
        "source_sha256": SOURCE_SHA,
        "observed_at": OBSERVED[side],
        "origin": "https://api.example.test",
        "method": "GET",
        "path_shape": "/records/{id}",
        "role_ref": role,
        "status_code": status,
    }
    values.update(changes)
    return SanitizedApiTrafficObservation(**values)


def inventory(events, *, side, **changes):
    values = {
        "observations": tuple(events),
        "tenant_id": "tenant:one",
        "context_id": "context:one",
        "context_sha256": CONTEXT_SHA,
        "scope_id": "scope:one",
        "scope_sha256": SCOPE_SHA,
        "snapshot_at": SNAPSHOTS[side],
        "maximum_age_seconds": AGE,
    }
    values.update(changes)
    return build_traffic_api_inventory(**values)


def archives_and_sources():
    before = (
        observation("event:reader-before"),
        observation("event:writer-before", role="role:writer", status=403),
    )
    after = (
        observation("event:reader-after", side="after", status=403),
        observation("event:writer-after", side="after", role="role:writer"),
    )
    baseline = load_traffic_api_inventory_json(
        json.dumps(inventory(before, side="before").to_dict()).encode("utf-8")
    )
    current = load_traffic_api_inventory_json(
        json.dumps(inventory(after, side="after").to_dict()).encode("utf-8")
    )
    return {
        "baseline": baseline,
        "current": current,
        "baseline_observations": before,
        "current_observations": after,
        "release_id": "release:one",
        "release_artifact_sha256": RELEASE_SHA,
        "release_at": RELEASE_AT,
    }


def delta_options(options):
    return {name: value for name, value in options.items() if not name.endswith("observations")}


def release_event(options):
    review = compare_api_release_role_responses(**options)
    verified = verify_api_release_role_response_review(review=review, **options)
    return review, event_from_evidence(verified, observed_at=SNAPSHOTS["after"])


class ApiStackCompositionTests(unittest.TestCase):
    def test_archive_source_matrix_release_event_and_durable_restart(self):
        options = archives_and_sources()
        matrices = []
        for side in ("baseline", "current"):
            archive = options[side]
            owned = verify_traffic_api_inventory_from_sources(
                archive, observations=options[side + "_observations"]
            )
            self.assertEqual(owned, archive)
            self.assertIsNot(owned, archive)
            self.assertEqual(owned.maximum_age_seconds, AGE)
            self.assertIs(type(owned.maximum_age_seconds), int)
            self.assertEqual(owned.to_dict()["authority_effect"], "none")
            self.assertEqual(owned.to_dict()["qualification_effect"], "none")
            self.assertFalse(owned.to_dict()["network_call_performed"])
            supplied = replace(archive, maximum_age_seconds=NativeAge(AGE))
            captured = verify_traffic_api_inventory_from_sources(
                supplied, observations=options[side + "_observations"]
            )
            self.assertIs(type(captured.maximum_age_seconds), int)
            self.assertIs(type(supplied.maximum_age_seconds), NativeAge)
            matrix = build_api_role_response_matrix(
                inventory=owned, observations=options[side + "_observations"]
            )
            matrix = replace(matrix, tenant_id=EqualText(matrix.tenant_id))
            caller_row = matrix.rows[0]
            object.__setattr__(caller_row, "role_ref", EqualText(caller_row.role_ref))
            replayed = verify_api_role_response_matrix_from_sources(
                matrix, inventory=owned, observations=options[side + "_observations"]
            )
            self.assertIsNot(replayed, matrix)
            self.assertIs(type(replayed.tenant_id), str)
            self.assertIs(type(replayed.rows[0].role_ref), str)
            self.assertIs(type(matrix.tenant_id), EqualText)
            self.assertIs(type(caller_row.role_ref), EqualText)
            self.assertTrue(
                all(value == "none" for value in replayed.to_dict()["effects"].values())
            )
            matrices.append(replayed)

        legacy = compare_api_release_inventories(**delta_options(options))
        legacy = replace(legacy, release_id=EqualText(legacy.release_id))
        verified_delta = verify_api_release_delta_from_sources(
            legacy,
            **{
                name: value
                for name, value in options.items()
                if name in {"baseline", "current", "baseline_observations", "current_observations"}
            },
        )
        self.assertIsNot(verified_delta, legacy)
        self.assertIs(type(verified_delta.release_id), str)
        self.assertIs(type(legacy.release_id), EqualText)
        self.assertEqual(verified_delta.gate_status, "inconclusive")

        review, event = release_event(options)
        self.assertEqual(review.gate_status, "review_required")
        self.assertEqual(len(review.new_associations), 2)
        self.assertEqual(len(review.not_reobserved_associations), 2)
        self.assertEqual(review.reobserved_count, 0)
        self.assertEqual(review.inventory_delta_sha256, verified_delta.delta_sha256)
        self.assertEqual(review.baseline_matrix_sha256, matrices[0].matrix_sha256)
        self.assertEqual(review.current_matrix_sha256, matrices[1].matrix_sha256)
        self.assertEqual(event.kind, EventKind.API_RELEASE_DELTA)
        self.assertEqual(event.evidence_sha256, review.review_sha256)
        self.assertTrue(event.change_signal)
        self.assertNotEqual(event.evidence_sha256, verified_delta.delta_sha256)
        self.assertTrue(all(value == "none" for value in review.to_dict()["effects"].values()))

        with tempfile.TemporaryDirectory(dir=TEMP_PARENT, prefix="composition-") as directory:
            self.assertEqual(Path(directory).resolve().parent, TEMP_PARENT.resolve())
            path = Path(directory) / "history.sqlite3"
            store = OfflineEventAssessmentHistoryStore(path, SCOPE_SHA)
            store.initialize()
            first = store.append(
                request_id="eventreq:api-first", events=(event,), as_of="2026-09-23T13:00:00Z"
            )
            self.assertEqual(first.candidates[0].disposition, CandidateDisposition.REVIEW_CANDIDATE)
            self.assertTrue(all(value == "none" for value in first.to_dict()["effects"].values()))
            self.assertTrue(first.event_set_sha256.startswith("sha256:"))
            self.assertTrue(first.prior_candidate_set_sha256.startswith("sha256:"))
            before_verify = path.read_bytes()
            head = OfflineEventAssessmentHistoryStore(path, SCOPE_SHA).verify()
            self.assertEqual(head.head_sequence, 1)
            self.assertEqual(head.last_batch, first)
            self.assertEqual(path.read_bytes(), before_verify)
            replayed = OfflineEventAssessmentHistoryStore(path, SCOPE_SHA).append(
                request_id="eventreq:api-first", events=(event,), as_of="2026-09-23T13:00:00Z"
            )
            self.assertEqual(replayed, first)
            self.assertEqual(store.verify().head_sha256, head.head_sha256)

    def test_malformed_and_truthful_foreign_archives_fail_before_candidate_use(self):
        options = archives_and_sources()
        original = options["baseline"].to_dict()
        for change in (
            {"unknown": "not allowed"},
            {"maximum_age_seconds": True},
            {"maximum_age_seconds": AGE + 1},
            {"network_call_performed": True},
        ):
            with self.subTest(change=change), self.assertRaises(TrafficApiInventoryError):
                load_traffic_api_inventory_json(json.dumps({**original, **change}).encode("utf-8"))
        with self.assertRaises(TrafficApiInventoryError):
            load_traffic_api_inventory_json(
                ('{"maximum_age_seconds":1,' + json.dumps(original)[1:]).encode("utf-8")
            )
        old_shape = dict(original)
        del old_shape["maximum_age_seconds"]
        with self.assertRaises(TrafficApiInventoryError):
            load_traffic_api_inventory_json(json.dumps(old_shape).encode("utf-8"))
        # An intact archive is inspectable, but incomplete evidence cannot establish source use.
        inspected = load_traffic_api_inventory_json(json.dumps(original).encode("utf-8"))
        self.assertEqual(inspected.inventory_sha256, options["baseline"].inventory_sha256)
        with self.assertRaises(TrafficApiInventoryError):
            verify_traffic_api_inventory_from_sources(inspected, observations=())

        foreign_events = tuple(
            replace(item, scope_id="scope:other", scope_sha256="sha256:" + "9" * 64)
            for item in options["baseline_observations"]
        )
        foreign = inventory(
            foreign_events,
            side="before",
            scope_id="scope:other",
            scope_sha256="sha256:" + "9" * 64,
        )
        foreign = load_traffic_api_inventory_json(json.dumps(foreign.to_dict()).encode("utf-8"))
        self.assertEqual(
            verify_traffic_api_inventory_from_sources(foreign, observations=foreign_events), foreign
        )
        with self.assertRaises(TrafficApiInventoryError):
            verify_traffic_api_inventory_from_sources(
                foreign, observations=options["baseline_observations"]
            )
        foreign_matrix = build_api_role_response_matrix(
            inventory=foreign, observations=foreign_events
        )
        # The digest remains truthful to foreign scope; overridden equality cannot mask it.
        object.__setattr__(foreign_matrix, "scope_id", EqualText("scope:other"))
        object.__setattr__(foreign_matrix, "scope_sha256", EqualText("sha256:" + "9" * 64))
        with self.assertRaises(ApiRoleResponseError):
            verify_api_role_response_matrix_from_sources(
                foreign_matrix,
                inventory=options["baseline"],
                observations=options["baseline_observations"],
            )
        with self.assertRaises(ApiReleaseDeltaError):
            compare_api_release_inventories(**{**delta_options(options), "baseline": foreign})
        with self.assertRaises(ApiReleaseRoleResponseReviewError):
            compare_api_release_role_responses(**{**options, "baseline": foreign})
        review, event = release_event(options)
        with self.assertRaises(EventAssessmentError):
            event_from_evidence(review, observed_at="2026-09-23T12:09:59Z")

        with tempfile.TemporaryDirectory(dir=TEMP_PARENT, prefix="composition-") as directory:
            self.assertEqual(Path(directory).resolve().parent, TEMP_PARENT.resolve())
            store = OfflineEventAssessmentHistoryStore(
                Path(directory) / "history.sqlite3", "sha256:" + "9" * 64
            )
            store.initialize()
            original_head = store.verify()
            with self.assertRaises(EventAssessmentError):
                store.append(
                    request_id="eventreq:wrong-scope",
                    events=(event,),
                    as_of="2026-09-23T13:00:00Z",
                )
            self.assertEqual(store.verify(), original_head)

    def test_stopped_retry_exact_request_and_reviewed_duplicate_after_restart(self):
        _, event = release_event(archives_and_sources())
        with tempfile.TemporaryDirectory(dir=TEMP_PARENT, prefix="composition-") as directory:
            self.assertEqual(Path(directory).resolve().parent, TEMP_PARENT.resolve())
            path = Path(directory) / "history.sqlite3"
            store = OfflineEventAssessmentHistoryStore(path, SCOPE_SHA)
            store.initialize()
            stopped = store.append(
                request_id="eventreq:stopped-api",
                events=(event,),
                as_of="2026-09-23T13:00:00Z",
                intake_stopped=True,
            )
            self.assertEqual(stopped.candidates[0].disposition, CandidateDisposition.STOPPED)
            store = OfflineEventAssessmentHistoryStore(path, SCOPE_SHA)
            resumed = store.append(
                request_id="eventreq:resumed-api",
                events=(event,),
                as_of="2026-09-23T14:00:00Z",
            )
            self.assertEqual(
                resumed.candidates[0].disposition, CandidateDisposition.REVIEW_CANDIDATE
            )
            self.assertNotEqual(
                resumed.prior_candidate_set_sha256, stopped.prior_candidate_set_sha256
            )
            before_replay = store.verify()
            self.assertEqual(
                store.append(
                    request_id="eventreq:resumed-api",
                    events=(event,),
                    as_of="2026-09-23T14:00:00Z",
                ),
                resumed,
            )
            self.assertEqual(store.verify().head_sha256, before_replay.head_sha256)
            with self.assertRaises(EventAssessmentHistoryError):
                store.append(
                    request_id="eventreq:resumed-api",
                    events=(event,),
                    as_of="2026-09-23T14:01:00Z",
                )
            duplicate = OfflineEventAssessmentHistoryStore(path, SCOPE_SHA).append(
                request_id="eventreq:duplicate-api",
                events=(event,),
                as_of="2026-09-23T14:01:00Z",
            )
            self.assertEqual(duplicate.candidates[0].disposition, CandidateDisposition.DUPLICATE)
            final = store.verify()
            self.assertEqual(final.head_sequence, 3)
            self.assertEqual(final.last_batch, duplicate)
            self.assertTrue(
                all(value == "none" for value in duplicate.to_dict()["effects"].values())
            )


if __name__ == "__main__":
    unittest.main()
