"""Traffic consumers verify and own the metadata behind supplied source digests."""

from __future__ import annotations

import unittest
from dataclasses import replace
from unittest.mock import patch

import sunderkey.api_role_response_matrix as matrices
import sunderkey.traffic_derived_api_inventory as traffic
from tests.agents.test_traffic_derived_api_inventory import inventory, observation

OLD_OBSERVATION_SHA = "sha256:d1d570365bb0f62e4f1e88926530d5a3d2f2b407a223b25ec4f22f91ad88e545"
WINDOW_BOUND_INVENTORY_SHA = (
    "sha256:aa4360ff2cc50d8bca9d9bef173eb2cc45e7c8ad93f267347cb45da4bd70a9d6"
)
WINDOW_BOUND_MATRIX_SHA = "sha256:671a93b9d1f971ce4804edbe1f6365815b843446b070417ce706fd514c41c574"


def matrix(source_inventory, *events):
    return matrices.build_api_role_response_matrix(
        inventory=source_inventory, observations=tuple(events)
    )


class ApiTrafficObservationIntegrityTests(unittest.TestCase):
    def test_window_bound_source_addresses_are_pinned(self) -> None:
        # Observation is unchanged from 2d1201b. Inventory binds #412's age window.
        # Matrix identity follows that explicit inventory identity change.
        event = observation("event:integrity")
        result = inventory(event)
        self.assertEqual(event.observation_sha256, OLD_OBSERVATION_SHA)
        self.assertEqual(result.inventory_sha256, WINDOW_BOUND_INVENTORY_SHA)
        self.assertEqual(matrix(result, event).matrix_sha256, WINDOW_BOUND_MATRIX_SHA)

    def test_valid_field_changes_cannot_retain_an_old_source_digest(self) -> None:
        changes = {
            "event_id": "event:changed",
            "tenant_id": "tenant:changed",
            "context_id": "context:changed",
            "context_sha256": "sha256:" + "e" * 64,
            "scope_id": "scope:changed",
            "scope_sha256": "sha256:" + "e" * 64,
            "collector_id": "collector:changed",
            "source_sha256": "sha256:" + "e" * 64,
            "observed_at": "2026-09-23T11:58:00Z",
            "origin": "https://other.example.test",
            "method": "POST",
            "path_shape": "/v1/changed",
            "role_ref": "role:changed",
            "status_code": 403,
        }
        for field, value in changes.items():
            event = observation("event:integrity")
            before = inventory(event)
            original_sha = event.observation_sha256
            object.__setattr__(event, field, value)
            with self.subTest(field=field):
                self.assertEqual(event.observation_sha256, original_sha)
                with self.assertRaisesRegex(traffic.TrafficApiInventoryError, "match content"):
                    inventory(event)
                with self.assertRaisesRegex(matrices.ApiRoleResponseError, "integrity"):
                    matrix(before, event)

    def test_invalid_mutated_fields_are_revalidated_not_aggregated(self) -> None:
        for field, value in (
            ("status_code", True),
            ("status_code", 200.0),
            ("status_code", 600),
            ("method", "TRACE"),
            ("origin", "http://api.example.test"),
            ("path_shape", "/../private"),
            ("role_ref", "admin"),
        ):
            event = observation("event:integrity")
            before = inventory(event)
            object.__setattr__(event, field, value)
            with self.subTest(field=field, value=value):
                with self.assertRaises(traffic.TrafficApiInventoryError):
                    inventory(event)
                with self.assertRaises(matrices.ApiRoleResponseError):
                    matrix(before, event)

    def test_missing_or_custom_digest_fields_are_rejected(self) -> None:
        class Digest(str):
            pass

        for value in (None, True, 1.0, "", "sha256:" + "0" * 64, Digest(OLD_OBSERVATION_SHA)):
            event = observation("event:integrity")
            before = inventory(event)
            object.__setattr__(event, "observation_sha256", value)
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(traffic.TrafficApiInventoryError):
                    inventory(event)
                with self.assertRaises(matrices.ApiRoleResponseError):
                    matrix(before, event)
        for field in ("observation_sha256", "status_code"):
            event = observation("event:integrity")
            before = inventory(event)
            object.__delattr__(event, field)
            with self.subTest(missing=field):
                with self.assertRaises(traffic.TrafficApiInventoryError):
                    inventory(event)
                with self.assertRaises(matrices.ApiRoleResponseError):
                    matrix(before, event)

    def test_reconstruction_cannot_trust_a_subclass_body_override(self) -> None:
        class ShadowBody(traffic.SanitizedApiTrafficObservation):
            def body(self):
                return {**super().body(), "status_code": 200}

        event = ShadowBody(**observation("event:integrity", status_code=403).body())
        self.assertEqual(event.observation_sha256, OLD_OBSERVATION_SHA)
        with self.assertRaisesRegex(traffic.TrafficApiInventoryError, "match content"):
            inventory(event)

    def test_owned_snapshot_is_used_even_if_original_changes_after_capture(self) -> None:
        original_verify = traffic._verified_observation

        def capture_then_change(event):
            captured = original_verify(event)
            object.__setattr__(event, "status_code", 403)
            return captured

        event = observation("event:integrity")
        with patch.object(traffic, "_verified_observation", side_effect=capture_then_change):
            result = inventory(event)
        self.assertEqual(result.inventory_sha256, WINDOW_BOUND_INVENTORY_SHA)
        self.assertEqual(result.endpoints[0].status_codes, (200,))
        event = observation("event:integrity")
        with patch.object(matrices, "_verified_observation", side_effect=capture_then_change):
            roles = matrix(result, event)
        self.assertEqual(roles.matrix_sha256, WINDOW_BOUND_MATRIX_SHA)
        self.assertEqual(roles.rows[0].status_codes, (200,))

    def test_explicit_new_observation_identity_and_duplicate_semantics_are_preserved(self) -> None:
        event = observation("event:integrity")
        changed = replace(event, status_code=403)
        self.assertNotEqual(changed.observation_sha256, event.observation_sha256)
        result = inventory(changed, changed)
        self.assertEqual(result.endpoints[0].event_count, 1)
        self.assertEqual(matrix(result, changed, changed).rows[0].status_codes, (403,))
        with self.assertRaisesRegex(traffic.TrafficApiInventoryError, "conflicting"):
            inventory(event, changed)


if __name__ == "__main__":
    unittest.main()
