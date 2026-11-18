"""Exact role-to-API response linkage over sanitized metadata."""

from __future__ import annotations

import unittest
from dataclasses import replace

from sunderkey.api_role_response_matrix import (
    ApiRoleResponseError,
    build_api_role_response_matrix,
    verify_api_role_response_matrix_from_sources,
)
from sunderkey.traffic_derived_api_inventory import (
    SanitizedApiTrafficObservation,
    build_traffic_api_inventory,
)

CONTEXT_SHA = "sha256:" + "c" * 64
SCOPE_SHA = "sha256:" + "d" * 64
SOURCE_SHA = "sha256:" + "e" * 64


def observation(
    event_id: str, *, role: str = "role:reader", status: int = 200,
    path: str = "/v1/users/{user_id}", scope_sha256: str = SCOPE_SHA,
):
    return SanitizedApiTrafficObservation(
        event_id=event_id, tenant_id="tenant:one", context_id="context:one",
        context_sha256=CONTEXT_SHA, scope_id="scope:one",
        scope_sha256=scope_sha256, collector_id="collector:approved",
        source_sha256=SOURCE_SHA, observed_at="2026-09-23T12:05:00Z",
        origin="https://api.example.test", method="GET", path_shape=path,
        role_ref=role, status_code=status,
    )


def inventory(events):
    return build_traffic_api_inventory(
        observations=tuple(events), tenant_id="tenant:one",
        context_id="context:one", context_sha256=CONTEXT_SHA,
        scope_id="scope:one", scope_sha256=SCOPE_SHA,
        snapshot_at="2026-09-23T12:10:00Z",
    )


class ApiRoleResponseMatrixTests(unittest.TestCase):
    def setUp(self):
        self.reader = observation("event:reader", role="role:reader", status=200)
        self.writer = observation("event:writer", role="role:writer", status=403)
        self.inventory = inventory((self.reader, self.writer))

    def test_role_status_pairing_is_retained_without_authorization_verdict(self):
        result = build_api_role_response_matrix(
            inventory=self.inventory, observations=(self.writer, self.reader),
        )
        self.assertEqual(
            [(row.role_ref, row.status_codes) for row in result.rows],
            [("role:reader", (200,)), ("role:writer", (403,))],
        )
        self.assertEqual(self.inventory.endpoints[0].status_codes, (200, 403))
        self.assertEqual(self.inventory.endpoints[0].role_refs, (
            "role:reader", "role:writer",
        ))
        self.assertEqual(result.to_dict()["effects"]["authorization_verdict"], "none")
        self.assertEqual(result.to_dict()["effects"]["authority"], "none")
        self.assertEqual(result.inventory_sha256, self.inventory.inventory_sha256)

    def test_duplicate_identical_event_is_deduplicated(self):
        result = build_api_role_response_matrix(
            inventory=self.inventory,
            observations=(self.reader, self.reader, self.writer),
        )
        self.assertEqual(sum(row.event_count for row in result.rows), 2)

    def test_missing_conflicting_and_cross_scope_events_fail_closed(self):
        with self.assertRaisesRegex(ApiRoleResponseError, "exactly cover"):
            build_api_role_response_matrix(
                inventory=self.inventory, observations=(self.reader,),
            )
        with self.assertRaisesRegex(ApiRoleResponseError, "conflicting"):
            build_api_role_response_matrix(
                inventory=self.inventory,
                observations=(self.reader, replace(self.reader, status_code=403), self.writer),
            )
        with self.assertRaisesRegex(ApiRoleResponseError, "scope differs"):
            build_api_role_response_matrix(
                inventory=self.inventory,
                observations=(replace(self.reader, scope_sha256="sha256:" + "f" * 64),
                              self.writer),
            )

    def test_extra_event_and_tampered_matrix_fail_closed(self):
        with self.assertRaisesRegex(ApiRoleResponseError, "exactly cover"):
            build_api_role_response_matrix(
                inventory=self.inventory,
                observations=(self.reader, self.writer, observation("event:extra")),
            )
        result = build_api_role_response_matrix(
            inventory=self.inventory, observations=(self.reader, self.writer),
        )
        with self.assertRaisesRegex(ApiRoleResponseError, "matrix_sha256"):
            replace(result, scope_id="scope:two")

    def test_no_observed_events_produces_no_role_claims(self):
        result = build_api_role_response_matrix(
            inventory=inventory(()), observations=(),
        )
        self.assertEqual(result.rows, ())

    def test_matrix_source_replay_requires_exact_inventory_and_events(self):
        result = build_api_role_response_matrix(
            inventory=self.inventory, observations=(self.reader, self.writer),
        )
        self.assertEqual(
            verify_api_role_response_matrix_from_sources(
                result,
                inventory=self.inventory,
                observations=(self.writer, self.reader, self.reader),
            ),
            result,
        )
        with self.assertRaisesRegex(ApiRoleResponseError, "exactly cover"):
            verify_api_role_response_matrix_from_sources(
                result, inventory=self.inventory, observations=(self.reader,),
            )
        changed_inventory = inventory((self.reader,))
        with self.assertRaisesRegex(ApiRoleResponseError, "exactly cover"):
            verify_api_role_response_matrix_from_sources(
                result,
                inventory=changed_inventory,
                observations=(self.reader, self.writer),
            )

    def test_mutated_observation_metadata_is_rejected_before_row_build(self):
        event = observation("event:one")
        result_inventory = inventory((event,))
        object.__setattr__(event, "collector_id", "collector:altered")
        with self.assertRaisesRegex(ApiRoleResponseError, "integrity"):
            build_api_role_response_matrix(
                inventory=result_inventory,
                observations=(event,),
            )


if __name__ == "__main__":
    unittest.main()
