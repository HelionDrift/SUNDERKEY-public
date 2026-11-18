"""Native scalar capture preserves truthful offline API evidence identities."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import fields, replace
from enum import IntEnum

import sunderkey.api_role_response_matrix as matrices
import sunderkey.traffic_derived_api_inventory as traffic
from sunderkey.api_release_delta_review import (
    ApiReleaseDeltaError,
    compare_api_release_inventories,
)
from sunderkey.api_release_role_response_review import (
    ApiReleaseRoleResponseReview,
    ApiReleaseRoleResponseReviewError,
    compare_api_release_role_responses,
    verify_api_release_role_response_review,
)
from sunderkey.assessment_transport_contracts import HttpMethod
from tests.agents.test_api_release_role_response_review import (
    observation as release_observation,
)
from tests.agents.test_api_release_role_response_review import sources as release_sources
from tests.agents.test_api_traffic_observation_integrity import (
    OLD_OBSERVATION_SHA,
    WINDOW_BOUND_INVENTORY_SHA,
    WINDOW_BOUND_MATRIX_SHA,
)
from tests.agents.test_traffic_derived_api_inventory import (
    CONTEXT_SHA,
    NOW,
    SCOPE_SHA,
    inventory,
    observation,
)

BINDINGS = {
    "tenant_id": "tenant:one",
    "context_id": "context:assessment-1",
    "context_sha256": CONTEXT_SHA,
    "scope_id": "scope:assessment-1",
    "scope_sha256": SCOPE_SHA,
}
FOREIGN = {
    "tenant_id": "tenant:other",
    "context_id": "context:other",
    "context_sha256": "sha256:" + "e" * 64,
    "scope_id": "scope:other",
    "scope_sha256": "sha256:" + "e" * 64,
}


class EqualText(str):
    __hash__ = str.__hash__

    def __eq__(self, other):
        return True


class HookText(str):
    def __str__(self):
        raise AssertionError("caller string conversion must not run")


class LaxInteger(int):
    def __ge__(self, other):
        return True

    def __le__(self, other):
        return True

    def __int__(self):
        return 200

    def __index__(self):
        return 200


class HookInteger(int):
    def __int__(self):
        raise AssertionError("caller integer conversion must not run")

    def __index__(self):
        raise AssertionError("caller integer index must not run")


class Status(IntEnum):
    OK = 200
    FORBIDDEN = 403


def plain(value):
    return json.loads(json.dumps(value, allow_nan=False))


def observation_address(event):
    return traffic._canonical_sha(
        "sunderkey.sanitized-api-traffic-observation.v1", plain(event.body())
    )


def inventory_address(source):
    body = plain(source.to_dict())
    for name in (
        "inventory_sha256",
        "authority_effect",
        "qualification_effect",
        "network_call_performed",
    ):
        body.pop(name)
    return traffic._canonical_sha("sunderkey.traffic-api-inventory.v1", body)


def requested_inventory(event, **binding_changes):
    """Address declared metadata exactly; matrix must check its source relation.

    This inert fixture never invents an observation digest or executes an adapter.
    Its inventory digest covers the underlying JSON, including the declared
    binding and exact event digest, whether those declarations agree or not.
    """

    endpoint = traffic.TrafficApiEndpoint(
        origin=event.origin,
        method=event.method,
        path_shape=event.path_shape,
        event_count=1,
        role_refs=(event.role_ref,),
        status_codes=(event.status_code,),
        first_observed_at=event.observed_at,
        last_observed_at=event.observed_at,
        source_sha256=(event.source_sha256,),
        contract_state="not_compared",
        matching_contract_endpoint_sha256=(),
    )
    values = {
        **BINDINGS,
        "snapshot_at": NOW,
        "maximum_age_seconds": 7 * 24 * 60 * 60,
        "contract_bundle_sha256": None,
        "observation_sha256": (event.observation_sha256,),
        "endpoints": (endpoint,),
        "not_definitively_observed_contract_endpoint_sha256": (),
    }
    values.update(binding_changes)
    payload = {
        **values,
        "observation_sha256": list(values["observation_sha256"]),
        "endpoints": [endpoint.to_dict()],
        "not_definitively_observed_contract_endpoint_sha256": [],
    }
    return traffic.TrafficApiInventory(
        **values,
        inventory_sha256=traffic._canonical_sha("sunderkey.traffic-api-inventory.v1", payload),
    )


class ApiTrafficScalarOwnershipTests(unittest.TestCase):
    def assert_truthful(self, event):
        self.assertEqual(event.observation_sha256, observation_address(event))

    def test_observation_subclass_equality_cannot_cross_any_binding(self):
        for name, actual in FOREIGN.items():
            with self.subTest(name=name):
                event = observation("event:foreign", **{name: EqualText(actual)})
                self.assert_truthful(event)
                self.assertEqual(plain(event.body())[name], actual)
                with self.assertRaisesRegex(traffic.TrafficApiInventoryError, "cross-boundary"):
                    inventory(event)

    def test_request_subclass_equality_cannot_cross_any_binding(self):
        for name, actual in FOREIGN.items():
            with self.subTest(name=name):
                event = observation("event:foreign", **{name: actual})
                self.assert_truthful(event)
                options = {
                    **BINDINGS,
                    "observations": (event,),
                    "snapshot_at": NOW,
                    name: EqualText(BINDINGS[name]),
                }
                with self.assertRaisesRegex(traffic.TrafficApiInventoryError, "cross-boundary"):
                    traffic.build_traffic_api_inventory(**options)

    def test_both_source_and_request_subclasses_preserve_underlying_difference(self):
        for name, actual in FOREIGN.items():
            with self.subTest(name=name):
                event = observation("event:foreign", **{name: EqualText(actual)})
                self.assert_truthful(event)
                options = {
                    **BINDINGS,
                    "observations": (event,),
                    "snapshot_at": NOW,
                    name: EqualText(BINDINGS[name]),
                }
                with self.assertRaisesRegex(traffic.TrafficApiInventoryError, "cross-boundary"):
                    traffic.build_traffic_api_inventory(**options)

    def test_matrix_owns_both_sides_before_binding_comparison(self):
        for name, actual in FOREIGN.items():
            for source_custom, request_custom in ((True, False), (False, True), (True, True)):
                with self.subTest(name=name, source=source_custom, request=request_custom):
                    event = observation(
                        "event:foreign", **{name: EqualText(actual) if source_custom else actual}
                    )
                    request = EqualText(BINDINGS[name]) if request_custom else BINDINGS[name]
                    source = requested_inventory(event, **{name: request})
                    self.assert_truthful(event)
                    self.assertEqual(source.inventory_sha256, inventory_address(source))
                    with self.assertRaisesRegex(matrices.ApiRoleResponseError, "context or scope"):
                        matrices.build_api_role_response_matrix(
                            inventory=source, observations=(event,)
                        )

    def test_native_integer_capture_rejects_truthful_out_of_bounds_status(self):
        for actual in (99, 600, 999):
            with self.subTest(actual=actual):
                event = observation("event:lax-status", status_code=LaxInteger(actual))
                self.assert_truthful(event)
                self.assertEqual(plain(event.body())["status_code"], actual)
                self.assertEqual(int(event.status_code), 200)
                with self.assertRaisesRegex(traffic.TrafficApiInventoryError, "status_code"):
                    inventory(event)
                source = requested_inventory(event)
                self.assertEqual(source.inventory_sha256, inventory_address(source))
                with self.assertRaisesRegex(matrices.ApiRoleResponseError, "inventory integrity"):
                    matrices.build_api_role_response_matrix(inventory=source, observations=(event,))

    def test_all_13_observation_text_fields_are_owned_without_conversion_hooks(self):
        original = observation("event:integrity")
        text_fields = [
            item.name for item in fields(original) if item.init and item.name != "status_code"
        ]
        self.assertEqual(len(text_fields), 13)
        values = {name: HookText(getattr(original, name)) for name in text_fields}
        values["status_code"] = HookInteger(200)
        event = traffic.SanitizedApiTrafficObservation(**values)
        self.assert_truthful(event)
        captured = traffic._verified_observation(event)
        self.assertIsNot(captured, event)
        self.assertEqual(captured.observation_sha256, original.observation_sha256)
        for name in text_fields:
            self.assertIs(type(getattr(captured, name)), str)
            self.assertIs(getattr(event, name), values[name])
        self.assertIs(type(captured.status_code), int)
        self.assertIs(event.status_code, values["status_code"])
        result = inventory(event)
        rows = matrices.build_api_role_response_matrix(inventory=result, observations=(event,))
        self.assertEqual(result.inventory_sha256, WINDOW_BOUND_INVENTORY_SHA)
        self.assertEqual(rows.matrix_sha256, WINDOW_BOUND_MATRIX_SHA)

    def test_requested_binding_conversion_hooks_do_not_run_and_output_is_primitive(self):
        event = observation("event:integrity")
        binding = {name: HookText(value) for name, value in BINDINGS.items()}
        snapshot = HookText(NOW)
        result = traffic.build_traffic_api_inventory(
            observations=(event,),
            **binding,
            snapshot_at=snapshot,
            maximum_age_seconds=HookInteger(86400),
        )
        self.assertEqual(
            result.inventory_sha256,
            "sha256:736cfa43231e579e2e3b5654dab271e481baa9d506575a30d7267e5e4f3f6901",
        )
        self.assertIs(type(result.maximum_age_seconds), int)
        self.assertEqual(result.maximum_age_seconds, 86400)
        for name in (*BINDINGS, "snapshot_at"):
            self.assertIs(type(getattr(result, name)), str)
        self.assertTrue(all(type(value) is HookText for value in binding.values()))
        self.assertIs(type(snapshot), HookText)

    def test_matrix_snapshot_owns_inventory_and_nested_endpoint_scalars(self):
        event = observation("event:integrity")
        source = inventory(event)
        endpoint = source.endpoints[0]
        endpoint_values = {item.name: getattr(endpoint, item.name) for item in fields(endpoint)}
        for name, value in tuple(endpoint_values.items()):
            if isinstance(value, str):
                endpoint_values[name] = HookText(value)
            elif isinstance(value, int):
                endpoint_values[name] = HookInteger(value)
            else:
                endpoint_values[name] = tuple(
                    HookText(item) if isinstance(item, str) else HookInteger(item) for item in value
                )
        caller_endpoint = traffic.TrafficApiEndpoint(**endpoint_values)
        caller = replace(
            source,
            endpoints=(caller_endpoint,),
            maximum_age_seconds=HookInteger(source.maximum_age_seconds),
            **{name: HookText(getattr(source, name)) for name in (*BINDINGS, "snapshot_at")},
        )
        captured = traffic._verified_inventory(caller)
        self.assertIsNot(captured, caller)
        self.assertIsNot(captured.endpoints[0], caller_endpoint)
        self.assertEqual(captured.inventory_sha256, source.inventory_sha256)
        self.assertIs(type(captured.maximum_age_seconds), int)
        self.assertIs(type(caller.maximum_age_seconds), HookInteger)
        for name in (*BINDINGS, "snapshot_at"):
            self.assertIs(type(getattr(captured, name)), str)
            self.assertIs(type(getattr(caller, name)), HookText)
        for value in captured.endpoints[0].to_dict().values():
            if isinstance(value, list):
                self.assertTrue(all(type(item) in (str, int) for item in value))
            else:
                self.assertIn(type(value), (str, int))
        rows = matrices.build_api_role_response_matrix(inventory=caller, observations=(event,))
        self.assertEqual(rows.matrix_sha256, WINDOW_BOUND_MATRIX_SHA)
        self.assertTrue(all(type(getattr(rows, name)) is str for name in BINDINGS))
        object.__setattr__(caller, "tenant_id", "tenant:changed")
        object.__setattr__(caller_endpoint, "status_codes", (403,))
        self.assertEqual(captured.tenant_id, "tenant:one")
        self.assertEqual(captured.endpoints[0].status_codes, (200,))
        self.assertEqual(rows.rows[0].status_codes, (200,))

    def test_inventory_freshness_capture_rejects_truthful_lax_integer_bounds(self):
        event = observation("event:integrity")
        for age in (0, traffic.MAX_AGE_SECONDS + 1):
            source = inventory(event)
            object.__setattr__(source, "maximum_age_seconds", LaxInteger(age))
            object.__setattr__(source, "inventory_sha256", inventory_address(source))
            with self.subTest(age=age):
                self.assertEqual(source.inventory_sha256, inventory_address(source))
                with self.assertRaisesRegex(
                    traffic.TrafficApiInventoryError, "maximum_age_seconds"
                ):
                    traffic._verified_inventory(source)
                with self.assertRaisesRegex(matrices.ApiRoleResponseError, "inventory integrity"):
                    matrices.build_api_role_response_matrix(
                        inventory=source, observations=(event,)
                    )

    def test_owned_observation_is_independent_after_caller_mutation(self):
        event = observation("event:integrity", method=HookText("GET"), status_code=HookInteger(200))
        captured = traffic._verified_observation(event)
        object.__setattr__(event, "method", "POST")
        object.__setattr__(event, "status_code", 403)
        self.assertEqual(captured.method, "GET")
        self.assertEqual(captured.status_code, 200)
        self.assertEqual(captured.observation_sha256, OLD_OBSERVATION_SHA)

    def test_bool_float_and_other_noninteger_statuses_are_still_rejected(self):
        for raw in (True, False, 200.0, "200", None):
            with self.subTest(raw=raw):
                event = observation("event:integrity")
                object.__setattr__(event, "status_code", raw)
                with self.assertRaises(traffic.TrafficApiInventoryError):
                    traffic._verified_observation(event)

    def test_supplied_digests_remain_verified_and_plain_observation_digest_is_required(self):
        event = observation("event:integrity")
        object.__setattr__(event, "observation_sha256", HookText(event.observation_sha256))
        with self.assertRaisesRegex(traffic.TrafficApiInventoryError, "plain digest"):
            traffic._verified_observation(event)
        event = observation("event:integrity")
        object.__setattr__(event, "status_code", HookInteger(403))
        with self.assertRaisesRegex(traffic.TrafficApiInventoryError, "match content"):
            traffic._verified_observation(event)
        source = inventory(observation("event:integrity"))
        object.__setattr__(source, "tenant_id", EqualText("tenant:other"))
        with self.assertRaisesRegex(traffic.TrafficApiInventoryError, "match content"):
            traffic._verified_inventory(source)

    def test_integer_age_subclasses_cannot_bypass_the_existing_bound(self):
        with self.assertRaisesRegex(traffic.TrafficApiInventoryError, "maximum_age_seconds"):
            traffic.build_traffic_api_inventory(
                observations=(observation("event:integrity"),),
                **BINDINGS,
                snapshot_at=NOW,
                maximum_age_seconds=LaxInteger(traffic.MAX_AGE_SECONDS + 1),
            )

    def test_http_method_and_integer_enums_build_and_replay_the_same_release(self):
        enum_before = release_observation("event:before", method=HttpMethod.GET, status=Status.OK)
        enum_after = release_observation(
            "event:after", side="after", method=HttpMethod.GET, status=Status.FORBIDDEN
        )
        options = release_sources((enum_before,), (enum_after,))
        review = compare_api_release_role_responses(**options)
        plain_options = release_sources(
            (release_observation("event:before", method="GET", status=200),),
            (release_observation("event:after", side="after", method="GET", status=403),),
        )
        expected = compare_api_release_role_responses(**plain_options)
        self.assertEqual(review.to_dict(), expected.to_dict())
        self.assertEqual(review.gate_status, "review_required")
        self.assertEqual(
            verify_api_release_role_response_review(review=review, **options).review_sha256,
            expected.review_sha256,
        )
        self.assertIs(enum_before.method, HttpMethod.GET)
        self.assertIs(enum_before.status_code, Status.OK)
        for item in (*review.new_associations, *review.not_reobserved_associations):
            self.assertIs(type(item.method), str)
            self.assertIs(type(item.status_code), int)
        for name, value in (("method", HttpMethod.GET), ("status_code", Status.FORBIDDEN)):
            changed = copy.deepcopy(review.to_dict())
            changed["new_associations"][0][name] = value
            with self.subTest(name=name):
                with self.assertRaises(ApiReleaseRoleResponseReviewError):
                    ApiReleaseRoleResponseReview.from_dict(changed)

    def test_window_bound_fixture_identities_stay_exact(self):
        event = observation("event:integrity")
        result = inventory(event)
        rows = matrices.build_api_role_response_matrix(inventory=result, observations=(event,))
        self.assertEqual(event.observation_sha256, OLD_OBSERVATION_SHA)
        self.assertEqual(result.inventory_sha256, WINDOW_BOUND_INVENTORY_SHA)
        self.assertEqual(rows.matrix_sha256, WINDOW_BOUND_MATRIX_SHA)

    def test_oversized_tuple_subclass_cannot_hide_size_or_invoke_iterator(self):
        class HiddenTuple(tuple):
            def __len__(self):
                return 0

            def __iter__(self):
                raise AssertionError("oversized tuple must be rejected before capture")

        event = observation("event:integrity")
        window = HiddenTuple((event,) * (traffic.MAX_OBSERVATIONS + 1))
        self.assertEqual(tuple.__len__(window), traffic.MAX_OBSERVATIONS + 1)
        with self.assertRaisesRegex(traffic.TrafficApiInventoryError, "hard limit"):
            traffic.build_traffic_api_inventory(observations=window, **BINDINGS, snapshot_at=NOW)
        with self.assertRaisesRegex(matrices.ApiRoleResponseError, "bounded tuple"):
            matrices.build_api_role_response_matrix(inventory=inventory(), observations=window)

    def test_native_tuple_capture_ignores_iteration_swaps_and_length_hooks(self):
        first = observation("event:integrity")
        other = observation("event:substituted", status_code=403)

        class SwappedTuple(tuple):
            def __len__(self):
                raise AssertionError("caller tuple length must not run")

            def __iter__(self):
                return iter((other,))

        window = SwappedTuple((first,))
        source = traffic.build_traffic_api_inventory(
            observations=window, **BINDINGS, snapshot_at=NOW
        )
        rows = matrices.build_api_role_response_matrix(inventory=source, observations=window)
        self.assertEqual(source.inventory_sha256, WINDOW_BOUND_INVENTORY_SHA)
        self.assertEqual(rows.matrix_sha256, WINDOW_BOUND_MATRIX_SHA)
        self.assertEqual(rows.rows[0].status_codes, (200,))
        self.assertIs(tuple.__getitem__(window, 0), first)

    def test_truthful_empty_inventories_cannot_cross_legacy_or_wrapper_lineage(self):
        before_time = "2026-09-23T01:00:00Z"
        after_time = "2026-09-23T03:00:00Z"
        release_time = "2026-09-23T02:00:00Z"
        for name, actual in FOREIGN.items():
            for side in ("baseline", "current"):
                with self.subTest(name=name, side=side):
                    before = traffic.build_traffic_api_inventory(
                        observations=(), **BINDINGS, snapshot_at=before_time
                    )
                    after = traffic.build_traffic_api_inventory(
                        observations=(), **BINDINGS, snapshot_at=after_time
                    )
                    options = {"baseline": before, "current": after}
                    foreign = traffic.build_traffic_api_inventory(
                        observations=(),
                        **{**BINDINGS, name: actual},
                        snapshot_at=before_time if side == "baseline" else after_time,
                    )
                    foreign = replace(foreign, **{name: EqualText(actual)})
                    self.assertEqual(foreign.inventory_sha256, inventory_address(foreign))
                    options[side] = foreign
                    release = {
                        **options,
                        "release_id": "release:lineage",
                        "release_artifact_sha256": "sha256:" + "f" * 64,
                        "release_at": release_time,
                    }
                    with self.assertRaisesRegex(ApiReleaseDeltaError, "lineage differs"):
                        compare_api_release_inventories(**release)
                    with self.assertRaisesRegex(
                        ApiReleaseRoleResponseReviewError, "source replay failed"
                    ):
                        compare_api_release_role_responses(
                            **release, baseline_observations=(), current_observations=()
                        )

    def test_legacy_and_wrapper_own_metadata_and_preserve_pinned_identities(self):
        before = release_observation("event:pinned-before")
        after = release_observation("event:pinned-after", side="after", status=403)
        options = release_sources((before,), (after,))
        for side in ("baseline", "current"):
            original = options[side]
            options[side] = replace(
                original,
                **{name: HookText(getattr(original, name)) for name in (*BINDINGS, "snapshot_at")},
            )
        for name in ("release_id", "release_artifact_sha256", "release_at"):
            options[name] = HookText(options[name])
        delta = compare_api_release_inventories(
            **{name: value for name, value in options.items() if not name.endswith("observations")}
        )
        review = compare_api_release_role_responses(**options)
        self.assertEqual(
            delta.delta_sha256,
            "sha256:0373577587f56902886a0114e6031db4bfe02490e9e659390b095daa20b88846",
        )
        self.assertEqual(
            review.review_sha256,
            "sha256:2d4bffed148e2acb76e722cfb48987738228a42a895aff589ac134aba452d85b",
        )
        for record in (delta, review):
            for name in (*BINDINGS, "release_id", "release_artifact_sha256", "release_at"):
                self.assertIs(type(getattr(record, name)), str)
        self.assertIs(type(review.baseline_snapshot_at), str)
        self.assertIs(type(review.current_snapshot_at), str)
        self.assertIs(type(options["baseline"].snapshot_at), HookText)
        self.assertIs(type(options["current"].tenant_id), HookText)
        self.assertIs(type(options["release_id"]), HookText)
        self.assertEqual(
            verify_api_release_role_response_review(review=review, **options).review_sha256,
            review.review_sha256,
        )


if __name__ == "__main__":
    unittest.main()
