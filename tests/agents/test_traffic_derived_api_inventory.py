"""Offline tests for redacted, traffic-derived API surface reconciliation."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from sunderkey.cli import build_parser
from sunderkey.errors import SunderkeyError
from sunderkey.service_contract_extractor import extract_service_contract_endpoints
from sunderkey.traffic_derived_api_inventory import (
    SanitizedApiTrafficObservation,
    TrafficApiInventoryError,
    build_traffic_api_inventory,
    load_traffic_api_inventory_json,
    verify_traffic_api_inventory_from_sources,
)

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
CONTEXT_SHA = "sha256:" + "c" * 64
SCOPE_SHA = "sha256:" + "d" * 64
NOW = "2026-09-23T12:00:00Z"


def observation(event_id: str, **changes: object) -> SanitizedApiTrafficObservation:
    fields = {
        "event_id": event_id,
        "tenant_id": "tenant:one",
        "context_id": "context:assessment-1",
        "context_sha256": CONTEXT_SHA,
        "scope_id": "scope:assessment-1",
        "scope_sha256": SCOPE_SHA,
        "collector_id": "collector:approved-metadata",
        "source_sha256": DIGEST_A,
        "observed_at": "2026-09-23T11:59:00Z",
        "origin": "https://api.example.test",
        "method": "GET",
        "path_shape": "/v1/users/{user_id}",
        "role_ref": "role:reader",
        "status_code": 200,
    }
    fields.update(changes)
    return SanitizedApiTrafficObservation(**fields)


def contract():
    document = {
        "openapi": "3.0.0",
        "info": {"title": "Example", "version": "1.0.0"},
        "servers": [{"url": "https://api.example.test"}],
        "paths": {
            "/v1/users/{id}": {"get": {"responses": {"200": {"description": "ok"}}}},
            "/v1/status": {"get": {"responses": {"200": {"description": "ok"}}}},
        },
    }
    return extract_service_contract_endpoints(
        json.dumps(document).encode("utf-8"),
        source_id="contract:api-1",
        media_type="application/json",
    )


def inventory(*events, contract_bundle=None):
    return build_traffic_api_inventory(
        observations=tuple(events),
        tenant_id="tenant:one",
        context_id="context:assessment-1",
        context_sha256=CONTEXT_SHA,
        scope_id="scope:assessment-1",
        scope_sha256=SCOPE_SHA,
        snapshot_at=NOW,
        contract_bundle=contract_bundle,
    )


class TrafficDerivedApiInventoryTests(unittest.TestCase):
    def test_documented_and_not_in_supplied_contract_are_kept_distinct(self) -> None:
        bundle = contract()
        first = observation("event:1")
        repeat = observation(
            "event:2", role_ref="role:writer", status_code=403, source_sha256=DIGEST_B
        )
        other = observation(
            "event:3", method="POST", path_shape="/v1/admin", role_ref="role:admin"
        )
        result = inventory(other, repeat, first, contract_bundle=bundle)
        self.assertEqual(len(result.endpoints), 2)
        documented = next(item for item in result.endpoints if item.method == "GET")
        self.assertEqual(documented.contract_state, "documented")
        self.assertEqual(documented.event_count, 2)
        self.assertEqual(documented.role_refs, ("role:reader", "role:writer"))
        self.assertEqual(documented.status_codes, (200, 403))
        self.assertEqual(documented.source_sha256, (DIGEST_A, DIGEST_B))
        undocumented = next(item for item in result.endpoints if item.method == "POST")
        self.assertEqual(undocumented.contract_state, "not_in_supplied_contract")
        self.assertEqual(
            len(result.not_definitively_observed_contract_endpoint_sha256), 1
        )
        self.assertFalse(result.to_dict()["network_call_performed"])
        self.assertEqual(result.to_dict()["authority_effect"], "none")

    def test_order_and_duplicate_delivery_do_not_change_inventory(self) -> None:
        first = observation("event:1")
        second = observation("event:2", role_ref="role:writer")
        left = inventory(first, second, first)
        right = inventory(second, first)
        self.assertEqual(left.inventory_sha256, right.inventory_sha256)
        self.assertEqual(left.endpoints[0].event_count, 2)
        self.assertEqual(left.endpoints[0].contract_state, "not_compared")

    def test_conflicting_event_identity_fails_closed(self) -> None:
        first = observation("event:1")
        conflict = observation("event:1", path_shape="/v1/other")
        with self.assertRaisesRegex(TrafficApiInventoryError, "conflicting"):
            inventory(first, conflict)

    def test_cross_boundary_and_stale_events_fail_closed(self) -> None:
        with self.assertRaisesRegex(TrafficApiInventoryError, "cross-boundary"):
            inventory(observation("event:1", tenant_id="tenant:other"))
        with self.assertRaisesRegex(TrafficApiInventoryError, "cross-boundary"):
            inventory(observation("event:1", scope_sha256=DIGEST_B))
        with self.assertRaisesRegex(TrafficApiInventoryError, "future or stale"):
            inventory(observation("event:1", observed_at="2026-08-01T00:00:00Z"))
        with self.assertRaisesRegex(TrafficApiInventoryError, "future or stale"):
            inventory(observation("event:1", observed_at="2026-09-24T00:00:00Z"))

    def test_raw_or_ambiguous_sensitive_metadata_is_rejected(self) -> None:
        bad_paths = (
            "/v1/users/123?token=value",
            "/v1//users",
            "/v1/../admin",
            "/v1/users/%31323",
            "/v1/users/alice@example.test",
        )
        for path in bad_paths:
            with self.subTest(path=path), self.assertRaisesRegex(
                TrafficApiInventoryError, "path_shape"
            ):
                observation("event:1", path_shape=path)
        with self.assertRaisesRegex(TrafficApiInventoryError, "role_ref"):
            observation("event:1", role_ref="alice@example.test")
        with self.assertRaisesRegex(TrafficApiInventoryError, "method"):
            observation("event:1", method=[])
        with self.assertRaisesRegex(TrafficApiInventoryError, "origin"):
            observation("event:1", origin="https://" + "a" * 300 + ".test")

    def test_template_ambiguity_is_not_called_undocumented(self) -> None:
        result = inventory(
            observation("event:1", path_shape="/v1/{dynamic}"),
            contract_bundle=contract(),
        )
        self.assertEqual(result.endpoints[0].contract_state, "ambiguous_template")

    def test_empty_inventory_does_not_claim_contract_coverage(self) -> None:
        result = inventory(contract_bundle=contract())
        self.assertEqual(result.endpoints, ())
        self.assertEqual(
            len(result.not_definitively_observed_contract_endpoint_sha256), 2
        )

    def test_content_address_and_endpoint_invariants_reject_tampering(self) -> None:
        result = inventory(observation("event:1"), contract_bundle=contract())
        with self.assertRaisesRegex(TrafficApiInventoryError, "does not match content"):
            replace(result, inventory_sha256=DIGEST_B)
        with self.assertRaisesRegex(TrafficApiInventoryError, "endpoint role_refs"):
            replace(result.endpoints[0], role_refs=("alice@example.test",))
        with self.assertRaisesRegex(TrafficApiInventoryError, "event coverage"):
            replace(result, observation_sha256=())

    def test_source_replay_requires_exact_observations_and_contract(self) -> None:
        first = observation("event:1")
        second = observation("event:2", role_ref="role:writer")
        bundle = contract()
        result = inventory(first, second, contract_bundle=bundle)
        self.assertEqual(
            verify_traffic_api_inventory_from_sources(
                result,
                observations=(second, first, first),
                contract_bundle=bundle,
            ),
            result,
        )
        with self.assertRaisesRegex(TrafficApiInventoryError, "source replay"):
            verify_traffic_api_inventory_from_sources(
                result,
                observations=(first,),
                contract_bundle=bundle,
            )
        with self.assertRaisesRegex(TrafficApiInventoryError, "source replay"):
            verify_traffic_api_inventory_from_sources(
                result,
                observations=(first, second),
            )

    def test_freshness_window_is_bound_to_inventory_content_address(self) -> None:
        event = observation("event:1")
        short = build_traffic_api_inventory(
            observations=(event,),
            tenant_id="tenant:one",
            context_id="context:assessment-1",
            context_sha256=CONTEXT_SHA,
            scope_id="scope:assessment-1",
            scope_sha256=SCOPE_SHA,
            snapshot_at=NOW,
            maximum_age_seconds=120,
        )
        long = inventory(event)
        self.assertNotEqual(short.inventory_sha256, long.inventory_sha256)
        self.assertEqual(short.to_dict()["maximum_age_seconds"], 120)
        with self.assertRaisesRegex(TrafficApiInventoryError, "does not match content"):
            replace(short, maximum_age_seconds=3600)

    def test_mutated_source_content_address_is_rejected(self) -> None:
        event = observation("event:1")
        object.__setattr__(event, "path_shape", "/v1/other")
        with self.assertRaisesRegex(TrafficApiInventoryError, "observation_sha256.*content"):
            inventory(event)

        bundle = contract()
        object.__setattr__(bundle, "bundle_sha256", DIGEST_B)
        with self.assertRaisesRegex(TrafficApiInventoryError, "integrity"):
            inventory(observation("event:2"), contract_bundle=bundle)

    def test_json_archive_round_trip_and_source_replay(self) -> None:
        event = observation("event:1")
        bundle = contract()
        result = inventory(event, contract_bundle=bundle)
        loaded = load_traffic_api_inventory_json(
            json.dumps(result.to_dict()).encode("utf-8")
        )
        self.assertEqual(loaded, result)
        self.assertEqual(
            SanitizedApiTrafficObservation.from_dict(event.to_dict()), event
        )
        self.assertEqual(
            verify_traffic_api_inventory_from_sources(
                loaded, observations=(event,), contract_bundle=bundle
            ),
            result,
        )

    def test_json_archive_rejects_duplicate_keys_unknown_fields_and_effects(self) -> None:
        result = inventory(observation("event:1"))
        document = result.to_dict()
        encoded = json.dumps(document).encode("utf-8")
        duplicated = encoded.replace(
            b'"tenant_id":', b'"tenant_id": "tenant:other", "tenant_id":', 1
        )
        with self.assertRaisesRegex(TrafficApiInventoryError, "repeats a key"):
            load_traffic_api_inventory_json(duplicated)
        document["unknown"] = "value"
        with self.assertRaisesRegex(TrafficApiInventoryError, "fields are invalid"):
            load_traffic_api_inventory_json(json.dumps(document).encode("utf-8"))
        document.pop("unknown")
        document["network_call_performed"] = 0
        with self.assertRaisesRegex(TrafficApiInventoryError, "effects are invalid"):
            load_traffic_api_inventory_json(json.dumps(document).encode("utf-8"))
        document = result.to_dict()
        document["endpoints"][0]["contract_state"] = []
        with self.assertRaisesRegex(TrafficApiInventoryError, "contract_state"):
            load_traffic_api_inventory_json(json.dumps(document).encode("utf-8"))
        with self.assertRaisesRegex(TrafficApiInventoryError, "nonfinite"):
            load_traffic_api_inventory_json(encoded.replace(b"false", b"NaN", 1))

    def test_json_archive_rejects_tampering_and_oversized_input(self) -> None:
        event = observation("event:1")
        result = inventory(event)
        document = result.to_dict()
        document["endpoints"][0]["path_shape"] = "/v1/other"
        with self.assertRaisesRegex(TrafficApiInventoryError, "does not match content"):
            load_traffic_api_inventory_json(json.dumps(document).encode("utf-8"))
        changed_observation = event.to_dict()
        changed_observation["collector_id"] = "collector:other"
        with self.assertRaisesRegex(TrafficApiInventoryError, "does not match content"):
            SanitizedApiTrafficObservation.from_dict(changed_observation)
        with self.assertRaisesRegex(TrafficApiInventoryError, "byte limit"):
            load_traffic_api_inventory_json(b" " * 16_000_001)

    def test_contract_match_count_is_bounded(self) -> None:
        result = inventory(observation("event:1"))
        matches = tuple(f"sha256:{index:064x}" for index in range(10_000))
        endpoint = replace(
            result.endpoints[0],
            contract_state="documented",
            matching_contract_endpoint_sha256=matches,
        )
        with self.assertRaisesRegex(TrafficApiInventoryError, "match count"):
            replace(result, endpoints=(endpoint,) * 6)

    def test_cli_verifies_archived_inventory_against_source_files(self) -> None:
        event = observation("event:1")
        bundle = contract()
        result = inventory(event, contract_bundle=bundle)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory_path = root / "inventory.json"
            observations_path = root / "observations.json"
            contract_path = root / "contract.json"
            inventory_path.write_text(json.dumps(result.to_dict()), encoding="utf-8")
            observations_path.write_text(json.dumps([event.to_dict()]), encoding="utf-8")
            contract_path.write_text(json.dumps(bundle.to_dict()), encoding="utf-8")
            args = build_parser().parse_args([
                "traffic-api-inventory-verify",
                "--inventory", str(inventory_path),
                "--observations", str(observations_path),
                "--contract-bundle", str(contract_path),
            ])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                args.handler(args)
            receipt = json.loads(output.getvalue())
            self.assertEqual(receipt["status"], "valid")
            self.assertEqual(receipt["inventory_sha256"], result.inventory_sha256)
            self.assertEqual(receipt["verification_scope"], "historical_source_replay_only")
            self.assertFalse(receipt["network_call_performed"])
            missing_contract_args = build_parser().parse_args([
                "traffic-api-inventory-verify",
                "--inventory", str(inventory_path),
                "--observations", str(observations_path),
            ])
            with self.assertRaisesRegex(SunderkeyError, "source replay"):
                missing_contract_args.handler(missing_contract_args)
            observations_path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(SunderkeyError, "source replay"):
                args.handler(args)
            observations_path.write_text(
                '{"event_id":"one","event_id":"two"}', encoding="utf-8"
            )
            with self.assertRaisesRegex(SunderkeyError, "Could not validate"):
                args.handler(args)


if __name__ == "__main__":
    unittest.main()
