from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, ValidationError

from sunderkey.errors import StoreIntegrityError
from sunderkey.mission_store_action_authority import (
    ActionAuthorityMaterialSnapshot,
    ActionAuthorityObservation,
    _canonical_sha256,
    action_fence_token_sha256,
    build_action_authority_observation,
)

from .test_mission_store_action_authority_phase195b import (
    MissionStoreActionAuthorityPhase195bTests,
)

SCHEMA_DIRECTORY = Path(__file__).parents[2] / "registry" / "schemas"
MATERIAL_SCHEMA = SCHEMA_DIRECTORY / "action-authority-material-snapshot-v1.schema.json"
PUBLICATION_SCHEMA = SCHEMA_DIRECTORY / "authenticated-action-authority-publication-v1.schema.json"
OBSERVATION_SCHEMA = SCHEMA_DIRECTORY / "action-authority-observation-v1.schema.json"


def _schema(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _high_water() -> dict[str, Any]:
    body = {
        "application_id": "application:001",
        "application_sha256": _digest("1"),
        "closure_id": "review-closure:001",
        "closure_sha256": _digest("2"),
        "event_count": 4,
        "event_head_occurred_at": 1_790_000_000,
        "event_head_sha256": _digest("3"),
        "mission_id": "mission:001",
        "mission_store_id": "mission-store:001",
        "revocation_id": None,
        "revocation_sha256": None,
        "snapshot_id": "review-snapshot:001",
        "snapshot_sha256": _digest("4"),
        "state": "closure_applied_unrevoked",
        "workspace_id": "workspace:001",
        "workspace_revision": 4,
        "workspace_store_id": "workspace-store:001",
        "workspace_store_path": r"C:\example\workspaces\workspace-001.db",
    }
    digest = _canonical_sha256(
        {"domain": "sunderkey.action-workspace-high-water.v1", "high_water": body}
    )
    return {
        **body,
        "high_water_id": "AWH-" + digest.removeprefix("sha256:")[:32].upper(),
        "high_water_sha256": digest,
    }


def _observations() -> tuple[ActionAuthorityObservation, ...]:
    material, _ = MissionStoreActionAuthorityPhase195bTests()._records()
    value = material.to_dict()
    worker = value["worker_session"]
    credential = value["credential_lease"]
    health = value["health"]
    stop = value["stop_conditions"]
    observed_at = "2026-09-21T10:30:00Z"
    valid_until = "2026-09-21T10:35:00Z"
    fence = action_fence_token_sha256(
        session_authority_id="session-authority:001",
        execution_session_id=worker["session_id"],
        owner_epoch=worker["leader_epoch"],
        fence_generation=9,
    )
    high_water = _high_water()
    payloads = {
        "execution_fence_observation": {
            "session_authority_id": "session-authority:001",
            "session_authority_sha256": _digest("5"),
            "execution_session_id": worker["session_id"],
            "execution_session_sha256": _digest("6"),
            "owner_epoch": worker["leader_epoch"],
            "fence_generation": 9,
            "fence_token_sha256": fence,
        },
        "credential_lease_observation": {
            "credential_lease": credential,
            "credential_lease_sha256": value["credential_lease_sha256"],
        },
        "executor_health_observation": {
            "health": health,
            "health_observation_sha256": value["health_observation_sha256"],
        },
        "executor_deployment_observation": {
            "worker_session": worker,
            "executor_deployment_sha256": value["executor_deployment_sha256"],
        },
        "stop_monitor_observation": {
            "monitor_id": "monitor:001",
            "principal_profile_id": stop["monitor_worker_id"],
            "principal_subject": "subject:monitor",
            "monitor_session_id": stop["monitor_session_id"],
            "monitor_worker_id": stop["monitor_worker_id"],
            "monitor_observation_sha256": value["monitor_observation_sha256"],
            "status": "healthy",
            "heartbeat_observed_at": observed_at,
            "heartbeat_expires_at": stop["expires_at"],
        },
        "workspace_high_water_observation": {
            "high_water": high_water,
            "high_water_sha256": high_water["high_water_sha256"],
        },
    }
    return tuple(
        build_action_authority_observation(
            observation_kind=kind,
            tenant_id="tenant:001",
            mission_id="mission:001",
            plan_id="plan:001",
            payload=payload,
            observed_at=observed_at,
            valid_until=valid_until,
        )
        for kind, payload in payloads.items()
    )


class ActionAuthoritySchemaPhase195bTests(unittest.TestCase):
    def test_schemas_are_valid_and_every_object_is_closed(self) -> None:
        for path in (MATERIAL_SCHEMA, PUBLICATION_SCHEMA, OBSERVATION_SCHEMA):
            schema = _schema(path)
            Draft202012Validator.check_schema(schema)

            def assert_closed(node: object, schema_name: str = path.name) -> None:
                if isinstance(node, dict):
                    if node.get("type") == "object" and "properties" in node:
                        self.assertIs(
                            node.get("additionalProperties"),
                            False,
                            f"object in {schema_name} is not closed",
                        )
                    for child in node.values():
                        assert_closed(child)
                elif isinstance(node, list):
                    for child in node:
                        assert_closed(child)

            assert_closed(schema)

    def test_runtime_material_publication_and_all_observations_validate(self) -> None:
        material, publication = MissionStoreActionAuthorityPhase195bTests()._records()
        Draft202012Validator(_schema(MATERIAL_SCHEMA)).validate(material.to_dict())
        Draft202012Validator(_schema(PUBLICATION_SCHEMA)).validate(publication.to_dict())
        observation_validator = Draft202012Validator(_schema(OBSERVATION_SCHEMA))
        observations = _observations()
        self.assertEqual(len(observations), 6)
        for observation in observations:
            observation_validator.validate(observation.to_dict())

    def test_unknown_fields_fail_at_every_contract_boundary(self) -> None:
        material, publication = MissionStoreActionAuthorityPhase195bTests()._records()
        material_value = material.to_dict()
        material_value["catalog"]["entries"][0]["unknown"] = True
        with self.assertRaises(ValidationError):
            Draft202012Validator(_schema(MATERIAL_SCHEMA)).validate(material_value)

        publication_value = publication.to_dict()
        publication_value["source_records"][0]["unknown"] = True
        with self.assertRaises(ValidationError):
            Draft202012Validator(_schema(PUBLICATION_SCHEMA)).validate(publication_value)

        observation_value = _observations()[0].to_dict()
        observation_value["payload"]["unknown"] = True
        with self.assertRaises(ValidationError):
            Draft202012Validator(_schema(OBSERVATION_SCHEMA)).validate(observation_value)

    def test_control_characters_hashes_timestamps_and_bounds_fail_closed(self) -> None:
        material, _ = MissionStoreActionAuthorityPhase195bTests()._records()
        validator = Draft202012Validator(_schema(MATERIAL_SCHEMA))
        bad_identifier = material.to_dict()
        bad_identifier["resolver_subject"] = "subject:\u0007control"
        with self.assertRaises(ValidationError):
            validator.validate(bad_identifier)
        bad_hash = material.to_dict()
        bad_hash["material_snapshot_sha256"] = "sha256:not-a-digest"
        with self.assertRaises(ValidationError):
            validator.validate(bad_hash)
        bad_timestamp = material.to_dict()
        bad_timestamp["observed_at"] = "2026-09-21 10:30:00+00:00"
        with self.assertRaises(ValidationError):
            validator.validate(bad_timestamp)
        excessive_obligations = material.to_dict()
        excessive_obligations["evidence_obligations"] = [
            copy.deepcopy(excessive_obligations["evidence_obligations"][0]) for _ in range(33)
        ]
        with self.assertRaises(ValidationError):
            validator.validate(excessive_obligations)

    def test_runtime_rejects_json_coercion_and_duplicate_obligations(self) -> None:
        material, _ = MissionStoreActionAuthorityPhase195bTests()._records()
        integer_key = material.to_dict()
        integer_key[1] = "coerced"
        with self.assertRaisesRegex(StoreIntegrityError, "non-string key"):
            ActionAuthorityMaterialSnapshot.from_dict(integer_key)

        integer_boolean = material.to_dict()
        integer_boolean["effects"]["network_call_performed"] = 0
        with self.assertRaisesRegex(StoreIntegrityError, "effects"):
            ActionAuthorityMaterialSnapshot.from_dict(integer_boolean)

        duplicate_obligations = material.to_dict()
        duplicate_obligations["evidence_obligations"] = [
            copy.deepcopy(duplicate_obligations["evidence_obligations"][0]),
            copy.deepcopy(duplicate_obligations["evidence_obligations"][0]),
        ]
        with self.assertRaisesRegex(StoreIntegrityError, "evidence obligations"):
            ActionAuthorityMaterialSnapshot.from_dict(duplicate_obligations)

    def test_observation_kind_selects_exact_payload_shape(self) -> None:
        validator = Draft202012Validator(_schema(OBSERVATION_SCHEMA))
        values = {item.KIND: item.to_dict() for item in _observations()}
        changed = values["execution_fence_observation"]
        changed["observation_kind"] = "credential_lease_observation"
        with self.assertRaises(ValidationError):
            validator.validate(changed)

        changed = values["workspace_high_water_observation"]
        changed["payload"]["high_water"]["revocation_id"] = "revocation:001"
        with self.assertRaises(ValidationError):
            validator.validate(changed)

    def test_publication_requires_one_binding_for_each_exact_source_kind(self) -> None:
        _, publication = MissionStoreActionAuthorityPhase195bTests()._records()
        value = publication.to_dict()
        value["source_records"][0] = copy.deepcopy(value["source_records"][1])
        with self.assertRaises(ValidationError):
            Draft202012Validator(_schema(PUBLICATION_SCHEMA)).validate(value)


if __name__ == "__main__":
    unittest.main()
