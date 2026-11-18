"""Distinct AMQP, MQTT and Redis evidence without delivery or shared-session claims."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task

ROOT = Path(__file__).resolve().parents[2]


def supplied_task() -> dict:
    selections = (
        ("z-amqp", "offline-amqp091-content-component.json"),
        ("a-mqtt", "offline-mqtt-topic-component.json"),
        ("m-redis", "offline-redis-acl-component.json"),
    )
    return {
        "schema_version": 1,
        "task_id": "synthetic.messaging-evidence-review",
        "jobs": [
            {
                "job_id": job_id,
                "request": components.load_offline_specialist_component_request(
                    ROOT / "examples" / filename
                ),
            }
            for job_id, filename in selections
        ],
    }


class OfflineAmqpMessagingTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def run_task(self, model: dict) -> task.OfflineSpecialistTaskResult:
        return task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)

    def test_three_original_sources_keep_separate_messaging_observations(self) -> None:
        model = supplied_task()
        original = copy.deepcopy(model)
        report = self.run_task(model)
        result = report.to_dict()
        self.assertEqual(result["model"], original)
        self.assertEqual(
            [row["job_id"] for row in result["model"]["jobs"]],
            ["z-amqp", "a-mqtt", "m-redis"],
        )
        self.assertEqual(
            [row["job_id"] for row in result["jobs"]],
            ["a-mqtt", "m-redis", "z-amqp"],
        )
        self.assertEqual(
            tuple(
                result[key]
                for key in ("job_count", "distinct_component_count", "distinct_profile_count")
            ),
            (3, 3, 3),
        )
        expected = (
            (
                "mqtt_supplied_topic_filter_arithmetic",
                "AOE-GD-D18-S15",
                "AOE-GD-D18-CMD",
                "AOE-HQ-33",
                "IW2-019",
            ),
            (
                "redis_supplied_acl_key_selectors",
                "AOE-GB-D07-S05",
                "AOE-GB-D07-CMD",
                "AOE-HQ-34",
                "IW2-005",
            ),
            (
                "amqp091_supplied_publish_content_assembly",
                "AOE-GB-D07-S07",
                "AOE-GB-D07-CMD",
                "AOE-HQ-34",
                "IW2-007",
            ),
        )
        self.assertEqual(
            {owner["commander_profile_id"] for owner in result["ownership_index"]},
            {"AOE-GD-D18-CMD", "AOE-GB-D07-CMD"},
        )
        requests = {row["job_id"]: row["request"] for row in original["jobs"]}
        for row, owner, identity in zip(
            result["jobs"], result["ownership_index"], expected, strict=True
        ):
            request = requests[row["job_id"]]
            component_result = row["result"]
            analysis = component_result["analysis"]
            self.assertEqual(
                tuple(
                    owner[key]
                    for key in (
                        "component_id",
                        "profile_id",
                        "commander_profile_id",
                        "independent_validator_id",
                    )
                ),
                identity[:4],
            )
            self.assertIs(owner["independent_review_required"], True)
            self.assertEqual(component_result["component"]["scheduled_wave_id"], identity[4])
            self.assertEqual(request["action_tier"], "R0")
            self.assertIs(request["dry_run"], True)
            self.assertEqual(request["credential_refs"], [])
            self.assertTrue(all(value == [] for value in request["resources"].values()))
            source_key = "source_model" if "source_model" in analysis else "model"
            self.assertEqual(analysis[source_key], request["payload"]["model"])
            self.assertEqual(component_result["input_provenance"], "operator_supplied_unverified")
            self.assertEqual(set(component_result["operational_effects"].values()), {"none"})
            self.assertIs(component_result["positive_use_approved"], False)
            self.assertIs(component_result["full_candidate_assembled"], False)
            self.assertEqual(
                components.verify_offline_specialist_component_result(
                    component_result,
                    request=request,
                    catalog=self.catalog,
                    repository_root=ROOT,
                ),
                component_result,
            )
        amqp = result["jobs"][-1]["result"]["analysis"]
        self.assertEqual(amqp["analysis_id"], "AMQA-50544EB621585EAD1578D248F0B94A78")
        self.assertEqual(amqp["analysis_status"], "consistent_with_supported_subset")
        self.assertEqual(amqp["accounting"]["complete_publication_count"], 2)
        self.assertEqual(amqp["known_contradictions"], [])
        self.assertTrue(all(value is False for value in amqp["claims"].values()))
        self.assertEqual(set(amqp["effects"].values()), {"none"})
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        self.assertEqual(result["input_provenance"], "operator_supplied_unverified")
        self.assertIs(result["offline_only"], True)
        for flag in ("full_candidate_assembled", "positive_use_approved", "qualification_claimed"):
            self.assertIs(result[flag], False)
        self.assertEqual(
            task.verify_offline_specialist_task(
                report, model=original, catalog=self.catalog, repository_root=ROOT
            ).to_json(),
            report.to_json(),
        )
        model["jobs"][0]["request"]["payload"]["model"]["source_id"] = "other-amqp"
        self.assertEqual(report.to_dict()["model"], original)
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.verify_offline_specialist_task(
                report, model=model, catalog=self.catalog, repository_root=ROOT
            )

    def test_later_amqp_resource_or_authority_change_blocks_all_dispatch(self) -> None:
        for change in ("network_resource", "action_tier"):
            with self.subTest(change=change):
                model = supplied_task()
                request = model["jobs"][0]["request"]
                if change == "network_resource":
                    request["resources"]["network"] = ["unapproved-broker"]
                else:
                    request["action_tier"] = "R1"
                with patch.object(components, "run_offline_specialist_component") as dispatch:
                    with self.assertRaises(task.OfflineSpecialistTaskError):
                        self.run_task(model)
                    dispatch.assert_not_called()

    def test_last_malformed_amqp_source_cannot_publish_partial_task(self) -> None:
        model = supplied_task()
        model["jobs"][0]["request"]["payload"]["model"]["frames_base64"] = "Tk9UQU1RUA=="
        with (
            patch.object(
                components,
                "run_offline_specialist_component",
                wraps=components.run_offline_specialist_component,
            ) as dispatch,
            patch.object(task, "_finalize", wraps=task._finalize) as finalize,
        ):
            with self.assertRaises(task.OfflineSpecialistTaskError) as caught:
                self.run_task(model)
            self.assertEqual(dispatch.call_count, 3)
            self.assertEqual(
                [call.args[0]["profile_id"] for call in dispatch.call_args_list],
                ["AOE-GD-D18-S15", "AOE-GB-D07-S05", "AOE-GB-D07-S07"],
            )
            finalize.assert_not_called()
        self.assertIsInstance(caught.exception.__cause__, ValueError)
        self.assertNotIsInstance(caught.exception.__cause__, TypeError)


if __name__ == "__main__":
    unittest.main()
