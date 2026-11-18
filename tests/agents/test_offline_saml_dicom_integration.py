"""Two supplied assertion and DICOM structures under the same inert R0 envelope."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_dicom_pdv_analysis as dicom
from sunderkey import offline_saml_conditions_analysis as saml
from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = (
    ("saml", "offline-saml-conditions-component.json", saml.COMPONENT_ID),
    ("dicom", "offline-dicom-pdv-component.json", dicom.COMPONENT_ID),
)


def checked_requests() -> dict[str, dict]:
    return {
        name: components.load_offline_specialist_component_request(ROOT / "examples" / filename)
        for name, filename, _component_id in EXAMPLES
    }


def supplied_task() -> dict:
    requests = checked_requests()
    return {
        "schema_version": 1,
        "task_id": "synthetic.saml-dicom-structure-review",
        "jobs": [
            {"job_id": name, "request": requests[name]}
            for name, _filename, _component_id in EXAMPLES
        ],
    }


def readdress_outer(result: dict) -> dict:
    forged = copy.deepcopy(result)
    body = {
        key: value
        for key, value in forged.items()
        if key not in {"result_id", "result_sha256"}
    }
    digest = hashlib.sha256(
        json.dumps(
            {"domain": components.RESULT_DOMAIN, "content": body},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()
    forged["result_id"] = "OSR-" + digest[:32].upper()
    forged["result_sha256"] = "sha256:" + digest
    return forged


class OfflineSamlDicomIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def run_component(self, request: dict) -> dict:
        return components.run_offline_specialist_component(
            request, catalog=self.catalog, repository_root=ROOT
        )

    def run_task(self, model: dict) -> task.OfflineSpecialistTaskResult:
        return task.run_offline_specialist_task(
            model, catalog=self.catalog, repository_root=ROOT
        )

    def test_checked_examples_have_exact_selectors_and_full_leaf_replay(self) -> None:
        requests = checked_requests()
        for name, _filename, component_id in EXAMPLES:
            with self.subTest(name=name):
                request = requests[name]
                original = copy.deepcopy(request)
                self.assertEqual(request["component_id"], component_id)
                self.assertEqual(request["action_tier"], "R0")
                self.assertIs(request["dry_run"], True)
                self.assertEqual(request["credential_refs"], [])
                self.assertTrue(all(value == [] for value in request["resources"].values()))
                result = self.run_component(request)
                self.assertEqual(result["component"]["component_id"], component_id)
                self.assertEqual(result["component"]["profile_id"], request["profile_id"])
                original_digest = hashlib.sha256(
                    json.dumps(
                        original,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                    ).encode("ascii")
                ).hexdigest()
                self.assertEqual(result["request_sha256"], "sha256:" + original_digest)
                self.assertEqual(set(result["operational_effects"].values()), {"none"})
                self.assertIs(result["full_candidate_assembled"], False)
                self.assertIs(result["positive_use_approved"], False)
                self.assertEqual(
                    components.verify_offline_specialist_component_result(
                        result, request=original, catalog=self.catalog, repository_root=ROOT
                    ),
                    result,
                )
                leaf = result["analysis"]
                source_model = original["payload"]["model"]
                if name == "saml":
                    owned = saml.SamlConditionsAnalysis.from_dict(leaf)
                    verified = saml.verify_supplied_saml_conditions_analysis(
                        owned, model=source_model
                    )
                else:
                    owned = dicom.DicomPdvAnalysis.from_dict(leaf)
                    verified = dicom.verify_supplied_dicom_pdv_analysis(
                        owned, model=source_model
                    )
                self.assertEqual(verified.to_dict(), leaf)
                request["payload"]["model"]["source_id"] = "changed-source"
                with self.assertRaises(components.OfflineSpecialistComponentError):
                    components.verify_offline_specialist_component_result(
                        result, request=request, catalog=self.catalog, repository_root=ROOT
                    )

    def test_explicit_new_selectors_do_not_change_an_existing_default(self) -> None:
        old = components.load_offline_specialist_component_request(
            ROOT / "examples" / "offline-http-byte-range-component.json"
        )
        self.assertNotIn("component_id", old)
        self.assertEqual(
            components.PROFILE_DEFAULT_COMPONENTS[old["profile_id"]],
            "http_supplied_byte_range_arithmetic",
        )
        default = self.run_component(old)
        explicit = copy.deepcopy(old)
        explicit["component_id"] = "http_supplied_byte_range_arithmetic"
        selected = self.run_component(explicit)
        self.assertEqual(default["analysis"], selected["analysis"])
        self.assertEqual(default["component"], selected["component"])
        self.assertNotEqual(default["request_sha256"], selected["request_sha256"])
        self.assertEqual(
            {request["component_id"] for request in checked_requests().values()},
            {saml.COMPONENT_ID, dicom.COMPONENT_ID},
        )

    def test_two_job_task_preserves_originals_and_never_promotes_authority(self) -> None:
        model = supplied_task()
        original = copy.deepcopy(model)
        report = self.run_task(model)
        result = report.to_dict()
        self.assertEqual(result["model"], original)
        self.assertEqual(
            (
                result["job_count"],
                result["distinct_component_count"],
                result["distinct_profile_count"],
            ),
            (2, 2, 2),
        )
        self.assertEqual([row["job_id"] for row in result["jobs"]], ["dicom", "saml"])
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        for field in ("full_candidate_assembled", "positive_use_approved", "qualification_claimed"):
            self.assertIs(result[field], False)
        self.assertEqual(
            task.verify_offline_specialist_task(
                report, model=original, catalog=self.catalog, repository_root=ROOT
            ).to_json(),
            report.to_json(),
        )
        model["jobs"][0]["request"]["payload"]["model"]["source_id"] = "different"
        self.assertEqual(report.to_dict()["model"], original)
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.verify_offline_specialist_task(
                report, model=model, catalog=self.catalog, repository_root=ROOT
            )

    def test_later_resource_denial_precedes_both_analyzers(self) -> None:
        model = supplied_task()
        model["jobs"][-1]["request"]["resources"]["network"] = ["forbidden"]
        with (
            patch.object(components, "analyze_supplied_saml_conditions") as saml_analyze,
            patch.object(components, "analyze_supplied_dicom_pdv") as dicom_analyze,
            patch.object(components, "run_offline_specialist_component") as dispatch,
            self.assertRaises(task.OfflineSpecialistTaskError),
        ):
            self.run_task(model)
        saml_analyze.assert_not_called()
        dicom_analyze.assert_not_called()
        dispatch.assert_not_called()

    def test_cohashed_false_leaf_and_promotion_are_not_replayed(self) -> None:
        requests = checked_requests()
        for name in ("saml", "dicom"):
            with self.subTest(name=name):
                request = requests[name]
                genuine = self.run_component(request)
                altered = copy.deepcopy(genuine)
                altered["analysis"]["analysis_status"] = "fabricated_positive"
                forged = readdress_outer(altered)
                with self.assertRaises(components.OfflineSpecialistComponentError):
                    components.verify_offline_specialist_component_result(
                        forged, request=request, catalog=self.catalog, repository_root=ROOT
                    )
                promoted = copy.deepcopy(genuine)
                promoted["positive_use_approved"] = True
                forged = readdress_outer(promoted)
                with self.assertRaises(components.OfflineSpecialistComponentError):
                    components.verify_offline_specialist_component_result(
                        forged, request=request, catalog=self.catalog, repository_root=ROOT
                    )


if __name__ == "__main__":
    unittest.main()
