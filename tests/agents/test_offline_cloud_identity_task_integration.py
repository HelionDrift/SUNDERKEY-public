"""Cloud and identity projections retain separate original task sources."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

from sunderkey import offline_cloud_org_support_billing_boundary as org
from sunderkey import offline_cloud_post_compromise_timeline as timeline
from sunderkey import offline_dc_topology_declarations as dc
from sunderkey import offline_enterprise_saas_admin_delegation as saas
from sunderkey import offline_hybrid_identity_mappings as hybrid
from sunderkey import offline_kerberos_ad_declarations as kerberos
from sunderkey import offline_ntlm_control_pairs as ntlm
from sunderkey import offline_secondary_cloud_control_declarations as secondary
from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task


ROOT = Path(__file__).resolve().parents[2]
MODULES = (kerberos, ntlm, dc, hybrid, secondary, org, saas, timeline)
LEGACY_EXAMPLES = (
    ("a-compute", "offline-compute-ingress-scope-component.json"),
    ("b-paas", "offline-managed-paas-grant-scope-component.json"),
    ("c-idp", "offline-workforce-idp-mfa-paths-component.json"),
    ("d-data", "offline-data-cloud-grant-scope-component.json"),
)
EXAMPLES = (
    ("a-kerberos", "offline-kerberos-ad-declarations-component.json"),
    ("b-ntlm", "offline-ntlm-control-pairs-component.json"),
    ("c-dc", "offline-dc-topology-declarations-component.json"),
    ("d-hybrid", "offline-hybrid-identity-mappings-component.json"),
    ("e-secondary", "offline-secondary-cloud-control-declarations-component.json"),
    ("f-org", "offline-cloud-org-support-billing-boundary-component.json"),
    ("g-saas", "offline-enterprise-saas-admin-delegation-component.json"),
    ("h-timeline", "offline-cloud-post-compromise-timeline-component.json"),
)


class OfflineCloudIdentityTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)

    def test_four_sources_compose_without_shared_authority(self) -> None:
        model = {
            "schema_version": 1,
            "task_id": "synthetic.cloud-identity-review",
            "jobs": [
                {
                    "job_id": job_id,
                    "request": components.load_offline_specialist_component_request(
                        ROOT / "examples" / filename
                    ),
                }
                for job_id, filename in LEGACY_EXAMPLES
            ],
        }
        original = copy.deepcopy(model)
        for job in model["jobs"]:
            result = components.run_offline_specialist_component(
                job["request"], catalog=self.catalog, repository_root=ROOT
            )
            self.assertEqual(result["analysis"]["candidate_count"], 1)
            self.assertFalse(result["full_candidate_assembled"])
            self.assertFalse(result["positive_use_approved"])
            self.assertEqual(set(result["operational_effects"].values()), {"none"})
            self.assertEqual(
                components.verify_offline_specialist_component_result(
                    result,
                    request=job["request"],
                    catalog=self.catalog,
                    repository_root=ROOT,
                ),
                result,
            )
        report = task.run_offline_specialist_task(
            model, catalog=self.catalog, repository_root=ROOT
        )
        value = report.to_dict()
        self.assertEqual(value["model"], original)
        self.assertEqual(value["job_count"], 4)
        self.assertEqual(value["distinct_component_count"], 4)
        self.assertEqual(value["distinct_profile_count"], 4)
        self.assertEqual(
            [row["profile_id"] for row in value["ownership_index"]],
            ["AOE-GC-D14-S02", "AOE-GC-D14-S16", "AOE-GC-D14-S20", "AOE-GC-D14-S21"],
        )
        self.assertEqual(set(value["operational_effects"].values()), {"none"})
        self.assertFalse(value["qualification_claimed"])
        self.assertFalse(value["positive_use_approved"])
        self.assertEqual(
            task.verify_offline_specialist_task(
                report, model=original, catalog=self.catalog, repository_root=ROOT
            ).to_json(),
            report.to_json(),
        )

    def test_module_ownership_matches_bound_catalog(self) -> None:
        by_profile = {
            item["profile_id"]: item for item in self.catalog.to_dict()["components"]
        }
        for module in MODULES:
            with self.subTest(profile_id=module.PROFILE_ID):
                item = by_profile[module.PROFILE_ID]
                self.assertEqual(module.COMPONENT_ID, item["component_id"])
                self.assertEqual(module.CAPABILITY_ID, item["primary_capability_id"])
                self.assertEqual(module.VECTOR_ID, item["vector_id"])
                self.assertEqual(module.WORK_PACKAGE_ID, item["package_id"])
                self.assertEqual(module.COMMANDER_ID, item["commander_profile_id"])
                self.assertEqual(module.INDEPENDENT_VALIDATOR_ID, item["independent_validator_id"])
                self.assertEqual(module.WAVE_ID, item["scheduled_wave_id"])
                self.assertEqual(module.BLUEPRINT_SHA256, item["blueprint_sha256"])

    def test_eight_sources_compose_without_shared_authority(self) -> None:
        model = {
            "schema_version": 1,
            "task_id": "synthetic.cloud-identity-review",
            "jobs": [
                {
                    "job_id": job_id,
                    "request": components.load_offline_specialist_component_request(
                        ROOT / "examples" / filename
                    ),
                }
                for job_id, filename in EXAMPLES
            ],
        }
        original = copy.deepcopy(model)
        for job in model["jobs"]:
            result = components.run_offline_specialist_component(
                job["request"], catalog=self.catalog, repository_root=ROOT
            )
            self.assertFalse(result["full_candidate_assembled"])
            self.assertFalse(result["positive_use_approved"])
            self.assertEqual(set(result["operational_effects"].values()), {"none"})
            self.assertEqual(
                components.verify_offline_specialist_component_result(
                    result,
                    request=job["request"],
                    catalog=self.catalog,
                    repository_root=ROOT,
                ),
                result,
            )
        report = task.run_offline_specialist_task(
            model, catalog=self.catalog, repository_root=ROOT
        )
        value = report.to_dict()
        self.assertEqual(value["model"], original)
        self.assertEqual(value["job_count"], 8)
        self.assertEqual(value["distinct_component_count"], 8)
        self.assertEqual(value["distinct_profile_count"], 8)
        self.assertEqual(set(value["operational_effects"].values()), {"none"})
        self.assertFalse(value["qualification_claimed"])
        self.assertFalse(value["positive_use_approved"])
        self.assertEqual(
            task.verify_offline_specialist_task(
                report, model=original, catalog=self.catalog, repository_root=ROOT
            ).to_json(),
            report.to_json(),
        )


if __name__ == "__main__":
    unittest.main()
