from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from typing import Any

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError:
    Draft202012Validator = None
    FormatChecker = None


ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "registry" / "schemas"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


@unittest.skipUnless(
    Draft202012Validator is not None,
    "Install the dev extra to run JSON Schema validation",
)
class JsonSchemaContractTests(unittest.TestCase):
    def validator(self, schema_name: str) -> Any:
        schema = load_json(SCHEMAS / schema_name)
        Draft202012Validator.check_schema(schema)
        return Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        )

    def test_every_schema_is_a_valid_draft_2020_12_schema(self) -> None:
        for path in sorted(SCHEMAS.glob("*.json")):
            with self.subTest(path=path.name):
                Draft202012Validator.check_schema(load_json(path))

    def test_registry_and_mission_examples_match_their_schemas(self) -> None:
        registry_validator = self.validator("registry.schema.json")
        registry_validator.validate(load_json(ROOT / "registry" / "army-v1.json"))

        mission_validator = self.validator("mission.schema.json")
        for path in sorted((ROOT / "examples" / "missions").glob("*.json")):
            with self.subTest(path=path.name):
                mission_validator.validate(load_json(path))

    def test_event_examples_match_the_event_schema(self) -> None:
        validator = self.validator("event.schema.json")
        for path in sorted((ROOT / "examples" / "events").glob("*.jsonl")):
            with self.subTest(path=path.name):
                for line_number, line in enumerate(
                    path.read_text(encoding="utf-8").splitlines(),
                    1,
                ):
                    if line.strip():
                        with self.subTest(line=line_number):
                            validator.validate(json.loads(line))

    def test_routing_assets_match_their_schemas(self) -> None:
        assets = (
            (
                "capability-catalog.schema.json",
                ROOT / "registry" / "capabilities-pilot-v1.json",
            ),
            (
                "capability-catalog.schema.json",
                ROOT / "registry" / "capabilities-army-v1.json",
            ),
            (
                "routing-policy.schema.json",
                ROOT / "registry" / "routing-policy-pilot-v1.json",
            ),
            (
                "routing-policy.schema.json",
                ROOT
                / "registry"
                / "routing-policy-army-qualified-v1.json",
            ),
            (
                "routing-request.schema.json",
                ROOT
                / "examples"
                / "routing"
                / "internet-api-to-data.json",
            ),
        )
        for schema_name, path in assets:
            with self.subTest(path=path.name):
                self.validator(schema_name).validate(load_json(path))

    def test_qualification_assets_match_their_schemas(self) -> None:
        assets = (
            (
                "qualification-standard.schema.json",
                ROOT / "registry" / "qualification-standard-v1.json",
            ),
            (
                "qualification-plan-catalog.schema.json",
                ROOT / "registry" / "qualification-plans-army-v1.json",
            ),
            (
                "qualification-evaluation-suite.schema.json",
                ROOT
                / "examples"
                / "qualification"
                / "passive-osint-suite.json",
            ),
            (
                "qualification-evaluation-suite.schema.json",
                ROOT
                / "examples"
                / "implementation"
                / "passive-osint"
                / "evaluation-suite-v1.json",
            ),
            (
                "qualification-observation-set.schema.json",
                ROOT
                / "examples"
                / "qualification"
                / "passive-osint-observations.json",
            ),
            (
                "candidate-implementation-catalog.schema.json",
                ROOT
                / "registry"
                / "candidate-implementations-v1.json",
            ),
            (
                "candidate-blueprint-catalog.schema.json",
                ROOT
                / "registry"
                / "candidate-blueprints-army-v1.json",
            ),
            (
                "candidate-component-catalog.schema.json",
                ROOT / "registry" / "candidate-components-v1.json",
            ),
            (
                "candidate-implementation-catalog.schema.json",
                ROOT
                / "examples"
                / "implementation"
                / "passive-osint"
                / "candidate-implementations-v1.json",
            ),
            (
                "candidate-component-catalog.schema.json",
                ROOT
                / "examples"
                / "implementation"
                / "passive-osint"
                / "candidate-components-v1.json",
            ),
            (
                "candidate-evaluation-submission.schema.json",
                ROOT
                / "examples"
                / "qualification"
                / "passive-osint-submission.json",
            ),
            (
                "implementation-wave-selection-report.schema.json",
                ROOT
                / "examples"
                / "implementation"
                / "iw-001-work-package.json",
            ),
            (
                "qualification-authority-dossier.schema.json",
                ROOT
                / "registry"
                / "qualification-authority-dossier-d008.json",
            ),
            (
                "qualification-authority-decision.schema.json",
                ROOT
                / "registry"
                / "qualification-authority-decision-d008.json",
            ),
            (
                "candidate-enrollment-dossier.schema.json",
                ROOT
                / "registry"
                / "candidate-enrollment-dossier-d009.json",
            ),
            (
                "collaboration-authority-dossier.schema.json",
                ROOT
                / "registry"
                / "collaboration-authority-dossier-d001-d005.json",
            ),
            (
                "managed-api-evaluation-boundary.schema.json",
                ROOT
                / "examples"
                / "implementation"
                / "passive-osint"
                / "managed-api-evaluation-boundary-v1.json",
            ),
        )
        for schema_name, path in assets:
            with self.subTest(path=path.name):
                self.validator(schema_name).validate(load_json(path))

    def test_collaboration_examples_match_their_schema(self) -> None:
        validator = self.validator("collaboration-plan.schema.json")
        for path in sorted(
            (ROOT / "examples" / "collaboration").rglob("*.json")
        ):
            with self.subTest(path=path.relative_to(ROOT)):
                validator.validate(load_json(path))

    def test_qualification_trust_contracts_match_their_schemas(self) -> None:
        from tests.agents.test_qualification_trust_phase32 import (
            qualification_reviewer_credential_document,
            qualification_trust_policy_document,
        )

        self.validator("qualification-trust-policy.schema.json").validate(
            qualification_trust_policy_document()
        )
        self.validator(
            "qualification-reviewer-credential.schema.json"
        ).validate(qualification_reviewer_credential_document())

    def test_qualification_evidence_contracts_match_their_schemas(self) -> None:
        from tests.agents.test_qualification_evidence_phase34 import (
            qualification_evidence_contract_documents,
        )

        manifest, attestation = qualification_evidence_contract_documents()
        self.validator("qualification-evidence-manifest.schema.json").validate(
            manifest
        )
        self.validator(
            "qualification-reviewer-attestation.schema.json"
        ).validate(attestation)

    def test_qualification_decision_matches_its_schema(self) -> None:
        from tests.agents.test_qualification_decisions_phase35 import (
            qualification_decision_document,
        )

        self.validator("qualification-decision.schema.json").validate(
            qualification_decision_document()
        )

    def test_qualification_status_transition_matches_its_schema(self) -> None:
        from tests.agents.test_qualification_lifecycle_phase36 import (
            qualification_status_transition_document,
        )

        self.validator(
            "qualification-status-transition.schema.json"
        ).validate(qualification_status_transition_document())

    def test_qualification_registry_contracts_match_their_schemas(self) -> None:
        from tests.agents.test_qualification_registry_phase37 import (
            qualification_registry_contract_documents,
        )

        review, revision = qualification_registry_contract_documents()
        self.validator(
            "qualification-registry-revision-review.schema.json"
        ).validate(review)
        self.validator("qualification-registry-revision.schema.json").validate(
            revision
        )

    def test_collaboration_schema_rejects_line_feeds_in_identifiers(self) -> None:
        validator = self.validator("collaboration-plan.schema.json")
        example = load_json(
            ROOT
            / "examples"
            / "collaboration"
            / "internet-api-to-data.json"
        )
        paths = (
            ("plan_id",),
            ("registry_sha256",),
            ("work_items", 0, "work_item_id"),
            ("work_items", 0, "owner_profile_id"),
        )
        for path in paths:
            with self.subTest(path=path):
                invalid = copy.deepcopy(example)
                target = invalid
                for component in path[:-1]:
                    target = target[component]
                target[path[-1]] += "\n"
                self.assertTrue(
                    tuple(validator.iter_errors(invalid))
                )

    def test_collaboration_schema_accepts_source_ascii_text_contract(self) -> None:
        validator = self.validator("collaboration-plan.schema.json")
        example = load_json(
            ROOT
            / "examples"
            / "collaboration"
            / "internet-api-to-data.json"
        )
        example["mission_objective"] = "Objective\n" + ("A" * 4097)
        example["scope_reference"] = "scope://reviewed\r\n" + ("B" * 2049)
        example["registry_catalog_id"] = "SUNDERKEY\nCATALOG"
        example["registry_catalog_version"] = "1.0\r\nreviewed"
        example["work_items"][0]["title"] = "Readiness\ncontinued"
        example["work_items"][0]["role_mission"] = (
            "Role mission\n" + ("C" * 4097)
        )
        example["work_items"][0]["deliverable"] = (
            "Deliverable\r\n" + ("D" * 4097)
        )

        validator.validate(example)


if __name__ == "__main__":
    unittest.main()
