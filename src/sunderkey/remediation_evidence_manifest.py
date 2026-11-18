"""Shared repository evidence paths for the offline remediation boundary."""

from types import MappingProxyType

REMEDIATION_EVIDENCE_ROLES = MappingProxyType(
    {
        "docs/remediation-case-review.md": "remediation_case_review_documentation",
        "docs/remediation-validation-contracts.md": "remediation_validation_documentation",
        "docs/remediation-workflow-visibility.md": "remediation_workflow_documentation",
        "registry/schemas/remediation-case-request-v1.schema.json": (
            "remediation_case_request_schema"
        ),
        "registry/schemas/remediation-case-review-v1.schema.json": "remediation_case_review_schema",
        "registry/schemas/remediation-validation-contract-v1.schema.json": (
            "remediation_validation_schema"
        ),
        "registry/schemas/remediation-workflow-review-v1.schema.json": (
            "remediation_workflow_schema"
        ),
        "src/sunderkey/cli.py": "remediation_read_only_cli",
        "src/sunderkey/remediation_case_review.py": "remediation_case_review",
        "src/sunderkey/remediation_case_review_io.py": "remediation_bounded_archive_io",
        "src/sunderkey/remediation_evidence_manifest.py": "remediation_evidence_manifest",
        "src/sunderkey/remediation_validation_contracts.py": "remediation_validation_planning",
        "src/sunderkey/remediation_workflow_visibility.py": "remediation_workflow_visibility",
        "tests/agents/test_remediation_case_review.py": "remediation_case_review_tests",
        "tests/agents/test_remediation_case_review_io.py": "remediation_archive_io_tests",
        "tests/agents/test_remediation_cli_output_bytes.py": "remediation_cli_byte_tests",
        "tests/agents/test_remediation_evidence_bindings.py": "remediation_evidence_binding_tests",
        "tests/agents/test_remediation_exception_source_replay.py": (
            "remediation_exception_replay_tests"
        ),
        "tests/agents/test_remediation_idempotency_source_replay.py": (
            "remediation_idempotency_replay_tests"
        ),
        "tests/agents/test_remediation_plan_context_replay.py": "remediation_plan_replay_tests",
        "tests/agents/test_remediation_source_replay.py": "remediation_closure_replay_tests",
        "tests/agents/test_remediation_validation_contracts_phase168.py": (
            "remediation_contract_tests"
        ),
        "tests/agents/test_remediation_workflow_visibility.py": "remediation_workflow_tests",
    }
)
REMEDIATION_EVIDENCE_PATHS = tuple(sorted(REMEDIATION_EVIDENCE_ROLES))
