"""Explicit repository evidence for bounded offline API, trace, and MCP slices.

This manifest performs no file I/O or discovery. Paths identify source artifacts,
not proof of live operation, source authenticity, authority, parity, or
qualification. Package associations do not change adopted package identities,
status, dependencies, or phase provenance. Supplemental read projections and
accounting support paths are separate from the 115 audited baseline paths.
"""

from collections.abc import Mapping
from types import MappingProxyType

RoleGroups = tuple[tuple[str, tuple[str, ...]], ...]

OFFLINE_EVIDENCE_GROUPS: Mapping[str, RoleGroups] = MappingProxyType(
    {
        "assessment_core": (
            (
                "offline_api_implementation",
                (
                    "src/sunderkey/offline_api_assessment.py",
                    "src/sunderkey/offline_api_receipt_evidence.py",
                ),
            ),
            ("offline_api_documentation", ("docs/offline-api-assessment.md",)),
            (
                "offline_api_regression",
                (
                    "tests/agents/test_offline_api_assessment.py",
                    "tests/agents/test_offline_api_assessment_cli.py",
                    "tests/agents/test_offline_api_receipt_evidence.py",
                ),
            ),
            (
                "offline_api_schema",
                (
                    "registry/schemas/offline-api-assessment-result-v1.schema.json",
                    "registry/schemas/offline-api-assessment-batch-v1.schema.json",
                ),
            ),
            ("offline_api_bounded_archive_runner", ("scripts/run_offline_api_assessment.py",)),
            (
                "offline_api_synthetic_fixture",
                ("examples/offline-api-assessment/corroborated-synthetic-case.json",),
            ),
        ),
        "declaration_access": (
            (
                "offline_api_implementation",
                (
                    "src/sunderkey/offline_api_security_matrix.py",
                    "src/sunderkey/offline_api_security_scheme_audit.py",
                    "src/sunderkey/offline_api_access_expectations.py",
                    "src/sunderkey/offline_api_expectation_attestation.py",
                ),
            ),
            (
                "offline_api_documentation",
                (
                    "docs/offline-api-security-matrix.md",
                    "docs/offline-api-security-scheme-audit.md",
                    "docs/offline-api-access-expectations.md",
                    "docs/offline-api-expectation-attestation.md",
                ),
            ),
            (
                "offline_api_regression",
                (
                    "tests/agents/test_offline_api_security_matrix.py",
                    "tests/agents/test_offline_api_security_scheme_audit.py",
                    "tests/agents/test_offline_api_access_expectations.py",
                    "tests/agents/test_offline_api_expectation_attestation.py",
                ),
            ),
        ),
        "custody_attestation": (
            (
                "offline_api_implementation",
                (
                    "src/sunderkey/offline_api_source_ledger.py",
                    "src/sunderkey/offline_api_source_attestation.py",
                    "src/sunderkey/offline_api_attested_planning.py",
                ),
            ),
            (
                "offline_api_documentation",
                (
                    "docs/offline-api-source-ledger.md",
                    "docs/offline-api-attested-planning.md",
                    "docs/offline-api-dual-attestation-chain.md",
                    "docs/offline-api-integrated-conformance.md",
                ),
            ),
            (
                "offline_api_regression",
                (
                    "tests/agents/test_offline_api_source_ledger.py",
                    "tests/agents/test_offline_api_source_attestation.py",
                    "tests/agents/test_offline_api_attested_planning.py",
                    "tests/agents/test_offline_api_dual_attestation_chain.py",
                    "tests/agents/test_offline_api_integrated_conformance.py",
                ),
            ),
        ),
        "world_planning_retest": (
            (
                "offline_api_implementation",
                (
                    "src/sunderkey/offline_api_world_projection.py",
                    "src/sunderkey/offline_api_planning_bundle.py",
                    "src/sunderkey/offline_api_retest_lineage.py",
                    "src/sunderkey/offline_api_retest_transition_bridge.py",
                ),
            ),
            (
                "offline_api_documentation",
                (
                    "docs/offline-api-planning-bundle.md",
                    "docs/offline-api-retest-lineage.md",
                    "docs/offline-api-retest-transition-bridge.md",
                ),
            ),
            (
                "offline_api_regression",
                (
                    "tests/agents/test_offline_api_world_projection.py",
                    "tests/agents/test_offline_api_planning_bundle.py",
                    "tests/agents/test_offline_api_retest_lineage.py",
                    "tests/agents/test_offline_api_retest_transition_bridge.py",
                ),
            ),
            ("offline_api_schema", ("registry/schemas/offline-api-retest-result-v1.schema.json",)),
            (
                "offline_api_synthetic_fixture",
                ("examples/offline-api-assessment/denied-synthetic-retest-case.json",),
            ),
        ),
        "pending_review": (
            (
                "offline_api_implementation",
                (
                    "src/sunderkey/offline_api_review_handoff.py",
                    "src/sunderkey/offline_api_review_plan_bridge.py",
                    "src/sunderkey/offline_api_reviewer_dossier.py",
                ),
            ),
            (
                "offline_api_documentation",
                (
                    "docs/offline-api-review-plan-bridge.md",
                    "docs/offline-api-reviewer-dossier.md",
                ),
            ),
            (
                "offline_api_regression",
                (
                    "tests/agents/test_offline_api_review_handoff.py",
                    "tests/agents/test_offline_api_review_plan_bridge.py",
                    "tests/agents/test_offline_api_reviewer_dossier.py",
                ),
            ),
        ),
        "traffic_release": (
            (
                "api_inventory_review_implementation",
                (
                    "src/sunderkey/traffic_derived_api_inventory.py",
                    "src/sunderkey/api_role_response_matrix.py",
                    "src/sunderkey/api_release_delta_review.py",
                    "src/sunderkey/api_release_role_response_review.py",
                    "src/sunderkey/event_assessment_planning.py",
                    "src/sunderkey/event_assessment_history.py",
                ),
            ),
            (
                "api_inventory_review_documentation",
                (
                    "docs/traffic-derived-api-inventory.md",
                    "docs/api-role-response-matrix.md",
                    "docs/api-release-delta-review.md",
                    "docs/api-release-role-response-review.md",
                    "docs/event-assessment-planning.md",
                    "docs/event-assessment-history.md",
                    "docs/offline-pr-chain-integration.md",
                ),
            ),
            (
                "api_inventory_review_schema",
                ("registry/schemas/api-release-role-response-review-v1.schema.json",),
            ),
            (
                "api_inventory_review_regression",
                (
                    "tests/agents/test_traffic_derived_api_inventory.py",
                    "tests/agents/test_api_role_response_matrix.py",
                    "tests/agents/test_api_release_delta_review.py",
                    "tests/agents/test_api_release_role_response_review.py",
                    "tests/agents/test_api_traffic_observation_integrity.py",
                    "tests/agents/test_api_traffic_scalar_ownership.py",
                    "tests/agents/test_api_release_role_response_events.py",
                    "tests/agents/test_event_assessment_planning.py",
                    "tests/agents/test_event_assessment_history.py",
                    "tests/agents/test_offline_api_event_chain_composition.py",
                ),
            ),
        ),
        "agent_trace": (
            (
                "agent_trace_implementation",
                (
                    "src/sunderkey/agent_trace_review.py",
                    "src/sunderkey/agent_trace_regression.py",
                ),
            ),
            (
                "agent_trace_documentation",
                (
                    "docs/agent-trace-review.md",
                    "docs/agent-trace-regression.md",
                ),
            ),
            (
                "agent_trace_regression",
                (
                    "tests/agents/test_agent_trace_review.py",
                    "tests/agents/test_agent_trace_regression.py",
                ),
            ),
            ("agent_trace_schema", ("registry/schemas/agent-trace-review-input-v1.schema.json",)),
        ),
        "mcp_preflight": (
            (
                "mcp_offline_implementation",
                (
                    "src/sunderkey/mcp_catalog_preflight.py",
                    "src/sunderkey/mcp_api_read_bindings.py",
                    "src/sunderkey/mcp_schema_byte_preflight.py",
                    "src/sunderkey/mcp_schema_semantic_preflight.py",
                    "src/sunderkey/mcp_header_annotation_preflight.py",
                    "src/sunderkey/mcp_header_value_codec.py",
                ),
            ),
            (
                "mcp_offline_documentation",
                (
                    "docs/mcp-catalog-preflight.md",
                    "docs/mcp-api-read-bindings.md",
                    "docs/mcp-schema-byte-preflight.md",
                    "docs/mcp-schema-semantic-preflight.md",
                    "docs/mcp-header-annotation-preflight.md",
                    "docs/mcp-header-value-codec.md",
                ),
            ),
            (
                "mcp_offline_regression",
                (
                    "tests/agents/test_mcp_catalog_preflight.py",
                    "tests/agents/test_mcp_api_read_bindings.py",
                    "tests/agents/test_mcp_schema_byte_preflight.py",
                    "tests/agents/test_mcp_schema_semantic_preflight.py",
                    "tests/agents/test_mcp_schema_semantic_scope.py",
                    "tests/agents/test_mcp_header_annotation_preflight.py",
                    "tests/agents/test_mcp_header_value_codec.py",
                ),
            ),
        ),
        "shared": (
            ("exact_json_replay_implementation", ("src/sunderkey/json_contract_integrity.py",)),
            (
                "exact_json_replay_regression",
                ("tests/agents/test_offline_typed_evidence_replay.py",),
            ),
            (
                "offline_effect_ownership_regression",
                ("tests/agents/test_offline_effect_declaration_ownership.py",),
            ),
            (
                "authorization_principal_pair_regression",
                ("tests/agents/test_authorization_principal_pair_integrity.py",),
            ),
            (
                "authorization_validator_rule_version_regression",
                ("tests/agents/test_authorization_validator_rule_version.py",),
            ),
            ("finding_validator_regression", ("tests/agents/test_finding_validators_phase160.py",)),
            ("finding_validator_documentation", ("docs/finding-validator-sdk.md",)),
            (
                "finding_validation_schema",
                ("registry/schemas/finding-validation-result-v1.schema.json",),
            ),
            ("finding_validators", ("src/sunderkey/finding_validators.py",)),
            ("remediation_read_only_cli", ("src/sunderkey/cli.py",)),
        ),
    }
)

SUPPLEMENTAL_EVIDENCE_GROUPS: Mapping[str, RoleGroups] = MappingProxyType(
    {
        "mcp_read_projection": (
            (
                "mcp_read_projection_implementation",
                (
                    "src/sunderkey/mcp_local_reference_closure.py",
                    "src/sunderkey/mcp_read_tool_closure.py",
                    "src/sunderkey/mcp_read_tool_list_preview.py",
                    "src/sunderkey/mcp_external_api_read_mapping.py",
                ),
            ),
            (
                "mcp_read_projection_documentation",
                (
                    "docs/mcp-local-reference-closure.md",
                    "docs/mcp-read-tool-closure.md",
                    "docs/mcp-read-tool-list-preview.md",
                    "docs/mcp-external-api-read-mapping.md",
                ),
            ),
            (
                "mcp_read_projection_regression",
                (
                    "tests/agents/test_mcp_local_reference_closure.py",
                    "tests/agents/test_mcp_read_tool_closure.py",
                    "tests/agents/test_mcp_read_tool_list_preview.py",
                    "tests/agents/test_mcp_external_api_read_mapping.py",
                ),
            ),
        ),
    }
)

ACCOUNTING_SUPPORT_ROLE_GROUPS: RoleGroups = (
    ("offline_evidence_manifest", ("src/sunderkey/offline_evidence_manifest.py",)),
    ("offline_evidence_binding_regression", ("tests/agents/test_offline_evidence_bindings.py",)),
    ("offline_evidence_accounting_documentation", ("docs/offline-evidence-accounting.md",)),
)


def _collect_roles(groups: Mapping[str, RoleGroups]) -> Mapping[str, str]:
    """Reject every repeated declaration, including conflicting path roles."""
    roles: dict[str, str] = {}
    for slice_id, role_groups in groups.items():
        if type(slice_id) is not str or not slice_id:
            raise ValueError("evidence slice identity must be a nonempty string")
        for role, paths in role_groups:
            if type(role) is not str or not role:
                raise ValueError("artifact role must be a nonempty string")
            for path in paths:
                if type(path) is not str or not path:
                    raise ValueError("artifact path must be a nonempty string")
                if path in roles:
                    if roles[path] != role:
                        raise ValueError(f"conflicting artifact roles for {path}")
                    raise ValueError(f"duplicate artifact declaration for {path}")
                roles[path] = role
    return MappingProxyType(roles)


OFFLINE_BASELINE_EVIDENCE_ROLES = _collect_roles(OFFLINE_EVIDENCE_GROUPS)
OFFLINE_BASELINE_EVIDENCE_PATHS = tuple(sorted(OFFLINE_BASELINE_EVIDENCE_ROLES))
SUPPLEMENTAL_EVIDENCE_ROLES = _collect_roles(SUPPLEMENTAL_EVIDENCE_GROUPS)
SUPPLEMENTAL_EVIDENCE_PATHS = tuple(sorted(SUPPLEMENTAL_EVIDENCE_ROLES))
ACCOUNTING_SUPPORT_ROLES = _collect_roles(
    {
        "accounting_support": ACCOUNTING_SUPPORT_ROLE_GROUPS,
    }
)
ACCOUNTING_SUPPORT_PATHS = tuple(sorted(ACCOUNTING_SUPPORT_ROLES))
OFFLINE_EVIDENCE_ROLES = _collect_roles(
    {
        **OFFLINE_EVIDENCE_GROUPS,
        **SUPPLEMENTAL_EVIDENCE_GROUPS,
        "accounting_support": ACCOUNTING_SUPPORT_ROLE_GROUPS,
    }
)
OFFLINE_EVIDENCE_PATHS = tuple(sorted(OFFLINE_EVIDENCE_ROLES))
OFFLINE_EVIDENCE_PATHS_BY_SLICE = MappingProxyType(
    {
        slice_id: tuple(sorted(path for _role, paths in role_groups for path in paths))
        for slice_id, role_groups in {
            **OFFLINE_EVIDENCE_GROUPS,
            **SUPPLEMENTAL_EVIDENCE_GROUPS,
        }.items()
    }
)

# These are explicit shared consumer views, not filename-derived categories.
VALIDATOR_PATHS = (
    "docs/finding-validator-sdk.md",
    "registry/schemas/finding-validation-result-v1.schema.json",
    "src/sunderkey/finding_validators.py",
    "tests/agents/test_authorization_principal_pair_integrity.py",
    "tests/agents/test_authorization_validator_rule_version.py",
    "tests/agents/test_finding_validators_phase160.py",
)
JSON_REPLAY_PATHS = (
    "src/sunderkey/json_contract_integrity.py",
    "tests/agents/test_offline_typed_evidence_replay.py",
)
EFFECT_OWNERSHIP_PATHS = ("tests/agents/test_offline_effect_declaration_ownership.py",)
COMMAND_PATHS = ("src/sunderkey/cli.py",)


def _union_paths(*views: tuple[str, ...]) -> tuple[str, ...]:
    """Reuse declared artifacts across consumers without redeclaring roles."""
    paths = {path for view in views for path in view}
    unknown = paths - OFFLINE_EVIDENCE_ROLES.keys()
    if unknown:
        raise ValueError(f"undeclared evidence paths: {sorted(unknown)!r}")
    return tuple(sorted(paths))


OFFLINE_INVENTORY_CAPABILITY_IDS = MappingProxyType(
    {
        "assessment_core": "sunderkey.api.offline-assessment-correlation",
        "declaration_access": "sunderkey.api.declaration-access-review",
        "custody_attestation": "sunderkey.api.source-custody-rehearsal",
        "world_planning_retest": "sunderkey.api.world-planning-retest",
        "pending_review": "sunderkey.api.pending-review-dossier",
        "traffic_release": "sunderkey.api.traffic-release-review",
        "agent_trace": "sunderkey.ai.agent-trace-review",
        "mcp_preflight": "sunderkey.interface.mcp-offline-preflight",
        "mcp_read_projection": "sunderkey.interface.mcp-read-projection",
    }
)

OFFLINE_INVENTORY_EVIDENCE_PATHS_BY_SLICE = MappingProxyType(
    {
        "assessment_core": _union_paths(
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["assessment_core"],
            VALIDATOR_PATHS,
            COMMAND_PATHS,
            ACCOUNTING_SUPPORT_PATHS,
        ),
        "declaration_access": _union_paths(
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["declaration_access"],
            ACCOUNTING_SUPPORT_PATHS,
        ),
        "custody_attestation": _union_paths(
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["custody_attestation"],
            ACCOUNTING_SUPPORT_PATHS,
        ),
        "world_planning_retest": _union_paths(
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["world_planning_retest"],
            ACCOUNTING_SUPPORT_PATHS,
        ),
        "pending_review": _union_paths(
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["pending_review"],
            ACCOUNTING_SUPPORT_PATHS,
        ),
        "traffic_release": _union_paths(
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["traffic_release"],
            EFFECT_OWNERSHIP_PATHS,
            COMMAND_PATHS,
            ACCOUNTING_SUPPORT_PATHS,
        ),
        "agent_trace": _union_paths(
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["agent_trace"],
            JSON_REPLAY_PATHS,
            COMMAND_PATHS,
            ACCOUNTING_SUPPORT_PATHS,
        ),
        "mcp_preflight": _union_paths(
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["mcp_preflight"],
            JSON_REPLAY_PATHS,
            COMMAND_PATHS,
            ACCOUNTING_SUPPORT_PATHS,
        ),
        "mcp_read_projection": _union_paths(
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["mcp_read_projection"],
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["mcp_preflight"],
            JSON_REPLAY_PATHS,
            ACCOUNTING_SUPPORT_PATHS,
        ),
    }
)
OFFLINE_INVENTORY_EVIDENCE_PATHS = MappingProxyType(
    {
        capability_id: OFFLINE_INVENTORY_EVIDENCE_PATHS_BY_SLICE[slice_id]
        for slice_id, capability_id in OFFLINE_INVENTORY_CAPABILITY_IDS.items()
    }
)

# Expand this existing row without renaming or promoting it.
VALIDATOR_INVENTORY_CAPABILITY_ID = "sunderkey.findings.validators"
VALIDATOR_INVENTORY_EVIDENCE_PATHS = VALIDATOR_PATHS

# Append these paths to existing package evidence. Never replace prior paths.
PACKAGE_EVIDENCE_EXTENSIONS = MappingProxyType(
    {
        "A2.2": _union_paths(
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["declaration_access"],
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["traffic_release"],
            EFFECT_OWNERSHIP_PATHS,
            COMMAND_PATHS,
            ACCOUNTING_SUPPORT_PATHS,
        ),
        "A2.3": _union_paths(
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["world_planning_retest"],
            ACCOUNTING_SUPPORT_PATHS,
        ),
        "A2.4": _union_paths(
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["world_planning_retest"],
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["traffic_release"],
            EFFECT_OWNERSHIP_PATHS,
            COMMAND_PATHS,
            ACCOUNTING_SUPPORT_PATHS,
        ),
        "A2.8": _union_paths(
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["assessment_core"],
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["declaration_access"],
            VALIDATOR_PATHS,
            COMMAND_PATHS,
            ACCOUNTING_SUPPORT_PATHS,
        ),
        "A2.11": _union_paths(
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["agent_trace"],
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["mcp_preflight"],
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["mcp_read_projection"],
            JSON_REPLAY_PATHS,
            COMMAND_PATHS,
            ACCOUNTING_SUPPORT_PATHS,
        ),
        "A2.12": _union_paths(
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["assessment_core"],
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["declaration_access"],
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["custody_attestation"],
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["pending_review"],
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["agent_trace"],
            VALIDATOR_PATHS,
            JSON_REPLAY_PATHS,
            COMMAND_PATHS,
            ACCOUNTING_SUPPORT_PATHS,
        ),
        "A2.13": _union_paths(
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["pending_review"],
            ACCOUNTING_SUPPORT_PATHS,
        ),
        "A2.14": _union_paths(
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["world_planning_retest"],
            ACCOUNTING_SUPPORT_PATHS,
        ),
        "P5.2": _union_paths(
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["mcp_preflight"],
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["mcp_read_projection"],
            JSON_REPLAY_PATHS,
            COMMAND_PATHS,
            ACCOUNTING_SUPPORT_PATHS,
        ),
        "P5.5": _union_paths(
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["assessment_core"],
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["custody_attestation"],
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["pending_review"],
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["agent_trace"],
            JSON_REPLAY_PATHS,
            COMMAND_PATHS,
            ACCOUNTING_SUPPORT_PATHS,
        ),
        "P5.8": _union_paths(
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["mcp_preflight"],
            OFFLINE_EVIDENCE_PATHS_BY_SLICE["mcp_read_projection"],
            COMMAND_PATHS,
            ACCOUNTING_SUPPORT_PATHS,
        ),
    }
)

OFFLINE_PACKAGE_STATUS = "implemented_nonqualifying"
OFFLINE_INVENTORY_EVIDENCE_STATE = "offline_deterministic"
OFFLINE_CLOSURE_STATE = "implemented_offline_behavior"

# Construction checks are pure in-memory checks, not filesystem assertions.
if len(OFFLINE_BASELINE_EVIDENCE_PATHS) != 115:
    raise ValueError("offline baseline must declare exactly 115 distinct paths")
if len(SUPPLEMENTAL_EVIDENCE_PATHS) != 12:
    raise ValueError("MCP read projection must declare exactly 12 supplemental paths")
if tuple(
    len(OFFLINE_EVIDENCE_PATHS_BY_SLICE[slice_id])
    for slice_id in OFFLINE_EVIDENCE_GROUPS
) != (
    10,
    12,
    12,
    13,
    8,
    24,
    7,
    19,
    10,
):
    raise ValueError("offline baseline slice partition does not match the audit")
if len(OFFLINE_EVIDENCE_PATHS_BY_SLICE["mcp_read_projection"]) != 12:
    raise ValueError("MCP read projection partition does not match the audit")
if len(ACCOUNTING_SUPPORT_PATHS) != 3 or len(OFFLINE_EVIDENCE_PATHS) != 130:
    raise ValueError("supplemental and accounting paths must extend the baseline")
if (
    _union_paths(
        VALIDATOR_PATHS,
        JSON_REPLAY_PATHS,
        EFFECT_OWNERSHIP_PATHS,
        COMMAND_PATHS,
    )
    != OFFLINE_EVIDENCE_PATHS_BY_SLICE["shared"]
):
    raise ValueError("shared consumer views must cover the exact shared partition")
if set(OFFLINE_INVENTORY_EVIDENCE_PATHS_BY_SLICE) != set(OFFLINE_INVENTORY_CAPABILITY_IDS):
    raise ValueError("inventory identities and evidence slices must agree")
if len(OFFLINE_INVENTORY_EVIDENCE_PATHS) != 9:
    raise ValueError("exactly nine offline inventory identities are declared")
if _union_paths(*OFFLINE_INVENTORY_EVIDENCE_PATHS.values()) != OFFLINE_EVIDENCE_PATHS:
    raise ValueError("inventory evidence must cover every declared artifact")
if _union_paths(*PACKAGE_EVIDENCE_EXTENSIONS.values()) != OFFLINE_EVIDENCE_PATHS:
    raise ValueError("package extensions must cover every declared artifact")
if OFFLINE_EVIDENCE_ROLES["src/sunderkey/cli.py"] != "remediation_read_only_cli":
    raise ValueError("the established CLI role must remain unchanged")
if OFFLINE_EVIDENCE_ROLES["src/sunderkey/finding_validators.py"] != "finding_validators":
    raise ValueError("the established validator role must remain unchanged")
