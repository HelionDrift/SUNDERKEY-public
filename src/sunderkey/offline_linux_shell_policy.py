"""Compare synthetic shell-tool declarations with supplied execution policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "linux_supplied_shell_tool_policy_projection"
PROFILE_ID = "AOE-GC-D12-S05"
CAPABILITY_ID = "army.gc.d12.s05"
VECTOR_ID = "AV-GC-D12-S05-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D12-S05"
WAVE_ID = "IW2-005"
COMMANDER_ID = "AOE-GC-D12-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:3630b3005aa10a341c745b5bddafe3ea35e6ff813326c8fc60dd83cb713898d6"
DOMAIN = "sunderkey.offline-linux-shell-policy.v1"
TOOL_FAMILIES = frozenset({"shell", "interpreter", "system_tool"})
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class LinuxShellPolicyError(ValueError):
    """A supplied shell-tool model or replay is invalid."""


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "approved_privileged_invocation_ids", "invocations",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise LinuxShellPolicyError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise LinuxShellPolicyError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    approved = [
        core.identifier(item, "approved invocation ID")
        for item in core.bounded_list(
            model["approved_privileged_invocation_ids"], 64, "approvals"
        )
    ]
    if len(approved) != len(set(approved)):
        raise LinuxShellPolicyError("Approved invocation IDs must be unique")
    invocations = core.bounded_list(model["invocations"], 64, "invocations")
    if not invocations:
        raise LinuxShellPolicyError("At least one invocation is required")
    rows = []
    seen = set()
    for item in invocations:
        row = core.exact(item, {
            "invocation_id", "tool_family", "privileged_context_declared",
        }, "invocation")
        invocation_id = core.identifier(row["invocation_id"], "invocation ID")
        family = core.identifier(row["tool_family"], "tool family")
        if invocation_id in seen or family not in TOOL_FAMILIES:
            raise LinuxShellPolicyError("Duplicate invocation or unknown tool family")
        seen.add(invocation_id)
        privileged = core.boolean(
            row["privileged_context_declared"], "privileged context declaration"
        )
        flags = (
            ["privileged_shell_tool_outside_supplied_approval"]
            if privileged and invocation_id not in approved else []
        )
        rows.append({
            "invocation_id": invocation_id,
            "tool_family": family,
            "privileged_context_declared": privileged,
            "declared_policy_flags": flags,
        })
    rows.sort(key=lambda row: row["invocation_id"])
    deviations = [row["invocation_id"] for row in rows if row["declared_policy_flags"]]
    unknown = [] if complete else ["supplied_shell_tool_inventory_incomplete"]
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_id": COMMANDER_ID,
        "group_owner_id": GROUP_OWNER_ID,
        "independent_validator_id": INDEPENDENT_VALIDATOR_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "synthetic_fixture_asserted": True,
        "inventory_complete_asserted": complete,
        "invocation_projections": rows,
        "declared_policy_deviation_invocation_ids": deviations,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_shell_tool_projection",
        "source_authenticated": False,
        "host_connected": False,
        "command_text_read": False,
        "command_executed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Tool families, contexts, approvals, and completeness are assertions.",
            "The model does not parse command text or verify effective privileges.",
            "An approval mismatch is a review signal, not proof of exploitation.",
            "No command, host, process, credential, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="LSP-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class LinuxShellPolicyReport:
    """Unsigned shell-tool projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise LinuxShellPolicyError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> LinuxShellPolicyReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_shell_tools(model: Any) -> LinuxShellPolicyReport:
    return LinuxShellPolicyReport._owned(_derive(model))


def verify_supplied_shell_tools(report: Any, *, model: Any) -> LinuxShellPolicyReport:
    if type(report) is not LinuxShellPolicyReport:
        raise LinuxShellPolicyError("Exact shell-tool wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise LinuxShellPolicyError("Report differs from separate original model")
    return LinuxShellPolicyReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-shell-tools",
        "synthetic_fixture": True,
        "inventory_complete": True,
        "approved_privileged_invocation_ids": ["approved-invocation"],
        "invocations": [{
            "invocation_id": "review-invocation",
            "tool_family": "system_tool",
            "privileged_context_declared": True,
        }],
    }
