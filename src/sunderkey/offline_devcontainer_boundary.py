"""Inert projection of supplied development-container execution surfaces."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "devcontainer_supplied_host_boundary_projection"
PROFILE_ID = "AOE-GC-D17-S13"
CAPABILITY_ID = "army.gc.d17.s13"
VECTOR_ID = "AV-GC-D17-S13-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D17-S13"
WAVE_ID = "IW2-025"
COMMANDER_ID = "AOE-GC-D17-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:5be74d4ab6b11d722d75bfbb5a7ba6419023107e4a16cdbb001b7a97aa1e113e"
DOMAIN = "sunderkey.offline-devcontainer-boundary.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_FEATURES = 16
MAX_HOOKS = 8
MAX_MOUNTS = 16
HOOK_PHASES = {
    "onCreate",
    "updateContent",
    "postCreate",
    "postStart",
    "postAttach",
}
SOURCE_KINDS = {"digest", "tag", "local", "unknown"}
MOUNT_SCOPES = {"workspace", "host_path", "host_socket", "unknown"}
EFFECTS = {
    key: "none"
    for key in (
        "authority",
        "execution",
        "filesystem",
        "network",
        "process",
        "provider",
        "credentials",
        "target_interaction",
        "finding_publication",
        "qualification",
    )
}


class DevcontainerBoundaryError(ValueError):
    """A reduced declaration or original-source replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version",
            "source_id",
            "inventory_complete",
            "image",
            "features",
            "hooks",
            "mounts",
            "privileged",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise DevcontainerBoundaryError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    core.boolean(model["privileged"], "privileged")
    image = core.exact(model["image"], {"reference_kind", "reviewed"}, "image")
    core.choice(image["reference_kind"], SOURCE_KINDS, "image reference kind")
    core.boolean(image["reviewed"], "image review")
    seen_features: set[str] = set()
    for row in core.bounded_list(model["features"], MAX_FEATURES, "features"):
        feature = core.exact(row, {"feature_id", "reference_kind", "reviewed"}, "feature")
        identifier = core.identifier(feature["feature_id"], "feature ID")
        if identifier in seen_features:
            raise DevcontainerBoundaryError("Duplicate feature ID")
        seen_features.add(identifier)
        core.choice(feature["reference_kind"], SOURCE_KINDS, "feature reference kind")
        core.boolean(feature["reviewed"], "feature review")
    seen_phases: set[str] = set()
    for row in core.bounded_list(model["hooks"], MAX_HOOKS, "hooks"):
        hook = core.exact(row, {"phase", "declared", "reviewed"}, "hook")
        phase = core.choice(hook["phase"], HOOK_PHASES, "hook phase")
        if phase in seen_phases:
            raise DevcontainerBoundaryError("Duplicate hook phase")
        seen_phases.add(phase)
        core.boolean(hook["declared"], "hook declaration")
        core.boolean(hook["reviewed"], "hook review")
        if not hook["declared"] and hook["reviewed"]:
            raise DevcontainerBoundaryError("An absent hook cannot be reviewed")
    seen_mounts: set[str] = set()
    for row in core.bounded_list(model["mounts"], MAX_MOUNTS, "mounts"):
        mount = core.exact(row, {"mount_id", "source_scope", "writable"}, "mount")
        identifier = core.identifier(mount["mount_id"], "mount ID")
        if identifier in seen_mounts:
            raise DevcontainerBoundaryError("Duplicate mount ID")
        seen_mounts.add(identifier)
        core.choice(mount["source_scope"], MOUNT_SCOPES, "mount scope")
        core.boolean(mount["writable"], "mount writability")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    sources: list[dict[str, str]] = []
    image = model["image"]
    if image["reference_kind"] == "tag":
        sources.append({"kind": "tag_based_image_reference", "id": "image"})
    if not image["reviewed"]:
        sources.append({"kind": "unreviewed_image", "id": "image"})
    for feature in sorted(model["features"], key=lambda row: row["feature_id"]):
        if feature["reference_kind"] == "tag":
            sources.append({"kind": "tag_based_feature_reference", "id": feature["feature_id"]})
        if not feature["reviewed"]:
            sources.append({"kind": "unreviewed_feature", "id": feature["feature_id"]})
    for hook in sorted(model["hooks"], key=lambda row: row["phase"]):
        if hook["declared"] and not hook["reviewed"]:
            sources.append({"kind": "unreviewed_hook", "id": hook["phase"]})
    sinks: list[dict[str, str]] = []
    if model["privileged"]:
        sinks.append({"kind": "privileged_container", "id": "container"})
    for mount in sorted(model["mounts"], key=lambda row: row["mount_id"]):
        if mount["source_scope"] == "host_socket":
            sinks.append({"kind": "host_socket_mount", "id": mount["mount_id"]})
        elif mount["source_scope"] == "host_path" and mount["writable"]:
            sinks.append({"kind": "writable_host_path", "id": mount["mount_id"]})
    links = [{"source": source, "host_boundary": sink} for source in sources for sink in sinks]
    uncertainty = []
    if not model["inventory_complete"]:
        uncertainty.append("incomplete_supplied_inventory")
    if image["reference_kind"] == "unknown":
        uncertainty.append("unknown_image_reference_kind")
    if any(row["reference_kind"] == "unknown" for row in model["features"]):
        uncertainty.append("unknown_feature_reference_kind")
    if any(row["source_scope"] == "unknown" for row in model["mounts"]):
        uncertainty.append("unknown_mount_scope")
    if links:
        disposition = "candidate_declared_source_to_host_boundary"
    elif sources or sinks:
        disposition = "declared_review_signal_without_join"
    elif uncertainty:
        disposition = "unknown"
    else:
        disposition = "no_declared_boundary_signal"
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
        "source_model_sha256": core.digest(source_text.encode("ascii")),
        "inventory_complete_asserted": model["inventory_complete"],
        "source_signals": sources,
        "host_boundary_signals": sinks,
        "declared_links": links,
        "candidate_count": len(links),
        "uncertainty": uncertainty,
        "unknown_count": len(uncertainty),
        "disposition": disposition,
        "source_authenticated": False,
        "configuration_parsed": False,
        "container_started": False,
        "hook_executed": False,
        "host_effect_observed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Image, feature, hook, mount, review and privilege facts are supplied assertions.",
            "No command text, image bytes, feature code, path or credential is accepted.",
            "A joined signal does not prove a command, container runtime or host effect.",
            "An absent signal does not prove that a development environment is safe.",
            "No devcontainer, editor, container runtime, repository or host is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="DCB-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class DevcontainerBoundaryReport:
    """Unsigned supplied-model projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise DevcontainerBoundaryError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> DevcontainerBoundaryReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_devcontainer_boundary(model: Any) -> DevcontainerBoundaryReport:
    return DevcontainerBoundaryReport._owned(_derive(model))


def verify_supplied_devcontainer_boundary(report: Any, *, model: Any) -> DevcontainerBoundaryReport:
    if type(report) is not DevcontainerBoundaryReport:
        raise DevcontainerBoundaryError("Exact boundary wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise DevcontainerBoundaryError("Report differs from separate original model")
    return DevcontainerBoundaryReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-devcontainer-boundary",
        "inventory_complete": True,
        "image": {"reference_kind": "digest", "reviewed": True},
        "features": [{"feature_id": "feature_a", "reference_kind": "tag", "reviewed": False}],
        "hooks": [{"phase": "postCreate", "declared": True, "reviewed": False}],
        "mounts": [{"mount_id": "host_workspace", "source_scope": "host_path", "writable": True}],
        "privileged": False,
    }
