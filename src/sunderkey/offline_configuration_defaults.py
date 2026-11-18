"""Compare supplied layered setting declarations with a required value."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "supplied_configuration_defaults"
PROFILE_ID = "AOE-GE-D23-S13"
CAPABILITY_ID = "army.ge.d23.s13"
VECTOR_ID = "AV-GE-D23-S13-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D23-S13"
WAVE_ID = "IW2-027"
COMMANDER_ID = "AOE-GE-D23-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:fbcdef8f7cce520c257b09c1cfad14aeef376aff8990d07b480ee8177d09353d"
SEMANTICS_PROFILE = "supplied-layered-configuration-defaults-v1"
DOMAIN = "sunderkey.offline-configuration-defaults.v1"
MAX_SOURCE_BYTES = 32_768
MAX_REPORT_BYTES = 65_536
MAX_OBSERVATIONS = 64
MAX_LAYERS = 8
_VALUES = {"enabled", "disabled", "unknown"}
_LAYER_VALUES = {"enabled", "disabled", "inherit", "unknown"}
_EFFECTS = dict.fromkeys(
    ("authority", "credential", "execution", "filesystem", "network",
     "publication", "qualification", "target"),
    "none",
)

ConfigurationDefaultsError = core.FrameworkDeclarationError


def _model(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_SOURCE_BYTES)
    model = json.loads(core.canonical(value))
    item = core.exact(
        model,
        {"schema_version", "semantics_profile", "source_id", "policy", "observations"},
        "model",
    )
    if type(item["schema_version"]) is not int or item["schema_version"] != 1:
        raise ConfigurationDefaultsError("Schema version is invalid")
    if item["semantics_profile"] != SEMANTICS_PROFILE:
        raise ConfigurationDefaultsError("Semantics profile is invalid")
    core.identifier(item["source_id"], "source ID")
    policy = core.exact(item["policy"], {"declaration_complete"}, "policy")
    core.boolean(policy["declaration_complete"], "policy completeness")
    observations = core.bounded_list(item["observations"], MAX_OBSERVATIONS, "observations")
    if not observations:
        raise ConfigurationDefaultsError("At least one observation is required")
    identities: set[str] = set()
    for raw in observations:
        observation = core.exact(
            raw,
            {"setting_id", "required_value", "default_value", "layers",
             "declared_effective_value", "capture_complete"},
            "observation",
        )
        identity = core.identifier(observation["setting_id"], "setting ID")
        if identity in identities:
            raise ConfigurationDefaultsError("Setting identifier is repeated")
        identities.add(identity)
        core.choice(observation["required_value"], _VALUES - {"unknown"}, "required value")
        core.choice(observation["default_value"], _VALUES, "default value")
        core.choice(observation["declared_effective_value"], _VALUES, "effective value")
        core.boolean(observation["capture_complete"], "capture completeness")
        layers = core.bounded_list(observation["layers"], MAX_LAYERS, "layers")
        layer_ids: set[str] = set()
        for raw_layer in layers:
            layer = core.exact(raw_layer, {"scope_id", "value"}, "layer")
            scope = core.identifier(layer["scope_id"], "scope ID")
            if scope in layer_ids:
                raise ConfigurationDefaultsError("Scope identifier is repeated")
            layer_ids.add(scope)
            core.choice(layer["value"], _LAYER_VALUES, "layer value")
    return model


def _derive(value: Any) -> dict:
    model = _model(value)
    projections = []
    for item in sorted(model["observations"], key=lambda row: row["setting_id"]):
        effective = item["default_value"]
        origin = "default"
        for layer in item["layers"]:
            if layer["value"] != "inherit":
                effective = layer["value"]
                origin = layer["scope_id"]
        if not model["policy"]["declaration_complete"] or not item["capture_complete"]:
            disposition = "unresolved_declaration_or_capture"
        elif effective == "unknown" or item["declared_effective_value"] == "unknown":
            disposition = "unresolved_effective_value"
        elif effective != item["declared_effective_value"]:
            disposition = "unresolved_effective_value_mismatch"
        elif effective == item["required_value"]:
            disposition = "declared_required_value_consistent"
        elif origin == "default":
            disposition = "candidate_declared_insecure_default"
        else:
            disposition = "candidate_declared_insecure_override"
        projections.append(
            {"setting_id": item["setting_id"], "computed_effective_value": effective,
             "effective_origin": origin, "disposition": disposition}
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": model,
        "observation_count": len(projections),
        "projections": projections,
        "flags": {
            "configuration_verified": False,
            "runtime_effect_verified": False,
            "insecure_default_verified": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Required values, defaults, layers and outcomes are caller assertions.",
            "A declared conflict does not verify a target configuration or weakness.",
            "Layer order is supplied and does not establish actual platform precedence.",
            "No file, credential, network, process or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="CFG-")
    report = {**body, "analysis_id": report_id, "analysis_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return json.loads(core.canonical(report))


@dataclass(frozen=True, slots=True, init=False)
class ConfigurationDefaults:
    """Immutable replay of one supplied layered-configuration model."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise ConfigurationDefaultsError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        core.validate_tree(document, maximum=MAX_REPORT_BYTES)
        if core.canonical(document) != core.canonical(expected):
            raise ConfigurationDefaultsError("Report differs from embedded source replay")
        object.__setattr__(self, "_document_json", core.canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_configuration_defaults(model: Any) -> ConfigurationDefaults:
    """Project supplied setting precedence without reading a configuration."""
    return ConfigurationDefaults(_derive(model))


def verify_supplied_configuration_defaults(
    report: Any, *, model: Any
) -> ConfigurationDefaults:
    if type(report) is not ConfigurationDefaults:
        raise ConfigurationDefaultsError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise ConfigurationDefaultsError("Report differs from supplied source replay")
    return ConfigurationDefaults(expected)
