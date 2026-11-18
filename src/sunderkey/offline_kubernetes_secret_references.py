"""Inert comparison of supplied Kubernetes Secret and ConfigMap references."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "kubernetes_supplied_secret_configmap_references"
PROFILE_ID = "AOE-GC-D15-S09"
CAPABILITY_ID = "army.gc.d15.s09"
VECTOR_ID = "AV-GC-D15-S09-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D15-S09"
WAVE_ID = "IW2-011"
COMMANDER_ID = "AOE-GC-D15-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:537186f4bcfb40063cd9502f78251d4abdef67af967c9fb99973dcdd67880cf4"
DOMAIN = "sunderkey.offline-kubernetes-secret-references.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_OBJECTS = 128
MAX_REFERENCES = 256
MAX_KEYS = 64
_REF = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")
_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}\Z")
EFFECTS = dict.fromkeys(
    ("authority", "credential", "execution", "filesystem", "network", "process",
     "provider", "qualification", "target"), "none"
)


class KubernetesSecretReferencesError(ValueError):
    """Invalid supplied reference declaration or failed original replay."""


def _ref(value: Any, label: str) -> str:
    if type(value) is not str or _REF.fullmatch(value) is None:
        raise KubernetesSecretReferencesError(f"{label} must be a bounded reference ID")
    return value


def _key(value: Any) -> str:
    if type(value) is not str or _KEY.fullmatch(value) is None:
        raise KubernetesSecretReferencesError("Key name must be a bounded data key")
    return value


def _rows(value: Any, maximum: int, key: str, label: str) -> list[dict]:
    rows = core.bounded_list(value, maximum, label)
    identifiers = [_ref(row[key], key) for row in rows if type(row) is dict and key in row]
    if len(identifiers) != len(rows) or identifiers != sorted(set(identifiers)):
        raise KubernetesSecretReferencesError(f"{label} IDs must be sorted and unique")
    return rows


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "objects", "references"},
        "Secret reference model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise KubernetesSecretReferencesError("Schema version 1 required")
    _ref(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    objects = _rows(model["objects"], MAX_OBJECTS, "object_id", "objects")
    references = _rows(model["references"], MAX_REFERENCES, "reference_id", "references")
    object_locations: set[tuple[str, str, str]] = set()
    for item in objects:
        core.exact(
            item,
            {"object_id", "object_kind", "namespace_id", "object_name", "keys",
             "metadata_complete"},
            "object metadata",
        )
        core.choice(item["object_kind"], {"secret", "configmap"}, "object kind")
        _ref(item["namespace_id"], "namespace ID")
        _ref(item["object_name"], "object name")
        core.boolean(item["metadata_complete"], "object metadata completeness")
        keys = [_key(key) for key in core.bounded_list(item["keys"], MAX_KEYS, "keys")]
        if keys != sorted(set(keys)):
            raise KubernetesSecretReferencesError("Keys must be sorted and unique")
        location = (item["object_kind"], item["namespace_id"], item["object_name"])
        if location in object_locations:
            raise KubernetesSecretReferencesError("Duplicate object location")
        object_locations.add(location)
    for item in references:
        core.exact(
            item,
            {"reference_id", "namespace_id", "object_kind", "object_name", "key_name",
             "optional", "supplied_resolution", "context_complete", "observation_complete"},
            "workload reference",
        )
        _ref(item["namespace_id"], "namespace ID")
        core.choice(item["object_kind"], {"secret", "configmap"}, "object kind")
        _ref(item["object_name"], "object name")
        _key(item["key_name"])
        core.boolean(item["optional"], "optional marker")
        core.choice(item["supplied_resolution"], {"resolved", "missing", "unknown"},
                    "supplied resolution")
        core.boolean(item["context_complete"], "reference context completeness")
        core.boolean(item["observation_complete"], "observation completeness")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    objects = {
        (row["object_kind"], row["namespace_id"], row["object_name"]): row
        for row in model["objects"]
    }
    rows = []
    for reference in model["references"]:
        location = (
            reference["object_kind"], reference["namespace_id"], reference["object_name"]
        )
        target = objects.get(location)
        expected = None
        reason = None
        if (
            model["inventory_complete"] and reference["context_complete"]
            and reference["observation_complete"] and not reference["optional"]
        ):
            if target is None:
                expected = "missing"
                reason = "declared_required_object_absent"
            elif target["metadata_complete"] and reference["key_name"] not in target["keys"]:
                expected = "missing"
                reason = "declared_required_key_absent"
        candidate = expected == "missing" and reference["supplied_resolution"] == "resolved"
        rows.append({
            "reference_id": reference["reference_id"],
            "expected_resolution": expected,
            "reason": reason,
            "disposition": "candidate_declared_reference_mismatch" if candidate else "unknown",
        })
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(source_text.encode("ascii")),
        "object_count": len(model["objects"]),
        "reference_count": len(rows),
        "reference_rows": rows,
        "candidate_count": sum(row["disposition"].startswith("candidate") for row in rows),
        "unknown_count": sum(row["disposition"] == "unknown" for row in rows),
        "source_authenticated": False,
        "api_contacted": False,
        "secret_values_accepted": False,
        "configmap_values_accepted": False,
        "object_existence_verified": False,
        "resolution_performed": False,
        "finding_claimed": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "All object inventories, key names, references and outcomes are caller declarations.",
            "Only object and key identifiers are accepted, never Secret or ConfigMap values.",
            "Optional references and incomplete premises remain unknown.",
            "A candidate is a declaration mismatch, not verified access or exposure.",
            "No Kubernetes API, object data, network, process or target is contacted.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="KSR-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class KubernetesSecretReferencesReport:
    """Detached report requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise KubernetesSecretReferencesError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> KubernetesSecretReferencesReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_kubernetes_secret_references(model: Any) -> KubernetesSecretReferencesReport:
    return KubernetesSecretReferencesReport._owned(_derive(model))


def analyze_supplied_kubernetes_secret_references_bytes(
    *, model_bytes: bytes
) -> KubernetesSecretReferencesReport:
    return analyze_supplied_kubernetes_secret_references(
        core.decode(model_bytes, maximum=MAX_MODEL_BYTES)
    )


def verify_supplied_kubernetes_secret_references(
    report: Any, *, model: Any
) -> KubernetesSecretReferencesReport:
    if type(report) is not KubernetesSecretReferencesReport:
        raise KubernetesSecretReferencesError("Exact native report family required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise KubernetesSecretReferencesError("Report differs from original model")
    return KubernetesSecretReferencesReport._owned(expected)


def verify_supplied_kubernetes_secret_references_bytes(
    report_bytes: bytes, *, model: Any
) -> KubernetesSecretReferencesReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise KubernetesSecretReferencesError("Exported report differs from original model")
    return KubernetesSecretReferencesReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-secret-references",
        "inventory_complete": True,
        "objects": [{
            "object_id": "app-config-ref", "object_kind": "configmap",
            "namespace_id": "team-a", "object_name": "app-config",
            "keys": ["mode"], "metadata_complete": True,
        }],
        "references": [{
            "reference_id": "missing-required-key", "namespace_id": "team-a",
            "object_kind": "configmap", "object_name": "app-config",
            "key_name": "endpoint", "optional": False,
            "supplied_resolution": "resolved", "context_complete": True,
            "observation_complete": True,
        }],
    }


__all__ = [
    "KubernetesSecretReferencesError", "KubernetesSecretReferencesReport",
    "analyze_supplied_kubernetes_secret_references",
    "analyze_supplied_kubernetes_secret_references_bytes",
    "verify_supplied_kubernetes_secret_references",
    "verify_supplied_kubernetes_secret_references_bytes", "component_fixture",
]
