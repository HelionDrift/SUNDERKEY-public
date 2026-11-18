"""Compare bounded, caller-supplied OCI image and layer declarations."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "oci_supplied_image_layer_metadata"
PROFILE_ID = "AOE-GC-D15-S01"
CAPABILITY_ID = "army.gc.d15.s01"
VECTOR_ID = "AV-GC-D15-S01-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D15-S01"
WAVE_ID = "IW2-003"
COMMANDER_ID = "AOE-GC-D15-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:5253e42e2269c5cc23866ba833bb8c0dc4977bba2b69e59fea625450367fd9e4"
DOMAIN = "sunderkey.offline-oci-image-layers.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_LAYERS = 64
MAX_HISTORY = 128
MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
LAYER_MEDIA_TYPES = frozenset(
    {
        "application/vnd.oci.image.layer.v1.tar",
        "application/vnd.oci.image.layer.v1.tar+gzip",
        "application/vnd.oci.image.layer.v1.tar+zstd",
        "application/vnd.oci.image.layer.nondistributable.v1.tar",
        "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
    }
)
_MEDIA = re.compile(r"[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+\Z")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class OciImageLayersError(ValueError):
    """A supplied OCI metadata declaration or original replay is invalid."""


def _descriptor(value: Any, label: str) -> dict:
    item = core.exact(value, {"media_type", "digest", "size"}, label)
    if type(item["media_type"]) is not str or _MEDIA.fullmatch(item["media_type"]) is None:
        raise OciImageLayersError(f"{label} media type is outside the finite subset")
    if type(item["digest"]) is not str or _SHA256.fullmatch(item["digest"]) is None:
        raise OciImageLayersError(f"{label} digest must use lowercase SHA-256")
    if type(item["size"]) is not int or not 0 <= item["size"] < (1 << 63):
        raise OciImageLayersError(f"{label} size must be a nonnegative native integer")
    return item


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "manifest", "configuration"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise OciImageLayersError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    manifest = core.exact(
        model["manifest"], {"schema_version", "media_type", "config", "layers"}, "manifest"
    )
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] < 0:
        raise OciImageLayersError("Manifest schema version must be a native integer")
    if type(manifest["media_type"]) is not str or _MEDIA.fullmatch(manifest["media_type"]) is None:
        raise OciImageLayersError("Manifest media type is outside the finite subset")
    _descriptor(manifest["config"], "config descriptor")
    layers = core.bounded_list(manifest["layers"], MAX_LAYERS, "layers")
    for index, layer in enumerate(layers):
        _descriptor(layer, f"layer descriptor {index}")
    configuration = core.exact(
        model["configuration"], {"media_type", "rootfs_type", "diff_ids", "history"},
        "configuration",
    )
    if (
        type(configuration["media_type"]) is not str
        or _MEDIA.fullmatch(configuration["media_type"]) is None
    ):
        raise OciImageLayersError("Configuration media type is outside the finite subset")
    core.identifier(configuration["rootfs_type"], "rootfs type")
    diff_ids = core.bounded_list(configuration["diff_ids"], MAX_LAYERS, "diff IDs")
    for index, digest in enumerate(diff_ids):
        if type(digest) is not str or _SHA256.fullmatch(digest) is None:
            raise OciImageLayersError(f"Diff ID {index} must use lowercase SHA-256")
    history = configuration["history"]
    if history is not None:
        for index, entry in enumerate(core.bounded_list(history, MAX_HISTORY, "history")):
            item = core.exact(entry, {"empty_layer"}, f"history entry {index}")
            core.boolean(item["empty_layer"], "empty-layer marker")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    manifest = model["manifest"]
    configuration = model["configuration"]
    layers = manifest["layers"]
    history = configuration["history"]
    supported_manifest = manifest["media_type"] == MANIFEST_MEDIA_TYPE
    supported_config = (
        manifest["config"]["media_type"] == CONFIG_MEDIA_TYPE
        and configuration["media_type"] == CONFIG_MEDIA_TYPE
    )
    rows = [
        {
            "layer_index": index,
            "descriptor": layer,
            "diff_id": configuration["diff_ids"][index]
            if index < len(configuration["diff_ids"]) else None,
            "media_type_supported": layer["media_type"] in LAYER_MEDIA_TYPES,
        }
        for index, layer in enumerate(layers)
    ]
    mismatches: list[dict[str, str]] = []

    def mismatch(issue: str, path: str) -> None:
        mismatches.append({"issue": issue, "path": path})

    if supported_manifest and manifest["schema_version"] != 2:
        mismatch("manifest_schema_version_not_two", "manifest/schema_version")
    if manifest["config"]["media_type"] != configuration["media_type"]:
        mismatch("config_media_type_conflict", "configuration/media_type")
    if supported_manifest and supported_config:
        if configuration["rootfs_type"] != "layers":
            mismatch("rootfs_type_not_layers", "configuration/rootfs_type")
        if len(configuration["diff_ids"]) != len(layers):
            mismatch("diff_id_layer_count_mismatch", "configuration/diff_ids")
        if history is not None and sum(not row["empty_layer"] for row in history) != len(layers):
            mismatch("history_layer_count_mismatch", "configuration/history")
    unsupported_count = (
        int(not supported_manifest) + int(not supported_config)
        + sum(not row["media_type_supported"] for row in rows)
    )
    if not model["inventory_complete"]:
        disposition = "unknown"
        candidate_count = 0
    elif mismatches:
        disposition = "candidate_supplied_oci_metadata_mismatch"
        candidate_count = len(mismatches)
    elif unsupported_count:
        disposition = "unknown"
        candidate_count = 0
    else:
        disposition = "supplied_oci_metadata_consistent"
        candidate_count = 0
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
        "layer_count": len(layers),
        "diff_id_count": len(configuration["diff_ids"]),
        "history_count": len(history) if history is not None else None,
        "layer_rows": rows,
        "mismatches": mismatches,
        "unsupported_media_type_count": unsupported_count,
        "disposition": disposition,
        "candidate_count": candidate_count,
        "unknown_count": int(disposition == "unknown"),
        "source_authenticated": False,
        "registry_contacted": False,
        "blob_bytes_verified": False,
        "layer_decompressed": False,
        "filesystem_overlay_applied": False,
        "runtime_executed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "All manifest, configuration, layer and completeness declarations are caller-supplied.",
            "Only a bounded OCI image-spec v1.1.1 metadata subset is compared.",
            "Layer descriptor digests and config DiffIDs are distinct and are never equated.",
            "No registry, content bytes, decompression, overlay, signature or runtime is assessed.",
            "Consistency of declarations does not establish image integrity or safety.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="OIL-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class OciImageLayersReport:
    """Unsigned image-layer metadata projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise OciImageLayersError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> OciImageLayersReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_oci_image_layers(model: Any) -> OciImageLayersReport:
    return OciImageLayersReport._owned(_derive(model))


def verify_supplied_oci_image_layers(
    report: Any, *, model: Any
) -> OciImageLayersReport:
    if type(report) is not OciImageLayersReport:
        raise OciImageLayersError("Exact OCI image-layer wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise OciImageLayersError("Report differs from separate original model")
    return OciImageLayersReport._owned(expected)


def verify_supplied_oci_image_layers_bytes(
    report_bytes: bytes, *, model: Any
) -> OciImageLayersReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise OciImageLayersError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise OciImageLayersError("Exported report differs from original replay")
    return OciImageLayersReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-oci-image",
        "inventory_complete": True,
        "manifest": {
            "schema_version": 2,
            "media_type": MANIFEST_MEDIA_TYPE,
            "config": {
                "media_type": CONFIG_MEDIA_TYPE,
                "digest": "sha256:" + "a" * 64,
                "size": 512,
            },
            "layers": [{
                "media_type": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": "sha256:" + "b" * 64,
                "size": 1024,
            }],
        },
        "configuration": {
            "media_type": CONFIG_MEDIA_TYPE,
            "rootfs_type": "layers",
            "diff_ids": ["sha256:" + "c" * 64],
            "history": [{"empty_layer": False}, {"empty_layer": True}],
        },
    }
