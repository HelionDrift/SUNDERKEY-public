"""Bounded OCI descriptor/blob integrity, not signed origin or image safety."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections import deque
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "oci_supplied_blob_graph_integrity"
PROFILE_ID = "AOE-GC-D17-S10"
CAPABILITY_ID = "army.gc.d17.s10"
VECTOR_ID = "AV-GC-D17-S10-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D17-S10"
WAVE_ID = "IW2-022"
COMMANDER_ID = "AOE-GC-D17-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:745ed6b69bd9b2e3b458debe7f1a4c8bd24ab5073b75d86599ab75fe78d841fd"
SEMANTICS_PROFILE = "oci-image-spec-1.1.1-sha256-supplied-blob-subset"
DOMAIN = "sunderkey.offline-oci-blob-analysis.v1"
MODEL_DOMAIN = "sunderkey.offline-oci-blob-model.v1"
MAX_MODEL_BYTES = 1024 * 1024
MAX_REPORT_BYTES = 2 * 1024 * 1024
MAX_BLOB_BYTES = 256 * 1024
MAX_TOTAL_BLOB_BYTES = 512 * 1024
MAX_BLOBS = 128
MAX_REFERENCES = 2048
MAX_GRAPH_DEPTH = 32
MAX_NATIVE_NODES = 32768
MAX_REPORT_NODES = 65536
MAX_NATIVE_DEPTH = 16
MAX_REPORT_DEPTH = 20
MAX_FINDINGS = 4096
MAX_WORK = 2_000_000
MAX_BASE64_CHARACTERS = 4 * ((MAX_BLOB_BYTES + 2) // 3)
INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
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
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_OCI_DIGEST = re.compile(r"[a-z0-9]+(?:[+._-][a-z0-9]+)*:[A-Za-z0-9=_-]+\Z")
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\Z")
_MEDIA = re.compile(r"[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+\Z")
_PLACEHOLDER = "sha256:" + "0" * 64
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "target",
        "execution",
        "routing",
        "qualification",
        "deployment",
        "network",
        "provider",
        "credential",
        "process",
        "registry",
        "publication",
    ),
    "none",
)
_FLAGS = {
    "source_authenticated": False,
    "signed_origin_verified": False,
    "registry_currentness_verified": False,
    "provenance_verified": False,
    "sbom_verified": False,
    "layer_structure_verified": False,
    "image_runtime_safety_verified": False,
    "live_use_approved": False,
    "qualification_claimed": False,
    "sanitized_for_publication": False,
}
_BOUNDS = {
    "model_bytes": MAX_MODEL_BYTES,
    "report_bytes": MAX_REPORT_BYTES,
    "blob_bytes": MAX_BLOB_BYTES,
    "aggregate_decoded_blob_bytes": MAX_TOTAL_BLOB_BYTES,
    "blobs": MAX_BLOBS,
    "descriptor_occurrences": MAX_REFERENCES,
    "graph_depth": MAX_GRAPH_DEPTH,
    "model_native_nodes": MAX_NATIVE_NODES,
    "report_native_nodes": MAX_REPORT_NODES,
    "model_native_depth": MAX_NATIVE_DEPTH,
    "report_native_depth": MAX_REPORT_DEPTH,
    "findings": MAX_FINDINGS,
    "processing_work_per_replay": MAX_WORK,
}
_LIMITATIONS = (
    "Only supplied SHA-256 byte integrity and a bounded OCI 1.1.1 image graph are evaluated.",
    "The report retains every supplied base64 blob and is not sanitized for publication.",
    "Original blob spelling is hashed exactly; OCI JSON is not recanonicalized for its digest.",
    "Indexes and manifests use an ASCII integer-only JSON software subset, not all OCI JSON.",
    "Opaque configuration and layer bytes are not parsed, extracted or decompressed.",
    "Unsupported algorithms, media types and optional metadata are explicitly unassessed.",
    "Supplied root selection, bytes and completeness do not authenticate a registry or signer.",
    "No platform selection, diff_ids, tar correctness, provenance or SBOM semantics are proved.",
    "No URLs, registries, providers, target systems, credentials or process ports are used.",
    "Integrity and deterministic replay do not grant current authority or qualification.",
)


class OciBlobAnalysisError(ValueError):
    """Closed input, software budget or exact reconstruction requirements failed."""


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _address(domain: str, value: Any) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            domain.encode("ascii") + b"\n" + _canonical(value).encode("ascii")
        ).hexdigest()
    )


def _capture_cost(
    value: Any, *, byte_limit: int, node_limit: int, depth_limit: int
) -> tuple[Any, int, int]:
    """Charge repeated subtrees, escapes and punctuation before retaining a copy."""
    nodes = size = 0
    active: set[int] = set()

    def charge(count: int) -> None:
        nonlocal size
        size += count
        if size > byte_limit:
            raise OciBlobAnalysisError("Canonical document exceeds its software byte budget")

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        if nodes > node_limit or depth > depth_limit:
            raise OciBlobAnalysisError("Document exceeds native node or depth budget")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_BASE64_CHARACTERS:
                raise OciBlobAnalysisError("String exceeds the finite software subset")
            charge(2 + len(item))
            for char in item:
                if not 32 <= ord(char) <= 126:
                    raise OciBlobAnalysisError("Strings must be printable ASCII in this subset")
                if char in '\\"':
                    charge(1)
            return item
        if kind is int:
            if item.bit_length() > 63:
                raise OciBlobAnalysisError("Integer exceeds signed63 magnitude")
            charge(len(str(item)))
            return item
        if kind is bool:
            charge(4 if item else 5)
            return item
        if item is None:
            charge(4)
            return None
        if kind not in {dict, list}:
            raise OciBlobAnalysisError("Only exact native integer-only JSON values are supported")
        if id(item) in active:
            raise OciBlobAnalysisError("Cyclic native input is refused")
        children = len(item) * (2 if kind is dict else 1)
        if children > node_limit - nodes:
            raise OciBlobAnalysisError("Collection exceeds remaining native node budget")
        charge(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
        active.add(id(item))
        try:
            if kind is list:
                return [visit(child, depth + 1) for child in item]
            result = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise OciBlobAnalysisError("Object keys must be exact native strings")
                result[visit(key, depth + 1)] = visit(child, depth + 1)
            return result
        finally:
            active.remove(id(item))

    return visit(value, 1), size, nodes


def _capture(value: Any, *, report: bool = False) -> Any:
    return _capture_cost(
        value,
        byte_limit=MAX_REPORT_BYTES if report else MAX_MODEL_BYTES,
        node_limit=MAX_REPORT_NODES if report else MAX_NATIVE_NODES,
        depth_limit=MAX_REPORT_DEPTH if report else MAX_NATIVE_DEPTH,
    )[0]


def _decode(text: Any, *, byte_limit: int, node_limit: int, depth_limit: int) -> tuple[Any, int]:
    """Bound raw integer grammar, nodes, scalar depth and strings before decoding."""
    if type(text) is not str or not text or len(text) > byte_limit or not text.isascii():
        raise OciBlobAnalysisError("JSON must be bounded exact native ASCII text")
    index = depth = nodes = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            if depth + 1 > depth_limit:
                raise OciBlobAnalysisError("Raw JSON scalar exceeds depth budget")
            nodes += 1
            length = 0
            index += 1
            closed = False
            while index < len(text):
                char = text[index]
                if char == '"':
                    index += 1
                    closed = True
                    break
                if char == "\\":
                    index += 1
                    if index == len(text):
                        raise OciBlobAnalysisError("Incomplete JSON escape")
                    escape = text[index]
                    if escape == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            c not in "0123456789abcdefABCDEF" for c in digits
                        ):
                            raise OciBlobAnalysisError("Malformed JSON Unicode escape")
                        if not 32 <= int(digits, 16) <= 126:
                            raise OciBlobAnalysisError("JSON strings exceed the ASCII subset")
                        index += 5
                    elif escape in '\\"/':
                        index += 1
                    else:
                        raise OciBlobAnalysisError("JSON strings exceed the printable subset")
                else:
                    if not 32 <= ord(char) <= 126:
                        raise OciBlobAnalysisError("JSON strings exceed the printable subset")
                    index += 1
                length += 1
                if length > MAX_BASE64_CHARACTERS:
                    raise OciBlobAnalysisError("Raw JSON string exceeds its software bound")
            if not closed:
                raise OciBlobAnalysisError("Unclosed JSON string")
        elif char in "[{":
            depth += 1
            nodes += 1
            index += 1
        elif char in "]}":
            depth -= 1
            index += 1
        elif char in " \t\r\n,:":
            index += 1
        else:
            if depth + 1 > depth_limit:
                raise OciBlobAnalysisError("Raw JSON scalar exceeds depth budget")
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}{["':
                index += 1
            token = text[start:index]
            nodes += 1
            if token not in {"true", "false", "null"} and (
                _INTEGER.fullmatch(token) is None or int(token).bit_length() > 63
            ):
                raise OciBlobAnalysisError("Raw JSON number exceeds the integer-only subset")
        if depth < 0 or depth > depth_limit or nodes > node_limit:
            raise OciBlobAnalysisError("Raw JSON exceeds pre-decoder structural budget")
    if depth:
        raise OciBlobAnalysisError("Incomplete JSON structure")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, child in items:
            if key in result:
                raise OciBlobAnalysisError("Duplicate JSON object member")
            result[key] = child
        return result

    def unsupported(_: str) -> None:
        raise OciBlobAnalysisError("Fractional and nonfinite JSON values are outside this subset")

    try:
        decoded = json.loads(
            text, object_pairs_hook=pairs, parse_float=unsupported, parse_constant=unsupported
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, OciBlobAnalysisError):
            raise
        raise OciBlobAnalysisError("Malformed JSON source") from exc
    owned, _, native_nodes = _capture_cost(
        decoded, byte_limit=byte_limit, node_limit=node_limit, depth_limit=depth_limit
    )
    return owned, native_nodes


def _fields(value: Any, required: set[str], *, exact: bool, label: str) -> dict:
    if (
        type(value) is not dict
        or not required <= value.keys()
        or (exact and value.keys() != required)
    ):
        raise OciBlobAnalysisError(f"{label} has missing or unsupported closed fields")
    return value


def _descriptor(value: Any) -> dict:
    _fields(value, {"mediaType", "digest", "size"}, exact=False, label="Descriptor")
    if any(len(key) > 128 for key in value):
        raise OciBlobAnalysisError("Descriptor keys exceed the finite metadata-name subset")
    media, digest, size = value["mediaType"], value["digest"], value["size"]
    if type(media) is not str or len(media) > 256 or _MEDIA.fullmatch(media) is None:
        raise OciBlobAnalysisError("Descriptor mediaType is outside the supported MIME subset")
    if type(digest) is not str or len(digest) > 256 or _OCI_DIGEST.fullmatch(digest) is None:
        raise OciBlobAnalysisError("Descriptor digest is outside the OCI digest grammar subset")
    if digest.startswith("sha256:") and _SHA256.fullmatch(digest) is None:
        raise OciBlobAnalysisError("SHA-256 descriptor requires lowercase 64-digit hex")
    if type(size) is not int or size < 0 or size.bit_length() > 63:
        raise OciBlobAnalysisError("Descriptor size must be a native nonnegative signed63 integer")
    return value


class _Work:
    def __init__(self) -> None:
        self.count = 0

    def charge(self, amount: int) -> None:
        if amount > MAX_WORK - self.count:
            raise OciBlobAnalysisError("Supplied processing exceeds the finite work budget")
        self.count += amount


def _prepare(model: Any) -> tuple[dict, dict[str, bytes], _Work]:
    owned = _capture(model)
    _fields(owned, {"schema_version", "root_descriptor", "blobs"}, exact=True, label="Model")
    if type(owned["schema_version"]) is not int or owned["schema_version"] != 1:
        raise OciBlobAnalysisError("schema_version must be the native integer 1")
    _descriptor(owned["root_descriptor"])
    blobs = owned["blobs"]
    if type(blobs) is not list or len(blobs) > MAX_BLOBS:
        raise OciBlobAnalysisError("blobs exceeds the native collection subset")
    total = 0
    seen = set()
    work = _Work()
    for item in blobs:
        _fields(item, {"digest", "content_base64"}, exact=True, label="Blob")
        digest, encoded = item["digest"], item["content_base64"]
        if type(digest) is not str or _SHA256.fullmatch(digest) is None or digest in seen:
            raise OciBlobAnalysisError(
                "Supplied blob addresses must be unique native SHA-256 digests"
            )
        seen.add(digest)
        if type(encoded) is not str or len(encoded) > MAX_BASE64_CHARACTERS or len(encoded) % 4:
            raise OciBlobAnalysisError("Blob base64 exceeds its finite canonical subset")
        # Upper-bound all decoded allocations before decoding or hashing any blob.
        decoded_size = len(encoded) // 4 * 3 - (
            2 if encoded.endswith("==") else int(encoded.endswith("="))
        )
        if decoded_size > MAX_BLOB_BYTES or decoded_size > MAX_TOTAL_BLOB_BYTES - total:
            raise OciBlobAnalysisError("Decoded blobs exceed per-blob or aggregate byte budget")
        total += decoded_size
        work.charge(len(encoded))
        if _BASE64.fullmatch(encoded) is None:
            raise OciBlobAnalysisError("Blob base64 is not canonical standard base64")
    work.charge(total)
    decoded = {}
    for item in blobs:
        encoded = item["content_base64"]
        try:
            content = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise OciBlobAnalysisError("Blob base64 cannot be decoded") from exc
        if base64.b64encode(content).decode("ascii") != encoded:
            raise OciBlobAnalysisError("Blob base64 has noncanonical padding bits")
        decoded[item["digest"]] = content
    return owned, decoded, work


class _Output:
    def __init__(self, body: dict) -> None:
        _, self.bytes, self.nodes = _capture_cost(
            body,
            byte_limit=MAX_REPORT_BYTES,
            node_limit=MAX_REPORT_NODES,
            depth_limit=MAX_REPORT_DEPTH,
        )
        self.findings = 0

    def append(self, target: list, item: dict, *, finding: bool = False) -> None:
        _, size, nodes = _capture_cost(
            item,
            byte_limit=MAX_REPORT_BYTES,
            node_limit=MAX_REPORT_NODES,
            depth_limit=MAX_REPORT_DEPTH - 1,
        )
        if size + 1 > MAX_REPORT_BYTES - self.bytes or nodes > MAX_REPORT_NODES - self.nodes:
            raise OciBlobAnalysisError("Report retention exceeds the cumulative output budget")
        if finding and self.findings >= MAX_FINDINGS:
            raise OciBlobAnalysisError("Report exceeds the finding budget")
        self.bytes += size + 1
        self.nodes += nodes
        self.findings += int(finding)
        target.append(item)


def _derive(model: Any) -> dict:
    owned, blobs, work = _prepare(model)
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
        "semantics_profile": SEMANTICS_PROFILE,
        "source_model": owned,
        "source_model_sha256": _PLACEHOLDER,
        "blob_observations": [],
        "references": [],
        "integrity_failures": [],
        "unassessed": [],
        "verdict": "incomplete",
        "supported_graph_closure_verified": False,
        "reachable_blob_count": MAX_BLOBS,
        "parsed_document_count": MAX_BLOBS,
        "maximum_graph_depth": MAX_GRAPH_DEPTH,
        "decoded_blob_bytes": MAX_TOTAL_BLOB_BYTES,
        "work_steps": MAX_WORK,
        "bounds": dict(_BOUNDS),
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "limitations": list(_LIMITATIONS),
        "analysis_id": "OBA-" + "0" * 32,
        "analysis_sha256": _PLACEHOLDER,
    }
    output = _Output(body)

    def finding(code: str, path: str, *, failure: bool = False) -> None:
        output.append(
            body["integrity_failures" if failure else "unassessed"],
            {"code": code, "path": path},
            finding=True,
        )

    actual = {}
    for index, (digest, content) in enumerate(blobs.items()):
        computed = "sha256:" + hashlib.sha256(content).hexdigest()
        actual[digest] = computed
        output.append(
            body["blob_observations"],
            {
                "blob_index": index,
                "declared_digest": digest,
                "actual_sha256": computed,
                "actual_bytes": len(content),
                "digest_matches": computed == digest,
            },
        )
        if computed != digest:
            finding("supplied_blob_sha256_mismatch", f"blobs/{index}", failure=True)

    pending = deque([(None, "root_descriptor", "root", owned["root_descriptor"])])
    expanded: set[str] = set()
    reachable: set[str] = set()
    declared_sizes: dict[str, set[int]] = {}
    declared_media: dict[str, set[str]] = {}
    graph: dict[str, list[str]] = {}
    parsed_nodes = 0
    while pending:
        parent, path, role, descriptor = pending.popleft()
        if len(body["references"]) >= MAX_REFERENCES:
            raise OciBlobAnalysisError("Descriptor occurrences exceed the graph reference budget")
        work.charge(1)
        descriptor = _descriptor(descriptor)
        digest, media, size = descriptor["digest"], descriptor["mediaType"], descriptor["size"]
        for key in sorted(descriptor.keys() - {"digest", "mediaType", "size"}):
            finding("descriptor_feature_unassessed", path + "/" + key)
        if digest in declared_sizes and size not in declared_sizes[digest]:
            finding("conflicting_descriptor_size", path, failure=True)
        declared_sizes.setdefault(digest, set()).add(size)
        if digest in declared_media and media not in declared_media[digest]:
            # Descriptor media types may legally vary; this single-type software
            # profile cannot interpret their combined graph semantics.
            finding("descriptor_media_interpretation_unassessed", path)
        declared_media.setdefault(digest, set()).add(media)
        is_sha256 = _SHA256.fullmatch(digest) is not None
        present = digest in blobs if is_sha256 else False
        size_matches = present and len(blobs[digest]) == size
        digest_matches = present and actual[digest] == digest
        row = {
            "reference_index": len(body["references"]),
            "parent_digest": parent,
            "path": path,
            "role": role,
            "digest": digest,
            "media_type": media,
            "declared_bytes": size,
            "sha256_supported": is_sha256,
            "blob_present": present,
            "size_matches": size_matches,
            "digest_matches": digest_matches,
        }
        output.append(body["references"], row)
        if not is_sha256:
            finding("digest_algorithm_unassessed", path)
            continue
        if not present:
            finding("referenced_blob_missing", path, failure=True)
            continue
        reachable.add(digest)
        graph.setdefault(digest, [])
        if parent is not None:
            graph.setdefault(parent, []).append(digest)
        if not size_matches:
            finding("descriptor_size_mismatch", path, failure=True)
        if not digest_matches:
            finding("descriptor_sha256_mismatch", path, failure=True)
        if not size_matches or not digest_matches:
            continue
        graph_media = media in {INDEX_MEDIA_TYPE, MANIFEST_MEDIA_TYPE}
        role_supported = (
            (role in {"root", "manifest"} and graph_media)
            or (role == "config" and media == CONFIG_MEDIA_TYPE)
            or (role == "layer" and media in LAYER_MEDIA_TYPES)
        )
        if not role_supported:
            finding("media_or_descriptor_role_unassessed", path)
            continue
        if not graph_media or digest in expanded:
            continue
        expanded.add(digest)
        work.charge(len(blobs[digest]))
        try:
            text = blobs[digest].decode("ascii")
        except UnicodeDecodeError as exc:
            raise OciBlobAnalysisError(
                "Referenced OCI JSON exceeds the ASCII software subset"
            ) from exc
        document, consumed_nodes = _decode(
            text,
            byte_limit=MAX_BLOB_BYTES,
            node_limit=MAX_NATIVE_NODES - parsed_nodes,
            depth_limit=MAX_NATIVE_DEPTH,
        )
        parsed_nodes += consumed_nodes
        if type(document) is not dict or "schemaVersion" not in document:
            raise OciBlobAnalysisError("Referenced OCI document lacks its native schemaVersion")
        if type(document["schemaVersion"]) is not int:
            raise OciBlobAnalysisError("OCI schemaVersion must be an exact native integer")
        if document["schemaVersion"] != 2:
            finding("schema_version_unassessed", path)
            continue
        if any(len(key) > 128 for key in document):
            raise OciBlobAnalysisError("OCI document keys exceed the metadata-name subset")
        if "mediaType" in document and type(document["mediaType"]) is not str:
            raise OciBlobAnalysisError("OCI document mediaType must be an exact native string")
        if "mediaType" in document and document["mediaType"] != media:
            finding("document_media_type_unassessed", path)
            continue
        core = (
            {"schemaVersion", "mediaType", "manifests"}
            if media == INDEX_MEDIA_TYPE
            else {"schemaVersion", "mediaType", "config", "layers"}
        )
        for key in sorted(document.keys() - core):
            finding("document_feature_unassessed", f"{digest}/{key}")
        if media == INDEX_MEDIA_TYPE:
            rows = document.get("manifests")
            if type(rows) is not list:
                raise OciBlobAnalysisError("OCI index manifests must be an exact native array")
            child_count = len(rows)
        else:
            if "config" not in document or type(document.get("layers")) is not list:
                raise OciBlobAnalysisError("OCI manifest requires native config and layers")
            child_count = 1 + len(document["layers"])
        if child_count > MAX_REFERENCES - len(body["references"]) - len(pending):
            raise OciBlobAnalysisError("Pending references exceed the graph reference budget")
        if media == INDEX_MEDIA_TYPE:
            children = [(f"manifests/{i}", "manifest", child) for i, child in enumerate(rows)]
        else:
            children = [("config", "config", document["config"])] + [
                (f"layers/{i}", "layer", child) for i, child in enumerate(document["layers"])
            ]
        # Bound pending occurrences before allocating queue entries. Every shared
        # document expands once; each incoming descriptor is nevertheless checked.
        for child_path, child_role, child in children:
            pending.append((digest, digest + "/" + child_path, child_role, child))

    # Linear topological longest-depth calculation covers shared descendants reached
    # through longer paths; it does not enumerate all paths through a DAG.
    incoming = dict.fromkeys(graph, 0)
    for children in graph.values():
        for child in children:
            incoming[child] += 1
    roots = deque(node for node, count in incoming.items() if not count)
    depths = dict.fromkeys(graph, 1)
    visited = maximum_depth = 0
    while roots:
        node = roots.popleft()
        work.charge(1)
        visited += 1
        maximum_depth = max(maximum_depth, depths[node])
        if depths[node] > MAX_GRAPH_DEPTH:
            raise OciBlobAnalysisError("Supplied graph exceeds the longest-path depth budget")
        for child in graph[node]:
            work.charge(1)
            depths[child] = max(depths[child], depths[node] + 1)
            incoming[child] -= 1
            if not incoming[child]:
                roots.append(child)
    if visited != len(graph):
        finding("cyclic_graph_unassessed", "root_descriptor")
    body["verdict"] = (
        "fail" if body["integrity_failures"] else "incomplete" if body["unassessed"] else "pass"
    )
    body["supported_graph_closure_verified"] = body["verdict"] == "pass"
    body["reachable_blob_count"] = len(reachable)
    body["parsed_document_count"] = len(expanded)
    body["maximum_graph_depth"] = maximum_depth
    body["decoded_blob_bytes"] = sum(len(content) for content in blobs.values())
    body["work_steps"] = work.count
    # Content SHA-256 was necessary before JSON consumption. Source/report
    # addressing occurs only after the complete retained result passes its budget.
    _capture(body, report=True)
    body["source_model_sha256"] = _address(MODEL_DOMAIN, owned)
    del body["analysis_id"]
    del body["analysis_sha256"]
    digest = _address(DOMAIN, body)
    body["analysis_id"] = "OBA-" + digest[7:39].upper()
    body["analysis_sha256"] = digest
    return body


def _replay(document: Any) -> dict:
    supplied = _capture(document, report=True)
    if type(supplied) is not dict or "source_model" not in supplied:
        raise OciBlobAnalysisError("Analysis lacks the original embedded model")
    expected = _derive(supplied["source_model"])
    if _canonical(supplied) != _canonical(expected):
        raise OciBlobAnalysisError("Analysis does not exactly replay its embedded original model")
    return expected


@dataclass(frozen=True, slots=True, init=False)
class OciBlobAnalysis:
    """Owned unsigned report that includes supplied blob bytes, not publishable evidence."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        object.__setattr__(self, "_document_json", _canonical(_replay(document)))

    @classmethod
    def from_dict(cls, document: Any) -> OciBlobAnalysis:
        return cls(document)

    @classmethod
    def from_json(cls, content: Any) -> OciBlobAnalysis:
        document, _ = _decode(
            content,
            byte_limit=MAX_REPORT_BYTES,
            node_limit=MAX_REPORT_NODES,
            depth_limit=MAX_REPORT_DEPTH,
        )
        return cls(document)

    def to_dict(self) -> dict:
        document, _ = _decode(
            getattr(self, "_document_json", None),
            byte_limit=MAX_REPORT_BYTES,
            node_limit=MAX_REPORT_NODES,
            depth_limit=MAX_REPORT_DEPTH,
        )
        return _replay(document)

    def to_json(self) -> str:
        return _canonical(self.to_dict())

    @property
    def analysis_id(self) -> str:
        return self.to_dict()["analysis_id"]

    @property
    def analysis_sha256(self) -> str:
        return self.to_dict()["analysis_sha256"]


def analyze_supplied_oci_blob_graph(model: Any) -> OciBlobAnalysis:
    """Check finite exact supplied bytes without fetching, extracting or executing."""
    return OciBlobAnalysis(_derive(model))


def analyze_supplied_oci_blob_graph_bytes(*, model_bytes: Any) -> OciBlobAnalysis:
    """Decode bounded native ASCII model bytes before exact supplied graph checks."""
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise OciBlobAnalysisError("Model bytes must be bounded exact native bytes")
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise OciBlobAnalysisError("Model JSON exceeds its ASCII software subset") from exc
    model, _ = _decode(
        text,
        byte_limit=MAX_MODEL_BYTES,
        node_limit=MAX_NATIVE_NODES,
        depth_limit=MAX_NATIVE_DEPTH,
    )
    return analyze_supplied_oci_blob_graph(model)


def verify_supplied_oci_blob_analysis(report: Any, *, model: Any) -> OciBlobAnalysis:
    """Replay separately supplied original bytes without authenticating their origin."""
    if type(report) is not OciBlobAnalysis:
        raise OciBlobAnalysisError("Report must be the exact native OciBlobAnalysis family")
    expected = _derive(model)
    if _canonical(report.to_dict()) != _canonical(expected):
        raise OciBlobAnalysisError("Report is not bound to the separately supplied original")
    return OciBlobAnalysis(expected)


__all__ = [
    "OciBlobAnalysis",
    "OciBlobAnalysisError",
    "analyze_supplied_oci_blob_graph",
    "analyze_supplied_oci_blob_graph_bytes",
    "verify_supplied_oci_blob_analysis",
]
