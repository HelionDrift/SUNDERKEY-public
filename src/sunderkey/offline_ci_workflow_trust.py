"""Bounded synthetic CI workflow trust-flow projection without execution."""

from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "ci_supplied_workflow_trust_flow"
PROFILE_ID = "AOE-GC-D17-S02"
CAPABILITY_ID = "supply-chain.ci-runner-workflow"
VECTOR_ID = "AV-GC-D17-S02-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D17-S02"
WAVE_ID = "IW2-014"
COMMANDER_ID = "AOE-GC-D17-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:54b3d6737b05c18cd71f2170fefc537402f57889507e1a35b8d1cfe60300bc48"
DOMAIN = "sunderkey.offline-ci-workflow-trust.v1"
MODEL_DOMAIN = "sunderkey.offline-ci-workflow-trust-model.v1"
SEMANTICS_PROFILE = "declared-ci-dataflow-shortest-witness.v1"
MAX_DOCUMENT_BYTES = 1_048_576
MAX_NATIVE_NODES = 32_768
MAX_NATIVE_DEPTH = 16
MAX_STRING_BYTES = 256
MAX_SOURCES = 8
MAX_JOBS = 24
MAX_ARTIFACTS = 24
MAX_LINKS = 128
MAX_WORK = 4_000_000
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_PLACEHOLDER = "sha256:" + "0" * 64
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "workflow_config_verified",
        "ci_provider_observed",
        "job_executed",
        "artifact_downloaded",
        "write_effect_observed",
        "exploitability_verified",
        "positive_use_approved",
        "qualification_claimed",
    ),
    False,
)
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "credential",
        "execution",
        "filesystem",
        "network",
        "process",
        "provider",
        "qualification",
        "target",
        "workflow",
    ),
    "none",
)
_BOUNDS = {
    "document_bytes": MAX_DOCUMENT_BYTES,
    "native_nodes": MAX_NATIVE_NODES,
    "scalar_inclusive_depth": MAX_NATIVE_DEPTH,
    "string_bytes": MAX_STRING_BYTES,
    "sources": MAX_SOURCES,
    "jobs": MAX_JOBS,
    "artifacts": MAX_ARTIFACTS,
    "links_per_list": MAX_LINKS,
    "work_steps": MAX_WORK,
}
_LIMITATIONS = (
    "The event, jobs, permissions, artifacts and links are caller-supplied normalized premises.",
    "A witness is a shortest declared data-flow path, not proof that a CI job executed.",
    "Job needs links are scheduling only; they do not transfer data in this model.",
    "Unknown source trust or permissions and incomplete graphs prevent negative conclusions.",
    "Write means only a supplied normalized permission label, not effective provider authority.",
    "No YAML, expressions, secrets, runner configuration or provider behavior is parsed.",
    "Candidate paths are not evidence of exploitability, compromise or actual write effects.",
    "No network, process, credentials, provider, target, authority or "
    "qualification is established.",
)


class CiWorkflowTrustAnalysisError(ValueError):
    """A supplied model or report is outside the exact bounded contract."""


@dataclass(slots=True)
class _Work:
    count: int = 0

    def charge(self, amount: int) -> None:
        if self.count + amount > MAX_WORK:
            raise CiWorkflowTrustAnalysisError("Software work bound exhausted")
        self.count += amount


def _measure(value: Any, work: _Work | None = None) -> tuple[int, int]:
    size = nodes = 0
    active: set[int] = set()

    def charge(amount: int) -> None:
        nonlocal size
        size += amount
        if size > MAX_DOCUMENT_BYTES:
            raise CiWorkflowTrustAnalysisError("Document byte bound exhausted")

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise CiWorkflowTrustAnalysisError("Native node/depth bound exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES:
                raise CiWorkflowTrustAnalysisError("Native string bound exhausted")
            charge(2 + len(item))
            for char in item:
                if not 32 <= ord(char) <= 126:
                    raise CiWorkflowTrustAnalysisError("Printable native ASCII strings required")
                if char in '\\"':
                    charge(1)
        elif kind is bool:
            charge(4 if item else 5)
        elif item is None:
            charge(4)
        elif kind is int:
            if item.bit_length() > 64 or not -(2**63) <= item < 2**63:
                raise CiWorkflowTrustAnalysisError("Native integer exceeds signed 64-bit")
            charge(len(str(item)))
        elif kind in (dict, list):
            if id(item) in active:
                raise CiWorkflowTrustAnalysisError("Cyclic native document")
            children = len(item) * (2 if kind is dict else 1)
            if children > MAX_NATIVE_NODES - nodes:
                raise CiWorkflowTrustAnalysisError("Native collection node bound exhausted")
            charge(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise CiWorkflowTrustAnalysisError("Exact native string keys required")
                        visit(key, depth + 1)
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise CiWorkflowTrustAnalysisError("Only exact native JSON primitives are supported")

    visit(value, 1)
    if work is not None:
        work.charge(size + nodes)
    return size, nodes


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _serialize(value: Any, work: _Work | None = None) -> str:
    _measure(value, work)
    return _canonical(value)


def _capture(value: Any, work: _Work | None = None) -> tuple[Any, str]:
    text = _serialize(value, work)
    return json.loads(text), text


def _integer(text: str) -> int:
    if len(text) > 20 or _INTEGER.fullmatch(text) is None:
        raise CiWorkflowTrustAnalysisError("Raw integer grammar or lexical bound failed")
    number = int(text)
    if not -(2**63) <= number < 2**63:
        raise CiWorkflowTrustAnalysisError("Raw integer exceeds signed 64-bit")
    return number


def _decode(text: Any) -> Any:
    """Bound raw tokens, escapes and duplicate members before JSON decoding."""
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES or not text.isascii():
        raise CiWorkflowTrustAnalysisError("Bounded native ASCII JSON required")
    index = depth = nodes = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            if depth + 1 > MAX_NATIVE_DEPTH:
                raise CiWorkflowTrustAnalysisError("Raw scalar depth bound exhausted")
            nodes += 1
            index += 1
            length = 0
            while True:
                if index >= len(text):
                    raise CiWorkflowTrustAnalysisError("Unterminated raw JSON string")
                char = text[index]
                if char == '"':
                    index += 1
                    break
                if char == "\\":
                    index += 1
                    if index >= len(text):
                        raise CiWorkflowTrustAnalysisError("Unterminated raw escape")
                    escape = text[index]
                    if escape == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            d not in "0123456789abcdefABCDEF" for d in digits
                        ):
                            raise CiWorkflowTrustAnalysisError("Malformed raw Unicode escape")
                        if not 32 <= int(digits, 16) <= 126:
                            raise CiWorkflowTrustAnalysisError("Printable ASCII escapes required")
                        index += 5
                    elif escape in '\\"/':
                        index += 1
                    else:
                        raise CiWorkflowTrustAnalysisError("Unsupported raw string escape")
                else:
                    if not 32 <= ord(char) <= 126:
                        raise CiWorkflowTrustAnalysisError("Printable ASCII strings required")
                    index += 1
                length += 1
                if length > MAX_STRING_BYTES:
                    raise CiWorkflowTrustAnalysisError("Raw string bound exhausted")
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
            if depth + 1 > MAX_NATIVE_DEPTH:
                raise CiWorkflowTrustAnalysisError("Raw scalar depth bound exhausted")
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}{["':
                index += 1
                if index - start > 20:
                    raise CiWorkflowTrustAnalysisError("Raw scalar lexical bound exhausted")
            nodes += 1
            token = text[start:index]
            if token not in {"true", "false", "null"}:
                _integer(token)
        if depth < 0 or depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise CiWorkflowTrustAnalysisError("Raw node/depth bound exhausted")
    if depth:
        raise CiWorkflowTrustAnalysisError("Unterminated raw structure")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                raise CiWorkflowTrustAnalysisError("Duplicate JSON object member")
            result[key] = value
        return result

    def unsupported(_: str) -> None:
        raise CiWorkflowTrustAnalysisError("Fractional/nonfinite JSON numbers unsupported")

    try:
        document = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=_integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, CiWorkflowTrustAnalysisError):
            raise
        raise CiWorkflowTrustAnalysisError("Malformed supplied JSON") from exc
    _measure(document)
    return document


def _identity(value: Any) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise CiWorkflowTrustAnalysisError("Bounded exact source identity required")
    return value


def _id_list(value: Any, limit: int) -> list[str]:
    if type(value) is not list or len(value) > limit:
        raise CiWorkflowTrustAnalysisError("Bounded exact identity list required")
    for item in value:
        _identity(item)
    if len(set(value)) != len(value) or value != sorted(value):
        raise CiWorkflowTrustAnalysisError("Sorted unique identity list required")
    return value


def _validate_model(value: Any, work: _Work) -> tuple[dict, str]:
    owned, text = _capture(value, work)
    if type(owned) is not dict or owned.keys() != {
        "schema_version",
        "workflow_id",
        "event",
        "jobs",
        "artifacts",
        "source_ids",
        "graph_complete",
    }:
        raise CiWorkflowTrustAnalysisError("Exact closed model fields required")
    if type(owned["schema_version"]) is not int or owned["schema_version"] != 1:
        raise CiWorkflowTrustAnalysisError("Exact native schema version 1 required")
    _identity(owned["workflow_id"])
    if type(owned["graph_complete"]) is not bool:
        raise CiWorkflowTrustAnalysisError("Exact graph completeness boolean required")
    event = owned["event"]
    if type(event) is not dict or event.keys() != {"event_id", "trust"}:
        raise CiWorkflowTrustAnalysisError("Exact closed event fields required")
    event_id = _identity(event["event_id"])
    if type(event["trust"]) is not str or event["trust"] not in {"untrusted", "trusted", "unknown"}:
        raise CiWorkflowTrustAnalysisError("Declared event trust required")
    jobs, artifacts = owned["jobs"], owned["artifacts"]
    if type(jobs) is not list or not 1 <= len(jobs) <= MAX_JOBS:
        raise CiWorkflowTrustAnalysisError("Bounded nonempty job list required")
    if type(artifacts) is not list or len(artifacts) > MAX_ARTIFACTS:
        raise CiWorkflowTrustAnalysisError("Bounded artifact list required")
    job_ids: set[str] = set()
    for job in jobs:
        work.charge(12)
        if type(job) is not dict or job.keys() != {
            "job_id",
            "permissions",
            "uses_event_input",
            "needs_job_ids",
            "uses_job_output_ids",
            "consumes_artifact_ids",
        }:
            raise CiWorkflowTrustAnalysisError("Exact closed job fields required")
        identity = _identity(job["job_id"])
        if identity in job_ids or identity == event_id:
            raise CiWorkflowTrustAnalysisError("Duplicate global source identity")
        job_ids.add(identity)
        if type(job["permissions"]) is not str or job["permissions"] not in {
            "read",
            "write",
            "unknown",
        }:
            raise CiWorkflowTrustAnalysisError("Declared normalized job permissions required")
        if type(job["uses_event_input"]) is not bool:
            raise CiWorkflowTrustAnalysisError("Exact event-input boolean required")
        for field in ("needs_job_ids", "uses_job_output_ids", "consumes_artifact_ids"):
            _id_list(job[field], MAX_LINKS)
    artifact_ids: set[str] = set()
    for artifact in artifacts:
        work.charge(5)
        if type(artifact) is not dict or artifact.keys() != {
            "artifact_id",
            "trust",
            "producer_job_id",
        }:
            raise CiWorkflowTrustAnalysisError("Exact closed artifact fields required")
        identity = _identity(artifact["artifact_id"])
        if identity in artifact_ids or identity in job_ids or identity == event_id:
            raise CiWorkflowTrustAnalysisError("Duplicate global source identity")
        artifact_ids.add(identity)
        if type(artifact["trust"]) is not str or artifact["trust"] not in {
            "untrusted",
            "trusted",
            "unknown",
        }:
            raise CiWorkflowTrustAnalysisError("Declared artifact trust required")
        producer = artifact["producer_job_id"]
        if producer is not None and (type(producer) is not str or producer not in job_ids):
            raise CiWorkflowTrustAnalysisError("Exact known artifact producer required")
    sources = _id_list(owned["source_ids"], MAX_SOURCES)
    if not sources or any(source not in artifact_ids and source != event_id for source in sources):
        raise CiWorkflowTrustAnalysisError("Exact event or artifact source IDs required")
    for job in jobs:
        if any(link not in job_ids or link == job["job_id"] for link in job["needs_job_ids"]):
            raise CiWorkflowTrustAnalysisError("Exact other-job needs references required")
        if any(link not in job_ids or link == job["job_id"] for link in job["uses_job_output_ids"]):
            raise CiWorkflowTrustAnalysisError("Exact other-job output references required")
        if any(link not in artifact_ids for link in job["consumes_artifact_ids"]):
            raise CiWorkflowTrustAnalysisError("Exact artifact consumption references required")
    return owned, text


def _graph(model: dict, work: _Work) -> dict[str, list[tuple[str, str]]]:
    event_id = model["event"]["event_id"]
    nodes = ["event:" + event_id]
    nodes.extend("job:" + job["job_id"] for job in model["jobs"])
    nodes.extend("artifact:" + artifact["artifact_id"] for artifact in model["artifacts"])
    graph: dict[str, list[tuple[str, str]]] = {node: [] for node in nodes}
    for job in model["jobs"]:
        target = "job:" + job["job_id"]
        if job["uses_event_input"]:
            graph["event:" + event_id].append((target, "event_input"))
        for source in job["uses_job_output_ids"]:
            graph["job:" + source].append((target, "job_output"))
        for source in job["consumes_artifact_ids"]:
            graph["artifact:" + source].append((target, "artifact_consumed"))
    for artifact in model["artifacts"]:
        producer = artifact["producer_job_id"]
        if producer is not None:
            graph["job:" + producer].append(
                ("artifact:" + artifact["artifact_id"], "artifact_produced")
            )
    for edges in graph.values():
        edges.sort()
        work.charge(len(edges) + 1)
    return graph


def _paths(source: str, graph: dict[str, list[tuple[str, str]]], work: _Work) -> dict:
    parent: dict[str, tuple[str, str] | None] = {source: None}
    pending = deque([source])
    while pending:
        node = pending.popleft()
        for target, channel in graph[node]:
            work.charge(1)
            if target not in parent:
                parent[target] = (node, channel)
                pending.append(target)
    return parent


def _witness(source: str, target: str, parents: dict, work: _Work) -> tuple[list[str], list[str]]:
    nodes = [target]
    channels: list[str] = []
    while nodes[-1] != source:
        work.charge(1)
        prior, channel = parents[nodes[-1]]
        channels.append(channel)
        nodes.append(prior)
    nodes.reverse()
    channels.reverse()
    return nodes, channels


def _observe(model: dict, work: _Work) -> tuple[list[dict], list[dict], list[dict]]:
    graph = _graph(model, work)
    trust = {model["event"]["event_id"]: model["event"]["trust"]}
    trust.update({artifact["artifact_id"]: artifact["trust"] for artifact in model["artifacts"]})
    permissions = {job["job_id"]: job["permissions"] for job in model["jobs"]}
    observations: list[dict] = []
    candidates: list[dict] = []
    unknowns: list[dict] = []
    for source_id in model["source_ids"]:
        source_kind = "event" if source_id == model["event"]["event_id"] else "artifact"
        source = source_kind + ":" + source_id
        parents = _paths(source, graph, work)
        candidate_count = unknown_count = 0
        for target_id in sorted(permissions):
            target = "job:" + target_id
            if target not in parents:
                continue
            permission = permissions[target_id]
            source_trust = trust[source_id]
            if source_trust == "trusted" or permission == "read":
                continue
            if source_trust == "untrusted" and permission == "write":
                category = "candidate"
            else:
                category = "unknown"
            nodes, channels = _witness(source, target, parents, work)
            witness = {
                "source_id": source_id,
                "target_job_id": target_id,
                "node_path": nodes,
                "edge_channels": channels,
                "hop_count": len(channels),
            }
            if category == "candidate":
                candidates.append(witness)
                candidate_count += 1
            else:
                if source_trust == "unknown":
                    witness["reason"] = "source_trust_unknown"
                else:
                    witness["reason"] = "target_permission_unknown"
                unknowns.append(witness)
                unknown_count += 1
        if candidate_count:
            outcome = "candidate_path_present"
        elif unknown_count or not model["graph_complete"]:
            outcome = "unknown"
        elif trust[source_id] == "trusted":
            outcome = "declared_trusted_source"
        else:
            outcome = "no_candidate_under_complete_supplied_graph"
        observations.append(
            {
                "source_id": source_id,
                "source_kind": source_kind,
                "declared_trust": trust[source_id],
                "candidate_target_count": candidate_count,
                "unknown_target_count": unknown_count,
                "outcome": outcome,
            }
        )
    return observations, candidates, unknowns


def _address(domain: str, text: str) -> str:
    return "sha256:" + hashlib.sha256((domain + "\n" + text).encode("ascii")).hexdigest()


def _derive(model: Any) -> dict:
    work = _Work()
    owned, source_text = _validate_model(model, work)
    observations, candidates, unknowns = _observe(owned, work)
    if candidates:
        overall = "candidate_paths_present"
    elif unknowns or not owned["graph_complete"]:
        overall = "unknown"
    else:
        overall = "no_candidate_under_complete_supplied_graph"
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
        "source_count": len(owned["source_ids"]),
        "candidate_witness_count": len(candidates),
        "unknown_witness_count": len(unknowns),
        "overall_outcome": overall,
        "source_observations": observations,
        "candidate_witnesses": candidates,
        "unknown_witnesses": unknowns,
        "bounds": dict(_BOUNDS),
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "limitations": list(_LIMITATIONS),
        "analysis_id": "CWT-" + "0" * 32,
        "analysis_sha256": _PLACEHOLDER,
    }
    report_size, report_nodes = _measure(body, work)
    work.charge(4 * (report_size + report_nodes))
    del body["analysis_id"]
    del body["analysis_sha256"]
    hash_size, _ = _measure(body, work)
    work.charge(len(MODEL_DOMAIN) + len(DOMAIN) + len(source_text) + hash_size + 2)
    body["source_model_sha256"] = _address(MODEL_DOMAIN, source_text)
    digest = _address(DOMAIN, _canonical(body))
    body["analysis_id"] = "CWT-" + digest[7:39].upper()
    body["analysis_sha256"] = digest
    return body


def _replay(document: Any) -> dict:
    owned, text = _capture(document)
    if type(owned) is not dict or "source_model" not in owned:
        raise CiWorkflowTrustAnalysisError("Source-bearing native analysis required")
    expected = _derive(owned["source_model"])
    if text != _serialize(expected):
        raise CiWorkflowTrustAnalysisError("Report does not exactly replay its embedded source")
    return expected


@dataclass(frozen=True, slots=True, init=False)
class CiWorkflowTrustAnalysis:
    """Detached declared-graph projection, never live CI evidence."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        object.__setattr__(self, "_document_json", _serialize(_replay(document)))

    @classmethod
    def from_dict(cls, document: Any) -> CiWorkflowTrustAnalysis:
        return cls(document)

    @classmethod
    def from_json(cls, content: Any) -> CiWorkflowTrustAnalysis:
        return cls(_decode(content))

    def to_dict(self) -> dict:
        return _replay(_decode(getattr(self, "_document_json", None)))

    def to_json(self) -> str:
        return _serialize(self.to_dict())

    @property
    def analysis_id(self) -> str:
        return self.to_dict()["analysis_id"]

    @property
    def analysis_sha256(self) -> str:
        return self.to_dict()["analysis_sha256"]


def analyze_supplied_ci_workflow_trust(model: Any) -> CiWorkflowTrustAnalysis:
    """Find shortest declared data-flow witnesses without interacting with CI."""
    return CiWorkflowTrustAnalysis(_derive(model))


def analyze_supplied_ci_workflow_trust_bytes(*, model_bytes: Any) -> CiWorkflowTrustAnalysis:
    """Accept exact bounded ASCII JSON bytes without reading a resource."""
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_DOCUMENT_BYTES:
        raise CiWorkflowTrustAnalysisError("Bounded exact native model bytes required")
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise CiWorkflowTrustAnalysisError("ASCII model bytes required") from exc
    return analyze_supplied_ci_workflow_trust(_decode(text))


def verify_supplied_ci_workflow_trust_analysis(
    report: Any, *, model: Any
) -> CiWorkflowTrustAnalysis:
    """Check a report against separately supplied original normalized premises."""
    if type(report) is not CiWorkflowTrustAnalysis:
        raise CiWorkflowTrustAnalysisError("Exact native CI trust analysis family required")
    expected = _derive(model)
    if _serialize(report.to_dict()) != _serialize(expected):
        raise CiWorkflowTrustAnalysisError("Report differs from separately supplied originals")
    return CiWorkflowTrustAnalysis(expected)


def component_fixture() -> dict:
    """Return a fresh synthetic event-to-artifact-to-write-job graph."""
    return {
        "schema_version": 1,
        "workflow_id": "synthetic-ci",
        "event": {"event_id": "pull-request", "trust": "untrusted"},
        "jobs": [
            {
                "job_id": "build",
                "permissions": "read",
                "uses_event_input": True,
                "needs_job_ids": [],
                "uses_job_output_ids": [],
                "consumes_artifact_ids": [],
            },
            {
                "job_id": "publish",
                "permissions": "write",
                "uses_event_input": False,
                "needs_job_ids": ["build"],
                "uses_job_output_ids": [],
                "consumes_artifact_ids": ["bundle"],
            },
        ],
        "artifacts": [
            {"artifact_id": "bundle", "trust": "unknown", "producer_job_id": "build"},
        ],
        "source_ids": ["pull-request"],
        "graph_complete": True,
    }


__all__ = [
    "CiWorkflowTrustAnalysisError",
    "CiWorkflowTrustAnalysis",
    "analyze_supplied_ci_workflow_trust",
    "analyze_supplied_ci_workflow_trust_bytes",
    "verify_supplied_ci_workflow_trust_analysis",
    "component_fixture",
]
