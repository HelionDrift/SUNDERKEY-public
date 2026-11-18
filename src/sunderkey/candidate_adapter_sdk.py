"""Typed, deny-by-default SDK for Phase 157 capability adapters."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

from .candidate_blueprints_v2 import CandidateBlueprintCatalogV2
from .candidate_implementation_strategy import CandidateImplementationStrategy
from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256

MANIFEST_DOMAIN = "sunderkey.candidate-adapter-manifest.v1"
CATALOG_DOMAIN = "sunderkey.candidate-adapter-catalog.v1"
EVIDENCE_DOMAIN = "sunderkey.candidate-adapter-evidence.v1"
RESULT_DOMAIN = "sunderkey.candidate-adapter-result.v1"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
ADAPTER_ID_PATTERN = re.compile(r"adapter\.aoe-g[a-e]-d[0-9]{2}-s[0-9]{2}\.[a-z0-9-]+")
REFERENCE_PROFILES = (
    ("AOE-GA-D01-S01", "passive", "oci_container"),
    ("AOE-GB-D06-S09", "api", "oci_container"),
    ("AOE-GA-D03-S14", "identity", "oci_container"),
    ("AOE-GC-D14-S01", "cloud", "microvm"),
    ("AOE-GC-D11-S08", "endpoint", "microvm"),
    ("AOE-GD-D19-S01", "high_consequence_restoration", "microvm"),
)
RESOURCE_FIELDS = ("network", "filesystem", "process", "credential")
SOURCE_PATH = "src/sunderkey/reference_adapters.py"


def _ascii(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or not value.isascii():
        raise QualificationError(f"{label} must be nonempty ASCII text")
    return value


def _sha256_bytes(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _strings(value: Any, label: str, *, minimum: int = 0) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise QualificationError(f"{label} must be a list")
    result = tuple(_ascii(item, f"{label} item") for item in value)
    if len(result) < minimum or len(result) != len(set(result)):
        raise QualificationError(f"{label} is incomplete or contains duplicates")
    return result


@dataclass(frozen=True)
class AdapterResourcePolicy:
    """Exact resource grants. Empty tuples mean deny."""

    network: tuple[str, ...] = ()
    filesystem: tuple[str, ...] = ()
    process: tuple[str, ...] = ()
    credential: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, raw: Any) -> AdapterResourcePolicy:
        if not isinstance(raw, dict) or set(raw) != set(RESOURCE_FIELDS):
            raise QualificationError("Adapter resource policy fields are invalid")
        return cls(
            **{field: _strings(raw[field], f"resource policy {field}") for field in RESOURCE_FIELDS}
        )

    @property
    def is_deny_all(self) -> bool:
        return not any(getattr(self, field) for field in RESOURCE_FIELDS)

    def to_dict(self) -> dict[str, list[str]]:
        return {field: list(getattr(self, field)) for field in RESOURCE_FIELDS}


@dataclass(frozen=True)
class AdapterManifest:
    adapter_id: str
    adapter_version: str
    profile_id: str
    vector_id: str
    primary_capability_id: str
    reference_role: str
    required_isolation: str
    source_sha256: str
    resource_policy: AdapterResourcePolicy
    manifest_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> AdapterManifest:
        expected = {
            "adapter_id",
            "adapter_version",
            "profile_id",
            "profile_name",
            "vector_id",
            "blueprint_sha256",
            "primary_capability_id",
            "reference_role",
            "implementation",
            "source_provenance",
            "runtime",
            "resource_policy",
            "contracts",
            "hooks",
            "evidence_semantics",
            "known_limitations",
            "implementation_status",
            "qualification_effect",
            "routing_effect",
            "execution_effect",
            "deployment_effect",
            "manifest_sha256",
        }
        if not isinstance(raw, dict) or set(raw) != expected:
            raise QualificationError("Adapter manifest fields are invalid")
        adapter_id = _ascii(raw.get("adapter_id"), "adapter ID")
        if ADAPTER_ID_PATTERN.fullmatch(adapter_id) is None:
            raise QualificationError("Adapter ID is invalid")
        source = raw.get("source_provenance")
        runtime = raw.get("runtime")
        contracts = raw.get("contracts")
        hooks = raw.get("hooks")
        if not isinstance(source, dict) or set(source) != {
            "kind",
            "repository_path",
            "source_sha256",
            "license",
            "external_dependencies",
        }:
            raise QualificationError("Adapter source provenance is invalid")
        if (
            source.get("kind") != "sunderkey_native_python"
            or source.get("repository_path") != SOURCE_PATH
        ):
            raise QualificationError("Adapter source binding is invalid")
        source_sha256 = source.get("source_sha256")
        if not isinstance(source_sha256, str) or SHA256_PATTERN.fullmatch(source_sha256) is None:
            raise QualificationError("Adapter source hash is invalid")
        if (
            source.get("license") != "LicenseRef-SUNDERKEY-All-Rights-Reserved"
            or source.get("external_dependencies") != []
        ):
            raise QualificationError("Adapter license or dependency record is invalid")
        if not isinstance(runtime, dict) or set(runtime) != {
            "language",
            "initial_host",
            "required_isolation",
            "development_mode",
            "maximum_action_tier",
        }:
            raise QualificationError("Adapter runtime fields are invalid")
        required_isolation = runtime.get("required_isolation")
        if (
            runtime.get("language") != "python_3_11_or_newer"
            or runtime.get("initial_host") != "linux"
            or required_isolation not in {"oci_container", "microvm"}
            or runtime.get("development_mode") != "offline_synthetic_only"
            or runtime.get("maximum_action_tier") != "R0"
        ):
            raise QualificationError("Adapter runtime binding is invalid")
        policy = AdapterResourcePolicy.from_dict(raw.get("resource_policy"))
        if not policy.is_deny_all:
            raise QualificationError("Reference adapter resource policy must deny all")
        if (
            not isinstance(contracts, dict)
            or set(contracts) != {"input", "output", "evidence", "restoration"}
            or any(
                not isinstance(value, str) or not value.startswith("sunderkey://")
                for value in contracts.values()
            )
        ):
            raise QualificationError("Adapter contracts are invalid")
        if (
            not isinstance(hooks, dict)
            or set(hooks)
            != {
                "dry_run",
                "timeout",
                "cancellation",
                "rate_limit",
                "structured_evidence",
                "cleanup_result",
            }
            or set(hooks.values()) != {True}
        ):
            raise QualificationError("Adapter hooks are incomplete")
        if (
            raw.get("implementation") != "reference_adapter"
            or raw.get("implementation_status") != "sdk_bound_pending_qualification"
            or any(
                raw.get(field) != "none"
                for field in (
                    "qualification_effect",
                    "routing_effect",
                    "execution_effect",
                    "deployment_effect",
                )
            )
        ):
            raise QualificationError("Adapter operational boundary is invalid")
        _strings(raw.get("evidence_semantics"), "adapter evidence semantics", minimum=3)
        _strings(raw.get("known_limitations"), "adapter limitations", minimum=3)
        manifest_sha256 = raw.get("manifest_sha256")
        body = {key: value for key, value in raw.items() if key != "manifest_sha256"}
        expected_sha256 = _canonical_sha256({"domain": MANIFEST_DOMAIN, "manifest": body})
        if manifest_sha256 != expected_sha256:
            raise QualificationError("Adapter manifest hash does not match content")
        return cls(
            adapter_id=adapter_id,
            adapter_version=_ascii(raw.get("adapter_version"), "adapter version"),
            profile_id=_ascii(raw.get("profile_id"), "adapter profile ID"),
            vector_id=_ascii(raw.get("vector_id"), "adapter vector ID"),
            primary_capability_id=_ascii(raw.get("primary_capability_id"), "adapter capability ID"),
            reference_role=_ascii(raw.get("reference_role"), "adapter reference role"),
            required_isolation=required_isolation,
            source_sha256=source_sha256,
            resource_policy=policy,
            manifest_sha256=manifest_sha256,
            document_json=_canonical_json(raw),
        )

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)


def build_reference_adapter_manifest(
    blueprint: Mapping[str, Any],
    reference_role: str,
    required_isolation: str,
    source_sha256: str,
) -> AdapterManifest:
    profile_slug = str(blueprint["profile_id"]).lower()
    adapter_id = f"adapter.{profile_slug}.{reference_role.replace('_', '-')}"
    contract_root = f"sunderkey://candidate-adapters/{adapter_id}/v1"
    body = {
        "adapter_id": adapter_id,
        "adapter_version": "0.1.0",
        "profile_id": blueprint["profile_id"],
        "profile_name": blueprint["name"],
        "vector_id": blueprint["vector_id"],
        "blueprint_sha256": blueprint["blueprint_sha256"],
        "primary_capability_id": blueprint["primary_capability_ids"][0],
        "reference_role": reference_role,
        "implementation": "reference_adapter",
        "source_provenance": {
            "kind": "sunderkey_native_python",
            "repository_path": SOURCE_PATH,
            "source_sha256": source_sha256,
            "license": "LicenseRef-SUNDERKEY-All-Rights-Reserved",
            "external_dependencies": [],
        },
        "runtime": {
            "language": "python_3_11_or_newer",
            "initial_host": "linux",
            "required_isolation": required_isolation,
            "development_mode": "offline_synthetic_only",
            "maximum_action_tier": "R0",
        },
        "resource_policy": {field: [] for field in RESOURCE_FIELDS},
        "contracts": {
            "input": f"{contract_root}/input",
            "output": f"{contract_root}/output",
            "evidence": f"{contract_root}/evidence",
            "restoration": f"{contract_root}/restoration",
        },
        "hooks": {
            "dry_run": True,
            "timeout": True,
            "cancellation": True,
            "rate_limit": True,
            "structured_evidence": True,
            "cleanup_result": True,
        },
        "evidence_semantics": [
            "Every conclusion cites deterministic input evidence identifiers.",
            "Verified findings, negative results, hypotheses, and abstentions remain distinct.",
            "Input, output, adapter, blueprint, and restoration digests are preserved.",
        ],
        "known_limitations": [
            "The reference adapter accepts offline synthetic inputs only.",
            "The reference adapter does not establish qualification or target authority.",
            "Active execution requires a later isolated runner and separate authority.",
        ],
        "implementation_status": "sdk_bound_pending_qualification",
        "qualification_effect": "none",
        "routing_effect": "none",
        "execution_effect": "none",
        "deployment_effect": "none",
    }
    digest = _canonical_sha256({"domain": MANIFEST_DOMAIN, "manifest": body})
    return AdapterManifest.from_dict({**body, "manifest_sha256": digest})


@dataclass(frozen=True)
class CandidateAdapterCatalog:
    catalog_sha256: str
    manifests: tuple[AdapterManifest, ...]
    document_json: str

    @property
    def manifests_by_profile_id(self) -> dict[str, AdapterManifest]:
        return {item.profile_id: item for item in self.manifests}

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        strategy: CandidateImplementationStrategy,
        blueprints: CandidateBlueprintCatalogV2,
        source_sha256: str,
    ) -> CandidateAdapterCatalog:
        expected = {
            "schema_version",
            "catalog_id",
            "catalog_version",
            "catalog_sha256",
            "strategy_id",
            "strategy_sha256",
            "blueprint_catalog_sha256",
            "development_mode",
            "reference_slice",
            "manifests",
            "coverage_summary",
            "qualification_effect",
            "routing_effect",
            "execution_effect",
            "deployment_effect",
            "limitations",
        }
        if not isinstance(raw, dict) or set(raw) != expected:
            raise QualificationError("Candidate adapter catalog fields are invalid")
        if (
            raw.get("schema_version") != 1
            or raw.get("catalog_id") != "sunderkey-candidate-adapters-v1"
            or raw.get("catalog_version") != "0.1.0"
            or raw.get("strategy_id") != strategy.strategy_id
            or raw.get("strategy_sha256") != strategy.strategy_sha256
            or raw.get("blueprint_catalog_sha256") != blueprints.catalog_sha256
            or raw.get("development_mode") != "offline_synthetic_only"
            or any(
                raw.get(field) != "none"
                for field in (
                    "qualification_effect",
                    "routing_effect",
                    "execution_effect",
                    "deployment_effect",
                )
            )
        ):
            raise QualificationError("Candidate adapter catalog binding is invalid")
        expected_slice = [item[0] for item in REFERENCE_PROFILES]
        if raw.get("reference_slice") != expected_slice:
            raise QualificationError("Candidate adapter reference slice is invalid")
        if not isinstance(raw.get("manifests"), list):
            raise QualificationError("Candidate adapter manifests must be a list")
        manifests = tuple(AdapterManifest.from_dict(item) for item in raw["manifests"])
        blueprint_map = blueprints.blueprints_by_profile_id
        expected_manifests = tuple(
            build_reference_adapter_manifest(
                blueprint_map[profile_id], role, isolation, source_sha256
            )
            for profile_id, role, isolation in REFERENCE_PROFILES
        )
        if tuple(item.to_dict() for item in manifests) != tuple(
            item.to_dict() for item in expected_manifests
        ):
            raise QualificationError("Candidate adapter manifests do not match reviewed inputs")
        if raw.get("coverage_summary") != {
            "reference_adapter_count": 6,
            "profile_count": 6,
            "oci_required_count": 3,
            "microvm_required_count": 3,
            "deny_all_resource_policy_count": 6,
            "offline_synthetic_only_count": 6,
        }:
            raise QualificationError("Candidate adapter coverage summary is invalid")
        _strings(raw.get("limitations"), "candidate adapter catalog limitations", minimum=4)
        body = {key: value for key, value in raw.items() if key != "catalog_sha256"}
        digest = _canonical_sha256({"domain": CATALOG_DOMAIN, "catalog": body})
        if raw.get("catalog_sha256") != digest:
            raise QualificationError("Candidate adapter catalog hash does not match content")
        return cls(digest, manifests, _canonical_json(raw))

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)


def build_candidate_adapter_catalog(
    strategy: CandidateImplementationStrategy,
    blueprints: CandidateBlueprintCatalogV2,
    source_sha256: str,
) -> CandidateAdapterCatalog:
    blueprint_map = blueprints.blueprints_by_profile_id
    manifests = [
        build_reference_adapter_manifest(blueprint_map[profile_id], role, isolation, source_sha256)
        for profile_id, role, isolation in REFERENCE_PROFILES
    ]
    body = {
        "schema_version": 1,
        "catalog_id": "sunderkey-candidate-adapters-v1",
        "catalog_version": "0.1.0",
        "strategy_id": strategy.strategy_id,
        "strategy_sha256": strategy.strategy_sha256,
        "blueprint_catalog_sha256": blueprints.catalog_sha256,
        "development_mode": "offline_synthetic_only",
        "reference_slice": [item[0] for item in REFERENCE_PROFILES],
        "manifests": [item.to_dict() for item in manifests],
        "coverage_summary": {
            "reference_adapter_count": 6,
            "profile_count": 6,
            "oci_required_count": 3,
            "microvm_required_count": 3,
            "deny_all_resource_policy_count": 6,
            "offline_synthetic_only_count": 6,
        },
        "qualification_effect": "none",
        "routing_effect": "none",
        "execution_effect": "none",
        "deployment_effect": "none",
        "limitations": [
            "Only the six-profile reference slice has SDK-bound manifests.",
            "No adapter is qualified, routable, deployed, or authorized for a real target.",
            "OCI and microVM isolation are declared requirements, not deployed infrastructure.",
            "The remaining 385 specialist implementations remain backlog work.",
        ],
    }
    digest = _canonical_sha256({"domain": CATALOG_DOMAIN, "catalog": body})
    return CandidateAdapterCatalog.from_dict(
        {**body, "catalog_sha256": digest}, strategy, blueprints, source_sha256
    )


def load_candidate_adapter_catalog(
    source: str | Path,
    strategy: CandidateImplementationStrategy,
    blueprints: CandidateBlueprintCatalogV2,
    source_root: str | Path,
) -> CandidateAdapterCatalog:
    try:
        raw = json.loads(Path(source).read_text(encoding="utf-8"))
        source_sha256 = _sha256_bytes((Path(source_root) / SOURCE_PATH).read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise QualificationError(f"Could not load candidate adapter catalog: {source}") from exc
    return CandidateAdapterCatalog.from_dict(raw, strategy, blueprints, source_sha256)


@dataclass(frozen=True)
class AdapterInvocation:
    invocation_id: str
    mission_id: str
    authority_ref: str
    profile_id: str
    vector_id: str
    target_id: str
    scope_id: str
    action_tier: str
    environment: str
    dry_run: bool
    credential_refs: tuple[str, ...]
    input_data: Mapping[str, Any]


@dataclass(frozen=True)
class AdapterEvidence:
    evidence_id: str
    media_type: str
    content_sha256: str
    content_json: str

    @classmethod
    def from_content(cls, evidence_id: str, content: Mapping[str, Any]) -> AdapterEvidence:
        content_json = _canonical_json(dict(content))
        return cls(
            evidence_id=_ascii(evidence_id, "evidence ID"),
            media_type="application/json",
            content_sha256=_canonical_sha256({"domain": EVIDENCE_DOMAIN, "content": dict(content)}),
            content_json=content_json,
        )

    @classmethod
    def from_dict(cls, raw: Any) -> AdapterEvidence:
        if not isinstance(raw, dict) or set(raw) != {
            "evidence_id",
            "media_type",
            "content_sha256",
            "content",
        }:
            raise QualificationError("Adapter evidence fields are invalid")
        if raw.get("media_type") != "application/json" or not isinstance(
            raw.get("content"), Mapping
        ):
            raise QualificationError("Adapter evidence media type or content is invalid")
        rebuilt = cls.from_content(raw.get("evidence_id"), raw["content"])
        if rebuilt.content_sha256 != raw.get("content_sha256"):
            raise QualificationError("Adapter evidence hash does not match content")
        return rebuilt

    @property
    def content(self) -> dict[str, Any]:
        return json.loads(self.content_json)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "media_type": self.media_type,
            "content_sha256": self.content_sha256,
            "content": self.content,
        }


@dataclass(frozen=True)
class AdapterResult:
    status: str
    disposition: str
    observations: tuple[Mapping[str, Any], ...]
    evidence: tuple[AdapterEvidence, ...]
    restoration_status: str
    residual_effects: tuple[str, ...]
    result_sha256: str

    @classmethod
    def build(
        cls,
        *,
        status: str,
        disposition: str,
        observations: tuple[Mapping[str, Any], ...],
        evidence: tuple[AdapterEvidence, ...],
        restoration_status: str,
        residual_effects: tuple[str, ...] = (),
    ) -> AdapterResult:
        if status not in {"completed", "abstained", "cancelled", "failed_closed"}:
            raise QualificationError("Adapter result status is invalid")
        if disposition not in {"verified_finding", "negative_result", "hypothesis", "abstention"}:
            raise QualificationError("Adapter result disposition is invalid")
        if restoration_status not in {"not_required", "verified", "failed_closed"}:
            raise QualificationError("Adapter restoration status is invalid")
        body = {
            "status": status,
            "disposition": disposition,
            "observations": [dict(item) for item in observations],
            "evidence": [item.content_sha256 for item in evidence],
            "restoration_status": restoration_status,
            "residual_effects": list(residual_effects),
        }
        return cls(
            status,
            disposition,
            observations,
            evidence,
            restoration_status,
            residual_effects,
            _canonical_sha256({"domain": RESULT_DOMAIN, "result": body}),
        )

    @classmethod
    def from_dict(cls, raw: Any) -> AdapterResult:
        if not isinstance(raw, dict) or set(raw) != {
            "status",
            "disposition",
            "observations",
            "evidence",
            "restoration_status",
            "residual_effects",
            "result_sha256",
        }:
            raise QualificationError("Adapter result fields are invalid")
        observations = raw.get("observations")
        evidence = raw.get("evidence")
        residual_effects = raw.get("residual_effects")
        if (
            not isinstance(observations, list)
            or any(not isinstance(item, Mapping) for item in observations)
            or not isinstance(evidence, list)
            or not isinstance(residual_effects, list)
        ):
            raise QualificationError("Adapter result collections are invalid")
        rebuilt = cls.build(
            status=raw.get("status"),
            disposition=raw.get("disposition"),
            observations=tuple(dict(item) for item in observations),
            evidence=tuple(AdapterEvidence.from_dict(item) for item in evidence),
            restoration_status=raw.get("restoration_status"),
            residual_effects=tuple(_ascii(item, "residual effect") for item in residual_effects),
        )
        if rebuilt.result_sha256 != raw.get("result_sha256"):
            raise QualificationError("Adapter result hash does not match content")
        return rebuilt

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "disposition": self.disposition,
            "observations": [dict(item) for item in self.observations],
            "evidence": [item.to_dict() for item in self.evidence],
            "restoration_status": self.restoration_status,
            "residual_effects": list(self.residual_effects),
            "result_sha256": self.result_sha256,
        }


class CandidateAdapter(Protocol):
    manifest: AdapterManifest

    def execute(self, invocation: AdapterInvocation) -> AdapterResult:
        """Execute one already admitted invocation."""


def validate_reference_invocation(
    manifest: AdapterManifest,
    invocation: AdapterInvocation,
) -> None:
    """Enforce the Phase 157 synthetic reference boundary before adapter code runs."""

    for value, label in (
        (invocation.invocation_id, "invocation ID"),
        (invocation.mission_id, "mission ID"),
        (invocation.authority_ref, "authority reference"),
        (invocation.target_id, "target ID"),
        (invocation.scope_id, "scope ID"),
    ):
        _ascii(value, label)
    if invocation.profile_id != manifest.profile_id or invocation.vector_id != manifest.vector_id:
        raise QualificationError("Adapter invocation does not match the manifest")
    if invocation.environment != "synthetic" or invocation.action_tier != "R0":
        raise QualificationError("Reference adapter requires synthetic R0 execution")
    if invocation.dry_run is not True:
        raise QualificationError("Reference adapter requires dry_run")
    if invocation.credential_refs:
        raise QualificationError("Reference adapter does not accept credentials")
    if not manifest.resource_policy.is_deny_all:
        raise QualificationError("Reference adapter resource policy is not deny-all")
    if not isinstance(invocation.input_data, Mapping):
        raise QualificationError("Adapter input data must be a mapping")


__all__ = [
    "AdapterEvidence",
    "AdapterInvocation",
    "AdapterManifest",
    "AdapterResourcePolicy",
    "AdapterResult",
    "CandidateAdapter",
    "CandidateAdapterCatalog",
    "REFERENCE_PROFILES",
    "SOURCE_PATH",
    "build_candidate_adapter_catalog",
    "build_reference_adapter_manifest",
    "load_candidate_adapter_catalog",
    "validate_reference_invocation",
]
