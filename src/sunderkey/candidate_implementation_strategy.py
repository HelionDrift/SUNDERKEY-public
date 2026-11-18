"""Versioned technical candidate implementation strategy contract."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256

STRATEGY_DOMAIN = "sunderkey.candidate-implementation-strategy.v1"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
STRATEGY_ID_PATTERN = re.compile(r"CIS-[0-9A-F]{32}")


def candidate_implementation_strategy_body() -> dict[str, Any]:
    """Return the technical adapter and safety strategy reference."""

    return {
        "schema_version": 1,
        "program": "SUNDERKEY",
        "reasoning_provider": {
            "initial_provider": "openai_managed_api",
            "binding": "existing_managed_api_boundary",
            "candidate_requirement": "pin_exact_model_and_revision",
            "portability": "stable_provider_neutral_contracts",
        },
        "adapter_substrate": {
            "language": "python",
            "ownership": "sunderkey",
            "interface": "typed_capability_adapter_sdk",
            "arbitrary_shell": "prohibited",
            "direct_model_tool_access": "prohibited",
            "unreviewed_plugins": "prohibited",
        },
        "tool_supply_chain": {
            "allowed_sources": ["reviewed_open_source", "sunderkey_native"],
            "required_records": [
                "license",
                "source",
                "version",
                "executable_digest",
                "dependency_digests",
                "configuration_digest",
                "capability_mapping",
                "known_limitations",
                "evidence_semantics",
            ],
        },
        "isolation": {
            "bounded_low_impact": "oci_container",
            "active_or_high_consequence": "microvm",
            "high_consequence_classes": [
                "credential_bearing",
                "kernel",
                "firmware",
                "ot",
                "transportation",
                "space",
                "clinical",
            ],
        },
        "execution_hosts": {
            "initial_host": "linux",
            "other_surfaces": "explicit_remote_adapters_or_approved_ranges",
            "host_boundary_weakening": "prohibited",
        },
        "resource_policy": {
            "default": "deny",
            "resources": ["network", "filesystem", "process", "credential"],
            "grant_mode": "exact_per_adapter_allowlist_through_authority_chain",
        },
        "phase157_scope": {
            "credentials": "synthetic_or_test_only",
            "targets": "synthetic_or_approved_test_only",
            "production_credentials": "prohibited",
            "real_target_access": "not_authorized_by_d016",
        },
        "rollout": {
            "initial_slice": [
                "passive",
                "api",
                "identity",
                "cloud",
                "endpoint",
                "high_consequence_restoration",
            ],
            "next_step": "validate_sdk_before_thirty_scheduled_waves",
            "phase158_gate": [
                "static_analysis",
                "unit",
                "integration",
                "containment",
                "evidence",
                "restoration",
            ],
        },
        "stable_contracts": ["capability", "input", "output", "evidence", "restoration"],
        "replaceable_bindings": ["provider", "model", "tool", "adapter"],
        "no_effects": [
            "qualification",
            "routing",
            "deployment",
            "production_infrastructure",
            "production_credentials",
            "target_authority",
        ],
        "limitations": [
            "This strategy does not approve any external tool or license.",
            "This strategy does not authorize model or adapter self-authorization.",
            "This strategy does not authorize production or real-target execution.",
            "This strategy does not qualify or route any candidate.",
            "Every active test still requires exact mission and target authority.",
        ],
    }


@dataclass(frozen=True)
class CandidateImplementationStrategy:
    """Content-addressed technical strategy with no runtime authority."""

    strategy_id: str
    strategy_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CandidateImplementationStrategy:
        if not isinstance(raw, dict):
            raise QualificationError("Strategy must be an object")
        body_fields = set(candidate_implementation_strategy_body())
        if set(raw) != body_fields | {"strategy_id", "strategy_sha256"}:
            raise QualificationError("Strategy fields are invalid")
        body = {key: value for key, value in raw.items() if key in body_fields}
        if body != candidate_implementation_strategy_body():
            raise QualificationError("Strategy does not match the versioned reference")
        digest = raw.get("strategy_sha256")
        strategy_id = raw.get("strategy_id")
        if not isinstance(digest, str) or SHA256_PATTERN.fullmatch(digest) is None:
            raise QualificationError("Strategy hash is invalid")
        if not isinstance(strategy_id, str) or STRATEGY_ID_PATTERN.fullmatch(strategy_id) is None:
            raise QualificationError("Strategy ID is invalid")
        expected_digest = _canonical_sha256({"domain": STRATEGY_DOMAIN, "strategy": body})
        expected_id = f"CIS-{expected_digest.removeprefix('sha256:')[:32].upper()}"
        if digest != expected_digest or strategy_id != expected_id:
            raise QualificationError("Strategy identity does not match content")
        return cls(strategy_id, digest, _canonical_json(raw))

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)


def build_candidate_implementation_strategy() -> CandidateImplementationStrategy:
    """Build the technical strategy artifact."""

    body = candidate_implementation_strategy_body()
    digest = _canonical_sha256({"domain": STRATEGY_DOMAIN, "strategy": body})
    return CandidateImplementationStrategy.from_dict(
        {
            **body,
            "strategy_id": f"CIS-{digest.removeprefix('sha256:')[:32].upper()}",
            "strategy_sha256": digest,
        }
    )


def load_candidate_implementation_strategy(
    source: str | Path,
) -> CandidateImplementationStrategy:
    try:
        raw = json.loads(Path(source).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise QualificationError(f"Could not load strategy: {source}") from exc
    return CandidateImplementationStrategy.from_dict(raw)


__all__ = [
    "CandidateImplementationStrategy",
    "build_candidate_implementation_strategy",
    "candidate_implementation_strategy_body",
    "load_candidate_implementation_strategy",
]
