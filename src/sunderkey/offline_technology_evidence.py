"""Reconcile supplied technology labels without live fingerprinting."""

from __future__ import annotations

from typing import Any

from .offline_recon_evidence_core import (
    ReconEvidenceReport,
    ReconEvidenceSpec,
    analyze,
    verify,
)

COMPONENT_ID = "supplied_technology_evidence_reconciliation"
PROFILE_ID = "AOE-GA-D01-S10"
CAPABILITY_ID = "army.ga.d01.s10"
VECTOR_ID = "AV-GA-D01-S10-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D01-S10"
WAVE_ID = "IW2-010"
COMMANDER_ID = "AOE-GA-D01-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:195234e583f12e8185ac460f87c9adf1592a6d71ebd556b5c7dfc3345bd8a907"
SPEC = ReconEvidenceSpec(
    component_id=COMPONENT_ID,
    profile_id=PROFILE_ID,
    semantics_profile="supplied-technology-evidence-v1",
    domain="sunderkey.offline-technology-evidence.v1",
    id_prefix="TER-",
    kinds=frozenset(
        ("response_header", "package_manifest", "artifact_metadata", "operator_assertion")
    ),
    limitation=(
        "A supplied technology label is not proof of installed software, "
        "version, exposure, or vulnerability."
    ),
)


def analyze_supplied_technology_evidence(model: Any) -> ReconEvidenceReport:
    """Group caller-supplied, opaque technology assertions."""
    return analyze(model, SPEC)


def verify_supplied_technology_evidence(report: Any, *, model: Any) -> ReconEvidenceReport:
    return verify(report, model=model, spec=SPEC)
