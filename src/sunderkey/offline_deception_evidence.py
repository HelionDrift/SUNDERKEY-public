"""Reconcile supplied deception cues without identifying live honeypots."""

from __future__ import annotations

from typing import Any

from .offline_recon_evidence_core import (
    ReconEvidenceReport,
    ReconEvidenceSpec,
    analyze,
    verify,
)

COMPONENT_ID = "supplied_deception_cue_reconciliation"
PROFILE_ID = "AOE-GA-D01-S12"
CAPABILITY_ID = "army.ga.d01.s12"
VECTOR_ID = "AV-GA-D01-S12-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D01-S12"
WAVE_ID = "IW2-012"
COMMANDER_ID = "AOE-GA-D01-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:ff95bd14c292eef7b9bf36833d3f890c87396f6d23ec036138c14b26f65d6b10"
SPEC = ReconEvidenceSpec(
    component_id=COMPONENT_ID,
    profile_id=PROFILE_ID,
    semantics_profile="supplied-deception-cues-v1",
    domain="sunderkey.offline-deception-evidence.v1",
    id_prefix="DCR-",
    kinds=frozenset(
        (
            "synthetic_marker",
            "service_identity_conflict",
            "route_identity_conflict",
            "operator_assertion",
        )
    ),
    limitation=(
        "A supplied cue pattern is only a review candidate, not proof of a "
        "honeypot or malicious deception."
    ),
)


def analyze_supplied_deception_cues(model: Any) -> ReconEvidenceReport:
    """Group caller-supplied cue assertions without target interaction."""
    return analyze(model, SPEC)


def verify_supplied_deception_cues(report: Any, *, model: Any) -> ReconEvidenceReport:
    return verify(report, model=model, spec=SPEC)
