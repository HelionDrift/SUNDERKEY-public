"""Compare supplied digest outputs with bounded local reference calculations."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "crypto_supplied_digest_vector_consistency"
PROFILE_ID = "AOE-GE-D22-S14"
CAPABILITY_ID = "army.ge.d22.s14"
VECTOR_ID = "AV-GE-D22-S14-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D22-S14"
WAVE_ID = "IW2-027"
COMMANDER_ID = "AOE-GE-D22-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:6226e95928d24d9b3a4606aba20a94be97388e67b8477c2d293687c8e0cbe6c5"
DOMAIN = "sunderkey.offline-digest-vector-consistency.v1"
MAX_MODEL_BYTES = 131_072
MAX_REPORT_BYTES = 131_072
MAX_VECTORS = 32
MAX_INPUT_BYTES = 256
ALGORITHMS = {
    "sha256": hashlib.sha256,
    "sha3_256": hashlib.sha3_256,
    "sha512": hashlib.sha512,
}
HEX = re.compile(r"(?:[0-9a-f]{2})*\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process",
        "provider", "credentials", "target_interaction",
        "finding_publication", "qualification",
    )
}


class DigestVectorConsistencyError(ValueError):
    """The supplied vectors or original-model replay are invalid."""


def _model(value: Any) -> tuple[dict, list[tuple[str, str, bytes, str]], str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "synthetic_fixture",
            "vector_inventory_complete", "vectors",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise DigestVectorConsistencyError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["synthetic_fixture"], "synthetic fixture")
    if not model["synthetic_fixture"]:
        raise DigestVectorConsistencyError("Only declared synthetic fixtures are accepted")
    core.boolean(model["vector_inventory_complete"], "vector inventory completeness")
    vectors = []
    seen = set()
    for item in core.bounded_list(model["vectors"], MAX_VECTORS, "vectors"):
        row = core.exact(
            item, {"vector_id", "algorithm", "input_hex", "claimed_digest_hex"}, "vector"
        )
        vector_id = core.identifier(row["vector_id"], "vector ID")
        if vector_id in seen:
            raise DigestVectorConsistencyError("Duplicate vector ID")
        seen.add(vector_id)
        algorithm = core.choice(row["algorithm"], set(ALGORITHMS), "algorithm")
        input_hex = row["input_hex"]
        if (
            type(input_hex) is not str
            or len(input_hex) > 2 * MAX_INPUT_BYTES
            or HEX.fullmatch(input_hex) is None
        ):
            raise DigestVectorConsistencyError("Input must be bounded lowercase byte hex")
        claimed = row["claimed_digest_hex"]
        expected_length = ALGORITHMS[algorithm]().digest_size * 2
        if (
            type(claimed) is not str
            or len(claimed) != expected_length
            or HEX.fullmatch(claimed) is None
        ):
            raise DigestVectorConsistencyError("Claimed digest has invalid encoding or length")
        vectors.append((vector_id, algorithm, bytes.fromhex(input_hex), claimed))
    if not vectors:
        raise DigestVectorConsistencyError("At least one vector is required")
    return model, vectors, core.canonical(model)


def _derive(value: Any) -> dict:
    model, vectors, source_text = _model(value)
    rows = []
    for vector_id, algorithm, input_bytes, claimed in vectors:
        calculated = ALGORITHMS[algorithm](input_bytes).hexdigest()
        rows.append({
            "vector_id": vector_id,
            "algorithm": algorithm,
            "input_byte_count": len(input_bytes),
            "matches_reference_digest": claimed == calculated,
        })
    rows.sort(key=lambda row: row["vector_id"])
    mismatch_ids = [row["vector_id"] for row in rows if not row["matches_reference_digest"]]
    unknown = [] if model["vector_inventory_complete"] else [
        "supplied_vector_inventory_incomplete"
    ]
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
        "synthetic_fixture_asserted": True,
        "vector_inventory_complete_asserted": model["vector_inventory_complete"],
        "supplied_vector_count": len(vectors),
        "vector_projections": rows,
        "mismatch_vector_ids": mismatch_ids,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_digest_consistency_projection",
        "source_authenticated": False,
        "claimed_implementation_executed": False,
        "implementation_verified": False,
        "cryptanalysis_performed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Fixture status, vector completeness, and claimed outputs are "
            "caller-supplied assertions.",
            "Only local unkeyed reference digests are calculated; no claimed "
            "implementation is executed.",
            "A mismatch does not establish an implementation defect or practical attack.",
            "The caller must provide synthetic nonsecret inputs; fixture status is not proven.",
            "No target, credential, finding, qualification, or action authority is involved.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="DVC-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class DigestVectorConsistencyReport:
    """Unsigned digest projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise DigestVectorConsistencyError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> DigestVectorConsistencyReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_digest_vectors(model: Any) -> DigestVectorConsistencyReport:
    return DigestVectorConsistencyReport._owned(_derive(model))


def verify_supplied_digest_vectors(
    report: Any, *, model: Any
) -> DigestVectorConsistencyReport:
    if type(report) is not DigestVectorConsistencyReport:
        raise DigestVectorConsistencyError("Exact digest vector wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise DigestVectorConsistencyError("Report differs from separate original model")
    return DigestVectorConsistencyReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-digest-vectors",
        "synthetic_fixture": True,
        "vector_inventory_complete": True,
        "vectors": [
            {
                "vector_id": "empty-sha256",
                "algorithm": "sha256",
                "input_hex": "",
                "claimed_digest_hex": hashlib.sha256(b"").hexdigest(),
            },
            {
                "vector_id": "abc-sha3",
                "algorithm": "sha3_256",
                "input_hex": "616263",
                "claimed_digest_hex": hashlib.sha3_256(b"abc").hexdigest(),
            },
        ],
    }
