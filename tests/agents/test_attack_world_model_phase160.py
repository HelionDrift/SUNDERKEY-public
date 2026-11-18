"""Phase 160 deterministic attack world model coverage."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.attack_world_model import (
    NO_EFFECTS,
    AttackEdge,
    AttackNode,
    AttackWorldModelError,
    AttackWorldSnapshot,
    EdgeKind,
    EvidenceBinding,
    GraphLimits,
    NodeKind,
    ObservationDelta,
    VerificationState,
    apply_observation_delta,
    build_attack_world_snapshot,
    compute_uncovered_frontier,
    detect_evidence_conflicts,
    query_candidate_attack_paths,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "registry" / "schemas" / "attack-world-model-v1.schema.json"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
SCOPE = ("scope:assessment",)
TECHNIQUE = ("technique:access",)


def evidence(
    state: VerificationState | str = VerificationState.VERIFIED,
    *,
    digest: str = DIGEST_A,
    observed_at: str = "2026-09-19T12:00:00Z",
    expires_at: str | None = None,
    confidence: float = 0.9,
) -> EvidenceBinding:
    return EvidenceBinding(
        provenance_artifact_digest=digest,
        observed_at=observed_at,
        confidence=confidence,
        verification_state=state,
        source_kind="artifact",
        expires_at=expires_at,
    )


def node(
    node_id: str,
    kind: NodeKind = NodeKind.ASSET,
    *,
    state: VerificationState | str = VerificationState.VERIFIED,
    credential_ref: str | None = None,
    expires_at: str | None = None,
) -> AttackNode:
    return AttackNode(
        node_id=node_id,
        node_kind=kind,
        label=f"Node {node_id}",
        scope_refs=SCOPE,
        technique_refs=(),
        evidence=evidence(state, expires_at=expires_at),
        credential_ref=credential_ref,
    )


def edge(
    fact_id: str,
    source: str,
    target: str,
    *,
    state: VerificationState | str = VerificationState.VERIFIED,
    kind: EdgeKind = EdgeKind.REACHABLE,
    technique_refs: tuple[str, ...] = TECHNIQUE,
    digest: str = DIGEST_B,
    expires_at: str | None = None,
) -> AttackEdge:
    return AttackEdge(
        fact_id=fact_id,
        source_node_id=source,
        target_node_id=target,
        edge_kind=kind,
        scope_refs=SCOPE,
        technique_refs=technique_refs,
        evidence=evidence(
            state,
            digest=digest,
            confidence=0.8,
            expires_at=expires_at,
        ),
    )


class AttackWorldModelPhase160Tests(unittest.TestCase):
    def base_snapshot(self):
        nodes = (
            node("asset:start", NodeKind.ASSET),
            node("service:middle", NodeKind.SERVICE),
            node("data:target", NodeKind.DATA_STORE),
        )
        edges = (
            edge("fact:start-middle", "asset:start", "service:middle"),
            edge(
                "fact:middle-target",
                "service:middle",
                "data:target",
                technique_refs=("technique:collect",),
            ),
        )
        return build_attack_world_snapshot(nodes, edges)

    def test_all_node_and_edge_types_are_explicit(self) -> None:
        self.assertEqual(
            {item.value for item in NodeKind},
            {
                "asset",
                "principal",
                "identity",
                "endpoint",
                "service",
                "data_store",
                "finding",
                "control",
                "credential",
                "trust_zone",
            },
        )
        self.assertEqual(
            {item.value for item in EdgeKind},
            {
                "observed",
                "asserted",
                "inferred",
                "reachable",
                "authenticated_as",
                "authorized_to",
                "contains",
                "depends_on",
                "communicates_with",
                "mitigated_by",
            },
        )

    def test_input_order_does_not_change_canonical_snapshot(self) -> None:
        original = self.base_snapshot()
        reversed_snapshot = build_attack_world_snapshot(
            reversed(original.nodes),
            reversed(original.edges),
        )
        self.assertEqual(original, reversed_snapshot)
        self.assertEqual(original.to_dict(), reversed_snapshot.to_dict())
        self.assertEqual(
            [item.node_id for item in original.nodes],
            ["asset:start", "data:target", "service:middle"],
        )

    def test_snapshot_tamper_and_noncanonical_documents_fail_closed(self) -> None:
        snapshot = self.base_snapshot()
        AttackWorldSnapshot.from_dict(snapshot.to_dict())

        tampered = copy.deepcopy(snapshot.to_dict())
        tampered["nodes"][0]["label"] = "Changed"
        with self.assertRaisesRegex(AttackWorldModelError, "identity"):
            AttackWorldSnapshot.from_dict(tampered)

        reordered = copy.deepcopy(snapshot.to_dict())
        reordered["nodes"].reverse()
        with self.assertRaisesRegex(AttackWorldModelError, "ordering"):
            AttackWorldSnapshot.from_dict(reordered)

        extra = copy.deepcopy(snapshot.to_dict())
        extra["unexpected"] = True
        with self.assertRaisesRegex(AttackWorldModelError, "fields"):
            AttackWorldSnapshot.from_dict(extra)

    def test_cycles_are_safe_and_paths_are_deterministic(self) -> None:
        snapshot = self.base_snapshot()
        snapshot = apply_observation_delta(
            snapshot,
            ObservationDelta(
                edges=(
                    edge(
                        "fact:cycle",
                        "service:middle",
                        "asset:start",
                        technique_refs=(),
                    ),
                )
            ),
        )
        first = query_candidate_attack_paths(
            snapshot,
            start_node_ids=("asset:start",),
            target_node_ids=("data:target",),
            required_scope_refs=SCOPE,
            required_technique_refs=("technique:access", "technique:collect"),
            as_of="2026-09-20T12:00:00Z",
        )
        second = query_candidate_attack_paths(
            snapshot,
            start_node_ids=("asset:start",),
            target_node_ids=("data:target",),
            required_scope_refs=SCOPE,
            required_technique_refs=("technique:collect", "technique:access"),
            as_of="2026-09-20T12:00:00Z",
        )
        self.assertEqual(first, second)
        self.assertEqual(len(first.verified_paths), 1)
        self.assertEqual(first.verified_paths[0].node_ids.count("asset:start"), 1)
        self.assertFalse(first.truncated)

    def test_conflicting_evidence_is_detected_and_suppressed(self) -> None:
        snapshot = self.base_snapshot()
        negative = edge(
            "fact:middle-target-negative",
            "service:middle",
            "data:target",
            state=VerificationState.NEGATIVE,
            technique_refs=("technique:collect",),
            digest=DIGEST_C,
        )
        snapshot = apply_observation_delta(
            snapshot,
            ObservationDelta(edges=(negative,)),
        )
        conflicts = detect_evidence_conflicts(snapshot, as_of="2026-09-20T12:00:00Z")
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(set(conflicts[0].verification_states), {"negative", "verified"})
        result = query_candidate_attack_paths(
            snapshot,
            start_node_ids=("asset:start",),
            target_node_ids=("data:target",),
            required_scope_refs=SCOPE,
            as_of="2026-09-20T12:00:00Z",
        )
        self.assertEqual(result.verified_paths, ())
        self.assertEqual(result.hypothesis_paths, ())
        self.assertEqual(result.conflicts, conflicts)

    def test_negative_evidence_cannot_be_overwritten_by_hypothesis(self) -> None:
        base = build_attack_world_snapshot(
            (node("asset:a"), node("asset:b")),
            (
                edge(
                    "fact:negative",
                    "asset:a",
                    "asset:b",
                    state=VerificationState.NEGATIVE,
                ),
            ),
        )
        updated = apply_observation_delta(
            base,
            ObservationDelta(
                edges=(
                    edge(
                        "fact:hypothesis",
                        "asset:a",
                        "asset:b",
                        state=VerificationState.HYPOTHESIS,
                    ),
                )
            ),
        )
        self.assertEqual(len(updated.edges), 2)
        self.assertEqual(len(updated.conflicts), 1)
        result = query_candidate_attack_paths(
            updated,
            start_node_ids=("asset:a",),
            target_node_ids=("asset:b",),
            required_scope_refs=SCOPE,
            as_of="2026-09-20T12:00:00Z",
        )
        self.assertEqual(result.hypothesis_paths, ())

    def test_verified_and_hypothesis_paths_are_separate(self) -> None:
        snapshot = build_attack_world_snapshot(
            (
                node("asset:start"),
                node("service:verified"),
                node("service:hypothesis"),
                node("data:target"),
            ),
            (
                edge("fact:v1", "asset:start", "service:verified"),
                edge("fact:v2", "service:verified", "data:target"),
                edge(
                    "fact:h1",
                    "asset:start",
                    "service:hypothesis",
                    state=VerificationState.HYPOTHESIS,
                ),
                edge("fact:h2", "service:hypothesis", "data:target"),
            ),
        )
        result = query_candidate_attack_paths(
            snapshot,
            start_node_ids=("asset:start",),
            target_node_ids=("data:target",),
            required_scope_refs=SCOPE,
            required_technique_refs=TECHNIQUE,
            as_of="2026-09-20T12:00:00Z",
        )
        self.assertEqual(len(result.verified_paths), 1)
        self.assertEqual(len(result.hypothesis_paths), 1)
        self.assertEqual(result.verified_paths[0].path_state, "verified")
        self.assertEqual(result.hypothesis_paths[0].path_state, "hypothesis")

    def test_stale_facts_are_excluded_and_enter_the_frontier(self) -> None:
        snapshot = build_attack_world_snapshot(
            (node("asset:a"), node("asset:b")),
            (
                edge(
                    "fact:stale",
                    "asset:a",
                    "asset:b",
                    expires_at="2026-09-20T00:00:00Z",
                ),
            ),
        )
        result = query_candidate_attack_paths(
            snapshot,
            start_node_ids=("asset:a",),
            target_node_ids=("asset:b",),
            required_scope_refs=SCOPE,
            as_of="2026-09-20T00:00:00Z",
        )
        self.assertEqual(result.verified_paths, ())
        frontier = compute_uncovered_frontier(
            snapshot,
            required_scope_refs=SCOPE,
            required_technique_refs=TECHNIQUE,
            start_node_ids=("asset:a",),
            target_node_ids=("asset:b",),
            as_of="2026-09-20T00:00:00Z",
        )
        self.assertIn("stale_evidence", {item.kind for item in frontier})
        self.assertIn("target_not_verified_reachable", {item.kind for item in frontier})

    def test_path_expansion_and_graph_limits_are_enforced(self) -> None:
        limits = GraphLimits(
            max_nodes=4,
            max_edges=4,
            max_delta_facts=2,
            max_depth=3,
            max_path_expansions=1,
            max_paths=2,
        )
        snapshot = build_attack_world_snapshot(
            (node("asset:a"), node("asset:b"), node("asset:c")),
            (
                edge("fact:a-b", "asset:a", "asset:b"),
                edge("fact:a-c", "asset:a", "asset:c"),
            ),
            limits=limits,
        )
        result = query_candidate_attack_paths(
            snapshot,
            start_node_ids=("asset:a",),
            target_node_ids=("asset:c",),
            required_scope_refs=SCOPE,
            as_of="2026-09-20T12:00:00Z",
        )
        self.assertEqual(result.expansions, 1)
        self.assertTrue(result.truncated)
        with self.assertRaisesRegex(AttackWorldModelError, "max_depth"):
            query_candidate_attack_paths(
                snapshot,
                start_node_ids=("asset:a",),
                target_node_ids=("asset:b",),
                as_of="2026-09-20T12:00:00Z",
                max_depth=4,
            )
        with self.assertRaisesRegex(AttackWorldModelError, "max_nodes"):
            build_attack_world_snapshot(
                tuple(node(f"asset:{index}") for index in range(5)),
                (),
                limits=limits,
            )

    def test_secret_material_is_rejected_and_credentials_are_references_only(self) -> None:
        credential = node(
            "credential:one",
            NodeKind.CREDENTIAL,
            credential_ref="credref:vault/team/credential-one",
        )
        self.assertEqual(
            credential.to_dict()["credential_ref"],
            "credref:vault/team/credential-one",
        )
        with self.assertRaisesRegex(AttackWorldModelError, "credref"):
            node(
                "credential:two",
                NodeKind.CREDENTIAL,
                credential_ref="cleartext-secret-value",
            )
        with self.assertRaisesRegex(AttackWorldModelError, "secret material"):
            AttackNode(
                node_id="service:bad",
                node_kind=NodeKind.SERVICE,
                label="Service password=hunter2",
                scope_refs=SCOPE,
                technique_refs=(),
                evidence=evidence(),
            )
        raw = credential.to_dict()
        raw["credential_value"] = "not-permitted"
        with self.assertRaisesRegex(AttackWorldModelError, "extra"):
            AttackNode.from_dict(raw)

    def test_provenance_is_required_hash_bound_and_tamper_evident(self) -> None:
        snapshot = self.base_snapshot()
        document = snapshot.to_dict()
        self.assertEqual(
            document["edges"][0]["evidence"]["provenance_artifact_digest"],
            DIGEST_B,
        )
        tampered = copy.deepcopy(document)
        tampered["edges"][0]["evidence"]["provenance_artifact_digest"] = DIGEST_C
        with self.assertRaisesRegex(AttackWorldModelError, "identity"):
            AttackWorldSnapshot.from_dict(tampered)
        invalid = copy.deepcopy(document["edges"][0])
        invalid["evidence"].pop("provenance_artifact_digest")
        with self.assertRaisesRegex(AttackWorldModelError, "missing"):
            AttackEdge.from_dict(invalid)

    def test_delta_builds_parent_chain_without_mutating_parent(self) -> None:
        parent = self.base_snapshot()
        child = apply_observation_delta(
            parent,
            ObservationDelta(
                nodes=(node("control:one", NodeKind.CONTROL),),
                edges=(
                    edge(
                        "fact:mitigation",
                        "data:target",
                        "control:one",
                        kind=EdgeKind.MITIGATED_BY,
                        technique_refs=(),
                    ),
                ),
            ),
        )
        self.assertIsNone(parent.parent_sha256)
        self.assertEqual(child.parent_sha256, parent.snapshot_sha256)
        self.assertNotEqual(child.snapshot_sha256, parent.snapshot_sha256)
        child.verify_parent(parent)
        AttackWorldSnapshot.from_dict(child.to_dict(), expected_parent=parent)
        wrong_parent = build_attack_world_snapshot((node("asset:other"),), ())
        with self.assertRaisesRegex(AttackWorldModelError, "parent hash"):
            child.verify_parent(wrong_parent)

    def test_no_effect_contract_applies_to_snapshots_queries_and_frontier(self) -> None:
        snapshot = self.base_snapshot()
        self.assertEqual(snapshot.to_dict()["effects"], NO_EFFECTS)
        result = query_candidate_attack_paths(
            snapshot,
            start_node_ids=("asset:start",),
            target_node_ids=("data:target",),
            required_scope_refs=SCOPE,
            as_of="2026-09-20T12:00:00Z",
        )
        self.assertEqual(result.to_dict()["effects"], NO_EFFECTS)
        frontier = compute_uncovered_frontier(
            snapshot,
            required_scope_refs=SCOPE,
            required_technique_refs=("technique:missing",),
            as_of="2026-09-20T12:00:00Z",
        )
        self.assertTrue(frontier)
        self.assertTrue(all(item.to_dict()["effects"] == NO_EFFECTS for item in frontier))

    @unittest.skipUnless(Draft202012Validator is not None, "jsonschema is not installed")
    def test_snapshot_matches_closed_published_schema(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(self.base_snapshot().to_dict())


if __name__ == "__main__":
    unittest.main()
