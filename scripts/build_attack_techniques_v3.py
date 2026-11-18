#!/usr/bin/env python3
# ruff: noqa: E501
"""Build or check the Phase 157 attack-technique reference catalog v3."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from sunderkey.attack_techniques_v3 import (
    CATALOG_DOMAIN,
    CATALOG_ID,
    CATALOG_STATUS,
    CATALOG_VERSION,
    EFFECT_FIELDS,
    REFERENCE_PROFILES,
    SCHEMA_VERSION,
    AttackTechniqueCatalog,
    canonical_sha256,
)

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = ROOT / "registry" / "attack-techniques-reference-v3.json"
SCHEMA_PATH = ROOT / "registry" / "schemas" / "attack-technique-catalog-v3.schema.json"

SOURCES = (
    {
        "source_id": "iec-62443-3-3",
        "title": "IEC 62443-3-3:2013 Industrial communication networks security",
        "publisher": "International Electrotechnical Commission",
        "source_version": "IEC 62443-3-3:2013",
        "release_date": "2013-08-07",
        "url": "https://webstore.iec.ch/en/publication/7033",
        "reference_ids": ["SR 5.1", "SR 5.2", "SR 7.4"],
    },
    {
        "source_id": "mitre-attack-enterprise",
        "title": "MITRE ATT&CK Enterprise",
        "publisher": "MITRE",
        "source_version": "19.2",
        "release_date": "2026-08-05",
        "url": "https://github.com/mitre-attack/attack-stix-data/releases/tag/v19.2",
        "reference_ids": [
            "T1053.005",
            "T1069.002",
            "T1069.003",
            "T1087.004",
            "T1098",
            "T1098.003",
            "T1543.003",
            "T1547.001",
            "T1593.003",
            "T1596.001",
            "T1596.003",
        ],
    },
    {
        "source_id": "owasp-api-security",
        "title": "OWASP API Security Top 10",
        "publisher": "OWASP Foundation",
        "source_version": "2023",
        "release_date": "2023-07-03",
        "url": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
        "reference_ids": ["API1:2023"],
    },
)

SOURCE_INDEX = {item["source_id"]: item for item in SOURCES}
PROFILE_INDEX = {item[0]: item for item in REFERENCE_PROFILES}


def _mapping(source_id: str, reference_id: str, rationale: str) -> dict[str, str]:
    source = SOURCE_INDEX[source_id]
    relationship = {
        "mitre-attack-enterprise": "related_technique",
        "owasp-api-security": "exact_risk",
        "iec-62443-3-3": "control_alignment",
    }[source_id]
    return {
        "source_id": source_id,
        "source_version": source["source_version"],
        "source_release_date": source["release_date"],
        "reference_id": reference_id,
        "relationship": relationship,
        "rationale": rationale,
    }


def _technique(
    technique_id: str,
    profile_id: str,
    name: str,
    record_kind: str,
    mechanic: str,
    description: str,
    prerequisites: list[str],
    observables: list[str],
    safe_proof: list[str],
    negative_controls: list[str],
    cleanup: list[str],
    blind_spots: list[str],
    mappings: list[dict[str, str]],
) -> dict[str, Any]:
    _, _, vector_id, family = PROFILE_INDEX[profile_id]
    value: dict[str, Any] = {
        "technique_id": technique_id,
        "profile_id": profile_id,
        "vector_id": vector_id,
        "name": name,
        "family": family,
        "record_kind": record_kind,
        "mechanic": mechanic,
        "description": description,
        "prerequisites": prerequisites,
        "observables": observables,
        "safe_proof": safe_proof,
        "negative_controls": negative_controls,
        "cleanup_and_restoration": cleanup,
        "blind_spots": blind_spots,
        "standards_mappings": mappings,
        **dict.fromkeys(EFFECT_FIELDS, "none"),
    }
    value["technique_sha256"] = canonical_sha256(
        {"domain": f"{CATALOG_DOMAIN}.technique", "technique": value}
    )
    return value


def build_techniques() -> list[dict[str, Any]]:
    """Return the concrete reference records in deterministic ID order."""

    records = [
        _technique(
            "AT3-GA-D01-S01-01",
            "AOE-GA-D01-S01",
            "Certificate transparency name expansion",
            "technique",
            "Join certificate subject alternative names to the scoped suffix and issuance window.",
            "Expand candidate hostnames from a fixed offline certificate transparency export.",
            [
                "A synthetic certificate export has stable record identifiers and timestamps.",
                "The approved synthetic suffix and observation window are fixed before analysis.",
            ],
            [
                "Subject alternative names sharing the scoped suffix.",
                "Issuer and not-before timestamps that support each name relationship.",
            ],
            [
                "Report only normalized names and cited synthetic record identifiers.",
                "Recompute the join from the same immutable export and compare its digest.",
            ],
            [
                "Include a certificate for an unrelated suffix and require its exclusion.",
                "Include a matching name outside the time window and require its exclusion.",
            ],
            [
                "Delete the disposable normalized-name table after evidence is hashed.",
                "Verify the source export digest is unchanged because analysis is read-only.",
            ],
            [
                "Private certification authorities are absent from public transparency data.",
                "Wildcard names do not establish that any concrete host is active.",
            ],
            [
                _mapping(
                    "mitre-attack-enterprise",
                    "T1596.003",
                    "Certificate records are used only as offline search-open-web evidence.",
                )
            ],
        ),
        _technique(
            "AT3-GA-D01-S01-02",
            "AOE-GA-D01-S01",
            "Passive DNS relationship correlation",
            "path",
            "Traverse time-bounded passive DNS name-to-address-to-name relationships.",
            "Correlate historical DNS observations without issuing a DNS query or touching a target.",
            [
                "An offline synthetic passive DNS table includes first-seen and last-seen times.",
                "Seed names and the maximum relationship depth are explicitly bounded.",
            ],
            [
                "Timestamped name and address edges used by each reported path.",
                "Path depth and temporal overlap for every correlation.",
            ],
            [
                "Emit the shortest bounded path with the evidence ID for every edge.",
                "Replay the traversal on a shuffled copy and require the same sorted result.",
            ],
            [
                "Add an address reuse edge with no temporal overlap and reject the path.",
                "Add a relationship beyond the depth bound and require its omission.",
            ],
            [
                "Discard the derived adjacency index after the result digest is recorded.",
                "Confirm no resolver or network interface was used during the proof.",
            ],
            [
                "Shared hosting can create relationships with no organizational ownership.",
                "Short retention windows can hide older name and address associations.",
            ],
            [
                _mapping(
                    "mitre-attack-enterprise",
                    "T1596.001",
                    "Historical DNS records provide a bounded offline analogue of DNS collection.",
                )
            ],
        ),
        _technique(
            "AT3-GA-D01-S01-03",
            "AOE-GA-D01-S01",
            "Public repository ownership hint extraction",
            "technique",
            "Correlate repository metadata tokens to a synthetic organization name without cloning code.",
            "Use a fixed metadata snapshot to identify declared domains, package namespaces, and owners.",
            [
                "Repository and package metadata are supplied as an immutable synthetic snapshot.",
                "Organization aliases and accepted metadata fields are enumerated in advance.",
            ],
            [
                "Declared homepage domains and package namespace strings.",
                "Repository owner identifiers and snapshot timestamps.",
            ],
            [
                "Cite the metadata field and synthetic record ID for every ownership hint.",
                "Label each result as a hint and never infer operational control from a string match.",
            ],
            [
                "Include a similarly named unrelated organization and require exact alias handling.",
                "Include an archived record after the cutoff date and require its exclusion.",
            ],
            [
                "Remove the temporary token index after deterministic results are produced.",
                "Retain only digests and cited synthetic metadata identifiers.",
            ],
            [
                "Metadata may be stale, copied, or intentionally misleading.",
                "Private repositories and registries cannot appear in the supplied snapshot.",
            ],
            [
                _mapping(
                    "mitre-attack-enterprise",
                    "T1593.003",
                    "Repository metadata is a non-interactive subset of code repository search.",
                )
            ],
        ),
        _technique(
            "AT3-GA-D03-S14-01",
            "AOE-GA-D03-S14",
            "Nested group entitlement path",
            "path",
            "Traverse user-to-group and group-to-group edges to a privileged entitlement.",
            "Find a shortest inherited group path in a synthetic identity graph.",
            [
                "Identity nodes and typed membership edges have stable synthetic identifiers.",
                "Privileged entitlement nodes and maximum traversal depth are declared.",
            ],
            [
                "Each user, group, and entitlement node on the selected path.",
                "Direct or inherited membership type for every path edge.",
            ],
            [
                "Return only a cited graph path and do not change any membership.",
                "Revoke one synthetic edge in a copied graph and require the path to disappear.",
            ],
            [
                "Provide a cycle with no privileged endpoint and require cycle-safe termination.",
                "Provide a disabled membership edge and require the traversal to ignore it.",
            ],
            [
                "Discard the copied graph used for edge-removal proof.",
                "Compare the original identity graph digest before and after analysis.",
            ],
            [
                "Dynamic groups may depend on attributes absent from a static export.",
                "Application-local roles can be omitted from a directory-only graph.",
            ],
            [
                _mapping(
                    "mitre-attack-enterprise",
                    "T1069.002",
                    "Domain group discovery is related to enumerating inherited group paths.",
                )
            ],
        ),
        _technique(
            "AT3-GA-D03-S14-02",
            "AOE-GA-D03-S14",
            "Delegated role activation chain",
            "path",
            "Join assignment, activation condition, and role edges into a delegated privilege path.",
            "Evaluate whether a synthetic principal can activate a privileged role through delegation.",
            [
                "Role assignments, eligibility windows, and activation conditions are in one snapshot.",
                "The evaluation time and privileged role set are fixed inputs.",
            ],
            [
                "Eligible assignment and delegating principal identifiers.",
                "Satisfied and unsatisfied activation conditions along the candidate path.",
            ],
            [
                "Evaluate conditions symbolically and emit no role activation request.",
                "Cite the exact assignment records that make the path reachable.",
            ],
            [
                "Move the evaluation time outside eligibility and require path rejection.",
                "Mark one approval condition unsatisfied and require path rejection.",
            ],
            [
                "Remove the temporary condition evaluation cache.",
                "Verify all assignment and eligibility records retain their initial digests.",
            ],
            [
                "External approval services can impose conditions missing from the snapshot.",
                "Emergency access processes may bypass normal activation relationships.",
            ],
            [
                _mapping(
                    "mitre-attack-enterprise",
                    "T1098.003",
                    "Additional cloud roles are related to the delegated role path being modeled.",
                )
            ],
        ),
        _technique(
            "AT3-GA-D03-S14-03",
            "AOE-GA-D03-S14",
            "Toxic entitlement combination",
            "path",
            "Intersect data-read and entitlement-delegation capabilities held by one principal.",
            "Identify a synthetic toxic combination that exists only when two capability sets converge.",
            [
                "Normalized effective entitlements identify capability, resource, and principal.",
                "The toxic-combination rule names both required capabilities and resource scope.",
            ],
            [
                "The independent grants contributing each required capability.",
                "The common principal and overlapping resource scope.",
            ],
            [
                "Produce a set-intersection witness with cited grant identifiers.",
                "Remove either grant in a copied entitlement set and require a negative result.",
            ],
            [
                "Supply the two capabilities on different principals and reject the combination.",
                "Supply non-overlapping resource scopes and reject the combination.",
            ],
            [
                "Destroy the copied entitlement sets used for counterfactual checks.",
                "Confirm no grant, role, or resource policy was altered.",
            ],
            [
                "Conditional denies may reduce an apparent effective entitlement.",
                "Session constraints can narrow privileges after the snapshot was taken.",
            ],
            [
                _mapping(
                    "mitre-attack-enterprise",
                    "T1098",
                    "Account manipulation provides context for harmful combinations of account grants.",
                )
            ],
        ),
        _technique(
            "AT3-GB-D06-S09-01",
            "AOE-GB-D06-S09",
            "Peer object identifier substitution",
            "technique",
            "Compare an owned-object fixture with a peer-object fixture under the same synthetic actor.",
            "Detect an object-level decision that relies on identifier validity but omits ownership.",
            [
                "An offline decision trace contains one actor and two same-type synthetic objects.",
                "Expected owner and policy decisions are declared for both objects.",
            ],
            [
                "Actor, object, ownership, policy-rule, and decision identifiers.",
                "Equivalent request shape with only the synthetic object identifier changed.",
            ],
            [
                "Replay the two stored decisions in a pure policy evaluator with no HTTP request.",
                "Require allow for the owned fixture and deny for the peer fixture.",
            ],
            [
                "Use an unknown object identifier and require a deny outcome.",
                "Use the peer owner as actor and require the expected allow outcome.",
            ],
            [
                "Discard evaluator state after recording cited decision traces.",
                "Verify fixture and policy digests remain unchanged.",
            ],
            [
                "A fixture cannot model undocumented application-side authorization hooks.",
                "Opaque indirect identifiers may hide whether two objects share a type.",
            ],
            [
                _mapping(
                    "owasp-api-security",
                    "API1:2023",
                    "Peer object substitution directly represents broken object-level authorization risk.",
                )
            ],
        ),
        _technique(
            "AT3-GB-D06-S09-02",
            "AOE-GB-D06-S09",
            "Nested subresource ownership mismatch",
            "path",
            "Resolve parent and child ownership separately before evaluating a nested object route.",
            "Detect a policy that validates a parent but fails to bind the requested child to that parent.",
            [
                "Synthetic parent-child records and ownership edges are complete for the fixture.",
                "A stored route template identifies both parent and child selectors.",
            ],
            [
                "Resolved parent owner, child owner, and parent-child relationship.",
                "Policy trace showing which selector each authorization rule consumed.",
            ],
            [
                "Evaluate a mismatched child in an offline route-policy model.",
                "Require the proof to stop at deny without invoking a resource handler.",
            ],
            [
                "Pair the parent with its legitimate child and require an allow decision.",
                "Pair a legitimate child with an unauthorized parent and require a deny decision.",
            ],
            [
                "Clear the in-memory route resolution table.",
                "Reconcile parent-child fixture hashes against their baseline values.",
            ],
            [
                "Eventual consistency can make parent-child exports temporarily disagree.",
                "Authorization performed downstream may be absent from a route-level trace.",
            ],
            [
                _mapping(
                    "owasp-api-security",
                    "API1:2023",
                    "Nested resource ownership is a concrete object-level authorization boundary.",
                )
            ],
        ),
        _technique(
            "AT3-GB-D06-S09-03",
            "AOE-GB-D06-S09",
            "Bulk selector mixed-ownership decision",
            "technique",
            "Partition a synthetic bulk selector by per-object ownership before aggregate evaluation.",
            "Find an aggregate authorization decision that masks one unauthorized object among owned ones.",
            [
                "A synthetic bulk request fixture contains at least two object identifiers.",
                "Per-object ownership and expected all-or-nothing behavior are declared.",
            ],
            [
                "The ordered object identifiers and their individual owner decisions.",
                "Aggregate allow or deny decision with the governing policy rule.",
            ],
            [
                "Evaluate the stored selector without sending an API request.",
                "Require a deny or explicit authorized subset when any object is unauthorized.",
            ],
            [
                "Use an all-owned selector and require its documented success behavior.",
                "Use an all-peer selector and require a complete deny outcome.",
            ],
            [
                "Erase the temporary selector partition after evidence capture.",
                "Confirm object fixtures and ownership records are byte-identical to baseline.",
            ],
            [
                "Streaming endpoints may authorize objects after the initial aggregate decision.",
                "Field-level filtering can obscure an object-level authorization defect.",
            ],
            [
                _mapping(
                    "owasp-api-security",
                    "API1:2023",
                    "A mixed-ownership bulk selector exercises object-level authorization for every ID.",
                )
            ],
        ),
        _technique(
            "AT3-GC-D11-S08-01",
            "AOE-GC-D11-S08",
            "Writable service configuration path",
            "path",
            "Join service start identity, configuration ACL, and binary ACL into a static privilege path.",
            "Identify a synthetic service path where an unprivileged principal can alter privileged startup state.",
            [
                "Offline service configuration and ACL fixtures identify principals by stable SID aliases.",
                "Privileged service identities and protected paths are labeled in the fixture.",
            ],
            [
                "Service identity, start mode, configuration path, and binary path.",
                "Effective write edges from the synthetic principal to service-controlled objects.",
            ],
            [
                "Construct a graph witness without editing a service or file.",
                "Cite the exact access-control entries that complete the path.",
            ],
            [
                "Remove the write edge in a copied ACL and require no path.",
                "Change the service identity to an unprivileged fixture and require no privileged endpoint.",
            ],
            [
                "Delete copied ACL and service graph material after comparison.",
                "Verify no service, registry key, or executable was created or modified.",
            ],
            [
                "Runtime security products can block changes allowed by a static ACL.",
                "Service launch protections can invalidate a path inferred from configuration alone.",
            ],
            [
                _mapping(
                    "mitre-attack-enterprise",
                    "T1543.003",
                    "Windows service configuration is the specific privilege-path surface modeled.",
                )
            ],
        ),
        _technique(
            "AT3-GC-D11-S08-02",
            "AOE-GC-D11-S08",
            "Privileged scheduled task edit path",
            "path",
            "Connect task run identity to writable task definition and referenced action artifacts.",
            "Model whether a synthetic user controls data consumed by a higher-privilege scheduled task.",
            [
                "Offline task definitions include run-as identity, triggers, and action paths.",
                "ACL fixtures cover each task definition and referenced local artifact.",
            ],
            [
                "Task run-as identity and action command metadata without executable content.",
                "Write permission edges to the task definition or referenced artifact.",
            ],
            [
                "Emit a static task-to-artifact-to-principal path only.",
                "Demonstrate path removal by tightening a copied ACL fixture.",
            ],
            [
                "Use a disabled task and require it to be classified non-triggerable.",
                "Use a writable artifact referenced only by an unprivileged task and reject escalation.",
            ],
            [
                "Dispose of copied task and ACL fixtures used by the proof.",
                "Assert that task definitions, triggers, and files were never written.",
            ],
            [
                "A static task export may omit runtime credential restrictions.",
                "Remote task actions can depend on permissions outside the endpoint fixture.",
            ],
            [
                _mapping(
                    "mitre-attack-enterprise",
                    "T1053.005",
                    "Scheduled task metadata is the Windows task surface represented by this path.",
                )
            ],
        ),
        _technique(
            "AT3-GC-D11-S08-03",
            "AOE-GC-D11-S08",
            "Privileged startup artifact path",
            "path",
            "Correlate startup location execution context with effective write access to its artifact.",
            "Find a synthetic startup entry consumed by a more privileged logon context.",
            [
                "Startup entry fixtures state scope, consuming identity class, and artifact path.",
                "Effective ACL fixtures are normalized for the unprivileged synthetic principal.",
            ],
            [
                "Startup location and consuming identity class.",
                "Artifact ownership plus inherited and explicit write permissions.",
            ],
            [
                "Report a read-only relationship path with no registry or filesystem write.",
                "Prove dependency by removing the startup edge in an isolated graph copy.",
            ],
            [
                "Use a user-only startup entry and require no higher-privilege path.",
                "Use a protected artifact ACL and require path rejection.",
            ],
            [
                "Destroy the isolated relationship graph after the proof.",
                "Compare registry and artifact fixture digests to their original values.",
            ],
            [
                "Application control policy can prevent execution despite the relationship.",
                "Logon ordering can affect whether the startup artifact is consumed.",
            ],
            [
                _mapping(
                    "mitre-attack-enterprise",
                    "T1547.001",
                    "Registry run keys and startup folders are the persistence surface being modeled.",
                )
            ],
        ),
        _technique(
            "AT3-GC-D14-S01-01",
            "AOE-GC-D14-S01",
            "Identity policy wildcard permission path",
            "path",
            "Resolve principal-to-policy attachments and wildcard action-resource allows.",
            "Trace a synthetic principal to an overbroad allow while preserving explicit deny precedence.",
            [
                "Normalized synthetic IAM policies include statements, attachments, and conditions.",
                "The evaluation context supplies every condition key referenced by a statement.",
            ],
            [
                "Principal, policy, statement, action, resource, and condition identifiers.",
                "Matched explicit deny and allow statements in evaluation order.",
            ],
            [
                "Use a pure policy evaluator and emit only the decision trace.",
                "Require an explicit deny to override a wildcard allow in the proof fixture.",
            ],
            [
                "Add a matching explicit deny and require the effective path to close.",
                "Narrow the requested resource outside the allow scope and require denial.",
            ],
            [
                "Clear the policy evaluation cache and synthetic request context.",
                "Verify no policy version, attachment, or cloud object was changed.",
            ],
            [
                "Service-specific authorization rules may differ from the normalized evaluator.",
                "Missing condition keys can make an offline decision indeterminate.",
            ],
            [
                _mapping(
                    "mitre-attack-enterprise",
                    "T1087.004",
                    "Cloud account discovery is related context for the principals in an IAM path.",
                )
            ],
        ),
        _technique(
            "AT3-GC-D14-S01-02",
            "AOE-GC-D14-S01",
            "Cross-account role trust path",
            "path",
            "Join caller permissions, role trust, and organization conditions across synthetic accounts.",
            "Determine whether both sides of a modeled role assumption path are satisfied.",
            [
                "Caller policy, role trust policy, and organization metadata share stable account aliases.",
                "External identifier and organization condition values are explicitly supplied or absent.",
            ],
            [
                "Caller-side allow statement and target-side trust statement.",
                "Condition results for organization, account, and external identifier constraints.",
            ],
            [
                "Evaluate the two policy halves without requesting any token.",
                "Report the minimal cited statement set required for reachability.",
            ],
            [
                "Remove the caller-side allow and require the path to fail.",
                "Use a nonmatching organization identifier and require the trust condition to fail.",
            ],
            [
                "Delete the temporary cross-account adjacency index.",
                "Confirm no role session, credential, or policy update was created.",
            ],
            [
                "Service control policies may block a path otherwise allowed by both role policies.",
                "Federation session attributes may change condition evaluation.",
            ],
            [
                _mapping(
                    "mitre-attack-enterprise",
                    "T1098.003",
                    "Additional cloud roles are related to cross-account role access paths.",
                )
            ],
        ),
        _technique(
            "AT3-GC-D14-S01-03",
            "AOE-GC-D14-S01",
            "Organization boundary effective permission path",
            "path",
            "Intersect identity allow, permissions boundary, and organization policy layers.",
            "Find a synthetic action that survives every applicable cloud IAM policy boundary.",
            [
                "The organization hierarchy and attached service control policies are immutable fixtures.",
                "Identity policy and permissions boundary inputs use one normalized action vocabulary.",
            ],
            [
                "Organization units traversed from account to root.",
                "Allow or deny contribution from each policy layer for the action and resource.",
            ],
            [
                "Compute set intersection and deny precedence without a cloud control-plane call.",
                "Cite every layer needed to support the final effective permission.",
            ],
            [
                "Attach a copied service control policy deny and require the path to close.",
                "Remove the identity allow in a copied fixture and require no effective permission.",
            ],
            [
                "Discard copied hierarchy and policy-layer fixtures.",
                "Verify all original organization and IAM fixture hashes are unchanged.",
            ],
            [
                "Resource policies and session policies can add layers absent from this fixture.",
                "Organization policy propagation delay is not represented offline.",
            ],
            [
                _mapping(
                    "mitre-attack-enterprise",
                    "T1069.003",
                    "Cloud role discovery is related to resolving effective organization role paths.",
                )
            ],
        ),
        _technique(
            "AT3-GD-D19-S01-01",
            "AOE-GD-D19-S01",
            "Unauthorized inter-zone flow path",
            "path",
            "Compare observed synthetic source-zone and destination-zone flows to the conduit matrix.",
            "Detect a modeled flow that crosses an undeclared industrial zone boundary.",
            [
                "A synthetic zone inventory and approved conduit matrix have stable identifiers.",
                "Offline flow records identify direction, protocol class, and observation time.",
            ],
            [
                "Source zone, destination zone, conduit, and protocol class.",
                "Policy matrix decision and cited flow record for each boundary crossing.",
            ],
            [
                "Compare immutable records only and emit no packet or rule change.",
                "Report the matrix cell and flow identifier that demonstrate the mismatch.",
            ],
            [
                "Use a declared conduit flow and require a compliant result.",
                "Reverse a one-way permitted flow and require an unauthorized result.",
            ],
            [
                "Remove the derived zone-pair index after the comparison.",
                "Verify the zone, conduit, and flow input digests remain unchanged.",
            ],
            [
                "Unmonitored serial or vendor links may not appear in flow records.",
                "NAT can obscure the original industrial asset zone.",
            ],
            [
                _mapping(
                    "iec-62443-3-3",
                    "SR 5.1",
                    "Network segmentation aligns with checking traffic against defined zones and conduits.",
                )
            ],
        ),
        _technique(
            "AT3-GD-D19-S01-02",
            "AOE-GD-D19-S01",
            "Conduit boundary protection gap",
            "technique",
            "Join each declared conduit to its synthetic boundary enforcement and monitoring controls.",
            "Identify a modeled conduit lacking a required deny, allowlist, or observation control.",
            [
                "Each conduit fixture names required control classes and enforcement points.",
                "Boundary control inventory is a read-only synthetic configuration export.",
            ],
            [
                "Conduit identifier, enforcement point, and configured control classes.",
                "Required control class with present, absent, or indeterminate status.",
            ],
            [
                "Produce a configuration join result without connecting to industrial equipment.",
                "Cite both the conduit requirement and control inventory records.",
            ],
            [
                "Provide a conduit with every required control and require no gap.",
                "Provide an unreferenced control device and require it not to satisfy the conduit.",
            ],
            [
                "Delete the temporary conduit-to-control join table.",
                "Confirm no firewall, switch, gateway, or monitoring configuration changed.",
            ],
            [
                "A configuration export cannot show a failed enforcement process.",
                "Proprietary gateway functions may not map cleanly to the control classes.",
            ],
            [
                _mapping(
                    "iec-62443-3-3",
                    "SR 5.2",
                    "Zone boundary protection aligns with verifying controls assigned to each conduit.",
                )
            ],
        ),
        _technique(
            "AT3-GD-D19-S01-03",
            "AOE-GD-D19-S01",
            "Temporary segmentation change restoration",
            "path",
            "Compare pre-change, approved temporary, and restored synthetic rule-state snapshots.",
            "Verify that a modeled maintenance conduit returns exactly to its recorded baseline.",
            [
                "Canonical before, temporary, and after rule snapshots share one device alias.",
                "The approved temporary delta and restoration deadline are explicit fixture fields.",
            ],
            [
                "Rules added, removed, or reordered in the temporary snapshot.",
                "Residual differences between baseline and restored snapshots.",
            ],
            [
                "Apply the declared delta only to an in-memory model and compare canonical hashes.",
                "Require the restored snapshot hash to equal the pre-change snapshot hash.",
            ],
            [
                "Leave one temporary rule in the restored fixture and require restoration failure.",
                "Restore equivalent rules in a different order and evaluate documented order semantics.",
            ],
            [
                "Erase the in-memory changed-state model after evidence generation.",
                "Record failed-closed status for any residual and never assert live restoration.",
            ],
            [
                "Snapshot equality cannot confirm that a device loaded the configuration.",
                "External controller state may reapply a temporary change after the snapshot.",
            ],
            [
                _mapping(
                    "iec-62443-3-3",
                    "SR 7.4",
                    "Control system recovery aligns with restoring and verifying a known configuration baseline.",
                )
            ],
        ),
    ]
    return sorted(records, key=lambda item: item["technique_id"])


def build_catalog() -> dict[str, Any]:
    techniques = build_techniques()
    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "catalog_id": CATALOG_ID,
        "catalog_version": CATALOG_VERSION,
        "catalog_status": CATALOG_STATUS,
        "reference_profiles": [
            {
                "profile_id": profile_id,
                "profile_name": name,
                "vector_id": vector_id,
                "family": family,
            }
            for profile_id, name, vector_id, family in REFERENCE_PROFILES
        ],
        "standards_sources": sorted(SOURCES, key=lambda item: item["source_id"]),
        "techniques": techniques,
        "coverage_summary": {
            "reference_profile_count": len(REFERENCE_PROFILES),
            "technique_count": len(techniques),
            "profiles_with_multiple_techniques": len(REFERENCE_PROFILES),
            "standards_source_count": len(SOURCES),
            "mapped_technique_count": len(techniques),
            "unique_mechanic_count": len(techniques),
            "non_operational_technique_count": len(techniques),
        },
        **dict.fromkeys(EFFECT_FIELDS, "none"),
        "limitations": [
            "This catalog describes offline synthetic evidence paths and grants no target authority.",
            "A mapping supplies standards context but does not claim successful execution or impact.",
            "Product, deployment, telemetry, and runtime behavior remain outside this reference catalog.",
        ],
    }
    document["catalog_sha256"] = canonical_sha256({"domain": CATALOG_DOMAIN, "catalog": document})
    ordered = {
        "schema_version": document["schema_version"],
        "catalog_id": document["catalog_id"],
        "catalog_version": document["catalog_version"],
        "catalog_sha256": document["catalog_sha256"],
        "catalog_status": document["catalog_status"],
        "reference_profiles": document["reference_profiles"],
        "standards_sources": document["standards_sources"],
        "techniques": document["techniques"],
        "coverage_summary": document["coverage_summary"],
        **{field: document[field] for field in EFFECT_FIELDS},
        "limitations": document["limitations"],
    }
    AttackTechniqueCatalog.from_dict(ordered)
    return ordered


def build_schema() -> dict[str, Any]:
    text = {"type": "string", "minLength": 1, "pattern": r"^[ -~]*[!-~][ -~]*$"}
    sha = {"type": "string", "pattern": r"^sha256:[0-9a-f]{64}$"}
    effects = {field: {"const": "none"} for field in EFFECT_FIELDS}
    list_of_text = {
        "type": "array",
        "minItems": 2,
        "uniqueItems": True,
        "items": {"$ref": "#/$defs/text"},
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://schemas.sunderkey.dev/attack-technique-catalog-v3.schema.json",
        "title": "SUNDERKEY Attack Technique Reference Catalog v3",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "catalog_id",
            "catalog_version",
            "catalog_sha256",
            "catalog_status",
            "reference_profiles",
            "standards_sources",
            "techniques",
            "coverage_summary",
            *EFFECT_FIELDS,
            "limitations",
        ],
        "properties": {
            "schema_version": {"const": SCHEMA_VERSION},
            "catalog_id": {"const": CATALOG_ID},
            "catalog_version": {"const": CATALOG_VERSION},
            "catalog_sha256": sha,
            "catalog_status": {"const": CATALOG_STATUS},
            "reference_profiles": {
                "type": "array",
                "minItems": 6,
                "maxItems": 6,
                "items": {"$ref": "#/$defs/profile"},
            },
            "standards_sources": {
                "type": "array",
                "minItems": 3,
                "maxItems": 3,
                "items": {"$ref": "#/$defs/source"},
            },
            "techniques": {
                "type": "array",
                "minItems": 18,
                "maxItems": 18,
                "items": {"$ref": "#/$defs/technique"},
            },
            "coverage_summary": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "reference_profile_count",
                    "technique_count",
                    "profiles_with_multiple_techniques",
                    "standards_source_count",
                    "mapped_technique_count",
                    "unique_mechanic_count",
                    "non_operational_technique_count",
                ],
                "properties": {
                    "reference_profile_count": {"const": 6},
                    "technique_count": {"const": 18},
                    "profiles_with_multiple_techniques": {"const": 6},
                    "standards_source_count": {"const": 3},
                    "mapped_technique_count": {"const": 18},
                    "unique_mechanic_count": {"const": 18},
                    "non_operational_technique_count": {"const": 18},
                },
            },
            **effects,
            "limitations": {
                "type": "array",
                "minItems": 3,
                "uniqueItems": True,
                "items": {"$ref": "#/$defs/text"},
            },
        },
        "$defs": {
            "text": text,
            "profile": {
                "type": "object",
                "additionalProperties": False,
                "required": ["profile_id", "profile_name", "vector_id", "family"],
                "properties": {
                    "profile_id": {
                        "pattern": r"^AOE-G[A-E]-D[0-9]{2}-S[0-9]{2}$",
                        "type": "string",
                    },
                    "profile_name": {"$ref": "#/$defs/text"},
                    "vector_id": {
                        "pattern": r"^AV-G[A-E]-D[0-9]{2}-S[0-9]{2}-01$",
                        "type": "string",
                    },
                    "family": {"$ref": "#/$defs/text"},
                },
            },
            "source": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "source_id",
                    "title",
                    "publisher",
                    "source_version",
                    "release_date",
                    "url",
                    "reference_ids",
                ],
                "properties": {
                    "source_id": {"$ref": "#/$defs/text"},
                    "title": {"$ref": "#/$defs/text"},
                    "publisher": {"$ref": "#/$defs/text"},
                    "source_version": {"$ref": "#/$defs/text"},
                    "release_date": {
                        "pattern": r"^20[0-9]{2}-[01][0-9]-[0-3][0-9]$",
                        "type": "string",
                    },
                    "url": {"pattern": r"^https://", "type": "string"},
                    "reference_ids": {
                        "type": "array",
                        "minItems": 1,
                        "uniqueItems": True,
                        "items": {"$ref": "#/$defs/text"},
                    },
                },
            },
            "mapping": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "source_id",
                    "source_version",
                    "source_release_date",
                    "reference_id",
                    "relationship",
                    "rationale",
                ],
                "properties": {
                    "source_id": {"enum": sorted(SOURCE_INDEX)},
                    "source_version": {"$ref": "#/$defs/text"},
                    "source_release_date": {
                        "pattern": r"^20[0-9]{2}-[01][0-9]-[0-3][0-9]$",
                        "type": "string",
                    },
                    "reference_id": {"$ref": "#/$defs/text"},
                    "relationship": {
                        "enum": ["control_alignment", "exact_risk", "related_technique"]
                    },
                    "rationale": {"$ref": "#/$defs/text"},
                },
            },
            "technique": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "technique_id",
                    "profile_id",
                    "vector_id",
                    "name",
                    "family",
                    "record_kind",
                    "mechanic",
                    "description",
                    "prerequisites",
                    "observables",
                    "safe_proof",
                    "negative_controls",
                    "cleanup_and_restoration",
                    "blind_spots",
                    "standards_mappings",
                    *EFFECT_FIELDS,
                    "technique_sha256",
                ],
                "properties": {
                    "technique_id": {
                        "pattern": r"^AT3-G[A-E]-D[0-9]{2}-S[0-9]{2}-[0-9]{2}$",
                        "type": "string",
                    },
                    "profile_id": {
                        "pattern": r"^AOE-G[A-E]-D[0-9]{2}-S[0-9]{2}$",
                        "type": "string",
                    },
                    "vector_id": {
                        "pattern": r"^AV-G[A-E]-D[0-9]{2}-S[0-9]{2}-01$",
                        "type": "string",
                    },
                    "name": {"$ref": "#/$defs/text"},
                    "family": {"$ref": "#/$defs/text"},
                    "record_kind": {"enum": ["path", "technique"]},
                    "mechanic": {"$ref": "#/$defs/text"},
                    "description": {"$ref": "#/$defs/text"},
                    "prerequisites": list_of_text,
                    "observables": list_of_text,
                    "safe_proof": list_of_text,
                    "negative_controls": list_of_text,
                    "cleanup_and_restoration": list_of_text,
                    "blind_spots": list_of_text,
                    "standards_mappings": {
                        "type": "array",
                        "minItems": 1,
                        "uniqueItems": True,
                        "items": {"$ref": "#/$defs/mapping"},
                    },
                    **effects,
                    "technique_sha256": sha,
                },
            },
        },
    }


def _render(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=True, indent=2) + "\n"


def _schema_validate(schema: dict[str, Any], document: dict[str, Any]) -> None:
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:
        raise RuntimeError("jsonschema is required to build the v3 catalog") from exc
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(document)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT_PATH)
    parser.add_argument("--schema-output", type=Path, default=SCHEMA_PATH)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    catalog = build_catalog()
    schema = build_schema()
    _schema_validate(schema, catalog)
    expected_catalog = _render(catalog)
    expected_schema = _render(schema)
    if args.check:
        if not args.output.is_file() or args.output.read_text(encoding="utf-8") != expected_catalog:
            raise SystemExit("attack-technique catalog is not current")
        if (
            not args.schema_output.is_file()
            or args.schema_output.read_text(encoding="utf-8") != expected_schema
        ):
            raise SystemExit("attack-technique schema is not current")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.schema_output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(expected_catalog, encoding="utf-8", newline="\n")
        args.schema_output.write_text(expected_schema, encoding="utf-8", newline="\n")
    print(
        json.dumps(
            {
                "catalog_sha256": catalog["catalog_sha256"],
                "reference_profile_count": catalog["coverage_summary"]["reference_profile_count"],
                "technique_count": catalog["coverage_summary"]["technique_count"],
                "status": "valid",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
