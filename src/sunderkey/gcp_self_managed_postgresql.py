"""Review declared self-managed PostgreSQL host intent without provider access."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .deployment_manifests import DeploymentManifestBundle
from .production_deployment_decision_dossier import ProductionDeploymentDecisionDossier

DOMAIN = "sunderkey.gcp-self-managed-postgresql-host-review.v1"
OPTION_ID = "self_managed_quorum_postgresql"
REGION = "us-west3"
ZONES = frozenset({"us-west3-a", "us-west3-b", "us-west3-c"})
_PROJECT = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]\Z")
_INSTANCE = re.compile(r"[a-z][a-z0-9-]{0,61}[a-z0-9]\Z|[a-z]\Z")
_REFERENCE = re.compile(r"(?:principalref|volref):[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z")
_DECLARATION_FIELDS = {"project_id", "region", "database_service_identity_ref", "nodes"}
_NODE_FIELDS = {"instance_id", "zone", "data_volume_ref"}
_EFFECTS = {
    "authorization": "none",
    "credential_access": "none",
    "deployment": "none",
    "network": "none",
    "qualification": "none",
    "storage_mutation": "none",
    "target_action": "none",
}


class GcpSelfManagedPostgresqlError(ValueError):
    """A declaration or checked source cannot support the offline review."""


def _exact(raw: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(raw) is not dict or set(raw) != fields or any(type(key) is not str for key in raw):
        raise GcpSelfManagedPostgresqlError(f"{label} fields are invalid")
    return raw


def _text(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise GcpSelfManagedPostgresqlError(f"{label} is invalid")
    return value


def _declaration(raw: Any) -> dict[str, Any]:
    value = _exact(raw, _DECLARATION_FIELDS, "host declaration")
    _text(value["project_id"], _PROJECT, "project ID")
    if type(value["region"]) is not str or value["region"] != REGION:
        raise GcpSelfManagedPostgresqlError("host declaration is outside us-west3")
    identity = _text(value["database_service_identity_ref"], _REFERENCE, "service identity")
    if not identity.startswith("principalref:"):
        raise GcpSelfManagedPostgresqlError("service identity reference is invalid")
    if type(value["nodes"]) is not list or len(value["nodes"]) != 3:
        raise GcpSelfManagedPostgresqlError("exactly three declared database nodes are required")
    nodes = []
    for item in value["nodes"]:
        node = _exact(item, _NODE_FIELDS, "database node")
        instance = _text(node["instance_id"], _INSTANCE, "instance ID")
        zone = node["zone"]
        if type(zone) is not str or zone not in ZONES:
            raise GcpSelfManagedPostgresqlError("node zone is outside the selected region")
        volume = _text(node["data_volume_ref"], _REFERENCE, "data volume")
        if not volume.startswith("volref:"):
            raise GcpSelfManagedPostgresqlError("data volume reference is invalid")
        nodes.append({"instance_id": instance, "zone": zone, "data_volume_ref": volume})
    if len({node["instance_id"] for node in nodes}) != 3:
        raise GcpSelfManagedPostgresqlError("database instance IDs must be distinct")
    if len({node["data_volume_ref"] for node in nodes}) != 3:
        raise GcpSelfManagedPostgresqlError("database data volumes must be distinct")
    return {
        "project_id": value["project_id"],
        "region": REGION,
        "database_service_identity_ref": identity,
        "nodes": sorted(nodes, key=lambda node: node["instance_id"]),
    }


def _sources(
    dossier: ProductionDeploymentDecisionDossier,
    bundle: DeploymentManifestBundle,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if (
        type(dossier) is not ProductionDeploymentDecisionDossier
        or type(bundle) is not DeploymentManifestBundle
    ):
        raise GcpSelfManagedPostgresqlError("exact typed D014 sources are required")
    try:
        selected_dossier = ProductionDeploymentDecisionDossier.from_dict(dossier.to_dict())
        selected_bundle = DeploymentManifestBundle.from_dict(bundle.to_dict())
    except (ValueError, TypeError, AttributeError) as exc:
        raise GcpSelfManagedPostgresqlError("checked D014 sources are invalid") from exc
    questions = [
        item for item in selected_dossier.to_dict()["decision_questions"]
        if item["question_id"] == "postgresql_topology"
    ]
    if (
        len(questions) != 1
        or OPTION_ID not in {item["option_id"] for item in questions[0]["options"]}
        or questions[0]["selection_status"] != "not_selected"
        or questions[0]["selected_option_id"] is not None
    ):
        raise GcpSelfManagedPostgresqlError("D014 database option source is incompatible")
    profiles = [
        item for item in selected_bundle.profiles
        if item.profile_type == "high_availability_postgresql"
    ]
    if len(profiles) != 1:
        raise GcpSelfManagedPostgresqlError("one checked HA PostgreSQL manifest is required")
    profile = profiles[0].to_dict()
    database_services = [
        item for item in profile["services"]
        if item["service_identity"] == "service:postgresql"
    ]
    if (
        len(database_services) != 1
        or database_services[0]["replicas"] != 3
        or profile["capacity"]["database_replicas"] != 3
        or profile["storage"]["persistent_volume_count"] != 3
        or profile["storage"]["backend"] != "postgresql"
    ):
        raise GcpSelfManagedPostgresqlError("manifest does not support the declared node count")
    return (
        {
            "dossier_id": selected_dossier.dossier_id,
            "dossier_sha256": selected_dossier.dossier_sha256,
            "manifest_bundle_id": selected_bundle.bundle_id,
            "manifest_bundle_sha256": selected_bundle.bundle_sha256,
            "manifest_profile_id": profiles[0].profile_id,
            "manifest_profile_sha256": profiles[0].profile_sha256,
        },
        profile,
    )


def review_gcp_self_managed_postgresql_hosts(
    declaration: dict[str, Any],
    *,
    dossier: ProductionDeploymentDecisionDossier,
    bundle: DeploymentManifestBundle,
) -> dict[str, Any]:
    """Check exact declared coordinates and retain every external acceptance gate."""

    intent = _declaration(declaration)
    source, profile = _sources(dossier, bundle)
    blockers = {
        "authenticated_d014_selection_required",
        "provider_coordinates_unverified",
        "host_image_machine_and_volume_pins_missing",
        "database_election_replication_and_writer_fencing_unverified",
        "wal_archive_backup_and_restore_unverified",
        "rpo_rto_retention_and_recovery_region_unselected",
        "signed_host_and_database_acceptance_missing",
        "independent_production_go_no_go_required",
    }
    zone_count = len({node["zone"] for node in intent["nodes"]})
    if zone_count < 3:
        blockers.add("three_zone_distribution_unproven")
    if not (
        profile["backup"]["continuous_archiving"]
        and profile["backup"]["point_in_time_recovery_required"]
        and profile["backup"]["restore_drill_required"]
    ):
        raise GcpSelfManagedPostgresqlError("manifest lacks required recovery declarations")
    body = {
        "status": "valid_for_offline_topology_review_only",
        "option_id": OPTION_ID,
        "declaration": intent,
        "source": source,
        "zone_count": zone_count,
        "blocker_codes": sorted(blockers),
        "identity_assurance": "operator_asserted_unsigned",
        "effects": dict(_EFFECTS),
        "network_call_performed": False,
    }
    digest = "sha256:" + hashlib.sha256(
        json.dumps(
            {"domain": DOMAIN, "review": body},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()
    return {
        **body,
        "review_id": "GSP-" + digest[7:39].upper(),
        "review_sha256": digest,
    }


def verify_gcp_self_managed_postgresql_host_review(
    review: dict[str, Any],
    *,
    dossier: ProductionDeploymentDecisionDossier,
    bundle: DeploymentManifestBundle,
) -> dict[str, Any]:
    """Reproduce a supplied unsigned review from exact sources and declaration."""

    if type(review) is not dict or type(review.get("declaration")) is not dict:
        raise GcpSelfManagedPostgresqlError("an exact offline host review is required")
    expected = review_gcp_self_managed_postgresql_hosts(
        review["declaration"], dossier=dossier, bundle=bundle
    )

    def same_native(actual: Any, wanted: Any) -> bool:
        if type(actual) is not type(wanted):
            return False
        if type(wanted) is dict:
            return set(actual) == set(wanted) and all(
                same_native(actual[key], item) for key, item in wanted.items()
            )
        if type(wanted) is list:
            return len(actual) == len(wanted) and all(
                same_native(item, target) for item, target in zip(actual, wanted, strict=True)
            )
        return actual == wanted

    if not same_native(review, expected):
        raise GcpSelfManagedPostgresqlError("offline host review differs from exact sources")
    return expected
