"""Project declared synthetic mobile pinset coverage without a TLS handshake."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "mobile_supplied_pinset_coverage_projection"
PROFILE_ID = "AOE-GB-D08-S09"
CAPABILITY_ID = "army.gb.d08.s09"
VECTOR_ID = "AV-GB-D08-S09-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D08-S09"
WAVE_ID = "IW2-013"
COMMANDER_ID = "AOE-GB-D08-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:8d7058564cca65cf025dabd32f578a26116999290e3ffb5b2e14e2bb5d6055a6"
DOMAIN = "sunderkey.offline-mobile-pinset-projection.v1"
MAX_MODEL_BYTES = 131_072
MAX_REPORT_BYTES = 131_072
MAX_HOSTS = 32
MAX_PINSETS = 32
MAX_PINS = 8
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
DAY = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process",
        "provider", "credentials", "target_interaction",
        "finding_publication", "qualification",
    )
}


class MobilePinsetProjectionError(ValueError):
    """The declared pinset model or original-model replay is invalid."""


def _hostname(value: Any, label: str) -> str:
    if (
        type(value) is not str
        or len(value) > 253
        or len(value) < 3
        or len(value.split(".")) < 2
        or any(LABEL.fullmatch(part) is None for part in value.split("."))
    ):
        raise MobilePinsetProjectionError(f"{label} must be a bounded lowercase DNS name")
    return value


def _day(value: Any, label: str) -> date:
    if type(value) is not str or DAY.fullmatch(value) is None:
        raise MobilePinsetProjectionError(f"{label} must be an ISO calendar day")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise MobilePinsetProjectionError(f"{label} is not a valid calendar day") from exc


def _model(value: Any) -> tuple[dict, date, list[tuple[str, str]], list[dict], str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "synthetic_fixture", "evaluation_day",
            "inventory_complete", "hosts", "pinsets",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise MobilePinsetProjectionError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["synthetic_fixture"], "synthetic fixture")
    if not model["synthetic_fixture"]:
        raise MobilePinsetProjectionError("Only declared synthetic fixtures are accepted")
    core.boolean(model["inventory_complete"], "inventory completeness")
    evaluation_day = _day(model["evaluation_day"], "evaluation day")
    hosts = []
    seen_host_ids = set()
    seen_hostnames = set()
    for item in core.bounded_list(model["hosts"], MAX_HOSTS, "hosts"):
        row = core.exact(item, {"host_id", "hostname"}, "host")
        host_id = core.identifier(row["host_id"], "host ID")
        hostname = _hostname(row["hostname"], "hostname")
        if host_id in seen_host_ids or hostname in seen_hostnames:
            raise MobilePinsetProjectionError("Duplicate host ID or hostname")
        seen_host_ids.add(host_id)
        seen_hostnames.add(hostname)
        hosts.append((host_id, hostname))
    if not hosts:
        raise MobilePinsetProjectionError("At least one host is required")
    pinsets = []
    seen_pinset_ids = set()
    for item in core.bounded_list(model["pinsets"], MAX_PINSETS, "pinsets"):
        row = core.exact(
            item, {"pinset_id", "domain", "include_subdomains", "pins"}, "pinset"
        )
        pinset_id = core.identifier(row["pinset_id"], "pinset ID")
        if pinset_id in seen_pinset_ids:
            raise MobilePinsetProjectionError("Duplicate pinset ID")
        seen_pinset_ids.add(pinset_id)
        domain = _hostname(row["domain"], "pinset domain")
        include_subdomains = core.boolean(
            row["include_subdomains"], "include subdomains"
        )
        pins = []
        seen_pin_ids = set()
        seen_digests = set()
        for pin_item in core.bounded_list(row["pins"], MAX_PINS, "pins"):
            pin = core.exact(
                pin_item, {"pin_id", "spki_sha256_hex", "not_after_day", "backup"}, "pin"
            )
            pin_id = core.identifier(pin["pin_id"], "pin ID")
            digest = pin["spki_sha256_hex"]
            if type(digest) is not str or DIGEST.fullmatch(digest) is None:
                raise MobilePinsetProjectionError("Pin digest must be lowercase SHA-256 hex")
            if pin_id in seen_pin_ids or digest in seen_digests:
                raise MobilePinsetProjectionError("Duplicate pin ID or digest")
            seen_pin_ids.add(pin_id)
            seen_digests.add(digest)
            pins.append({
                "pin_id": pin_id,
                "not_after": _day(pin["not_after_day"], "pin expiry"),
                "backup": core.boolean(pin["backup"], "backup flag"),
            })
        if not pins:
            raise MobilePinsetProjectionError("At least one pin is required")
        pinsets.append({
            "pinset_id": pinset_id,
            "domain": domain,
            "include_subdomains": include_subdomains,
            "pins": pins,
        })
    if not pinsets:
        raise MobilePinsetProjectionError("At least one pinset is required")
    return model, evaluation_day, hosts, pinsets, core.canonical(model)


def _matches(hostname: str, domain: str, include_subdomains: bool) -> bool:
    return hostname == domain or (
        include_subdomains and hostname.endswith("." + domain)
    )


def _derive(value: Any) -> dict:
    model, evaluation_day, hosts, pinsets, source_text = _model(value)
    rows = []
    matched_by_host: dict[str, list[str]] = {host_id: [] for host_id, _ in hosts}
    for pinset in pinsets:
        matched = sorted(
            host_id for host_id, hostname in hosts
            if _matches(hostname, pinset["domain"], pinset["include_subdomains"])
        )
        for host_id in matched:
            matched_by_host[host_id].append(pinset["pinset_id"])
        active = [pin for pin in pinset["pins"] if pin["not_after"] >= evaluation_day]
        rows.append({
            "pinset_id": pinset["pinset_id"],
            "matched_host_ids": matched,
            "declared_pin_count": len(pinset["pins"]),
            "nonexpired_pin_count": len(active),
            "nonexpired_primary_count": sum(not pin["backup"] for pin in active),
            "nonexpired_backup_count": sum(pin["backup"] for pin in active),
            "declared_nonexpired_pair_present": (
                any(not pin["backup"] for pin in active)
                and any(pin["backup"] for pin in active)
            ),
        })
    rows.sort(key=lambda row: row["pinset_id"])
    uncovered = sorted(host_id for host_id, ids in matched_by_host.items() if not ids)
    overlapping = sorted(host_id for host_id, ids in matched_by_host.items() if len(ids) > 1)
    expired = sorted(
        row["pinset_id"] for row in rows if row["nonexpired_pin_count"] == 0
    )
    unknown = [] if model["inventory_complete"] else ["supplied_pinset_inventory_incomplete"]
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
        "evaluation_day_asserted": model["evaluation_day"],
        "inventory_complete_asserted": model["inventory_complete"],
        "supplied_host_count": len(hosts),
        "supplied_pinset_count": len(pinsets),
        "pinset_projections": rows,
        "uncovered_host_ids": uncovered,
        "overlapping_host_ids": overlapping,
        "expired_pinset_ids": expired,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_pinset_coverage_projection",
        "source_authenticated": False,
        "platform_pinning_semantics_verified": False,
        "application_inspected": False,
        "tls_handshake_performed": False,
        "pinning_enforced": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Hosts, pinsets, expiry dates, and inventory completeness are supplied assertions.",
            "Hostname matching is a declared model, not Android or iOS platform behavior.",
            "A declared backup pair does not prove live pinning, trust, or rollover safety.",
            "No application, certificate, handshake, target, or credential is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="MPS-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class MobilePinsetProjectionReport:
    """Unsigned pinset projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise MobilePinsetProjectionError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> MobilePinsetProjectionReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_mobile_pinsets(model: Any) -> MobilePinsetProjectionReport:
    return MobilePinsetProjectionReport._owned(_derive(model))


def verify_supplied_mobile_pinsets(
    report: Any, *, model: Any
) -> MobilePinsetProjectionReport:
    if type(report) is not MobilePinsetProjectionReport:
        raise MobilePinsetProjectionError("Exact pinset wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise MobilePinsetProjectionError("Report differs from separate original model")
    return MobilePinsetProjectionReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-mobile-pinsets",
        "synthetic_fixture": True,
        "evaluation_day": "2026-01-01",
        "inventory_complete": True,
        "hosts": [
            {"host_id": "api", "hostname": "api.example.invalid"},
            {"host_id": "admin", "hostname": "admin.example.invalid"},
        ],
        "pinsets": [{
            "pinset_id": "base",
            "domain": "example.invalid",
            "include_subdomains": True,
            "pins": [
                {
                    "pin_id": "primary", "spki_sha256_hex": "1" * 64,
                    "not_after_day": "2027-01-01", "backup": False,
                },
                {
                    "pin_id": "backup", "spki_sha256_hex": "2" * 64,
                    "not_after_day": "2027-01-01", "backup": True,
                },
            ],
        }],
    }
