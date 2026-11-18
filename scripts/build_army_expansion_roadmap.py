#!/usr/bin/env python3
# ruff: noqa: E501
"""Build the deterministic technical Army v2 expansion reference."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sunderkey.army_expansion import build_army_expansion_roadmap

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "registry" / "army-expansion-roadmap-v1.json"


def profile(profile_id: str, name: str) -> dict[str, str]:
    return {"profile_id": profile_id, "name": name}


def command(
    command_id: str,
    group_id: str,
    name: str,
    specialists: list[dict[str, str]],
    *,
    new: bool = False,
) -> dict[str, object]:
    result: dict[str, object] = {
        "command_id": command_id,
        "group_id": group_id,
        "name": name,
        "specialists": specialists,
    }
    if new:
        result["commander_profile_id"] = f"{command_id}-CMD"
    return result


def phase(
    number: int,
    title: str,
    objective: str,
    dependencies: list[int],
    artifacts: list[str],
    gate: str,
) -> dict[str, object]:
    return {
        "phase_id": f"Phase{number}",
        "title": title,
        "objective": objective,
        "dependency_phase_ids": [f"Phase{item}" for item in dependencies],
        "required_artifacts": artifacts,
        "completion_gate": gate,
        "operational_effect": "none_without_separate_authority",
    }


def roadmap_body() -> dict[str, object]:
    existing = [
        command(
            "AOE-GA-D02",
            "GA",
            "Human and Physical Access",
            [profile("AOE-GA-D02-S13", "Insider, contractor and trusted-operator abuse")],
        ),
        command(
            "AOE-GA-D03",
            "GA",
            "Identity and Trust",
            [profile("AOE-GA-D03-S17", "Biometric identity, liveness and presentation attacks")],
        ),
        command(
            "AOE-GA-D04",
            "GA",
            "Campaign Engineering and Adversary Emulation",
            [profile("AOE-GA-D04-S17", "Third-party, MSP and trusted-relationship compromise")],
        ),
        command(
            "AOE-GB-D08",
            "GB",
            "Mobile and Thick Client",
            [
                profile("AOE-GB-D08-S15", "Windows native desktop clients"),
                profile("AOE-GB-D08-S16", "macOS native desktop clients"),
                profile("AOE-GB-D08-S17", "Linux native desktop clients"),
                profile("AOE-GB-D08-S18", "Electron and hybrid desktop clients"),
            ],
        ),
        command(
            "AOE-GC-D13",
            "GC",
            "Network, Wireless and Telecom",
            [
                profile("AOE-GC-D13-S19", "Open RAN, carrier NFV and mobile-core control planes"),
                profile("AOE-GC-D13-S20", "SIM, eSIM, UICC, IMS and subscriber provisioning"),
                profile("AOE-GC-D13-S21", "SASE, SD-WAN and zero-trust network fabrics"),
            ],
        ),
        command(
            "AOE-GC-D14",
            "GC",
            "Cloud Provider and SaaS Control Plane",
            [
                profile(
                    "AOE-GC-D14-S19", "Google Workspace tenant and collaboration control plane"
                ),
                profile("AOE-GC-D14-S20", "Workforce IdP control planes"),
                profile("AOE-GC-D14-S21", "Data-cloud control planes"),
            ],
        ),
        command(
            "AOE-GD-D19",
            "GD",
            "OT, ICS and Cyber-Physical",
            [
                profile("AOE-GD-D19-S17", "Building automation, BACnet and KNX"),
                profile("AOE-GD-D19-S18", "Robotics, ROS 2 and DDS"),
                profile("AOE-GD-D19-S19", "Power-grid protection and IEC 61850-class protocols"),
                profile("AOE-GD-D19-S20", "Industrial Ethernet and vendor control protocols"),
            ],
        ),
        command(
            "AOE-GD-D20",
            "GD",
            "AI, ML, GenAI and Agentic Systems",
            [
                profile("AOE-GD-D20-S19", "Agent goal and plan hijacking"),
                profile(
                    "AOE-GD-D20-S20", "Multi-agent trust, cascading failure and rogue coordination"
                ),
            ],
        ),
        command(
            "AOE-GE-D21",
            "GE",
            "Vulnerability Research and Exploit Engineering",
            [
                profile("AOE-GE-D21-S19", "Managed runtimes, JIT and WebAssembly exploitation"),
                profile(
                    "AOE-GE-D21-S20",
                    "Malware unpacking, configuration extraction and anti-analysis",
                ),
            ],
        ),
    ]

    new_commands = [
        command(
            "AOE-GD-D24",
            "GD",
            "Platform Firmware, Peripheral and Accelerator Security",
            [
                profile("AOE-GD-D24-S01", "Platform firmware: UEFI, BIOS, SMM and ACPI"),
                profile("AOE-GD-D24-S02", "BMC, IPMI and Redfish"),
                profile("AOE-GD-D24-S03", "USB, HID and removable-device protocols"),
                profile("AOE-GD-D24-S04", "PCIe, Thunderbolt, DMA and IOMMU"),
                profile("AOE-GD-D24-S05", "GPU drivers, kernels and management planes"),
                profile("AOE-GD-D24-S06", "AI accelerator and multi-tenant compute isolation"),
                profile("AOE-GD-D24-S07", "RISC-V and heterogeneous SoC security"),
                profile("AOE-GD-D24-S08", "Platform measured boot and remote attestation"),
                profile("AOE-GD-D24-S09", "Peripheral and multifunction-device firmware"),
                profile("AOE-GD-D24-S10", "Chipset, management engine and platform controllers"),
            ],
            new=True,
        ),
        command(
            "AOE-GD-D25",
            "GD",
            "Transportation, Space and Clinical Systems",
            [
                profile(
                    "AOE-GD-D25-S01", "Connected vehicle architecture, gateways and telematics"
                ),
                profile("AOE-GD-D25-S02", "Automotive diagnostics, CAN, UDS and DoIP"),
                profile("AOE-GD-D25-S03", "Automotive Ethernet and SOME/IP"),
                profile("AOE-GD-D25-S04", "V2X, vehicle PKI and EV charging"),
                profile("AOE-GD-D25-S05", "Rail signaling, control and rolling stock"),
                profile("AOE-GD-D25-S06", "Avionics, aircraft networks and ground support"),
                profile(
                    "AOE-GD-D25-S07", "Maritime bridge, engine, cargo and communications systems"
                ),
                profile("AOE-GD-D25-S08", "Space systems, satellite control and ground segments"),
                profile("AOE-GD-D25-S09", "GNSS, PNT and satellite communications"),
                profile("AOE-GD-D25-S10", "UAS, drones and autonomous systems"),
                profile("AOE-GD-D25-S11", "Medical devices, implantables and wearables"),
                profile("AOE-GD-D25-S12", "Clinical networks, DICOM, HL7 and FHIR"),
            ],
            new=True,
        ),
    ]

    return {
        "schema_version": 1,
        "program": "SUNDERKEY",
        "migration": {
            "source_catalog": "registry/army-v1.json",
            "target_catalog": "registry/army-v2.json",
            "strategy": "parallel_versioned_migration",
            "stable_id_policy": "preserve_all_v1_profile_ids",
            "activation_policy": "qualified_only_with_separate_routing_authority",
        },
        "counts": {
            "baseline": {
                "groups": 5,
                "commands": 23,
                "specialists": 348,
                "domain_commanders": 23,
                "shared_profiles": 32,
                "total_profiles": 403,
                "pilot_specialists": 20,
            },
            "target": {
                "groups": 5,
                "commands": 25,
                "specialists": 391,
                "domain_commanders": 25,
                "shared_profiles": 35,
                "total_profiles": 451,
                "pilot_specialists": 20,
            },
            "delta": {
                "groups": 0,
                "commands": 2,
                "specialists": 43,
                "domain_commanders": 2,
                "shared_profiles": 3,
                "total_profiles": 48,
                "pilot_specialists": 0,
            },
        },
        "group_targets": [
            {
                "group_id": "GA",
                "baseline_specialists": 56,
                "added_specialists": 3,
                "target_specialists": 59,
            },
            {
                "group_id": "GB",
                "baseline_specialists": 86,
                "added_specialists": 4,
                "target_specialists": 90,
            },
            {
                "group_id": "GC",
                "baseline_specialists": 108,
                "added_specialists": 6,
                "target_specialists": 114,
            },
            {
                "group_id": "GD",
                "baseline_specialists": 50,
                "added_specialists": 28,
                "target_specialists": 78,
            },
            {
                "group_id": "GE",
                "baseline_specialists": 48,
                "added_specialists": 2,
                "target_specialists": 50,
            },
        ],
        "existing_command_additions": existing,
        "new_commands": new_commands,
        "shared_profile_additions": [
            profile("AOE-HQ-33", "Target Restoration and Cleanup Verifier"),
            profile("AOE-HQ-34", "Evidence Redaction and Hostile-Content Examiner"),
            profile("AOE-HQ-35", "Cross-System Effect Reconciliation Steward"),
        ],
        "standards_sources": [
            {
                "source_id": "mitre-attack",
                "version": "19.2",
                "url": "https://attack.mitre.org/resources/versions/",
                "use": "Enterprise, Mobile and ICS tactic and technique coverage",
            },
            {
                "source_id": "mitre-capec",
                "version": "3.9",
                "url": "https://capec.mitre.org/data/downloads",
                "use": "Attack mechanism and pattern coverage",
            },
            {
                "source_id": "mitre-cwe",
                "version": "rolling",
                "url": "https://cwe.mitre.org/data/index.html",
                "use": "Weakness-class ownership and validation design",
            },
            {
                "source_id": "owasp-api-security",
                "version": "2023",
                "url": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
                "use": "API abuse and authorization coverage",
            },
            {
                "source_id": "owasp-wstg",
                "version": "stable",
                "url": "https://owasp.org/www-project-web-security-testing-guide/",
                "use": "Web application test coverage",
            },
            {
                "source_id": "owasp-agentic",
                "version": "2026",
                "url": (
                    "https://genai.owasp.org/2025/12/09/"
                    "owasp-top-10-for-agentic-applications-the-benchmark-for-"
                    "agentic-security-in-the-age-of-autonomous-ai/"
                ),
                "use": "Agentic and language-model application coverage",
            },
            {
                "source_id": "nist-ai-100-2e2025",
                "version": "2025",
                "url": "https://csrc.nist.gov/pubs/ai/100/2/e2025/final",
                "use": "Adversarial machine-learning taxonomy and terminology",
            },
            {
                "source_id": "mitre-atlas",
                "version": "rolling",
                "url": "https://atlas.mitre.org/",
                "use": "AI-system adversary behavior crosswalk",
            },
        ],
        "vector_contract_fields": [
            "vector_id",
            "standards_mappings",
            "platforms_and_protocols",
            "primary_specialist_id",
            "supporting_specialist_ids",
            "independent_validator_id",
            "prerequisites_and_observations",
            "allowed_action_tiers",
            "tools_and_credentials",
            "expected_evidence",
            "cleanup_and_restoration",
            "qualification_scenario_id",
            "known_blind_spots",
        ],
        "phases": [
            phase(
                150,
                "Army expansion roadmap",
                "Bind exact additions, migration rules, standards sources and delivery gates.",
                [],
                [
                    "registry/army-expansion-roadmap-v1.json",
                    "registry/schemas/army-expansion-roadmap-v1.schema.json",
                ],
                "Roadmap rebuilds deterministically and validates all approved counts, identities and dependencies.",
            ),
            phase(
                151,
                "Army registry v2",
                "Create a parallel v2 registry with all approved commands and profiles while retaining every v1 identifier.",
                [150],
                ["registry/army-v2.json", "registry/schemas/registry-v2.schema.json"],
                "The v2 registry contains 391 specialists, 25 commanders and 35 shared profiles, with all new profiles defined and inactive.",
            ),
            phase(
                152,
                "Atomic attack-vector taxonomy",
                "Define the machine-readable vector graph and crosswalk it to authoritative external taxonomies.",
                [151],
                [
                    "registry/attack-vectors-v2.json",
                    "registry/schemas/attack-vector-catalog-v2.schema.json",
                ],
                "Every vector has ownership, evidence, safeguards, cleanup, qualification and blind-spot fields.",
            ),
            phase(
                153,
                "Capability graph v2",
                "Replace name-restatement capabilities with primary, supporting and validation relationships for every specialist.",
                [151, 152],
                [
                    "registry/capabilities-army-v2.json",
                    "registry/schemas/capability-catalog-v2.schema.json",
                ],
                "Every specialist has meaningful capability edges and every vector has primary and supporting coverage.",
            ),
            phase(
                154,
                "Qualification plans v2",
                "Generate vector-specific scenarios, expected evidence, critical failures and action-tier boundaries.",
                [152, 153],
                ["registry/qualification-plans-army-v2.json"],
                "Every v2 specialist has a non-generic qualification plan with independent validation requirements.",
            ),
            phase(
                155,
                "Candidate blueprints v2",
                "Define implementable inputs, tools, adapters, outputs, controls and evidence contracts for all v2 specialists.",
                [153, 154],
                ["registry/candidate-blueprints-army-v2.json"],
                "Every v2 specialist has an implementation-ready, fail-closed blueprint.",
            ),
            phase(
                156,
                "Commander work packages v2",
                "Generate dependency-ordered implementation packages and commander review queues.",
                [151, 153, 154, 155],
                [
                    "registry/specialist-implementation-roadmap-v2.json",
                    "registry/implementation-work-packages-v2.json",
                ],
                "All candidate builds are ordered by risk, dependency, coverage gain and verification capacity.",
            ),
            phase(
                157,
                "Candidate implementation waves",
                "Implement bounded candidates in prioritized waves without granting qualification or routing authority.",
                [156],
                ["registry/candidate-components-v2.json", "implementation evidence packets"],
                "Each candidate passes static, unit, integration, containment and evidence-contract checks.",
            ),
            phase(
                158,
                "Independent qualification waves",
                "Run signed, reproducible scenario packs with independent control and assurance review.",
                [157],
                ["qualification evidence manifests", "signed qualification decisions"],
                "Only candidates with complete evidence and no unresolved critical failures become qualified.",
            ),
            phase(
                159,
                "Shadow routing and collaboration",
                "Exercise qualified specialists on mirrored missions and score their handoffs, conflicts and coverage.",
                [158],
                ["shadow-routing reports", "collaboration scorecards"],
                "Routing changes remain non-production until coverage, correctness and safety thresholds are met.",
            ),
            phase(
                160,
                "Controlled canaries",
                "Authorize bounded live canaries for selected qualified profiles in approved real environments.",
                [159],
                ["canary authorization packets", "provider receipts", "cleanup verification"],
                "Each canary has explicit target authority, action tier, monitoring, stop conditions, evidence custody and restoration proof.",
            ),
            phase(
                161,
                "Migration completion",
                "Retire superseded v1 ownership only after v2 equivalence and operational evidence are independently verified.",
                [160],
                ["v1-to-v2 equivalence report", "retirement decisions", "rollback plan"],
                "No v1 route is retired without a qualified replacement, successful canary evidence and a tested rollback path.",
            ),
        ],
        "migration_rules": [
            "Do not modify or delete the trusted v1 registry during v2 construction.",
            "Preserve every existing profile ID and make additions only through unused command and specialist numbers.",
            "Treat broad v1 specialists as integration owners until explicit retirement evidence exists.",
            "Create every new profile in defined status with pilot false and no implied qualification.",
            "Keep production routing bound to qualified profiles and separately authorized routing policy versions.",
            "Require independent control and assurance for qualification, canary and retirement decisions.",
            "Require restoration evidence for any controlled action that changes an approved target.",
        ],
        "limitations": [
            "This roadmap does not create legal authority or expand any target scope.",
            "This roadmap does not qualify, deploy, route to or execute any specialist.",
            "Taxonomy references are planning inputs and must be version-pinned when vector records are generated.",
            "Defined profiles are design records, not evidence that a capable implementation exists.",
            "Real-environment operations require separate mission, target, identity, action-tier, monitoring and cleanup authority.",
            "Production deployment decisions remain separate from the Army v2 catalog migration.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    roadmap = build_army_expansion_roadmap(roadmap_body())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(roadmap.to_dict(), indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "roadmap_id": roadmap.roadmap_id,
                "roadmap_sha256": roadmap.roadmap_sha256,
                "specialist_additions": roadmap.delta_counts["specialists"],
                "target_specialists": roadmap.target_counts["specialists"],
                "status": "valid",
                "operational_effect": "none",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
