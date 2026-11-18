# SUNDERKEY

SUNDERKEY is an open-source control plane for coordinated, authorized offensive security assessments. SUNDER stands for Signals Unmasking, Network Discovery, Exploitation, and Reconnaissance.

The platform brings narrowly specialized security roles into one mission. Specialists analyze different surfaces, domain commanders coordinate their work, and independent control and assurance roles review authority and evidence. A shared plan connects their results so an assessment can follow relationships across systems instead of treating each test as an isolated task.

SUNDERKEY is designed for assessments of real systems with the owner's permission. Installing it does not grant target access, start an assessment, or activate a network adapter. Live use requires an exact authorized scope and separately operated infrastructure.

## Capabilities

### Army of Experts

The included registry defines 451 roles: 391 specialist profiles, 25 domain commanders, and 35 shared roles across five groups. These are role and capability definitions, not 451 independently running agents. A mission selects the roles it needs and assigns bounded work through a common plan.

| Group | Areas of Expertise |
| --- | --- |
| Targeting, Access, and Campaigns | Attack surface, human and physical access, identity and trust, adversary emulation |
| Applications, Data, and Digital Assets | Web and browser, APIs and integrations, data systems, mobile and desktop clients, business logic, distributed ledgers |
| Enterprise, Cloud, and Supply Chain | Windows and Active Directory, open systems, networks and telecom, cloud and SaaS, containers and serverless, enterprise platforms, software supply chain |
| Cyber-Physical and Intelligent Systems | Embedded systems and firmware, operational technology, AI and agentic systems, platform firmware, transportation, space, and clinical systems |
| Exploit Science and Cross-Surface Patterns | Vulnerability research, cryptography and protocols, cross-surface attack patterns |

The catalog also defines collaboration, handoff, and review responsibilities. See the [Expert Control Plane](docs/expert-control-plane.md) and [Registry Guide](registry/README.md).

### Mission Control and Action Governance

- Build mission plans with explicit scope, target, operator, role, time, and action-tier bindings.
- Evaluate proposed actions against current authorization, independent approval, budget, and stop conditions before use.
- Track work ownership, leases, handoffs, cancellations, recovery, and terminal mission state.
- Preserve revocation and historical integrity without treating an old approval as current authority.
- Keep specialist and model output separate from the authority to act.

The action tiers run from R0 through R5. Higher-impact activity requires the controls appropriate to its tier. See [Signed Assessment Scope](docs/signed-assessment-scope.md) and [Action Admission Contracts](docs/action-admission-contracts.md).

### Discovery and Specialist Analysis

- Correlate imported, passive, or previously collected observations into assets, services, endpoints, ownership claims, conflicts, and coverage gaps.
- Model attack paths and cross-surface relationships without promoting an unverified hypothesis into a finding.
- Run deterministic offline analyzers for selected web, API, identity, cloud, enterprise, protocol, firmware, and cyber-physical evidence types.
- Use capability maps, blueprints, and qualification plans to identify what a specialist is defined to do and what remains unproven.

Offline analysis operates on supplied evidence. It does not by itself scan a target or establish that a collector, specialist, or result is qualified for live use. See [Attack Surface Discovery](docs/attack-surface-discovery.md) and [Offline Specialist Components](docs/offline-specialist-wave-components.md).

### Evidence, Findings, and Remediation

- Bind observations and decisions to source identities, timestamps, canonical content hashes, and typed mission events.
- Maintain finding states, review decisions, evidence references, and retest outcomes.
- Assemble assessment reports with tested, untested, and undetermined coverage kept distinct.
- Preserve negative results, uncertainty, residual risk, and restoration state rather than reporting only successful paths.

See [Finding Lifecycle](docs/finding-lifecycle.md) and [Assessment Reporting](docs/assessment-reporting.md).

### Interfaces and Integration

SUNDERKEY includes a Python package, a command-line interface, machine-readable registries and schemas, and an in-process local service contract for mission, finding, evidence, and report resources. It also includes guarded interfaces for HTTP, browser, target-session, and credential workflows, plus an optional OpenAI Responses expert-provider adapter. These components are integration points, not a preconfigured live assessment service.

Deployments must supply and qualify the applicable identity, credential, network egress, containment, storage, monitoring, and target-specific adapters. The [Local API Service](docs/local-api-service.md) is an in-process core, not an HTTP server. The [OpenAI Expert Provider Adapter](docs/openai-expert-provider-adapter.md) cannot approve its own action or grant tool access.

## How an Assessment Fits Together

1. An operator establishes the target owner's authorization and exact scope.
2. A mission plan assigns bounded work to specialists and domain commanders.
3. Specialists analyze admitted evidence and propose actions or findings.
4. Independent control checks action authority, while assurance reviews evidence and limitations.
5. Authorized adapters perform only admitted operations and return bound observations.
6. Findings, retests, reports, cleanup, and stop decisions remain traceable to their source records.

The source supplies many of these contracts and local behaviors. A real deployment must independently validate the adapters and operating environment before live execution. Synthetic fixtures, hashes, and successful local tests are not substitutes for target authorization or operational qualification.

## Quick Start

Python 3.11 or later is required. From the repository root:

```sh
python -m pip install -e .
python -m sunderkey.cli validate-registry --registry registry/army-v2.json
python -m sunderkey.cli --help
```

The registry command validates the included expert catalog. It makes no target request and grants no assessment authority. For a local analysis example using supplied JSON, follow the [Offline Review Workflow](docs/offline-review-workflow.md). The [Documentation Index](docs/README.md) covers the architecture, interfaces, examples, and integration contracts.

## Repository Layout

| Path | Contents |
| --- | --- |
| `src/sunderkey/` | Control plane, analysis, custody, and adapter code |
| `registry/` | Expert profiles, capability catalogs, policies, and JSON schemas |
| `examples/` | Synthetic inputs and nonqualifying examples |
| `docs/` | Architecture and implementation guides |
| `tests/` | Local contract and regression tests |
| `scripts/` | Builders, checks, and operator utilities |

## Responsible Use

Use SUNDERKEY only against systems you own or are expressly authorized to assess. Define the permitted targets, methods, time window, data handling, stop conditions, and recovery obligations before any live interaction. Do not place credentials, customer data, or private approval records in the repository.

See [SECURITY.md](SECURITY.md) for private vulnerability reporting and [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance.

## License

Copyright 2026 Morgan Bleck. Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
