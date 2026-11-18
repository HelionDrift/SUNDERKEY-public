# Offline Specialist Breadth Feasibility Audit

This audit compares the 391 specialist packages in
[`registry/implementation-work-packages-v2.json`](../registry/implementation-work-packages-v2.json)
with the staged 376-component catalog in
[`registry/offline-specialist-components-v1.json`](../registry/offline-specialist-components-v1.json).
The catalog has partial, nonqualifying work for 367 distinct profiles. The
remaining 24 profiles are not silently treated as implemented. A partial
component is not a full candidate, a qualified agent, or a live capability.

| Domain | Uncovered profiles | Feasible offline work | Evidence needed before stronger claims |
| --- | ---: | --- | --- |
| GA-D04 Red Team Tradecraft | 12 | Bounded synthetic path and control-effect models for approved exercise plans | Controlled infrastructure, telemetry, and independent validation before C2, implant, persistence, impairment, or impact claims |
| GA-D02 Social and Physical Operations | 2 | Consent, scope, artifact-handling, and stop-rule rehearsal against synthetic exercise records | Human and organizational authorization, safe delivery controls, and exercise oversight |
| GE-D21 Exploit Engineering | 1 | Extend bounded static parser and mitigation-state analysis over supplied binaries or disassembly | Reproducible target builds, isolated execution, exploitability validation, and independent review |
| GD-D18 Hardware and Embedded | 1 | Static trace, netlist, or protocol-declaration checks where a concrete format is available | Device or lab measurements and hardware safety review before leakage, fault, or radio claims |
| GD-D19 Industrial Systems | 6 | Inert process-model and zone-policy checks with explicit model assumptions | Site-specific process and safety model, operator approval, containment, and independent safety review |
| GD-D25 Transport and Medical Systems | 2 | Synthetic asset-relationship and safety-case consistency checks | Platform-specific simulator or lab, custodian authority, and domain safety review |

## Recommended Offline Order

1. Extend GE-D21 static binary analysis only where the repository has a
   bounded format parser and an independent corpus of safe fixtures. Reject
   shellcode generation, exploit-chain execution, and target-facing tests in
   this stage.
2. Extend GD-D18 supplied hardware or radio metadata analysis only for a
   specified document or trace format, not by renaming a generic policy
   comparison as side-channel or fault-injection testing.
3. Add GA-D04 synthetic exercise-plan path checks with explicit action-tier,
   stop, and evidence boundaries. Do not add live C2, persistence, impairment,
   or exfiltration under an offline component label.
4. Keep uncovered GA-D02, GD-D19, and GD-D25 roles as role and plan coverage
   until consent, domain safety, and realistic test fixtures are approved.
   The new synthetic SIS/BPCS declaration can prepare a review but cannot
   prove physical effects or safety.

This triage does not grant new authority or remove D014 deployment and
containment dependencies. The minidump directory, SIS/BPCS resource comparison,
PE byte triage, consent URI comparison, OOXML relationship review, SMS URI
review, email authentication-result parsing, MFA audit review, visitor escort
record comparison, OSDP poll-frame parsing, Windows device-event review,
ActivityStreams identifier comparison, recovery-test date projection, and
operator offboarding chronology, unverified PASSporT claim decoding, and
OT vendor support mapping, seccomp BPF subset projection, and FHIR DeviceAssociation review reduce the inventory gap to 24 only as partial synthetic analyses.
Every future component still needs a distinct source-bound analyzer, checked
fixture, negative tests, original-model replay, common-task ownership, and
clear nonqualification limits. The work queue remains open for those
substantive offline increments.
