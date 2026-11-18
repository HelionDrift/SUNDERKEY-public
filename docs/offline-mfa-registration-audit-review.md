# Supplied MFA Registration Audit Review

The GA-D02-S05 partial component parses one synthetic subset of a Microsoft
Graph [directoryAudit item](https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit).
Microsoft's [authentication-method activity reference](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities)
names the modeled registration activities. The checked example is
[`examples/offline-mfa-registration-audit-component.json`](../examples/offline-mfa-registration-audit-component.json).

It checks activity, category, UTC time, result, actor, and target fields and
compares actor and target IDs with caller-declared expectations. It hashes
IDs in the report. Even a declared success is an unauthenticated log claim,
not proof of current MFA method state or of a help-desk interaction. No Graph
request, enrollment, human contact, finding, or qualification occurs.
