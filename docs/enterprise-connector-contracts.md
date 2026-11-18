# Enterprise Connector Contracts

This reference defines local contracts for Jira and Microsoft security integrations. It builds
vendor-specific requests and normalizes a response from a caller-supplied
transport. It contains no network client, endpoint resolver, credential
resolver, timer, retry loop, or outbox mutation.

## Supported boundaries

Jira Cloud issue creation is pinned to REST API version 3 and the create-issue
path. Microsoft Sentinel delivery is pinned to the Azure Monitor Logs Ingestion
API version `2023-01-01` and binds the data collection rule and stream by opaque
reference. Security Copilot integration binds an OpenAPI 3.0.1 description and
plugin manifest by opaque reference and SHA-256 digest.

The source snapshot was checked on 2026-09-20 against:

- <https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/>
- <https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview>
- <https://learn.microsoft.com/en-us/copilot/security/custom-plugins>
- <https://learn.microsoft.com/en-us/copilot/security/plugin-api>

These URLs support request-shape planning only. They are not runtime evidence.

## Secret and evidence boundary

Bindings contain only opaque endpoint and credential references. Request bodies
contain safe summaries, normalized state, severity, subject references, event
digests, and artifact references. The implementation rejects secret-like fields,
authorization material, cookies, raw tokens, private keys, and common exploit
payload text. It never places credentials into a serialized request.

`deliver_with_connector` reconstructs the binding and request, then replays the
exact pinned vendor path and body from the supplied binding and event projection.
It checks canonical documents, tenant, destination, operation and validity
windows before invoking one supplied transport. Parser integrity alone does not
establish an authenticated binding or event source. Success,
retryable failure, and permanent failure are normalized for the durable outbox.
A failed response cannot claim an external resource.

## External completion evidence

Production completion still requires deployed endpoint and credential resolvers,
TLS and egress enforcement, vendor tenant configuration, consent and permission
review, signed delivery observations, rate-limit testing, dead-letter operations,
regional-custody review, and independent verification of actual Jira, Sentinel,
and Security Copilot behavior.
