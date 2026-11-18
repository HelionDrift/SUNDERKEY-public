# Supplied consent purpose timeline

The `AOE-GB-D09-S11` partial specialist replays a caller-supplied sequence of
purpose-specific grant, withdrawal, and processing labels. It keeps local
active state separately for each declared purpose. Repeated grants,
withdrawals without a prior local grant, processing labels without a local
grant, and declared state mismatches are separate review signals. The original
model and event positions remain in the replay-checked report.

The exact native JSON model declares `schema_version: 1`,
`semantics_profile: supplied-consent-purpose-timeline-v1`, one digest-shaped
opaque subject reference, one to 128 unique purposes, and one to 512 ordered
events. Every event has a unique ID, declared purpose, action, claimed active
state afterward, and source label. Input, structure, strings, and reports are
bounded. The typed report supports replay against the current supplied model.

These are caller assertions, not authenticated consent or observed
processing. A processing label without a local grant is not proof of a
privacy violation: another lawful basis, consent validity, purpose scope,
jurisdiction, and data-subject identity are not assessed. The component does
not contact a subject, target, service, credential, or consent store. It does
not make a legal finding, authorize positive use, or qualify a candidate.
The [synthetic example](../examples/offline-consent-purpose-component.json)
contains only fictitious events.
