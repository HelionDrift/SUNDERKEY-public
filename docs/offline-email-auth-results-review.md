# Supplied Email Authentication-Results Review

The GA-D02-S01 partial component parses a bounded, synthetic subset of the
[RFC 8601 Authentication-Results field](https://www.rfc-editor.org/rfc/rfc8601.html).
The checked example is
[`examples/offline-email-auth-results-component.json`](../examples/offline-email-auth-results-component.json).

The analyzer reads one single-line field, compares its declared authserv ID
and SPF, DKIM, and DMARC domain properties with caller-declared expectations,
and hashes domains in its report. It rejects duplicate method names, unsupported
properties, non-synthetic domains, and control characters. It does not
authenticate the field's origin, recompute mail authentication, evaluate
phishing effectiveness, or observe delivery. No message is built or sent, and
no finding or qualification is produced.
