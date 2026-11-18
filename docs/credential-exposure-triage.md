# Credential-exposure triage

This repository-only V9.6 slice screens caller-supplied exposure signals for
human review. It accepts bounded, content-addressed records for one tenant and
scope. Principal and credential identifiers must be opaque `principal:sha256:`
and `credential:sha256:` references. The module does not accept a password,
reusable password hash, credential value, email address, or account name.
These references must be derived from opaque random identifiers, not from
password or credential bytes. This origin rule requires external enforcement;
the module validates only the reference format.

Signals identify a closed exposure category, opaque source feed, source digest,
observation time, and expiry. Caller-supplied consent records bind a principal
reference, allowed categories, tenant, scope, source digest, and short expiry.
A current signal with a matching current consent becomes a human-review
candidate. Missing or expired consent blocks candidacy. Expired signals are
stale even if consent is current. The plan preserves each disposition, source
digest, and the exact matching consent digests for independent inspection.

These records are metadata assertions, not verified consent, feed authenticity,
proof of credential validity, or proof of compromise. The plan does not grant
target authority or execute a password audit. It never resolves secrets,
authenticates, attempts a login, rotates a credential, contacts a feed, or
initiates a network call. Duplicate identical events are deduplicated, while
conflicting evidence for one event ID fails closed. Signals expire within 30
days and consent records within 90 days of their respective issue times.

Production completion still needs independently authenticated consent and
intelligence provenance, approved feeds, isolated computation for any
separately authorized password audit, lockout controls, independent identity
review, secure rotation integration, deletion receipts, and governed retention.
Do not infer present credential validity or rotate an account from this plan.
