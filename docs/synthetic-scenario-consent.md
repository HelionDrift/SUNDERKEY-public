# Synthetic scenario consent screening

This repository-only V9.7 slice evaluates metadata for proposed synthetic
phishing-impact and insider-start-position scenarios. It does not deliver a
message, create a persona, collect credentials, access a target, or execute an
attack path. A request names one synthetic principal, one opaque surface, one
scenario ID, and a window no longer than 24 hours. Consent names the exact
scenario, kind, approved synthetic population, surfaces, scope, and expiry.

The planner produces a human-review candidate only when a current consent
matches the request and covers the whole requested window. Missing, mismatched,
or expired consent blocks the candidate. Expired requests stay expired even if
a consent exists. Every item carries obligations for population assurance,
exact scope and window, activity trace, cleanup receipt, and independent
review. Those obligations are not satisfied by this plan.

Principal and surface references are opaque digests of synthetic identifiers.
They must not be derived from real user identities, passwords, or credential
bytes. The module validates reference shape, not origin or consent signatures.
Caller-supplied consent and source digests are unverified assertions. The plan
is not action authority, admission, proof of impact, or evidence of cleanup.

Production work still requires authenticated owner consent, population
verification, ephemeral identity custody, exact target scope, stop propagation,
independent safety review, bounded runner controls, telemetry, cleanup, and
external evidence custody. Any live simulation remains separately authorized
and must pass the ordinary action-admission boundary.
