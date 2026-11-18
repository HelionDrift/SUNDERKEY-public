# Offline OT Engineering Project Provenance

This R0 component supports a narrow part of `AOE-GD-D19-S04`. It compares
caller-supplied reviewed and supplied engineering-package SHA-256 labels and a
declared review-record flag. A digest difference or an explicitly absent review
record is only an unsigned provenance-gap candidate. Missing digests, an unknown
review-record state, or incomplete context yields `unknown`, not a candidate.

The component does not open a project package, authenticate a review, contact
an engineering workstation or controller, use credentials, send commands, or
interact with a network or physical process. It establishes neither deployment
nor process behavior, impact, safety, exploitability, finding status, or
qualification. Replay verification requires the separately retained original
caller model.

The [synthetic example](../examples/offline-ot-engineering-project-provenance-component.json)
uses fictitious digest labels and no target resources.
