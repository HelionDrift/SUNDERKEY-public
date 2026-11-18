# Offline task work-product review receipts

An offline work-product candidate binds a caller-supplied result digest and
evidence digests to one immutable coverage task, schedule, scope, and world
snapshot. It cannot predate the schedule. The candidate does not authenticate
the producer or the underlying evidence.

Two review attestations can sign the exact work-product digest with Ed25519:
one independent-control role and one independent-assurance role. Verification
requires distinct reviewer identities and keys, and neither reviewer may be
the task specialist or commander. It checks each signature against an explicit
caller-provided public-key binding. A rejected attestation remains valid as a
record but yields a declined local review state.

At consumption, the exact `ReviewerKeyBinding` family is required and its
current native key identifier, reviewer identifier, role and Ed25519 public
key are captured and revalidated before context comparison or signature use.
Task and evidence identifiers, hashes, timestamps, attestation roles,
decisions and signature strings must be native JSON strings. Mapping keys
are checked before lookup, sorting, set construction or local review-state
classification. A binding changed after construction cannot substitute an
untyped verifier. Native-key read-only mapping views remain supported, and
ordinary JSON work-product and review packet identities are unchanged.
The consumed schedule and task context is checked before schedule replay,
including native schedule identifiers and digests, the schedule time, task
identifiers and digests, and the specialist and commander identifiers. A
caller string subclass cannot suppress the self-review exclusion.

These are local integrity and separation checks, not production identity
assurance. The key bindings have no certified custody in this module, reviewer
organizational independence is not established, and source evidence is not
replayed or made current. Even two locally accepted signatures leave
`positive_use_approved: false`. The packet cannot authorize execution,
qualification, finding publication, or a successful task outcome for live use.
The primitive checks do not establish general ownership of arbitrary caller
mappings or protection against concurrent caller mutation.
