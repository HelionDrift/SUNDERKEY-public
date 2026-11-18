# Supplied Cross-Channel Session Revocation

The `AOE-GE-D23-S08` partial specialist projects a finite, caller-supplied
timeline across distinct session channels. It compares an issue, one revoke,
and later observed use only where the policy explicitly declares cross-channel
revocation and the observer explicitly asserts that revocation was effective
before observation. No token or cookie value is accepted, replayed, or sent.

The model uses opaque `ref:` session and channel labels. It refuses duplicate
issues, revocations without a prior issue, and a second revocation. A declared
accepted outcome after an effective revocation on another channel is only a
`candidate_declared_cross_channel_conflict`. Missing event completeness,
incomplete policy or observation, unknown outcome, unknown session, or unknown
revocation effectiveness withholds that conclusion. Event order, outcome,
policy and effectiveness are unverified caller assertions. The labels are a
format guard, not proof that supplied data was sanitized.

This is distinct from the single-channel session and device-binding timeline:
it compares declared cross-channel revocation propagation, not device binding
or live token state. The native model is limited to 128 events and a 64 KiB
document ceiling. Its report embeds the original model for independent-source
replay. No file, network, process, credential, target, publication, execution,
or qualification effect is produced. The [synthetic example](../examples/offline-cross-channel-session-component.json)
uses inert labels only.
