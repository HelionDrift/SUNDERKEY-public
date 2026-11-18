# Offline identity path hop plan

`sunderkey.identity_path_hop_plan` turns an already reviewed, replayed identity path into a bounded evidence checklist. It does not validate a live provider account, use a credential, contact a target, authorize an action, or claim qualification.

The builder requires the snapshot, search result, reviewed validation plan, original condition attributes, and evaluation time. It first replays the reviewed plan. Each returned path is then decomposed into ordered steps:

- the workload-to-principal binding;
- each trust relation or declared session transition;
- the terminal direct allow, with its operative policy and permission-fact records.

Each step lists exact source and target node IDs, a relation or resolution ID, source-record IDs, and evidence-binding IDs. A session transition may contain an opaque credential reference ID. It never includes the credential key or credential value. The terminal step must include a directly allowed permission fact and a current attached policy. The total step count must equal the reviewed plan's bound validation budget.

The content-addressed artifact binds the source snapshot, search result, reviewed plan, path IDs, attribute digest, evaluation time, and ordered steps. `verify_identity_path_hop_plan` reconstructs the artifact from those original sources before a stored checklist is used. The strict Python parser and `registry/schemas/identity-path-hop-plan-v1.schema.json` reject extra fields, changed effects, malformed values, and content-address tampering.

This is a historical, caller-supplied evidence map. Reviewer identities and evidence custody are not authenticated here. Provider currentness, separate action authority, credential brokerage, live per-hop observations, stop controls, and cleanup remain external requirements. None of the recorded steps is an instruction or permission to traverse a target.
