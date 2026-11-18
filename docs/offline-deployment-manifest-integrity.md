# Offline deployment manifest integrity

Deployment manifests are checked descriptions, not observations of a deployed
environment. Their public parsers require an exact canonical JSON replay of
the repository templates and bundle.

## Checked boundary

`DeploymentManifest.from_dict()` compares the canonical profile body with the
checked template before verifying its existing content address.
`DeploymentManifestBundle.from_dict()` compares the complete canonical input
with the builder's canonical document. The text parser still requires canonical
ASCII JSON.

These comparisons distinguish native JSON booleans, integers and floating-point
numbers. Python mapping equality does not: it considers `true`, `1` and `1.0`
equal, and likewise `false`, `0` and `0.0`. That equality must not make changed
document bytes valid under an old address or permit a coherently readdressed
profile that differs from its checked template.

Mapping key order is not a content change. Array order, exact fields, nested
template values and content addresses remain fixed. Valid descriptions retain
their original profile and bundle IDs, hashes and canonical documents. The
checked manifest registry is unchanged.

## Verification

`tests/agents/test_deployment_manifest_exact_replay.py` covers:

- both public bundle entrypoints rejecting all eight native metadata aliases;
- standalone profiles rejecting coherently readdressed aliases at every native
  boolean or integer template field;
- existing-address profile tampering and valid golden document identities;
- key-order independence, input preservation, unknown fields and array order;
- unchanged rejection of positive deployment or qualification claims; and
- unchanged checked registry bytes and nonqualifying effects.

The adjacent Phase170 deployment, D014 dossier and GCP acceptance-checklist
tests retain the distinction between a software template and external proof.

## Limits

No host, filesystem discovery, credential, database, provider, process, target
or network operation is added. Template replay does not verify signatures,
observe TLS or egress, perform migrations, prove runtime image authenticity,
execute recovery drills, deploy a service or qualify an environment.

GCP `us-west3` remains an unsigned planning assumption. This change does not
choose Cloud SQL versus self-managed PostgreSQL, resolve any D014 selection,
regenerate an approval, or readdress historical signed evidence.
