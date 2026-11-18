# Supplied GCP VPC new-flow rule predicates

This partial analyzer calculates predicates from explicitly supplied declarations.
It cannot contact Google Cloud, acquire a firewall or target, prove effective
access or authorize traffic. The input is a closed projection, not a Compute
Engine resource parser, deployment instruction or full GCP API-validity check.

Ownership is `AOE-GC-D14-S07`, capability `army.gc.d14.s07`, vector
`AV-GC-D14-S07-01`, work package `IWP2-AOE-GC-D14-S07`, wave `IW2-010`, commander
`AOE-GC-D14-CMD`, group owner `AOE-HQ-05` and independent validator `AOE-HQ-19`.
The blueprint is
`sha256:e6adfbee776bae2c829904271d023368b12f8e26b6f810d48922b2cc4e7a6eb8`.
This contributes partial A7.4 supplied-model evidence, never S06 IAM coverage,
candidate readiness, live authority, routing or qualification promotion.

## Declared model

The root has exactly `schema_version` (native integer 1), `network_id`,
`rules_complete` (native bool), `traffic_kind` (literal `new_flow`), `rules` and
a nonempty `flows` array. The one declared network, rule-set completeness,
target applicability and new-flow classification are caller premises. None is
authenticated, fetched or verified as current.

Each rule has exactly `rule_id`, `network_id`, `direction`, `disabled`,
`priority`, `action`, `targets`, `predicate`. Both rule and flow network IDs
must equal the root ID. Rule IDs and flow IDs are independently unique. Rules
may share priorities. Directions are `INGRESS` or `EGRESS`; action is `allow`
or `deny`; disabled is a native bool; priority is a native integer 0..65535.
Rules that are disabled or in the other direction cannot match.

Targets are one of these closed declarations:

- `{"kind":"all"}`: all caller-declared targets in the network.
- `{"kind":"declared_ids","target_ids":["synthetic-nic"]}`: a complete
  caller-supplied applicability set, not a tag, service-account or NIC resolver.
- `{"kind":"unsupported","reason":"target_tag"}`: potential applicability.
  Other reasons are `target_service_account` and `other_target`.

An ID-set is nonempty and unique. It can contain IDs not queried by a flow.
The supported packet predicate is exactly:

```json
{
  "kind": "cidr_protocol_ports",
  "protocol": "tcp",
  "source_cidrs": ["10.0.0.0/24"],
  "destination_cidrs": ["10.0.1.0/24"],
  "destination_ports": [[443, 443]]
}
```

Both CIDR dimensions are explicit, nonempty, unique and canonical strict
network addresses. Every source and destination range in one rule has the same
IP version. This subset supports explicit source and destination filters in
both directions. It does not infer omitted defaults, NIC addresses, source-tag
unions, service-account membership or IP-forwarding applicability.

Protocol is `tcp`, `udp` or `all`. Empty destination-port arrays explicitly mean
all ports. Nonempty inclusive native integer `[low, high]` pairs, bounded
0..65535, are allowed only with tcp or udp; duplicate exact pairs and reversed
ranges reject. Overlapping distinct ranges are allowed. There are no source-port
predicates. A rule represents one protocol alternative; full mixed-protocol
resource arrays are outside this model.

The other closed packet predicate is
`{"kind":"unsupported","reason":"protocol"}`. Other reasons are `source_tag`,
`source_service_account` and `other_predicate`. It means the entire packet
predicate remains unresolved, not that a tag name was interpreted as a CIDR.
Known target nonmembership can still rule it out. Conversely, a known packet
nonmatch can rule out an unknown target selector. Unknown declarations are
retained at their priorities rather than silently omitted.

Flows have exactly `flow_id`, `network_id`, `target_id`, `direction`, `protocol`,
`source_ip`, `destination_ip`, `destination_port`. Protocol is tcp or udp;
addresses are canonical, unscoped and one IP family. Coordinates are supplied
at the intended predicate layer. This does not establish valid VM emission,
packet routing or verified pre/post-NAT addressing.

`component_fixture()` returns fresh wholly synthetic input: two equal-priority
known ingress Allow witnesses and one unresolved egress target-tag selector,
with separate ingress and egress queries. No fixture is real provider evidence.
Its literal report is `GCFA-8E3869008A986AF8D276431ADA36B8A3`; source model digest is
`sha256:5c9cfab6bd6d73292c098d1e5440967ac6ff73a48964e9c557c4e8b26e8c9806`.
The two observations are Allow under supplied predicates and unassessed,
respectively. The ingress result retains both equal-priority known witnesses.

## Priority, ties and uncertainty

Primary sources are Google's [VPC firewall rule documentation](https://docs.cloud.google.com/firewall/docs/firewalls)
and [Compute Engine Firewall resource reference](https://docs.cloud.google.com/compute/docs/reference/rest/v1/firewalls).
They describe lower numerical priority precedence, equal-priority Deny,
indeterminate choice among same-action ties, destination ports, two-direction
address filters and the distinction between new and existing connections.

For each flow the analyzer finds the lowest priority group containing a known
or potentially matching rule. It preserves all known matches in `matched_rules`
and unresolved candidates with reason codes in `possible_rules`, both ordered
by rule ID. It does not claim one same-action rule was processed by GCP.

A known Deny at that group determines `deny_under_supplied_vpc_predicates`,
including when unknown rules share its priority. A known Allow determines
`allow_under_supplied_vpc_predicates` only if no unresolved same-priority Deny
could override it. Only unknown candidates at an earlier group yield
`unassessed`, even if later known rules have the same action. This deliberately
conservative subset does not enumerate every completion of unknown rules.

`winning_rule_ids` contains every known matching rule with the selected action.
`winning_witnesses_complete` describes only the conditional supplied-model
winner set, not inventory completeness. A possible same-action rule makes that
set incomplete, even if action is certain. An unknown Allow cannot win against
a known equal-priority Deny, so it does not make the Deny witness set incomplete.
The unresolved rule remains visible in either case. Unassessed observations
have no claimed winners and native false witness completeness.

`rules_complete: false` withholds the whole conclusion and witness claims.
No supplied match is unassessed: no implied ingress/egress action, default
network rule or catch-all is fabricated. Explicitly supplied predicates at
priority 65535 are arithmetic inputs, not authenticated implied rules.

## Pure APIs, ownership and source replay

`analyze_supplied_gcp_firewall(model)` and
`analyze_supplied_gcp_firewall_bytes(*, model_bytes)` return a frozen
`GcpFirewallAnalysis`. The bytes API accepts native ASCII JSON bytes, not a path.
`from_dict`, `from_json`, `to_dict`, `to_json` and identity properties rederive
every observation from the detached embedded `source_model` in one bounded
operation. Exports return owned copies, not references into caller input.
The retained configuration is unsanitized metadata, not a publication artifact.

`verify_supplied_gcp_firewall_analysis(report, *, model)` also requires separately
supplied originals. A coherent changed source can replay itself but cannot verify
against an unchanged original. Rehashing false observations cannot bypass source
reconstruction. The `GCFA-` report address and `source_model_sha256` use separate
domains. These unsigned content addresses imply no provider identity, signature,
custody, currentness or access permission.

## Finite software costs

Model/report ceilings are 256 KiB/1 MiB and 16,384/65,536 native nodes, counting
keys and scalar values. Scalar-inclusive depth is 16; printable ASCII strings
are at most 512 bytes; IDs at most 64; IP/CIDR strings at most 64. Generic native
integers fit signed 64-bit before decimal conversion. Schema, priority and port
checks additionally reject bool/int and float/int aliases.

Limits are 256 rules, 128 flows and 64 target IDs, CIDRs per dimension or port
pairs. Maxima are separate ceilings, not a promise they fit simultaneously.
Large tie groups across many flows can exhaust retained-output limits while
their input still fits; that raises `GcpFirewallAnalysisError`, not a negative
firewall finding.

One public operation has an 8,388,608-step cumulative budget. It funds repeated
native subtrees, escaped canonical bytes, key ordering, copying, CIDR parsing,
rule ordering, predicate tests, witnesses, report retention, full final encoding,
digest inputs, equality scans and owned wrapper storage before any digest.
Fixed-width address placeholders reserve the final fields before hashing.
Separate-original verification funds both complete derivations before either
source or result is hashed. Each new public operation has a fresh finite budget;
there is no unlimited reset inside one operation or lifetime-budget claim.

Raw byte/string/int/node/depth checks precede JSON decoder allocation, with
duplicate-key rejection in the decoder. Raw decoding additionally reserves
18 times text length plus twice lexical nodes before allocation. Native aliases,
cycles, floats, giant integers, non-ASCII strings, unsupported fields, missing
wrapper storage and false replay reject through the leaf error. JSON whitespace
and equivalent printable ASCII escapes normalize to the same canonical source.
Below-byte-cap documents can still exceed their work or replay/export budgets.

## Boundaries

This is not an effective GCP firewall verdict, permission, browser/server test,
provider inventory or complete firewall evaluation. Hierarchical, global and
regional policies; metadata and VM-self exceptions; routing, NAT, load balancers,
forwarding, connection tracking, return traffic, existing flows and actual target
membership are excluded. Even a predicate Deny for a metadata-server coordinate
does not claim GCP blocks that traffic. Every effect is `none`; all proof,
authority, currentness and qualification flags are native false. There are no
callbacks, credentials, resource readers, sockets, processes or remote actions.
