# Supplied Azure NSG directional predicates

This partial component calculates declared Azure Network Security Group (NSG)
rule predicates for supplied packet coordinates. It cannot connect to Azure or
a target, acquire rules, authorize traffic, prove reachability or qualify an
expert. Every input is an unauthenticated caller assertion.

Existing ownership is `AOE-GC-D14-S05`, capability `army.gc.d14.s05`, vector
`AV-GC-D14-S05-01`, package `IWP2-AOE-GC-D14-S05`, wave `IW2-008`, commander
`AOE-GC-D14-CMD`, group owner `AOE-HQ-05` and independent validator `AOE-HQ-19`.
Blueprint: `sha256:8e08953c3b08ca3bbf9eafee8f429ff727ec444c8104d2bf11141d8d6f492ec9`.
This is partial A7.4 supplied-model evidence only. No package, phase gate,
original D016 candidate, live authority or qualification state is promoted.

## Exact closed model

The root has exactly `schema_version` (native integer 1), `nsgs`, `attachments`
and a nonempty `flows` array. The example below illustrates that shape.
`component_fixture()` returns fresh wholly synthetic input with the same inbound
predicate and an additional unresolved outbound service-tag rule and query.

```json
{
  "schema_version": 1,
  "nsgs": [{
    "nsg_id": "synthetic-nsg",
    "rules_complete": true,
    "rules": [{
      "rule_id": "inbound-tls",
      "priority": 100,
      "direction": "Inbound",
      "access": "Allow",
      "predicate": {
        "kind": "cidr_ports",
        "protocol": "TCP",
        "source_cidrs": ["10.0.0.0/24"],
        "destination_cidrs": ["10.0.1.0/24"],
        "source_ports": [[0, 65535]],
        "destination_ports": [[443, 443]]
      }
    }]
  }],
  "attachments": {
    "complete": true,
    "subnet_nsg_id": "synthetic-nsg",
    "nic_nsg_id": null
  },
  "flows": [{
    "flow_id": "synthetic-inbound",
    "direction": "Inbound",
    "protocol": "TCP",
    "source_ip": "10.0.0.7",
    "source_port": 49152,
    "destination_ip": "10.0.1.8",
    "destination_port": 443
  }]
}
```

The actual two-query fixture has literal report identity
`NSGA-6757B2E65C44905F4C8812CFC956D390` and source digest
`sha256:5b86106d482a0ab104104c983cc0554addc26651b8d1d34bd743d3249438cbad`.
Its inbound query is `allow_under_supplied_nsg_predicates`; its outbound query
is `unassessed`. These literal test observations are not real Azure evidence.

Each NSG has exactly `nsg_id`, `rules_complete`, `rules`. Rule IDs are unique
within the NSG; direction/priority pairs are unique. Priority is a native integer
100..4096 or one of the supported declared default priorities 65000, 65001,
65500. This does not identify a rule as an authentic Azure default.

Each rule has the five fields shown. A supported predicate has exactly the six
fields shown, with `kind: cidr_ports`, protocol `TCP`, `UDP` or `Any`, nonempty
unique CIDRs and nonempty unique inclusive `[low, high]` port pairs. Ports are
native integers 0..65535. Overlapping ranges are allowed; repeated exact ranges
are rejected. CIDRs must be canonical, strict network addresses. IP addresses
must be canonical and unscoped. A flow is one IPv4 or IPv6 tuple, never mixed.
Each CIDR dimension is OR; all four dimensions and protocol are AND.

The other exact predicate is
`{"kind":"unsupported","reason":"service_tag"}`. Reason is one of
`service_tag`, `application_security_group`, `unsupported_protocol` or
`other_predicate`. Its entire predicate is unassessed, not resolved from a name
or guessed from a packet. Direction, priority and declared access remain bound.
Unknown fields are rejected as outside this software model, not universally
invalid Azure resources. There is no ARM text, service tag or resource parser.

Both attachment IDs are native IDs or null and every nonnull ID must join a
supplied NSG. Null declares absence at that NSG attachment coordinate. The
separate `complete` bool declares whether the attachment projection covers the
intended two layers; false withholds all final conclusions. `rules_complete`
false withholds a definite result from that NSG, even if a supplied rule matches.
Neither completeness declaration is authenticated or independently verified.

## Mathematics and uncertainty

Primary references are Microsoft's
[NSG rules overview](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview)
and [NSG attachment processing](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-group-how-it-works).
Lower numerical priority is evaluated first. Source array order does not replace
priority. Rules in the other direction cannot match. Inbound records order the
subnet layer before NIC; outbound records order NIC before subnet. Same-subnet
traffic does not receive an invented NSG exemption.

For a complete declared NSG, the first matching supported predicate determines
that layer. An unsupported predicate in the relevant direction is potentially
matching, so it stops evaluation at its declared priority with `unassessed`.
A higher-priority supported match can finish before a later unsupported rule.
No supplied match remains unassessed: no catch-all, default rules or tag
membership is invented. A caller can supply an explicit supported catch-all or
retain unresolved default predicates at their actual declared priorities.

The two layer results form a declared conjunction. A known Deny in one complete
NSG can dominate uncertainty in the other layer, but the report retains that
other layer's uncertainty. This is only an NSG-predicate observation; security
admin rules or other excluded Azure behavior can change effective processing.
Allow requires every attached layer to Allow. Two absent attachments produce
`not_filtered_by_declared_nsgs`, not an actual network Allow. In particular,
standard public-IP secure defaults must not be inferred from this outcome.

Queries describe coordinates at the NSG layer, not verified pre/post-NAT traffic.
There is no return-packet inference, flow record or existing-connection state.
The output does not settle a stateful flow, enforce policy or authorize use.

## Source replay and finite costs

`analyze_supplied_azure_nsg(model)` and
`analyze_supplied_azure_nsg_bytes(*, model_bytes)` return an owned frozen
`AzureNsgAnalysis`. The latter accepts native ASCII JSON bytes, not a path.
`from_dict`, `from_json`, `to_dict`, `to_json` and identity properties fully
rederive from the detached embedded original model. The report retains that
supplied configuration and is not a sanitized publication artifact.
`verify_supplied_azure_nsg_analysis(report, *, model)` additionally compares
against separately supplied originals. A coherently changed source may describe
itself but cannot verify against the unchanged original.

`NSGA-` report and source addresses use distinct domains. They provide integrity
and content correlation, not provider identity, signatures, authenticated
currentness or a grant. Native type aliases, unknown fields, duplicate JSON
members, nonfinite/fractional numbers and forged wrapper storage fail through
`AzureNsgAnalysisError`. Ordinary JSON whitespace is accepted; source addressing
uses canonical native content, not the original JSON whitespace spelling.

Model/report byte ceilings are 1 MiB/2 MiB; node ceilings are 32,768/65,536.
Scalar-inclusive depth is 16, printable ASCII strings are limited to 512 bytes,
IDs to 128 and IP/CIDR strings to 64. Native integers must fit signed 64-bit
before decimal conversion, with narrower schema/priority/port checks. Limits
are 16 NSGs, 256 rules per NSG, 2,048 aggregate rules, 64 atoms per predicate
dimension and 128 flows. Source ordering is retained in the embedded model.

One operation has a cumulative 4,194,304-step work budget. Native nodes, escaped
bytes, structural punctuation, key ordering, owned copying, CIDR parsing, rule
ordering and predicate comparisons are charged. Raw lexical integer/escape/
string/node/depth bounds precede decoder allocation. Raw decoding conservatively
reserves 18 times text length plus twice its node count for allocation, native
validation and key ordering, in addition to the lexical scan and byte copy.
The cumulative work budget can therefore reject a document below its byte cap.

Rows are byte/node checked and charged before retention. Full final reports,
digest inputs, canonical encoding, equality scans and wrapper storage are funded
before the first digest. Produce, replay, equality and export share one budget
within each operation. Separate-original verification prepares and funds both
derivations before either is addressed. Each new public operation has its own
finite budget; there is no unlimited nested-budget reset or global lifetime
accounting. Budget refusals are software subset limits, not Azure invalidity.

## Exclusions and effects

No inventory acquisition, credentials, Azure SDK, requests, callbacks, sockets,
targets or processes exist in this leaf. NAT, routing, stateful return, existing
flows, service tags, ASGs, security-admin rules, provider-exempt traffic,
load-balancer behavior and authentic attachment/currentness are not evaluated.
Every effect is `none`; proof, approval and qualification flags are native false.
The result is neither full Azure parity nor an in-process malicious-code sandbox.
