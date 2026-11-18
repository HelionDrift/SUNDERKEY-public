# Supplied single-zone DNS lookup analysis

This partial component evaluates a caller-supplied name-tree projection. It
does not send DNS requests, load a resolver, inspect a target, or acquire a
zone. Its conclusions describe only the supplied data and its declared
completeness, not authenticated DNS answers or operational findings.

## Ownership and sequencing

The existing owner is `AOE-GA-D01-S03`, capability `army.ga.d01.s03`, vector
`AV-GA-D01-S03-01`, package `IWP2-AOE-GA-D01-S03`, wave `IW2-003`, commander
`AOE-GA-D01-CMD`, group owner `AOE-HQ-03`, and independent validator
`AOE-HQ-19`. Its blueprint is
`sha256:d242f5ad785667eda0f2669fef8f3e92f75e473fb39ac939fdc8aedd324f6dae`.
The component identifier is `dns_supplied_zone_lookup`.

D016 revision 2 permits this inert implementation and synthetic tests before
real-host containment validation. This is partial evidence for `A7.4`, not a
completed specialist, attack-world-model integration, qualified profile or
live DNS adapter. The original six reference candidates, D016 source record,
six development gates and every live-use prerequisite remain unchanged.

## Closed supplied model

The APIs are `analyze_supplied_dns_zone(model)`,
`analyze_supplied_dns_zone_bytes(model_bytes=...)`, and
`verify_supplied_dns_zone_analysis(report, model=...)`. The latter two arguments
are keyword-only. They return a detached `DnsZoneAnalysis`; invalid input
raises `DnsZoneAnalysisError`.

The exact top-level fields are:

```json
{
  "schema_version": 1,
  "semantics_profile": "single-declared-zone-lookup-v1",
  "zone": {
    "apex": "example.test.",
    "complete": true,
    "rrsets": [
      {"owner": "api.example.test.", "rrtype": "A", "rdata": ["192.0.2.10"]},
      {"owner": "alias.example.test.", "rrtype": "CNAME", "rdata": ["api.example.test."]}
    ],
    "ordinary_data_owners": [
      {"owner": "example.test.", "rrtypes": ["SOA", "NS"]}
    ],
    "delegations": []
  },
  "queries": [
    {"query_id": "query:alias", "qname": "alias.example.test.", "qtype": "A"}
  ]
}
```

Every field is required. RRsets support only A, AAAA and CNAME. Addresses must
have the correct family and canonical spelling. A CNAME has exactly one
literal absolute target and cannot coexist with other modeled or declared
ordinary data at its owner. Apex CNAME is unsupported in this single-zone
profile, not accepted as a valid alias zone.

An ordinary-data owner declares actual, unmodeled TXT, MX, SRV, PTR, CAA, SOA
or NS data. Its nonempty unique `rrtypes` list is not an arbitrary empty-node
insertion mechanism. SOA/NS declarations are apex-only, and their RDATA is
not validated. Neither those declarations nor the apex role prove that a
real valid zone exists. Empty non-terminals are derived only from descendants.

Delegations contain exactly `owner` and a nonempty unique `nameservers` list.
Cut owners are nonwildcard strict descendants of the apex; overlapping cuts
are outside this one-zone projection. Nameserver values are literal supplied
names, not proof that those servers exist or are reachable. A/AAAA rows at
and below a cut remain in the source and are listed as ignored observations.
They are never this zone's answers, even if they look like glue.

Names are absolute lowercase ASCII with whole LDH/underscore labels or a
whole `*` label. Asterisk labels within query names and CNAME targets are
literal labels, not input patterns. The narrower supported text ceiling is
253 bytes, with at most 32 labels of at most 63 bytes. The independent DNS
wire-length check sums every label length octet, label contents and terminal
zero against 255 octets. The textual ceiling is this software subset, not a
claim about every legal binary DNS name.

## Mathematical semantics

Lookup processes cuts before data or wildcard synthesis. Exact names and
empty non-terminals suppress fallback. For a missing name, only the wildcard
immediately below its closest existing ancestor can supply data. A missing
candidate does not cause a search for a higher wildcard. A wildcard may itself
be an empty non-terminal, producing no requested data rather than fallback.
See [RFC4592 existence and synthesis](https://www.rfc-editor.org/rfc/rfc4592.html#section-3.3.1).

Exact and synthesized CNAMEs retain the literal target. A CNAME question
returns the declared CNAME without following it. Other supported questions
follow the alias inside the supplied zone, preserving query owner, source
index and synthesis provenance. Delegation, off-zone targets, known loops and
the alias traversal ceiling cannot produce resolved addresses. See
[RFC1034 lookup](https://www.rfc-editor.org/rfc/rfc1034.html#section-4.3.2) and
[RFC2181 CNAME and zone-cut rules](https://www.rfc-editor.org/rfc/rfc2181.html#section-10.1).

`complete=false` globally withholds final query conclusions. Labeled supplied
records and ignored-cut indexes remain inspectable, but even a supplied
address is not promoted into a final lookup answer. `complete=true` permits
only conditional conclusions in that declared projection; it does not prove
actual completeness. A missing alias target is attributed to the terminal
name, not mistaken for absence of the original alias. Negative outcomes are
not wire RCODEs or authoritative NXDOMAIN.

## Costs and integrity

Per native document, source and report ceilings are 1 MiB, 32,768 visited
nodes, depth 16 including scalars, and 512 printable ASCII bytes per string.
The source supports 1,024 RRsets, 1,024 ordinary-data owners, 128 delegations,
16 values per RRset or delegation and 64 queries. Derived costs are capped
at 16,384 trie nodes, 32 alias transitions per query and 262,144 work steps.

Exact native types are validated before copying or hashing. Booleans cannot
replace integers, floats and subclasses are denied, and shared subtrees are
charged repeatedly. Cycles, large integers and strings fail before expensive
conversion. Raw JSON depth, node, decoded-string, escape and integer-token
costs are checked before the JSON decoder. Duplicate members are rejected.
Tree nodes are charged before creation; traces and cumulative report costs
are charged before retention or hashing. Work/tree/report exhaustion produces
no public result and no automatic retry. The alias ceiling instead retains a
bounded, explicitly incomplete trace. Cost ceilings apply per reconstruction,
not as a global service quota.

Report construction, parsing and every wrapper read reconstruct the complete
result from its captured source. Domain-separated addresses identify content,
not signatures. The separate verifier also re-derives from the supplied
original model, denying a valid report for a different source. Mutable input
and returned dictionaries are detached. These checks do not isolate malicious
code in the same interpreter, authenticate source acquisition or prove clocks
or currentness.

## Exclusions and tests

There is no zonefile or DNS wire parser, recursive resolver, cache or TTL
freshness, DNSSEC, DNAME, wildcard NS, dynamic update, provider-specific alias
synthesis, registrar check, hostname authorization or takeover proof. Every
authority, target, execution, routing, qualification, deployment, network,
provider, credential, process and DNS effect is `none`. All authentication,
real completeness, live resolution, target-existence and qualification flags
are false.

The independent test oracle uses suffix/ancestor sets, not the implementation
trie. Small exhaustive trees, alias graphs and delegation boundaries compare
lookup outcomes and terminal names. Hostile intake, source substitutions,
coherently rehashed false conclusions, native aliases, literal goldens,
detachment and pre-decoder/pre-hash ceilings are separate controls. Synthetic
results do not satisfy live containment or independent qualification.
