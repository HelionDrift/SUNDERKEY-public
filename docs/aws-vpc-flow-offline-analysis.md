# Supplied same-VPC flow predicate analysis

`sunderkey.aws_vpc_flow_analysis` evaluates supplied security-group and network
ACL declarations over explicit TCP or UDP packet tuples. It does not contact
AWS, query a route or connection table, acquire credentials, send packets,
change policies, install software or call an injected provider or process.

## Existing ownership and partial scope

Component `aws_supplied_vpc_flow_predicates` belongs to profile
`AOE-GC-D14-S03`, capability `army.gc.d14.s03`, vector `AV-GC-D14-S03-01`,
package `IWP2-AOE-GC-D14-S03` and wave `IW2-006`. The commander is
`AOE-GC-D14-CMD`, group commander `AOE-HQ-05`, independent validator
`AOE-HQ-19`, and blueprint digest is
`sha256:8c5b708f933616e92a8f22e5b46063b8299db660fac1f31b4aa92df983bf9a23`.

This is partial offline evidence under the D016 sequencing amendment. It
does not satisfy containment, live entry, routing, deployment or qualification
gates and does not replace an original reference SDK, AWS IAM policy analysis,
SCP analysis or the provider-neutral privilege graph.

## Exact model and interfaces

```python
analyze_supplied_aws_vpc_flow(model) -> AwsVpcFlowAnalysis
analyze_supplied_aws_vpc_flow_bytes(*, model_bytes) -> AwsVpcFlowAnalysis
verify_supplied_aws_vpc_flow_analysis(report, *, model) -> AwsVpcFlowAnalysis
```

The root has exactly `schema_version` (native integer 1), `vpc`, `subnets`,
`endpoints`, `security_groups`, `network_acls` and `flows`. All nested fields
below are mandatory. Missing completeness declarations never gain defaults.

| Projection | Exact fields |
| --- | --- |
| VPC | `vpc_id`, `cidr` |
| Subnet | `subnet_id`, `cidr`, `network_acl_id` |
| Endpoint | `endpoint_id`, `eni_id`, `subnet_id`, `address`, `security_group_ids`, `security_groups_complete` |
| Security group | `security_group_id`, `ingress_complete`, `egress_complete`, `ingress`, `egress` |
| Network ACL | `network_acl_id`, `ingress_complete`, `egress_complete`, `ingress`, `egress` |
| SG rule | `rule_id`, `protocol`, `cidr`, `from_port`, `to_port` |
| ACL rule | `rule_number`, `action`, `protocol`, `cidr`, `from_port`, `to_port` |
| Flow | `flow_id`, `source_endpoint_id`, `destination_endpoint_id`, `protocol`, `source_port`, `destination_port`, `traffic_class`, `return_mode` |

This software profile has one explicit VPC CIDR and one address family, either
IPv4 or IPv6. Subnets must be contained in that CIDR and distinct subnets must
not overlap. Each represented ENI has one address, which must be within its
explicit subnet. IDs, addresses, SG membership, ACL associations and every
flow endpoint must join exactly. Duplicate identities or rule numbers reject.
Endpoint SG references are nonempty, unique and explicit. These restrictions
are a sanitized software subset, not a general AWS response parser, resource
existence check, API admission validator or complete multi-CIDR snapshot.

CIDRs and addresses require canonical spelling. Host bits, scoped IPv6,
mixed address families, named ports, SG references, prefix lists, unsupported
protocols and unknown fields reject. API-side CIDR normalization is not
silently reproduced. Rule CIDRs need not be contained in the VPC CIDR.
[AWS ACL rule fields and CIDR normalization](https://docs.aws.amazon.com/vpc/latest/userguide/nacl-rules.html)

Flow protocol is `TCP` or `UDP`. Rules support these protocols and `ALL`.
TCP/UDP rules have inclusive native integer port bounds from 0 through 65535;
`ALL` requires both bounds to be null. Packet ports are explicit native
integers in the same range. No ephemeral port, application, service or
actual packet validity is inferred from a port number.

## SG and ACL predicates

SG rules are allow-only. The selected groups combine additively. A known
matching rule is sufficient for a declared directional allow, even when
additional additive membership or rules are marked incomplete. With no
matching rule, a directional block requires complete supplied membership
and complete relevant rules for every selected group; otherwise it is unknown.
An empty complete direction has no allow. No default SG or initial outbound
rule is invented. Ingress CIDRs match source addresses; egress CIDRs match
destination addresses, and port ranges match the packet's destination port.
[AWS SG rules](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)

NACL entries use native rule numbers 1 through 32766 and actions `allow` or
`deny`. Within each direction, the lowest-numbered matching entry wins.
Its original source-array index is retained as a witness. A complete list
with no match derives the terminal default denial without inventing an
explicit source rule. An incomplete list stays unknown even with a supplied
matching entry: an omitted earlier entry could supersede it. ACLs are
stateless, so the reverse packet requires its own CIDR and port checks.
Source egress and destination ingress ACL gates both apply across subnets.
[AWS NACL semantics](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html)

When both endpoints have the same explicit subnet identity, ACL filtering is
not applied. The neutral gate records `not_applied_same_subnet`; SG predicates
still apply. Two distinct subnets associated with the same ACL do not receive
this exemption. This is a predicate for the declared direct path, not proof
of route-table contents or a path that bypasses a middlebox.
[AWS subnet filtering boundary](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html)

## Forward and reverse are distinct declarations

Forward reasoning combines source SG egress, destination SG ingress, source
ACL egress and destination ACL ingress. A known blocking gate dominates
unknown gates in this conjunction; unknown information remains visible.
The reverse tuple swaps endpoint identities and both supplied ports. In
particular, its destination port is the original explicit source port.

`return_mode` is exactly one of these values:

- `assumed_tracked_response`: reverse SG allowance is conditional on the
  caller's tracked-response premise and a permitted forward policy model.
  Reverse ACL predicates still apply. A denied or unknown forward model
  leaves the entire assumed response unassessed, not fabricated as established.
- `independent_reverse_packet`: reverse SG and ACL rules are evaluated as a
  separate packet, even if the forward packet is blocked. This is not evidence
  of a response or an established connection.
- `unknown`: reverse reasoning remains unassessed.

A conditional result never establishes actual connection state. AWS has
untracked-flow exceptions, timeouts and finite tracking allowances. The code
does not inspect any of them or infer a successful connection from rules.
[AWS connection tracking](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-connection-tracking.html)

## Exemptions and uncertainty

`traffic_class` is exactly `ordinary_eni_to_eni`, `provider_exempt` or `unknown`.
The latter two classes leave both directions unassessed before gate reasoning,
never incorrectly denied through ordinary ENI predicates. Classification is
an unverified caller declaration, not a provider-attested fact.

Reserved or special addresses also make a referenced endpoint unassessed.
The conservative profile excludes unspecified, multicast, loopback,
link-local, Python-classified reserved and IPv4-mapped IPv6 addresses; the
first four and final addresses of a subnet; and the familiar IPv6 EC2 service
coordinates `fd00:ec2::123`, `fd00:ec2::253` and `fd00:ec2::254`. This does not
assert allocation or comprehensively detect all provider services. BYOIP and
provider endpoint allocation remain outside this profile. Same-endpoint
traffic is also unassessed rather than guessed to be blocked.
[AWS subnet reserved addresses and BYOIP distinction](https://docs.aws.amazon.com/vpc/latest/userguide/subnet-sizing.html)
The IPv6 service coordinates were checked against the provider's
[DNS documentation](https://docs.aws.amazon.com/vpc/latest/userguide/AmazonDNS-concepts.html),
[IMDS documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
and [Time Sync documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configure-ec2-ntp.html).

DNS, DHCP, EC2/ECS metadata, Windows license activation, Time Sync and reserved
router traffic can be exempt from these filters. No provider-service bypass
is turned into a general ordinary-flow allow. Unknown classifications must
be supplied as such, not disguised as complete ENI topology. NAT, gateways,
load balancers, SG references, prefix lists, cross-VPC routing, middleboxes,
OS firewalls, actual conntrack and runtime reachability are not evaluated.
[AWS SG filter exceptions](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html)

## Ownership, replay and finite costs

`AwsVpcFlowAnalysis` owns detached canonical metadata and has `to_dict`,
`to_json`, `from_dict` and `from_json`. The complete source model, policy
digests, packet tuples, witnesses, predicates, limits and limitations replay
exactly. Coherently readdressed false results reject. A genuinely recomputed
record for changed sources is still unsigned metadata for a different model;
the separate original-model verifier rejects that substitution. Object order
and whitespace are not raw-wire provenance. Source arrays remain bound.

Limits are 1 MiB per model/report, depth 16, 32768 visited nodes, 512 printable
ASCII bytes per string and signed63 native integer magnitude; 32 subnets,
64 endpoints, 64 SGs, 32 ACLs, 64 flows, 16 group references per endpoint,
64 rules per direction, 2048 total rules, 1000000 matching work units and
1024 witnesses. Limits compose and reject rather than truncate. CIDRs are
parsed once; address spaces, port ranges and possible endpoint pairs are
never enumerated. Rule and gate visits are charged before matching, and
witnesses before publication. These units are not a CPU or wall-clock budget.

Native capture charges punctuation, escaping and repeated subtrees before
copying or hashing. Raw bytes are bounded before ASCII decoding; raw JSON
depth, node, string, integer and escape costs precede JSON decoding. Duplicate
keys, subclasses, cycles, unknown fields, scalar aliases, oversized integers,
floats and nonfinite values reject. The full report, with fixed-width address
placeholders, is charged before its hashes. Public construction and exports
can repeat the bounded derivation to validate the record.

All authenticity, completeness, route, conntrack, provider-exemption,
reachability, live-use and qualification flags remain false. Every authority,
target, execution, routing, qualification, deployment, network, provider,
credential and process effect is `none`. The code does not authenticate
sources, provide current authority, prove effective cloud denial, sandbox
arbitrary same-process code, defend concurrent caller mutation or detect
valid replacements made before entry. Reports retain supplied inert metadata;
they are not a secret-redaction interface.
