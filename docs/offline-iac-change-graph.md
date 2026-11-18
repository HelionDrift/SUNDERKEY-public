# Supplied Infrastructure-as-Code Change Graph

The `AOE-GC-D17-S12` specialist now has one partial, inert change-dependency
projection. It accepts a small, operator-prepared model of resource addresses,
planned action sequences, declared dependency edges, and protected addresses.
For each protected address, it traces declared dependencies and identifies
any resource on that path with a supplied delete or replacement action. It
also reports missing nodes and declared dependency cycles as model-quality
uncertainty. It performs no Terraform, cloud, repository, provider, target, or
credential operation.

The accepted action sequences are the structural `actions` variants in the
[Terraform JSON output format](https://developer.hashicorp.com/terraform/internals/json-format):
`no-op`, `create`, `read`, `update`, `delete`, `delete` then `create`, and
`create` then `delete`. The model is not a parser for Terraform output. The
addresses and dependency graph are supplied assertions, and other
Infrastructure-as-Code systems may use the same reduced model only after an
operator maps their semantics explicitly.

## Input Boundary

The model has exactly these fields: `schema_version`, `source_id`,
`inventory_complete`, `resources`, and `protected`. Each resource has exactly
`address`, `actions`, and `depends_on`. Resource addresses are treated as
bounded opaque comparison keys. The model accepts no configuration attributes,
before or after values, state, outputs, tokens, provider responses, or raw
plans. Unknown fields fail closed. Identifiers can still reveal infrastructure
names, so an operator must review and minimize them before submission.

Do not pass `terraform show -json` output directly. HashiCorp warns that
[`terraform show -json` can display sensitive state values in plain text](https://developer.hashicorp.com/terraform/cli/commands/show).
The reduction must occur in an appropriately controlled environment. This
component does not perform or verify that reduction and does not certify that
an operator-prepared model is free of sensitive identifiers.

```json
{
  "schema_version": 1,
  "source_id": "synthetic-iac-change-graph",
  "inventory_complete": true,
  "resources": [
    {"address": "aws_security_group.edge", "actions": ["delete", "create"], "depends_on": []},
    {"address": "aws_instance.web", "actions": ["no-op"], "depends_on": ["aws_security_group.edge"]}
  ],
  "protected": ["aws_instance.web"]
}
```

## Interpretation

The synthetic example yields a candidate declared destructive path from
`aws_instance.web` to `aws_security_group.edge`. It does not prove that the
provider will delete the group, that the instance will be disrupted, or that
either resource is exposed or exploitable. If the inventory is incomplete,
protected nodes are missing, or dependency rows are inconsistent, the report
preserves `unknown` or explicit model-quality issues. An absence of declared
destructive paths never establishes safety.

The report binds the exact supplied model digest and is independently
replayed from the original model. It is unsigned, nonqualifying, and cannot
publish a finding or authorize use. No candidate is assembled, routed, or
admitted to live execution. Real plan extraction, secret custody, provider
observation, impact validation, independent review, and qualification remain
separate work.
