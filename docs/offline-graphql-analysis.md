# Offline GraphQL structural analysis

`sunderkey.offline_graphql_analysis` implements a finite, passive structural
algorithm for the GraphQL lane `AOE-GB-D06-S02`, capability `army.gb.d06.s02`,
and vector `AV-GB-D06-S02-01`. It analyzes supplied native bytes without reading
files, querying an endpoint, invoking a callback or executing an operation.
This is a partial offline specialist implementation, not full specialist
completion, a production adapter, accepted provider evidence or qualification.

## Inputs and API

The local schema is an unsigned SUNDERKEY output-type projection, not SDL or a
raw introspection response. Its exact JSON shape is:

```json
{
  "query_type": "Query",
  "types": [
    {
      "name": "Query",
      "kind": "OBJECT",
      "fields": [{"name": "users", "type": "[User!]!"}]
    },
    {
      "name": "User",
      "kind": "OBJECT",
      "fields": [{"name": "id", "type": "ID!"}]
    },
    {"name": "ID", "kind": "SCALAR", "fields": []}
  ]
}
```

`OBJECT` has declared fields; `SCALAR` and `ENUM` have empty field lists. Type
and field names are unique, referenced named types must exist, and the root
must be an object. Nested list and non-null output type wrappers are supported.
The projection intentionally omits arguments, enum values, resolvers, input
types and authorization facts. A successful result cannot establish required
argument compliance or full GraphQL schema or operation validity.

```python
from sunderkey.offline_graphql_analysis import (
    GraphQLAnalysisLimits,
    analyze_graphql_operation,
    verify_graphql_operation_analysis,
)

limits = GraphQLAnalysisLimits(
    max_schema_bytes=65536,
    max_query_bytes=65536,
    max_depth=32,
    max_tokens=10000,
    max_nodes=10000,
    max_expanded_selections=1000000,
)
report = analyze_graphql_operation(
    schema_content=supplied_schema_bytes,
    query_content=b"query Example { users { id } }",
    schema_source_id="schema:local-v1",
    query_source_id="query:example-v1",
    operation_name="Example",
    limits=limits,
)
replayed = verify_graphql_operation_analysis(
    report,
    schema_content=supplied_schema_bytes,
    query_content=b"query Example { users { id } }",
    schema_source_id="schema:local-v1",
    query_source_id="query:example-v1",
    operation_name="Example",
    limits=limits,
)
```

All analysis source/configuration inputs are keyword-only. The verifier's first
argument is the exact `GraphQLAnalysisReport` family. `operation_name=None`
requires exactly one query operation; a named selection must exist. Every
operation and fragment definition is checked, including nonselected operations.
Native bytes, native source/name strings and an exact native limits object are
required. At-use validation rejects aliases and incomplete or altered wrappers.

## Closed query subset

The supported subset contains shorthand or named queries, field aliases,
nested object fields and named fragments with an exact matching object type
condition. Comments, whitespace, insignificant commas and BOM are ignored.
Names are ASCII, at most 128 characters and cannot begin with `__` in this
subset. Duplicate definitions, undefined fields or fragments, object fields
without selections and leaf fields with selections are rejected.

Mutations, subscriptions, arguments, variables, directives, descriptions,
inline fragments, introspection meta fields, abstract type conditions and schema
definitions are unsupported and fail closed. Differing shapes under a repeated
response key are also rejected conservatively. In particular, some operations
that GraphQL can merge legitimately are outside this subset.

The grammar and checks were reviewed against the primary
[GraphQL September 2025 specification](https://spec.graphql.org/September2025/),
particularly [leaf field selections](https://spec.graphql.org/September2025/#sec-Leaf-Field-Selections),
[fragment cycles](https://spec.graphql.org/September2025/#sec-Fragment-Spreads-Must-Not-Form-Cycles)
and [field selection merging](https://spec.graphql.org/September2025/#sec-Field-Selection-Merging).
GraphQL collects fields by response key; this analyzer instead measures expanded
syntactic occurrences. Its counts are not merged resolver invocation counts.

## Algorithm, limits and output

All fragment definitions form one dependency graph. Undefined targets and
cycles are rejected before unused-fragment checks, including cycles unreachable
from the selected operation. Fragments must be used by some operation in the
document. A deterministic topological order memoizes each fragment's bounded
summary. Repeated spreads and aliases retain their multiplicity without
materializing the expanded selection tree or enumerating every path.

Metrics include expanded field, alias and spread occurrences, field-path depth,
list-type layers along a path and maximum sibling field occurrences. The
selected AST field count excludes fields defined in fragments. Equal maxima
choose a lexically deterministic field/alias witness. No list cardinality,
resolver behavior, execution cost, vulnerability severity or denial-of-service
conclusion is inferred from these structural counts.

The six explicit limits have no defaults. Upper ceilings are 1 MiB per source,
depth 64, 50,000 tokens, 50,000 nodes/work units and 1,000,000 expanded
occurrences. `max_nodes` applies separately to the decoded schema's native JSON
nodes, query AST nodes and deterministic analysis work, not their combined sum.
`max_depth` separately bounds JSON/type/selection/dependency and expanded paths.
Report documents additionally have a 1 MiB, depth-64, 50,000-node native JSON
budget; strings are ASCII and at most 8,192 characters, and integer magnitude
cannot exceed `2**63 - 1`. Repeated shared subtrees and escaped strings are
charged before serialization. Duplicate JSON keys, floats and nonfinite numbers
are rejected. These are local software-cost bounds, not target budgets.

Reports bind exact source identifiers, raw-byte SHA-256 values and lengths,
operation selection and all limits. They use schema version 1, the
`sunderkey.offline-graphql-analysis.v1` domain and a content-addressed `GQA-`
identity. `to_dict()` returns detached metadata and `to_json()` canonical JSON.
The document contains source correlations, selected names, counts and witness
labels, not the raw source bodies or generated queries.

`GraphQLAnalysisReport.from_dict/from_json` verify bounded unsigned metadata
shape and content integrity. A coherently readdressed count can still be parsed:
only `verify_graphql_operation_analysis` reproduces the complete report from
the supplied exact sources and configuration. Schema/query permutations can
retain metrics but change the raw source digest and report identity. The
verifier returns a detached existing report, not a new authority receipt.

All effects are `none`; `offline_only` is true and positive use, qualification
and server-cost claims are false. Source identifiers and hashes do not establish
authenticity, consent, currentness, real schema deployment or provider custody.
There is no clock, transport, secret resolution, mutation, subscription,
automatic retry or operational dispatch. The implementation does not sandbox
arbitrary Python code or concurrent caller mutation. Catalog integration must
remain additive and must not turn this result into six-reference completion,
live acceptance, routing permission or qualification.
