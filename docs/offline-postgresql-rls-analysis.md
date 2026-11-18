# Supplied PostgreSQL SELECT and RLS analysis

This partial offline algorithm belongs to AOE-GB-D07-S14, capability
army.gb.d07.s14, vector AV-GB-D07-S14-01, package IWP2-AOE-GB-D07-S14 and
wave IW2-014. Its commander is AOE-GB-D07-CMD, group commander AOE-HQ-04
and independent validator AOE-HQ-34. Relational-database profile S01 remains
a collaborator, not a newly assembled or promoted candidate.

The analyzer evaluates finite supplied ordinary-table SELECT-grant and RLS
declarations. It does not parse, generate or execute SQL, open a database,
discover roles, read files, use credentials, invoke callbacks or contact a
target. It is independent of the existing PostgreSQL persistence adapter and
executable schema description. It neither installs RLS nor qualifies them.

## API and exact source model

```python
report = analyze_supplied_postgresql_rls(model)
owned = verify_supplied_postgresql_rls_analysis(report, model=model)
model = parse_supplied_postgresql_rls_model(supplied_json_bytes)
```

The exact report family is `SuppliedPostgreSQLRlsAnalysis`; controlled failures
use `PostgreSQLRlsAnalysisError`. The verifier's `model` argument is keyword-only.
The pure bytes parser requires native nonempty ASCII UTF-8 `bytes`, validates
the source structure and returns a detached model without hashing or execution.
No path loader or acquisition port exists.

The root contains exactly:

```python
{
    "schema_version": 1,
    "semantics_profile": "postgresql-18-select-rls-subset-v1",
    "roles": [{"name": "alice", "superuser": False, "bypass_rls": False}],
    "memberships": [],
    "role_membership_complete": True,
    "table": {
        "table_ref": "table:synthetic",
        "relation_kind": "ordinary_table",
        "owner_role": "alice",
        "rls_enabled": True,
        "force_rls": False,
        "policy_inventory_complete": True,
        "select_grantees": [{"kind": "public"}],
        "select_grants_complete": True,
        "columns": {"value": "int8"},
        "policies": [],
    },
    "contexts": [{"context_id": "context:alice", "current_role": "alice",
                  "row_security_on": True}],
    "rows": [{"row_id": "one", "values": {"value": 1}}],
    "queries": [{"query_id": "q:one", "context_id": "context:alice", "row_id": "one"}],
}
```

Role and column names use exact ASCII identifiers
`[A-Za-z_][A-Za-z0-9_]{0,62}`. References use 1 through 128 ASCII letters,
digits, underscore, dot, colon or hyphen. No SQL quoting, case folding or name
resolution occurs. A name is an explicit symbol in this supplied projection.

Memberships contain exactly `member_role`, `granted_role` and native boolean
`inherit`. Every referenced role must exist. Duplicate definitions/edges,
self-membership and cycles reject, including cycles with noninherited edges.
Contexts name a supplied current role, not a login or authenticated principal.
Rows have exactly every declared column. A missing value is unavailable input
and rejects; it is never substituted with SQL NULL. Explicit native `None`
is a known SQL NULL in any declared column.

SELECT grantees and policy `to_roles` use either `{"kind": "public"}` or
`{"kind": "role", "name": "reader"}`. Empty SELECT grantees mean no declared
ordinary table SELECT grant. Policy `to_roles` must be nonempty; an explicit
PUBLIC selector, not absence or spelling inference, models the default role.
Only ordinary full-table SELECT grants are projected. Column-only privileges,
schema privileges and other access mechanisms are outside this subset and
must not be presented as complete coverage of its explicit grant projection.

Each policy contains exactly `policy_id`, `command`, `mode`, `to_roles` and
`using`. Commands are `ALL`, `SELECT`, `INSERT`, `UPDATE` and `DELETE`; only
ALL and SELECT participate in this plain SELECT analysis. Modes are explicitly
PERMISSIVE or RESTRICTIVE. Native null `using` represents an absent USING
clause and its implicit true predicate. `{"op": "bool", "value": None}`
is instead an explicitly known SQL NULL predicate. INSERT cannot declare a
USING expression. WITH CHECK or any DML operation is not evaluated.

## Finite predicate AST

Boolean expressions are:

- `{"op": "bool", "value": True | False | None}`;
- `{"op": "and" | "or", "args": [expression, expression, ...]}`;
- `{"op": "not", "arg": expression}`;
- `{"op": "eq" | "ne" | "lt" | "le" | "gt" | "ge", "left": operand, "right": operand}`;
- `{"op": "is_null" | "is_not_null", "arg": operand}`.

Operands are exactly a declared `{"kind": "column", "name": ...}`, an
explicit `{"kind": "literal", "type": ..., "value": ...}` or
`{"kind": "current_user"}`. CURRENT_USER returns the supplied current-role
name. Types are boolean, int8 and text_c. Integers support the complete signed
int8 interval -9,223,372,036,854,775,808 through 9,223,372,036,854,775,807.
Text uses bounded printable ASCII and exact C-style equality; ordered
comparisons are supported only for int8. Comparisons require equal declared
types. No implicit cast, numeric boolean coercion, locale-dependent comparison
or user-defined operator is interpreted.

`{"op": "unsupported", "feature": ...}` explicitly records an unavailable
function, subquery, cast, collation or other predicate semantic. Such a node
anywhere withholds every query conclusion, including in a non-SELECT policy.
It is not a SQL parser that detects undisclosed features. Missing coverage
(`role_membership_complete`, `select_grants_complete` or
`policy_inventory_complete` false) also conservatively withholds all query
conclusions. Malformed closed shapes reject instead of becoming negative results.

## Grants and row filtering are different gates

Role inheritance is derived by bounded graph traversal through inherit=true
edges only and cached once per current role. The current role itself belongs
to its closure. SUPERUSER and BYPASSRLS attributes come only from the current
role; neither is inherited through a grant. Owner privileges may be inherited.

A supplied SELECT grant to PUBLIC or an effective role, or the current role's
own superuser attribute, satisfies the separate supplied SELECT gate. Ownership
and BYPASSRLS do not manufacture SELECT: an owner can revoke their ordinary
privileges. [PostgreSQL privilege rules](https://www.postgresql.org/docs/18/ddl-priv.html)

For the row-security gate, disabled RLS ignores policies. An own superuser or
BYPASSRLS role bypasses RLS even under FORCE. Owner privileges bypass only when
FORCE is false. Otherwise applicable RLS with `row_security_on=False` reports
a declared error, not unrestricted visibility. There is no RI/no-force
context, view, SET ROLE, SELECT FOR UPDATE/SHARE or extension interpretation.
[Row security](https://www.postgresql.org/docs/18/ddl-rowsecurity.html),
[row_security setting](https://www.postgresql.org/docs/18/runtime-config-client.html#GUC-ROW-SECURITY)

Applicable SELECT/ALL policies match PUBLIC or the derived role closure.
Permissive predicates are OR-combined, restrictive predicates AND-combined,
then those two results are AND-combined. No applicable permissive policy is
default deny; restrictive policies cannot grant access on their own. Only true
passes a row. False and known SQL NULL do not. Witness values preserve
`true`, `false` and `sql_null` distinctly.
[CREATE POLICY](https://www.postgresql.org/docs/18/sql-createpolicy.html),
[SQL logical operators](https://www.postgresql.org/docs/18/functions-logical.html),
[comparison and NULL rules](https://www.postgresql.org/docs/18/functions-comparison.html)

The result separately records SELECT witnesses and row filtering even when the
SELECT gate does not pass. It does not claim engine error ordering or return
actual query results. Supplied membership, ownership, grants, attributes,
coverage and row contents are declarations, not acquired or authenticated facts.
[Role membership](https://www.postgresql.org/docs/18/role-membership.html)

## Source identity and unsigned replay

The report embeds the complete detached source model. Canonical native object
key order and JSON formatting do not change identity; array order and every
supplied value remain source-bound. `context_results` records cached derived
closures and noninherited flags. `query_results` records exact original query
references, separate SELECT evidence, row-filter mode, predicate witnesses and
bounded outcomes. There is no unsupported-to-allowed fallback.

The `PRL-` identity and analysis SHA address the whole report under
`sunderkey.postgresql-supplied-select-rls.v1`; its source SHA uses the separate
model domain. Public `to_dict`, `to_json`, constructor and from_dict/from_json/
from_bytes exports reconstruct all embedded-source results. Direct construction
requires exact canonical JSON; JSON/bytes parsers may normalize presentation.
Rehashing a false outcome, closure, witness, bound, flag or source digest cannot
replace reconstruction. A coherently different valid source can produce a
different valid unsigned report; separately original-model verification rejects
that substitution.

Input/output documents are detached and exact wrapper families revalidated.
This is not protection against arbitrary code in the process or an atomic
capture guarantee against concurrent caller mutation. No hash or replay proves
identity, consent, snapshot completeness, effective authorization, vulnerability,
live server behavior, readiness or qualification. All proof/positive-use flags
remain false and all declared operational effects remain none.

## Software-cost bounds and synthetic tests

Each model/report has its own 1 MiB canonical escaped-byte budget, native/raw
depth 32, 32,768 nodes and 512 printable ASCII characters per string. Native
queued nodes, repeated shared subtrees, quote/backslash escaping and signed
integer magnitudes are checked before copies/serialization/new hashes. Raw
bytes are byte-, node-, every-node-depth-, decoded-string-, escaped-byte- and
integer-grammar-bounded before JSON decoding. Duplicate keys, floats, nonfinite
numbers, subclasses, tuple/mapping replacements and boolean integer aliases
reject. These are local software-cost limits, never database authority.

Other independent ceilings are 64 roles, 256 membership edges, 32 columns,
128 policies, 32 contexts, 256 rows and 512 query rows. Predicate nodes,
including operands, total at most 4,096; AST depth is at most 12 and AND/OR
arguments number 2 through 32. One reconstruction permits at most one million
charged graph, selector and predicate visits/comparisons. This metric is not
CPU time or every Python instruction. Native source/output traversal is
separately capped. Graph closures and compiled predicates are cached per
reconstruction. Derived rows are budgeted once as retained, not by repeatedly
serializing all previous rows. The complete source/context output is reserved
first; each result's nodes and escaped bytes, separator and work-counter width
are charged before retaining that result. Complete output is bounded before addresses.
The ceilings are independent, not permission to allocate their Cartesian product.

The test `component_fixture()` supplies alice->reader inheritance, an explicit
reader SELECT grant, an owner-row permissive predicate, an active-row
restrictive predicate and three inert rows. The first passes both gates, the
foreign owner and explicit NULL active rows are filtered. Fixtures use only
synthetic metadata and contain no SQL engine, database, credentials or live data.
Independent controls cover three-valued policy composition, noninherited
attributes, owner without SELECT, full int8, NULL versus absent USING,
an independent small inheritance-graph oracle, malformed/cyclic graphs, exact
output-cost boundaries, detached output and source falsification. A fixed
literal fixture control preserves PRL-289CEA05ECF972F68D012DE260DD6540 and
its 5,469 canonical bytes; this identity is not signed database evidence.
