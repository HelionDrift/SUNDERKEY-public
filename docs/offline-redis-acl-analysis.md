# Supplied Redis ACL key-selector analysis

This component computes a finite command/key permission projection from a
caller-supplied, normalized Redis 7.2.5 ACL model. It is not a Redis client,
SETUSER interpreter, authenticated ACL export, connection admission check or
effective-access decision. No command is dispatched and no key value is read.

The partial algorithm component belongs to `AOE-GB-D07-S05`, capability
`army.gb.d07.s05`, vector `AV-GB-D07-S05-01`, work package
`IWP2-AOE-GB-D07-S05`, wave `IW2-005` and roadmap package `C4.8`. Its commander
is `AOE-GB-D07-CMD`, group commander is `AOE-HQ-04` and independent validator
is `AOE-HQ-34`. Blueprint binding:
`sha256:300f14cfa8939b3b80c939327fbddacc04740723275f1504223f5996c58134a7`.
These identifiers do not qualify, route or deploy the specialist.

## Public interface and supplied model

`src/sunderkey/offline_redis_acl_analysis.py` exposes:

- `analyze_supplied_redis_acl(model)` for an exact native JSON object.
- `analyze_supplied_redis_acl_bytes(*, model_json)` for bounded native bytes.
- `verify_supplied_redis_acl_analysis(report, *, model)` to replay against a
  separately supplied original model.
- `RedisAclAnalysis.from_dict`, `from_json`, `to_dict` and `to_json` for
  detached, addressed report serialization and embedded-source replay.

The closed model has these fields:

```json
{
  "schema_version": 1,
  "semantics": "redis_7_2_5_acl_key_subset",
  "resource_ref": "supplied:cache:test",
  "username": "application",
  "selectors_complete": true,
  "unsupported_features": [],
  "root_selector": {
    "selector_id": "root",
    "commands": ["get", "mget"],
    "key_patterns": [{"pattern": "app:*", "permissions": "read"}]
  },
  "selectors": [],
  "queries": [{"query_id": "read", "command": "GET", "keys": ["app:user"]}]
}
```

Commands in the normalized selectors must be lowercase members of the fixed
subset. Query commands are ASCII case-insensitive; key matching remains
case-sensitive. Selector and query IDs must be unique. Arrays retain their
original source order in the model digest, while result queries, selector
checks and chosen pattern witnesses are deterministically ordered by IDs or
patterns. This does not reproduce Redis's error-selection or selector logging
order. Positional key order and repeated key occurrences remain significant.

`tests/agents/test_offline_redis_acl_analysis.py::component_fixture()` returns
`{"model": ...}` with public inert inputs, positive reads, adverse writes,
split-selector MGET and directional COPY cases. It contains no connection or
credential material.

## Exact supported arithmetic

| Command | Positional keys | Required permission per position |
| --- | --- | --- |
| GET | Exactly one | Read |
| MGET | One through 32 | Read for every key |
| DEL | One through 32 | Write for every key |
| Plain COPY | Exactly source and destination | Source read; destination write |
| GETDEL | Exactly one | Read and write together |

One selector must allow the command and every positional key. Selectors are
alternative complete checks, not pools whose command or key grants can be
combined. Within a key position, one matching pattern must contain all required
flags. A read pattern and a different overlapping write pattern cannot jointly
satisfy GETDEL. COPY has separate source and destination positions, even when
the two supplied key strings are equal.

Permissions are `read`, `write` or `read_write`. Duplicate identical pattern
strings within a selector are rejected as a nonnormalized snapshot. Redis
merges flags when identical key-pattern rules are applied; this component
expects that normalization to have happened in the supplied model, rather than
interpreting ordered rule application. Identical patterns in different
selectors remain valid and do not merge across selectors.

Patterns and keys are nonempty printable ASCII. The supported well-formed glob
subset includes `*`, `?`, character classes, first-character `^` class negation
and backslash escapes. Reversed range endpoints are swapped. `!` is a literal,
not class negation. Empty or unclosed classes, dangling escapes and ambiguous
range ends are rejected as closed-subset limitations. The implementation is an
independently written bounded token/dynamic-programming matcher, not copied
Redis code and not a full binary `stringmatchlen` parser.

The plain COPY model has no DB or REPLACE options. No values, command categories,
subcommands, first-argument rules, module commands, scripts, transactions,
PubSub, cluster routing or incremental SETUSER rules are evaluated. Unknown
commands and query arities reject instead of receiving an invented grant.

## Incomplete and unsupported declarations

`selectors_complete=false` withholds all final conclusions. Any member of the
closed `unsupported_features` list has the same conservative effect:

```text
command_categories, subcommands, first_argument_rules, module_commands,
scripts, transactions, pubsub, connection_authentication,
binary_key_semantics, cluster_routing, incremental_acl_rules
```

The report can retain known matching selectors and key witnesses, but every
result is `inconclusive` when those declarations are present. With a declared
complete supported model, results are only `allowed_by_supplied_acl` or
`not_allowed_by_supplied_acl`. Neither means effective Redis access or an
authenticated server denial. Resource identity, username and completeness are
unsigned caller declarations. User on/off state is intentionally absent:
Redis's handling of already authenticated connections must not be reduced to
a fabricated connection revocation conclusion.

## Bounds, ownership and replay

| Resource | Ceiling |
| --- | --- |
| Supplied model bytes / logical native nodes / depth | 256 KiB / 16,384 / 16 |
| Retained report bytes / logical native nodes / depth | 1 MiB / 32,768 / 20 |
| General text / key or pattern characters | 256 / 128 |
| Selectors including root / patterns per selector | 32 / 64 |
| Aggregate patterns / queries | 512 / 128 |
| Keys per query / aggregate positional keys | 32 / 1,024 |
| Compilation and matching work units | 2,000,000 |
| Retained key witnesses / pattern-key cache entries | 4,096 / 8,192 |

Exact native dict/list/string/bool/integer/null families are captured before
serialization or hashing. Cycles reject; repeated shared containers are
charged and copied per logical occurrence. Queued children, ASCII escapes and
the final primitive charge cannot evade the budgets. Raw JSON bytes have
byte, token, decoded-string, logical-node and scalar-depth preflights before
the decoder. Duplicate fields reject at every object level. Floats, nonfinite
numbers, subclasses and signed-64 overflow reject; lexical integer bounds
precede integer conversion. These bounds are supported-subset ceilings, not
runtime throughput or Redis capacity claims.

Compilation, matching, cache entries, selector/key iterations and conservative
sorting work are charged. Retained result records, reasons and witnesses are
cumulatively bounded before insertion and addressing. No recursive wildcard
expansion or character-range materialization is used.

Model-byte parsing binds the original canonical parsed model, not raw input
bytes. Whitespace and equivalent ASCII JSON escapes can produce the same
model digest. Source list permutations can preserve the computed arithmetic
but change the model and report digests. Query digests retain each original
query including its declared command spelling and positional keys.

The frozen wrapper stores canonical report JSON. Reads produce detached
records and replay the entire embedded model, including counters, witnesses,
effects and addresses. Rehashing a false result does not make it valid. The
separate original-model verifier rejects a genuine report for a different
valid model. Embedded consistency and hash possession are not source
authentication. A valid model substituted before entry is a new supplied
model; no arbitrary Python-code isolation, concurrent-memory snapshot or
external truth guarantee is claimed.

`offline_only=true`; source/principal authentication, effective access, live
use and qualification flags remain false. Authority, target, execution,
routing, qualification, deployment, network, provider, credential and process
effects remain `none`. There is no engine, socket, SDK, callback, file writer,
credential resolution or backend default.

## Primary semantics and tests

The supplied subset is pinned to Redis 7.2.5 selector/key checks and glob
semantics, with current official command documentation corroborating the
fixed positional projection:

- [Redis ACL documentation](https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/).
- [Redis 7.2.5 ACL implementation](https://raw.githubusercontent.com/redis/redis/7.2.5/src/acl.c),
  specifically `ACLSelectorCheckKey`, `ACLSelectorCheckCmd` and
  `ACLCheckAllUserCommandPerm`, plus identical-pattern flag merging.
- [Redis 7.2.5 glob implementation](https://raw.githubusercontent.com/redis/redis/7.2.5/src/util.c),
  specifically `stringmatchlen_impl`.
- Official command key specifications:
  [GET](https://redis.io/docs/latest/commands/get/),
  [MGET](https://redis.io/docs/latest/commands/mget/),
  [DEL](https://redis.io/docs/latest/commands/del/),
  [COPY](https://redis.io/docs/latest/commands/copy/) and
  [GETDEL](https://redis.io/docs/latest/commands/getdel/).

The focused tests cover selector and pattern nonunion, flag truth tables,
independently expressed finite glob expectations, positional multiplicity,
incomplete sources, source permutation, duplicate/native/raw bounds,
pre-hash work and retained-output denial, exact source replay and cohashed
false reports. They use inert synthetic models only. Passing them is neither
Redis engine differential testing nor specialist qualification.
