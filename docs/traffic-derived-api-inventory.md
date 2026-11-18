# Traffic-derived API inventory

`build_traffic_api_inventory` reconciles caller-supplied, sanitized HTTPS
transaction metadata with a content-addressed OpenAPI or Swagger endpoint
bundle. It does not collect traffic, read credentials, open a socket, authorize
an action, schedule tests, or approve a release.

Each event carries exact tenant, context, and scope identities plus the context
and signed-scope content digests; an opaque role
reference; an event identity; a collector reference; a source digest; a UTC
observation time; a canonical HTTPS origin; a closed HTTP method; a redacted
path shape; and a response status. The input type has no fields for headers,
query values, bodies, session identifiers, or raw principal identities.
Paths allow only conservative literal segments and named placeholders such as
`/v1/users/{user_id}`. The caller remains responsible for sanitizing dynamic
segments before creating an event. A source digest is not a verified collector
signature or proof that redaction occurred.

The inventory rejects mixed tenant, context, or scope identities or revisions;
future or
stale events; conflicting reuse of an event ID; invalid path shapes; and
resource ceilings. Identical redeliveries of one event are deduplicated.
The hard ceilings are 10,000 events, 2,000 observed endpoint shapes, and
50,000 total contract matches. The
default maximum age is seven days and cannot exceed 30 days. The result is
stable under input reordering and is content-addressed, including the chosen
freshness window. Source observations and a supplied contract bundle are
integrity-checked before reconciliation. A stored result can be replayed with
`verify_traffic_api_inventory_from_sources` against caller-supplied source
observations and the same contract bundle. This verifies the historical
derivation only. It does not prove the inputs are complete or presently current.
`load_traffic_api_inventory_json` loads a bounded UTF-8 result archive with
a 16,000,000-byte limit, duplicate-key and exact-field checks, and
content-address validation. The
observation record also supports exact-field `to_dict` and `from_dict` round
trips. An archive can be loaded and replayed, but its origin is not
authenticated by either operation.

To replay saved JSON files without importing Python, run:

```powershell
$env:PYTHONPATH = 'src'
python -m sunderkey.cli traffic-api-inventory-verify `
  --inventory inventory.json `
  --observations observations.json `
  --contract-bundle contract-bundle.json
```

Omit `--contract-bundle` only when the inventory was built without one. The
command prints a historical replay result and performs no network request.

Before aggregation, each supplied observation is reconstructed from the declared
fields into an owned base record. Its newly computed digest must exactly match
the supplied observation digest. A changed status, role, scope, source label,
or other field cannot retain an old content address. Later changes to the
original object do not change the captured record. This verifies local content
integrity, not collector identity, signed-scope authenticity, or live coverage.

Capture uses the underlying base string and integer values without calling a
subclass's conversion or comparison hooks. All 13 observation text fields, the
status code, requested binding strings and maximum age are owned before
validation or comparison. Boolean and non-integer statuses remain invalid.
String and integer enums retain the same canonical JSON identities as their
underlying valid values. The observation tuple's native length is bounded
before its native contents are captured; subclass length or iterator overrides
cannot hide excess input or substitute observations.

Contract comparison uses the endpoint address and method, including an exact
origin. A whole-segment contract placeholder can match a redacted observed
segment. If a placeholder on the observed side could conceal a contract
literal, the match is `ambiguous_template`. Other classifications are
`documented`, `not_in_supplied_contract`, and `not_compared`. The inventory
also lists contract endpoints not definitively matched by traffic. Neither
absence of traffic nor absence from the supplied document proves an endpoint
is inactive, undocumented in every source, vulnerable, or in assessment scope.

The [API release-delta review](api-release-delta-review.md) compares two
inventories around a supplied release boundary. A passing release gate cannot
be inferred from this inventory alone:
source completeness, authenticated collection, release identity, and current
target authorization remain external evidence.

The [matrix-bound release review](api-release-role-response-review.md) also
compares exact role/status associations from both complete supplied windows;
it does not infer that independently summarized role and status sets preserve
those associations.

Offline validation:

```powershell
$env:PYTHONPATH = 'src'
python -m unittest -q tests.agents.test_traffic_derived_api_inventory
```
