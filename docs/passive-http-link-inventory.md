# Passive HTTP link inventory

`extract_passive_link_inventory` turns one completed, authorized HTML exchange
into bounded same-origin link proposals. It verifies that the supplied intent
and response bytes match the content-addressed exchange receipt. It performs
no DNS lookup, request, browser action, scheduling, scope expansion, or action
admission. Every proposed path still needs a separate current scope and
execution decision before any target interaction.

The extractor accepts UTF-8 `text/html` only, with at most 1 MiB of response
bytes. It considers `a[href]`, `link[href]`, `script[src]`, and `form[action]`.
It ignores HTML base tags and resolves relative references against the exact
request URL. External origins, non-HTTPS schemes, malformed references, and
noncanonical hosts are rejected. Query values are never placed in the result;
only safe query parameter names are retained. At most 2,048 raw references and
256 distinct accepted candidates are processed. A ceiling breach fails closed
instead of publishing a partial inventory.

The output contains a digest over the source receipt, intent, response digest,
candidate set, and rejection count. It is a discovery proposal, not proof that
the candidate exists or is in scope. Paths themselves may still contain
sensitive data, so inventories must remain in the assessment evidence custody
and must not be placed in public logs.

Offline test:

```powershell
$env:PYTHONPATH = 'src'
python -m unittest -q tests.agents.test_passive_http_link_inventory
```
