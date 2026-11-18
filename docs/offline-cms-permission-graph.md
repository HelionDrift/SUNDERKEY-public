# Supplied CMS permission graph projection

This R0 component belongs to `AOE-GB-D05-S17`, capability
`army.gb.d05.s17`, vector `AV-GB-D05-S17-01`, package
`IWP2-AOE-GB-D05-S17`, and wave `IW2-017`. Its component ID is
`web_supplied_cms_permission_graph_projection`. It contributes partial
offline evidence only and does not qualify the specialist.

The schema version 1 model declares a CMS, plugin or low-code label; an
acyclic role-inheritance graph; direct permission grants; principal role
assignments; one required permission for each resource; and supplied access
outcomes. Names are exact and case-sensitive. Role inheritance produces an
effective permission set for each principal. Plugin hooks, contextual rules,
explicit denies and tenant policy are not inferred.

The projection compares a supplied outcome to its declared permission result
only when the graph, extension policy, role assignments, resource rule,
enforcement scope and outcome are all declared complete. A supplied allow
against a declared deny yields
`candidate_declared_deny_allowed_contradiction`. A supplied deny against a
declared allow is an availability mismatch, not a bypass candidate. A match
only describes internal consistency. An incomplete premise yields `unknown`.

`analyze_supplied_cms_permission_graph` accepts a native model; the `_bytes`
variant accepts bounded ASCII JSON. The report embeds its source model and
domain-separated addresses. `from_json` replays that embedded source, while
`verify_supplied_cms_permission_graph_analysis` additionally checks a
separately supplied original. The synthetic R0 request is
`examples/offline-cms-permission-graph-component.json`.

No CMS, plugin or low-code runtime is queried. No network, process,
credential, provider or target is accessed. No actual access bypass,
authority, positive use, live finding or qualification is claimed.
