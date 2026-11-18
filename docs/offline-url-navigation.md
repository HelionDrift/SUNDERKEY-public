# Supplied HTTPS URL navigation projection

This R0 partial component belongs to `AOE-GB-D05-S05`, capability
`army.gb.d05.s05`, vector `AV-GB-D05-S05-01`, and wave `IW2-005`.
It projects a bounded sequence of supplied Location references from one
supplied HTTPS base URL. It does not navigate, fetch, authenticate, or infer
an exploitable redirect.

The exact schema version 1 model contains `base_url` and ordered `hops` with
unique IDs and Location text. The parser admits a deliberately narrow ASCII
HTTPS DNS-name subset. It refuses ambiguous or unsupported forms, including
userinfo, IP literals, percent escapes, backslashes, Unicode, non-HTTPS
schemes, and unsupported authority syntax. Each processed hop records the
projected URL and origin relation. A refused hop stops the projection; later
hops are counted as unprocessed rather than silently followed. Origin changes
are supplied-string arithmetic, not observations of browser or server behavior.

`analyze_supplied_url_navigation` returns a source-bearing report.
`verify_supplied_url_navigation_analysis` rederives it against the separately
supplied model. The catalog verifier also replays the complete original
request. The checked synthetic example is
`examples/offline-url-navigation-component.json`; no target, network,
process, credential, qualification, or positive-use effect is granted.
