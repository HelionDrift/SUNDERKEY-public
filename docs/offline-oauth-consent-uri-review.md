# Supplied OAuth Consent URI Review

The GA-D02-S06 partial component parses one bounded synthetic Microsoft Entra
authorization URI without opening it. The [Microsoft consent documentation](https://learn.microsoft.com/en-us/entra/identity-platform/application-consent-experience)
explains that consent depends on tenant policy, user authority, and requested
permissions. The [scope documentation](https://learn.microsoft.com/en-us/entra/identity-platform/scopes-oidc)
distinguishes `.default` from dynamic scopes. The checked example is
[`examples/offline-oauth-consent-uri-component.json`](../examples/offline-oauth-consent-uri-component.json).

The component checks a constrained code-flow request, unique query fields,
synthetic client and redirect expectations, requested scopes, and `.default`
mixing. It hashes the URI and any unlisted scope names in the report. Its
expectations are caller assertions, not a tenant policy or an authenticated
app identity. A structurally consistent URI does not prove a consent grant,
social-engineering effect, or delivery. No URL is opened, no message or lure
is generated or sent, and no finding or qualification is produced.
