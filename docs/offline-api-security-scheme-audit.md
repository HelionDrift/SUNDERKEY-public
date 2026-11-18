# Offline API security-scheme audit

`sunderkey.offline_api_security_scheme_audit` replays the exact source bytes
of an extracted OpenAPI or Swagger endpoint bundle and checks each referenced
security scheme against local contract definitions. It reports undefined
scheme names, incomplete or unsupported definitions, undeclared OAuth scopes,
scopes attached to non-OAuth schemes, and OpenID Connect scopes whose source
is external to the contract.

For supported OpenAPI 3.0, 3.1, and 3.2 documents and Swagger 2.0, the audit
checks each OAuth flow name, required authorization, token, or device URL,
and string-valued scope map. It treats missing or non-absolute HTTP(S) URLs
as unresolved. This is a conservative local rule and does not contact an
identity provider. OpenAPI 3.1 and 3.2 mutual TLS declarations can resolve
locally, while role names attached to non-OAuth schemes remain unverified.
OpenAPI versions beyond 3.2 are withheld pending an explicit audit update.
The version-specific rules follow the [OpenAPI 3.0](https://spec.openapis.org/oas/v3.0.3),
[OpenAPI 3.1](https://spec.openapis.org/oas/v3.1.2.html),
[OpenAPI 3.2](https://spec.openapis.org/oas/v3.2.1.html), and
[Swagger 2.0](https://spec.openapis.org/oas/v2.0.html) specifications.

The audit also binds a security-declaration matrix built from caller-asserted
principal grants. A pair counts as locally resolved only when every scheme
referenced by that endpoint's alternatives has no listed issue. This is a
conservative filter: one incomplete alternative withholds the entire
operation, even if another alternative is complete. It does not verify the
server's deployed configuration, the principal's actual rights, customer
authorization, or permission to probe.

Rows contain endpoint digests and issue codes, not URLs, credentials, or
response bodies. The source content and matrix inputs are required for
verification. The result never grants positive use or performs target
interaction.

Run the focused local check from the repository root:

```powershell
$env:PYTHONPATH = "src"
python -m unittest tests.agents.test_offline_api_security_scheme_audit -v
```
