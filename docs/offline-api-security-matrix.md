# Offline API security-declaration matrix

`sunderkey.offline_api_security_matrix` accepts a verified, content-addressed
OpenAPI or Swagger endpoint bundle from the service contract extractor and a
bounded list of caller-asserted principal capabilities. It evaluates each
operation's declared security alternatives. Schemes inside one alternative
must all match; separate alternatives are choices. The output identifies
opaque pairs whose assertions differ against the declaration.

The matrix does not create requests, resolve credentials, contact a target,
or assert that either principal has permission. OpenAPI security declarations
are not an authorization policy. Principal capabilities are unsigned caller
assertions. The extractor does not prove that referenced scheme definitions
are complete or deployed. An empty requirement permits an anonymous
alternative in the declaration; a missing or empty requirement list is
reported separately as `no_security_requirement_declared` and is not treated
as proof of public access.

Rows contain endpoint digests, methods, declaration matches, and candidate
principal pairs, not target addresses or response data. Verification rebuilds
the matrix and rejects altered principal assertions, rows, or effect claims.
The result always sets `target_authorization_verified` and
`positive_use_approved` to false.

Run the focused local check from the repository root:

```powershell
$env:PYTHONPATH = "src"
python -m unittest tests.agents.test_offline_api_security_matrix -v
```
