# Supplied Request-Origin Trust Predicates

The `AOE-GE-D23-S09` partial specialist compares a caller-supplied request
observation with a caller-supplied origin and anti-forgery policy. It accepts
only declared state-changing HTTP method names, a narrow lexical HTTPS origin
or no origin, a Boolean indicating token presence, and a declared outcome.
It never accepts a token value or issues a request.

The projection lists three possible negative predicates: a required origin is
absent, a presented origin is not on the declared allowlist, or a required
anti-forgery token is absent. If policy declaration or observation capture is
incomplete, or the outcome is unknown, it withholds a conflict conclusion.
Otherwise, a declared accepted outcome with a negative predicate is only a
`candidate_declared_trust_boundary_conflict`. It does not verify browser origin
equivalence, token validity, request forgery, or target behavior. A declared
accepted outcome without a negative predicate does not approve positive use.

The finite native model is bounded to 128 observations and 16 allowed origins.
Each origin must be lowercase lexical HTTPS with an optional port in range.
This representation is not browser or DNS canonicalization. The report embeds
the original model and can be verified against a separately supplied source.
No file, network, process, credential, target, publication, execution, or
qualification effect is produced. The [synthetic example](../examples/offline-request-origin-trust-component.json)
contains only declared observations.
