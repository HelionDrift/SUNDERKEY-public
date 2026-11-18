# Supplied Linux Pod security controls

This leaf analyzes five declared Linux controls from the Kubernetes v1.34
Restricted Pod Security Standards. It is partial candidate software, not a
complete PSS checker, Kubernetes API validator, cluster admission decision,
runtime isolation observation, or live authorization. No cluster, image,
process, credential, host profile, or network is accessed.

The existing lane is AOE-GC-D15-S05, capability `army.gc.d15.s05`, vector
AV-GC-D15-S05-01, wave IW2-007. The blueprint digest is
`sha256:234e287aec5569750d2e7b4a4e30b213a37c2656bfb56cabf975ee2b676a0510`.
Its commander is AOE-GC-D15-CMD, group commander AOE-HQ-05, and independent
validator AOE-HQ-19. These are declared repository coordinates, not an authority
grant or an independent qualification. The original D016 decision, reference
SDKs, containment requirements, and every live-use gate remain unchanged.

## Input and entry points

`analyze_supplied_kubernetes_pod_security(model)` returns a detached
`PodSecurityAnalysis`. `analyze_supplied_kubernetes_pod_security_bytes` accepts
only the keyword `model_bytes`, containing bounded native ASCII JSON bytes.
`verify_supplied_kubernetes_pod_security_analysis(report, *, model)` rederives
the complete analysis from a separately supplied original model.

The closed model has exactly `schema_version: 1`,
`benchmark_version: "kubernetes-v1.34-linux-restricted-core"`, and `pod`.
The Pod projection requires `pod_ref`, `os_name`, `host_users`,
`security_context`, `containers`, `init_containers`, and
`ephemeral_containers`. Application containers are nonempty; the other two
arrays may be empty. Container references must be unique across all arrays.
Original array and capability order is preserved.

Pod security context requires exactly:

- `run_as_non_root`: native boolean or null.
- `run_as_user`: nonnegative native integer through 9223372036854775807, or null.
- `seccomp_profile`: null, or exactly `type` and `localhost_profile`.

Every container requires `container_ref` and `security_context`. Its context
requires those three slots plus `allow_privilege_escalation` (native boolean
or null) and `capabilities` (null, or exactly native `add` and `drop` arrays).
Capability arrays contain unique nonblank printable ASCII strings. Null means
declared unset, never an omitted field or silently inferred default. Missing
and unsupported fields are rejected rather than normalized.

The supported seccomp projection has native nonblank strings: RuntimeDefault
and Unconfined require `localhost_profile: null`; Localhost requires a nonblank
declared profile string. Unknown types and contradictory type/profile pairs
make the analysis unsupported, not a claim of Kubernetes API invalidity. No
Localhost path is opened or certified to exist.

## Five-control reasoning

All application, init, and ephemeral containers are checked:

- Non-root: effective `run_as_non_root` must be true. A child inherits only
  when its value is null. Explicit false at Pod scope is a violation even
  when every child declares true.
- UID: every explicitly supplied Pod or container `run_as_user` must be
  nonzero. Null is permitted by this control. Explicit Pod zero is not
  masked by a safer child value. Nonzero declarations do not establish the
  actual image user or process UID.
- Privilege escalation: every container must explicitly declare false.
  There is no Pod-scope inheritance for this slot.
- Seccomp: each container must effectively declare RuntimeDefault or
  Localhost. Fallback occurs only when the child's complete profile is null.
  Explicit Pod Unconfined remains a violation even with safer child profiles.
- Capabilities: each container must drop exact `ALL`, and additions may
  contain only exact `NET_BIND_SERVICE`. Capability spelling, availability,
  and application by the runtime are not certified. Additional drop strings
  are preserved without pretending their syntax or names were validated.

Linux is required for reasoning. `os_name: windows` or `unknown`, and any
`host_users: false` declaration, globally withhold the five-control evaluation.
The latter avoids inventing policy conclusions about user-namespace relaxation
or feature-gate configuration. `host_users: null` or true is only a supplied
declaration, not proof of a host setting.

The result is `satisfies_supported_controls`, `violates_supported_controls`,
or `unsupported`. Even the first result is not a PSS pass. Check witnesses
carry field paths, original declared values, declared effective inheritance,
and reasons. Full Baseline and all other Restricted controls are expressly
excluded, including privileged/host namespaces, host paths and ports, volume
types, AppArmor, SELinux, procMount, sysctls, and host probes/lifecycle hooks.

## Bounded replay and effects

Per-model and per-report limits are 1 MiB canonical ASCII bytes, 32768 visited
nodes, depth 16 including scalars, and 256 decoded printable ASCII characters
per string. There are at most 64 containers total and 64 capabilities per
array. Evaluation is capped at 8192 check/capability steps. Repeated native
graph branches are charged repeatedly; cycles and subclasses are rejected.
Structural punctuation, escaping quotes/backslashes, and queued children are
charged before copying. Cumulative report bytes and nodes are reserved before
retaining witnesses, and the final document is bounded before any digest.

Raw JSON is bounded before decoding, including decoded string lengths,
escaped characters, container/scalar depth, nodes, and finite integer grammar.
Integers use canonical decimal spelling, excluding negative zero, fractions,
exponents, malformed signs, and magnitudes beyond the supported signed-63-bit
cost subset. Duplicate fields, nonfinite values, controls, and non-ASCII
strings are rejected. Whitespace and printable escapes need not use the
canonical serializer's spelling.

`PodSecurityAnalysis.from_dict/from_json` reconstruct every result, witness,
counter, flag, digest, and address from the report's embedded model. Public
reads repeat that exact native replay. Canonical comparisons distinguish
boolean/integer and integer/floating aliases. A coherent different source can
produce its own truthful report; only verification against the separately
supplied original establishes that particular source join. Neither operation
authenticates a cluster, author, or supplied metadata. There is no protection
claim against arbitrary code modifying a Python process or filesystem.

All effects remain `none`. `offline_only` is true; full PSS, API validity,
cluster admission, runtime isolation, image UID, capability availability,
source authentication, live-use approval, and qualification flags are false.
The synthetic test fixture uses explicit inert declarations, not host or
provider evidence, and does not alter current roadmap readiness.

Primary semantics: [Kubernetes v1.34 Pod Security Standards](https://v1-34.docs.kubernetes.io/docs/concepts/security/pod-security-standards/)
and [v1.34 user namespaces](https://v1-34.docs.kubernetes.io/docs/concepts/workloads/pods/user-namespaces/).
This is an independently authored finite subset, not copied upstream code or
an assertion of parity with Kubernetes admission implementation.
