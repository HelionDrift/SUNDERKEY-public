# Offline Workforce IdP MFA Paths

This R0 component supports a narrow part of `AOE-GC-D14-S20`. It compares caller-supplied privileged application sign-in paths with a declared MFA requirement and enforcement labels. A review candidate requires complete policy context and an enabled path marked as lacking MFA enforcement for a privileged application that requires MFA.

The component does not query an identity provider, resolve conditional access or inherited rules, or attempt authentication. Application labels, policies, and path states are caller-supplied. A mismatch does not prove that a usable authentication bypass exists.

The unsigned report requires separately retained original-model replay and grants no finding, qualification, or positive-use authority.

Example: [`examples/offline-workforce-idp-mfa-paths-component.json`](../examples/offline-workforce-idp-mfa-paths-component.json).
