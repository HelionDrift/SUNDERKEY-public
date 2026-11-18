# Offline Managed PaaS Grant Scope

This R0 component supports a narrow part of `AOE-GC-D14-S16`. It compares caller-supplied intended and granted scopes for principals bound to managed database, application, and queue services. A review candidate requires complete context and an active grant broader than the intended resource, project, or tenant scope.

The component does not query a provider, resolve inherited roles or conditions, or use a credential. Service kind, principal, intended scope, and granted scope are caller-supplied. A broader declared grant does not prove effective permission or privilege use.

The unsigned report requires separately retained original-model replay and grants no finding, qualification, or positive-use authority.

Example: [`examples/offline-managed-paas-grant-scope-component.json`](../examples/offline-managed-paas-grant-scope-component.json).
