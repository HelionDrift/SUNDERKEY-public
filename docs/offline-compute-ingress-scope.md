# Offline Compute Ingress Scope

This R0 component supports a narrow part of `AOE-GC-D14-S02`. It compares a caller-supplied private-only requirement with a declared ingress scope for compute, container, and serverless workloads. A review candidate requires complete context and a public ingress label for a workload marked private-only.

The component does not query AWS, inspect provider configuration, resolve routes, or contact a workload. Workload type, private intent, ingress scope, and authentication are caller-supplied labels. A mismatch does not prove reachability or unauthorized access.

The unsigned report requires separately retained original-model replay and grants no finding, qualification, or positive-use authority.

Example: [`examples/offline-compute-ingress-scope-component.json`](../examples/offline-compute-ingress-scope-component.json).
