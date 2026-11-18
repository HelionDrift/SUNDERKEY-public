# Offline Enterprise SaaS Admin Delegation

This R0 component supports a narrow part of `AOE-GC-D14-S17`. It compares caller-supplied tenant policy with declared external privileged delegations for one SaaS product family. A review candidate requires complete context, an active external privileged delegation, and a declared policy that forbids it. An unknown principal scope or incomplete context produces `unknown`.

The product family is only a label. The component does not query Salesforce, ServiceNow, Workday, Atlassian, or another SaaS provider, resolve inherited roles, or establish effective access. The unsigned report requires separately retained original-model replay and grants no finding, qualification, or positive-use authority.

Example: [`examples/offline-enterprise-saas-admin-delegation-component.json`](../examples/offline-enterprise-saas-admin-delegation-component.json).
