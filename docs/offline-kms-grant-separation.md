# Offline KMS Grant Separation

This R0 component supports a narrow part of `AOE-GC-D14-S13`. It groups active caller-supplied grants by key and principal. A review candidate requires one principal to hold both declared decrypt and policy-management actions when the caller states that those duties must be separated. The actions may appear in separate grants.

The component does not query a KMS, evaluate effective provider policies, deny rules or grant constraints, or access key material. Grant activity, principal identities and the separation rule are caller-supplied. An overlap is a review signal, not proof of key use or a policy bypass.

The unsigned report requires separately retained original-model replay and grants no finding, qualification or positive-use authority.

Example: [`examples/offline-kms-grant-separation-component.json`](../examples/offline-kms-grant-separation-component.json).
