# Offline AD CS Template-Rights Projection

This R0 component compares caller-supplied certificate template principal-right
declarations with a caller-supplied local enrollment allowlist and rights policy.
The closed vocabulary is Read, Enroll, and Autoenroll. A local policy can require
Read whenever an enrollment right is declared and Enroll when Autoenroll is
declared. The report identifies declaration-policy mismatches, not effective
permissions, certificate issuance, or an exploit classification.

[Microsoft's certificate template guidance](https://learn.microsoft.com/en-us/windows-server/remote/remote-access/tutorial-aovpn-deploy-create-certificates)
describes Read, Enroll, and Autoenroll permissions and notes that Read is needed
for enrollment in its documented configuration. A separate
[Microsoft template permission planning guide](https://learn.microsoft.com/en-us/intune/configmgr/protect/plan-design/planning-for-certificate-template-permissions)
explains how Read and Enroll permissions for users or computers affect that
Configuration Manager scenario. These sources inform the bounded vocabulary.
The component does not claim universal policy conformance or model Windows
effective-access behavior.

The input and output are bounded exact native JSON structures. Principal
references are opaque digests. One declaration per principal and template
represents already aggregated supplied allow rights. Deny entries, inherited
rights, group expansion, CA publication, issuance constraints, template
contents, identity proof, and certificate request behavior are outside scope.
An incomplete inventory returns `unknown`, leaves row policy issues unset,
produces no mismatch entries, and cannot yield a positive candidate count.
Verification recomputes the report against the separate original model.

No Active Directory domain, certification authority, identity provider,
credential, network, or target is contacted. The component never requests or
issues a certificate and does not infer an ESC category or qualification.
