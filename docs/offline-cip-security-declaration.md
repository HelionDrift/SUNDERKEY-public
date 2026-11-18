# Offline CIP Security Declaration

This R0 component supports a narrow part of `AOE-GD-D19-S20`. It compares caller-supplied connection requirements with declared endpoint authentication, message integrity, and encryption labels. A review candidate requires complete context and a specifically required property that is not declared. [ODVA's CIP Security overview](https://www.odva.org/publication_download/cip-security-at-a-glance-pub-319/) describes these transport properties and notes that encryption is optional, so the component does not impose confidentiality unless the supplied local policy requires it.

The component does not read EtherNet/IP traffic, inspect a device security profile or certificate, use credentials, or send a control message. Required and declared properties are caller-supplied. A mismatch does not prove effective exposure or an exploitable control connection.

The unsigned report requires separately retained original-model replay and grants no finding, qualification, or positive-use authority.

Example: [`examples/offline-cip-security-declaration-component.json`](../examples/offline-cip-security-declaration-component.json).
