# Offline IEC 61850 Subscription References

This R0 component supports a narrow part of `AOE-GD-D19-S19`. It compares caller-supplied publication and subscription IDs with dataset references. A review candidate requires complete context and a missing publication or mismatched dataset label. [IEC 61850-6](https://webstore.iec.ch/en/publication/103863) defines a configuration-description format for IED and communication-system relationships, but this component does not claim IEC conformance or parse that format.

The component does not read an SCL file, query an IED, observe GOOSE traffic, or interact with a power system. All station, IED, publication, and dataset IDs are caller-supplied abstractions. A mismatch does not prove a protection failure or exploit path.

The unsigned report requires separately retained original-model replay and grants no finding, qualification, or positive-use authority.

Example: [`examples/offline-iec61850-subscription-refs-component.json`](../examples/offline-iec61850-subscription-refs-component.json).
