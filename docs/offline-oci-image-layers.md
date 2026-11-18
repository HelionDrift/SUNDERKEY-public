# Offline OCI Image and Layer Metadata

This R0 partial component compares bounded, caller-supplied OCI image manifest,
configuration and layer metadata. It does not fetch or authenticate a registry
artifact. A discrepancy is an unsigned candidate about the declarations only.
The component does not complete the OCI Images and Layers specialist or grant
live use, qualification or publication authority.

Ownership is profile `AOE-GC-D15-S01`, capability `army.gc.d15.s01`, vector
`AV-GC-D15-S01-01`, work package `IWP2-AOE-GC-D15-S01`, wave `IW2-003`,
commander `AOE-GC-D15-CMD`, group owner `AOE-HQ-05` and independent validator
`AOE-HQ-19`. The bound blueprint is
`sha256:5253e42e2269c5cc23866ba833bb8c0dc4977bba2b69e59fea625450367fd9e4`.

## Supplied Declaration

The native model contains exactly `schema_version`, `source_id`,
`inventory_complete`, `manifest` and `configuration`. The manifest declares
`schema_version`, `media_type`, one `config` descriptor and ordered `layers`
descriptors. Each descriptor declares `media_type`, `digest` and `size`.
The configuration declares `media_type`, `rootfs_type`, ordered `diff_ids`
and optional `history`. In this finite subset, history is either `null` or
an array of objects with Boolean `empty_layer` values. The example file is a
synthetic input for the component dispatcher.

The parser accepts at most 64 layer descriptors and DiffIDs and 128 history
markers. Digests in this software subset are lowercase SHA-256 strings, and
sizes are nonnegative native integers. Other valid OCI digest algorithms and
additional OCI fields are outside this closed model, not declared invalid OCI.
The source and report JSON ceilings are 64 KiB and 128 KiB respectively;
the shared declaration core also bounds JSON nodes, depth and string lengths.

## Checks and Evidence Boundary

The pinned basis is [OCI image-spec v1.1.1 image manifests](https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md)
and [OCI image configuration](https://github.com/opencontainers/image-spec/blob/v1.1.1/config.md).
For the supported manifest and configuration media types, the component checks
that the manifest schema version is 2, `rootfs_type` is `layers`, the supplied
DiffID count matches the supplied layer descriptor count, and nonempty history
markers match the layer count when history is supplied. It also compares the
manifest config descriptor media type with the separately supplied config media
type. Unknown media types are retained as unknown, not rejected as invalid OCI.
An empty layer array and absent optional history are allowed.

The layer descriptor digest is not compared with the corresponding DiffID:
OCI defines the former over compressed or uncompressed layer content and the
latter over the uncompressed tar archive. This component has no layer bytes and
cannot compute either digest. It does not decompress, inspect tar structure,
apply overlays, read runtime config, verify signatures, or inspect a registry.
It has no filesystem, process, network, provider, credential, target or
qualification effect.

`analyze_supplied_oci_image_layers(model)` returns a detached, addressed
`OciImageLayersReport`. The `verify_supplied_oci_image_layers` and
`verify_supplied_oci_image_layers_bytes` functions reconstruct the report
against a separately supplied original model. An incomplete inventory returns
`unknown` and never a positive candidate. A consistency disposition is limited
to the supplied metadata and never proves image integrity, safety, provenance,
currentness or execution readiness.
