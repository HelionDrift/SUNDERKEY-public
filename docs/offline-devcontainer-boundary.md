# Supplied Development Container Host Boundary

`AOE-GC-D17-S13` has one partial, inert development-container review. The
operator supplies a reduced declaration of image and Feature reference kinds,
review states, lifecycle hook presence, mount scopes, and container privilege.
The analysis joins source-review signals to declared host-boundary signals.
It never reads or executes a development container configuration.

The [Development Container Specification](https://containers.dev/overview)
defines `devcontainer.json` as metadata for development environments. Its
[supporting-tools guide](https://containers.dev/supporting.html) describes
Features and lifecycle scripts such as `postCreateCommand`. A Feature can
include an installation script, as shown in the
[Feature authoring guide](https://containers.dev/guide/author-a-feature).
The local model does not implement this specification and does not infer
commands or effects from a real configuration.

## Input Boundary

The model accepts only these top-level fields: `schema_version`, `source_id`,
`inventory_complete`, `image`, `features`, `hooks`, `mounts`, and `privileged`.
Image and Feature rows contain only an opaque ID, reference kind, and
operator-asserted review Boolean. Hook rows contain a named lifecycle phase,
presence Boolean, and review Boolean. Mount rows contain an opaque ID, one of
`workspace`, `host_path`, `host_socket`, or `unknown`, and writability.
No path, command, environment value, extension setting, image content,
credential, or provider response is accepted. Unknown fields fail closed.

The projection flags a declared source-to-host relationship when an
unreviewed hook, image, Feature, or tag-based reference coexists with a
privileged container, a host-socket mount, or a writable host-path mount.
These are metadata relationships, not proof that one input can affect another
or that a host operation occurs. An operator must separately validate the
complete original configuration and the actual runtime before any finding.

## Interpretation

The synthetic example has an unreviewed `postCreate` hook and a tag-based,
unreviewed Feature in a configuration with a declared writable host path.
It produces candidate metadata links without running the hook or reading the
path. Incomplete inventory and unknown reference or mount kinds remain
explicit uncertainty. A clean result does not establish safety.

Reports are content-addressed and replayed against the original supplied
model. They are unsigned and nonqualifying. No specialist candidate is
assembled, no finding is published, and no authority is issued. Real source
inspection, secret minimization, image and Feature integrity, runtime
observation, independent review, and qualification remain separate work.
