# Offline WASM Host Import Boundary

This R0 component supports a narrow part of `AOE-GB-D10-S02`. It compares bounded, caller-supplied host function import names with a caller-supplied allowlist. An import outside that list produces a review candidate only when the caller declares the module context complete.

The component does not parse a WASM binary, inspect Rust or Move source, verify function signatures, load a host runtime or execute a module. Neither the imported names nor the allowlist are authenticated. An unmatched label does not prove a dangerous host capability or vulnerability.

The unsigned report requires separately retained original-model replay and grants no finding, qualification or positive-use authority.

Example: [`examples/offline-wasm-host-import-boundary-component.json`](../examples/offline-wasm-host-import-boundary-component.json).
