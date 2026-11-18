# CLI Reference Examples

Run these commands from the repository root after installing the package. They read local catalogs and do not contact a target.

```sh
python -m sunderkey.cli --help
python -m sunderkey.cli validate-registry --registry registry/army-v2.json
python -m sunderkey.cli army-readiness --help
```

The registry validation command checks the source catalog structure. It does not qualify specialists, activate workers, or grant target authority. Inspect each command's `--help` output and the relevant boundary documentation before using any operation that can create, change, or consume mission state.

Provider keys, operator signing keys, mission scopes, target authorization, and production resources are intentionally not supplied with this repository. For the governing rules, see [Safety Boundary Reference](safety-boundary-reference.md) and [Action Admission Contracts](action-admission-contracts.md).
