"""Compare supplied WASM host imports with a declared allowlist."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "wasm_supplied_host_import_allowlist"
PROFILE_ID = "AOE-GB-D10-S02"
CAPABILITY_ID = "army.gb.d10.s02"
VECTOR_ID = "AV-GB-D10-S02-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D10-S02"
WAVE_ID = "IW2-002"
COMMANDER_ID = "AOE-GB-D10-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:61bd1625dec05b32b787ae673c675d594d2ef6beeaec793b546fc68e469f4cee"
DOMAIN = "sunderkey.offline-wasm-host-import-boundary.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
EFFECTS = {
    key: "none"
    for key in (
        "authority",
        "execution",
        "filesystem",
        "network",
        "process",
        "provider",
        "credentials",
        "target_interaction",
        "finding_publication",
        "qualification",
    )
}


class WasmHostImportBoundaryError(ValueError):
    """A supplied WASM import declaration or replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "modules"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise WasmHostImportBoundaryError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    modules = core.bounded_list(model["modules"], 16, "modules")
    if not modules:
        raise WasmHostImportBoundaryError("At least one module is required")
    seen_modules: set[str] = set()
    for item in modules:
        row = core.exact(
            item, {"module_id", "context_complete", "imports", "allowed_imports"}, "module"
        )
        module_id = core.identifier(row["module_id"], "module ID")
        if module_id in seen_modules:
            raise WasmHostImportBoundaryError("Duplicate module ID")
        seen_modules.add(module_id)
        core.boolean(row["context_complete"], "context completeness")
        imports = core.bounded_list(row["imports"], 64, "imports")
        allowed = core.bounded_list(row["allowed_imports"], 64, "allowed imports")
        seen_imports: set[str] = set()
        for item_import in imports:
            entry = core.exact(item_import, {"import_id", "namespace_id", "function_id"}, "import")
            import_id = core.identifier(entry["import_id"], "import ID")
            if import_id in seen_imports:
                raise WasmHostImportBoundaryError("Duplicate import ID")
            seen_imports.add(import_id)
            core.identifier(entry["namespace_id"], "namespace ID")
            core.identifier(entry["function_id"], "function ID")
        allowed_pairs: set[tuple[str, str]] = set()
        for item_allowed in allowed:
            entry = core.exact(item_allowed, {"namespace_id", "function_id"}, "allowed import")
            pair = (
                core.identifier(entry["namespace_id"], "namespace ID"),
                core.identifier(entry["function_id"], "function ID"),
            )
            if pair in allowed_pairs:
                raise WasmHostImportBoundaryError("Duplicate allowed import")
            allowed_pairs.add(pair)
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    projections = []
    for row in model["modules"]:
        allowed = {
            (entry["namespace_id"], entry["function_id"]) for entry in row["allowed_imports"]
        }
        outside = [
            entry["import_id"]
            for entry in row["imports"]
            if (entry["namespace_id"], entry["function_id"]) not in allowed
        ]
        disposition = (
            "unknown"
            if not row["context_complete"]
            else "candidate_declared_host_import_outside_allowlist"
            if outside
            else "declared_host_imports_within_allowlist"
        )
        projections.append(
            {
                "module_id": row["module_id"],
                "import_count": len(row["imports"]),
                "outside_allowlist_import_ids": sorted(outside),
                "disposition": disposition,
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "module_count": len(model["modules"]),
        "module_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"] == "unknown" for row in projections),
        "source_authenticated": False,
        "wasm_binary_parsed": False,
        "host_capabilities_verified": False,
        "module_executed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Import names, module identity and the allowlist are caller-supplied.",
            "No WASM binary, host runtime, imported function signature or capability is checked.",
            "An unmatched name does not prove that a host exposes a dangerous function.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="WHI-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class WasmHostImportBoundaryReport:
    """Unsigned import projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise WasmHostImportBoundaryError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> WasmHostImportBoundaryReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_wasm_host_imports(model: Any) -> WasmHostImportBoundaryReport:
    return WasmHostImportBoundaryReport._owned(_derive(model))


def verify_supplied_wasm_host_imports(report: Any, *, model: Any) -> WasmHostImportBoundaryReport:
    if type(report) is not WasmHostImportBoundaryReport:
        raise WasmHostImportBoundaryError("Exact WASM-import wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise WasmHostImportBoundaryError("Report differs from separate original model")
    return WasmHostImportBoundaryReport._owned(expected)


def verify_supplied_wasm_host_imports_bytes(
    report_bytes: bytes, *, model: Any
) -> WasmHostImportBoundaryReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise WasmHostImportBoundaryError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise WasmHostImportBoundaryError("Exported report differs from original replay")
    return WasmHostImportBoundaryReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-wasm-imports",
        "modules": [
            {
                "module_id": "module-one",
                "context_complete": True,
                "allowed_imports": [{"namespace_id": "safe-host", "function_id": "read-state"}],
                "imports": [
                    {
                        "import_id": "import-one",
                        "namespace_id": "safe-host",
                        "function_id": "read-state",
                    },
                    {
                        "import_id": "import-two",
                        "namespace_id": "extra-host",
                        "function_id": "write-state",
                    },
                ],
            }
        ],
    }
