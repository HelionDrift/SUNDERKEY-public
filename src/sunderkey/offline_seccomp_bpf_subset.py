"""Interpret a bounded synthetic classic-BPF seccomp subset without kernel use."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "exploit_supplied_seccomp_bpf_subset_projection"
PROFILE_ID = "AOE-GE-D21-S08"
CAPABILITY_ID = "army.ge.d21.s08"
VECTOR_ID = "AV-GE-D21-S08-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D21-S08"
WAVE_ID = "IW2-020"
COMMANDER_ID = "AOE-GE-D21-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:1c945556208fc3e929cf295c935a4f86a63b78df6b069174769884676d64b604"
DOMAIN = "sunderkey.offline-seccomp-bpf-subset.v1"
MAX_MODEL_BYTES = 32_768
MAX_REPORT_BYTES = 65_536
BPF_LD_W_ABS = 0x20
BPF_JMP_JEQ_K = 0x15
BPF_RET_K = 0x06
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_ALLOW = 0x7FFF0000
ACTIONS = {
    SECCOMP_RET_KILL_PROCESS: "kill_process",
    SECCOMP_RET_ERRNO: "errno",
    SECCOMP_RET_ALLOW: "allow",
}
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class SeccompBpfSubsetError(ValueError):
    """A synthetic BPF program or original-model replay is invalid."""


def _uint(value: Any, bits: int, label: str) -> int:
    if type(value) is not int or not 0 <= value < (1 << bits):
        raise SeccompBpfSubsetError(f"Unsigned {bits}-bit {label} required")
    return value


def _instruction(value: Any) -> dict:
    row = core.exact(value, {"code", "jt", "jf", "k"}, "instruction")
    code = _uint(row["code"], 16, "instruction code")
    jt = _uint(row["jt"], 8, "true jump")
    jf = _uint(row["jf"], 8, "false jump")
    k = _uint(row["k"], 32, "instruction constant")
    if code == BPF_LD_W_ABS:
        if jt or jf or k not in (0, 4):
            raise SeccompBpfSubsetError("Only nr and arch word loads are modeled")
    elif code == BPF_JMP_JEQ_K:
        pass
    elif code == BPF_RET_K:
        if jt or jf or (k & 0xFFFF0000) not in ACTIONS:
            raise SeccompBpfSubsetError("Only kill, errno, and allow returns are modeled")
        if (k & 0xFFFF0000) != SECCOMP_RET_ERRNO and (k & 0xFFFF):
            raise SeccompBpfSubsetError("Unexpected return-action data")
    else:
        raise SeccompBpfSubsetError("Unsupported BPF opcode")
    return {"code": code, "jt": jt, "jf": jf, "k": k}


def _validate_control_flow(program: list[dict]) -> None:
    length = len(program)
    visited: set[int] = set()

    def visit(pc: int) -> None:
        if pc >= length:
            raise SeccompBpfSubsetError("BPF branch falls beyond program")
        if pc in visited:
            return
        visited.add(pc)
        row = program[pc]
        if row["code"] == BPF_RET_K:
            return
        if row["code"] == BPF_LD_W_ABS:
            visit(pc + 1)
        else:
            visit(pc + 1 + row["jt"])
            visit(pc + 1 + row["jf"])

    visit(0)
    if len(visited) != length:
        raise SeccompBpfSubsetError("Unreachable BPF instruction")


def _evaluate(program: list[dict], arch: int, syscall_nr: int) -> tuple[str, int]:
    pc = 0
    accumulator = 0
    while True:
        row = program[pc]
        code = row["code"]
        if code == BPF_LD_W_ABS:
            accumulator = syscall_nr if row["k"] == 0 else arch
            pc += 1
        elif code == BPF_JMP_JEQ_K:
            pc += 1 + (row["jt"] if accumulator == row["k"] else row["jf"])
        else:
            action = row["k"] & 0xFFFF0000
            return ACTIONS[action], row["k"] & 0xFFFF


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "synthetic_fixture", "instructions", "cases"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise SeccompBpfSubsetError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise SeccompBpfSubsetError("Only synthetic fixtures are accepted")
    raw_program = core.bounded_list(model["instructions"], 64, "instructions")
    if not raw_program:
        raise SeccompBpfSubsetError("Nonempty BPF program required")
    program = [_instruction(row) for row in raw_program]
    _validate_control_flow(program)
    raw_cases = core.bounded_list(model["cases"], 32, "cases")
    if not raw_cases:
        raise SeccompBpfSubsetError("Nonempty synthetic cases required")
    seen: set[str] = set()
    results: list[dict] = []
    for value in raw_cases:
        case = core.exact(value, {"case_id", "arch", "syscall_nr"}, "case")
        case_id = core.identifier(case["case_id"], "case ID")
        if case_id in seen:
            raise SeccompBpfSubsetError("Duplicate case ID")
        seen.add(case_id)
        arch = _uint(case["arch"], 32, "architecture")
        syscall_nr = _uint(case["syscall_nr"], 32, "syscall number")
        action, action_data = _evaluate(program, arch, syscall_nr)
        results.append({
            "case_id": case_id,
            "declared_arch": arch,
            "declared_syscall_nr": syscall_nr,
            "projected_action": action,
            "projected_errno": action_data if action == "errno" else None,
        })
    results.sort(key=lambda row: row["case_id"])
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_id": COMMANDER_ID,
        "independent_validator_id": INDEPENDENT_VALIDATOR_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "synthetic_fixture_asserted": True,
        "instruction_count": len(program),
        "modeled_opcode_subset": ["ld_w_abs_nr_or_arch", "jmp_jeq_k", "ret_k"],
        "case_count": len(results),
        "cases": results,
        "candidate_count": 0,
        "uncertainty": [
            "kernel_filter_installation_and_composition_unobserved",
            "host_architecture_and_syscall_abi_unverified",
            "runtime_side_effects_and_sandbox_escape_unobserved",
        ],
        "unknown_count": 3,
        "disposition": "unknown",
        "source_authenticated": False,
        "kernel_behavior_verified": False,
        "sandbox_escape_verified": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Only a three-opcode, forward-branch classic-BPF subset is interpreted.",
            "Results are projections for supplied cases, not kernel enforcement claims.",
            "Filter stacking, arguments, user notification, and alternate ABIs are not modeled.",
            "No BPF filter is loaded and no syscall, VM, or target is executed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="SBR-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class SeccompBpfSubsetReport:
    """Unsigned BPF projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise SeccompBpfSubsetError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> SeccompBpfSubsetReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_seccomp_bpf_subset(model: Any) -> SeccompBpfSubsetReport:
    return SeccompBpfSubsetReport._owned(_derive(model))


def verify_supplied_seccomp_bpf_subset(
    report: Any, *, model: Any
) -> SeccompBpfSubsetReport:
    if type(report) is not SeccompBpfSubsetReport:
        raise SeccompBpfSubsetError("Exact seccomp wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise SeccompBpfSubsetError("Report differs from separate original model")
    return SeccompBpfSubsetReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-seccomp-bpf-subset",
        "synthetic_fixture": True,
        "instructions": [
            {"code": 0x20, "jt": 0, "jf": 0, "k": 4},
            {"code": 0x15, "jt": 0, "jf": 4, "k": 0xC000003E},
            {"code": 0x20, "jt": 0, "jf": 0, "k": 0},
            {"code": 0x15, "jt": 0, "jf": 1, "k": 59},
            {"code": 0x06, "jt": 0, "jf": 0, "k": 0x00050001},
            {"code": 0x06, "jt": 0, "jf": 0, "k": 0x7FFF0000},
            {"code": 0x06, "jt": 0, "jf": 0, "k": 0x80000000},
        ],
        "cases": [
            {"case_id": "x86-execve", "arch": 0xC000003E, "syscall_nr": 59},
            {"case_id": "x86-read", "arch": 0xC000003E, "syscall_nr": 0},
            {"case_id": "i386-read", "arch": 0x40000003, "syscall_nr": 0},
        ],
    }
