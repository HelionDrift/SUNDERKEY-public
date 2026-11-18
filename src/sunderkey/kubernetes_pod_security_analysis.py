"""Bounded, nonauthoritative reasoning over five supplied Linux Pod controls."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_NODES = 32768
MAX_DEPTH = 16
MAX_STRING_LENGTH = 256
MAX_CONTAINERS = 64
MAX_CAPABILITIES = 64
MAX_WORK = 8192
MAX_INTEGER = (1 << 63) - 1

MODEL_DOMAIN = "SUNDERKEY:SUPPLIED-LINUX-POD-SECURITY-MODEL:V1"
REPORT_DOMAIN = "SUNDERKEY:SUPPLIED-LINUX-POD-SECURITY-ANALYSIS:V1"
BENCHMARK_VERSION = "kubernetes-v1.34-linux-restricted-core"
COMPONENT_ID = "kubernetes_supplied_linux_pod_security_controls"
PROFILE_ID = "AOE-GC-D15-S05"
CAPABILITY_ID = "army.gc.d15.s05"
VECTOR_ID = "AV-GC-D15-S05-01"
WAVE_ID = "IW2-007"
BLUEPRINT_SHA256 = "sha256:234e287aec5569750d2e7b4a4e30b213a37c2656bfb56cabf975ee2b676a0510"

_CONTROLS = (
    "run_as_non_root",
    "run_as_user",
    "allow_privilege_escalation",
    "seccomp_profile",
    "capabilities",
)
_ROLES = ("containers", "init_containers", "ephemeral_containers")
_POD_CONTEXT = {"run_as_non_root", "run_as_user", "seccomp_profile"}
_CONTAINER_CONTEXT = _POD_CONTEXT | {"allow_privilege_escalation", "capabilities"}
_MODEL_FIELDS = {"schema_version", "benchmark_version", "pod"}
_POD_FIELDS = {
    "pod_ref",
    "os_name",
    "host_users",
    "security_context",
    *_ROLES,
}
_EXCLUSIONS = (
    "all_other_baseline_and_restricted_controls",
    "kubernetes_api_validation_and_cluster_policy_configuration",
    "privileged_host_namespaces_host_ports_and_host_paths",
    "volume_types_apparmor_selinux_proc_mount_and_sysctls",
    "host_probes_lifecycle_hooks_and_windows_controls",
    "user_namespace_relaxation_and_feature_gate_state",
    "image_uid_and_actual_process_credentials",
    "capability_name_availability_and_runtime_application",
    "localhost_seccomp_profile_existence_and_application",
    "cluster_admission_runtime_isolation_and_live_authority",
)
_SOURCES = (
    "https://v1-34.docs.kubernetes.io/docs/concepts/security/pod-security-standards/",
    "https://v1-34.docs.kubernetes.io/docs/concepts/workloads/pods/user-namespaces/",
)
_FALSE_FLAGS = (
    "full_pss_verified",
    "kubernetes_api_validity_verified",
    "cluster_admission_proven",
    "runtime_isolation_proven",
    "image_uid_verified",
    "capability_availability_verified",
    "source_authenticated",
    "live_use_approved",
    "qualification_claimed",
)
_EFFECTS = (
    "network",
    "process",
    "provider",
    "credential",
    "target",
    "deployment",
    "authorization",
    "qualification",
)
_REPORT_FIELDS = {
    "schema_version",
    "component_id",
    "profile_id",
    "capability_id",
    "vector_id",
    "wave_id",
    "blueprint_sha256",
    "benchmark_version",
    "analysis_scope",
    "source_model",
    "model_sha256",
    "outcome",
    "controls",
    "unsupported_reasons",
    "summary",
    "exclusions",
    "primary_sources",
    "flags",
    "effects",
    "bounds",
    "analysis_id",
    "analysis_sha256",
}
_INTEGER_TOKEN = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z", re.ASCII)


class PodSecurityAnalysisError(ValueError):
    """The declared model, bounded input, or exact report replay was rejected."""


class _Cost:
    def __init__(self) -> None:
        self.nodes = 0
        self.bytes = 0
        self.pending = 0

    def charge(self, *, nodes: int = 0, size: int = 0) -> None:
        self.nodes += nodes
        self.bytes += size
        if self.nodes > MAX_NODES or self.bytes > MAX_DOCUMENT_BYTES:
            raise PodSecurityAnalysisError("Native document exceeds its aggregate budget")


def _capture(value: Any) -> tuple[Any, int, int]:
    """Capture exact native JSON families, charging repeated graphs before copying."""
    cost = _Cost()
    active: set[int] = set()

    def visit(item: Any, depth: int) -> Any:
        if depth > MAX_DEPTH:
            raise PodSecurityAnalysisError("Native document exceeds its depth budget")
        cost.charge(nodes=1)
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_LENGTH:
                raise PodSecurityAnalysisError("Native string exceeds its length budget")
            size = len(item) + 2
            for character in item:
                if not 32 <= ord(character) <= 126:
                    raise PodSecurityAnalysisError("Strings require printable ASCII")
                if character in {'"', "\\"}:
                    size += 1
            cost.charge(size=size)
            return item
        if kind is bool:
            cost.charge(size=4 if item else 5)
            return item
        if item is None:
            cost.charge(size=4)
            return None
        if kind is int:
            if item.bit_length() > 63 or abs(item) > MAX_INTEGER:
                raise PodSecurityAnalysisError("Integer exceeds the finite native magnitude")
            cost.charge(size=len(str(item)))
            return item
        if kind not in {dict, list}:
            raise PodSecurityAnalysisError("Only exact native JSON families are supported")
        identity = id(item)
        if identity in active:
            raise PodSecurityAnalysisError("Cyclic native documents are unsupported")
        children = len(item) * (2 if kind is dict else 1)
        if cost.nodes + cost.pending + children > MAX_NODES:
            raise PodSecurityAnalysisError("Native collection exceeds its queue budget")
        cost.charge(size=2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
        active.add(identity)
        cost.pending += children
        try:
            if kind is list:
                result = []
                for child in item:
                    cost.pending -= 1
                    result.append(visit(child, depth + 1))
            else:
                result = {}
                for key, child in item.items():
                    if type(key) is not str:
                        raise PodSecurityAnalysisError("Object keys require native strings")
                    cost.pending -= 1
                    captured_key = visit(key, depth + 1)
                    cost.pending -= 1
                    result[captured_key] = visit(child, depth + 1)
            return result
        finally:
            active.remove(identity)

    owned = visit(value, 1)
    return owned, cost.nodes, cost.bytes


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
    )


def _digest(domain: str, value: Any) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            domain.encode("ascii") + b"\x00" + _canonical(value).encode("ascii")
        ).hexdigest()
    )


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PodSecurityAnalysisError("Duplicate JSON object fields are unsupported")
        result[key] = value
    return result


def _unsupported_number(value: str) -> Any:
    raise PodSecurityAnalysisError("Floating point and nonfinite JSON numbers are unsupported")


def _decode(text: Any) -> Any:
    """Bound lexical JSON structure, strings and numbers before the real decoder."""
    if type(text) is not str or len(text) > MAX_DOCUMENT_BYTES or not text.isascii():
        raise PodSecurityAnalysisError("JSON requires bounded native ASCII text")
    position = 0
    nodes = 0
    stack: list[str] = []
    while position < len(text):
        character = text[position]
        if character in " \t\r\n,:":
            position += 1
            continue
        if character in "{[":
            stack.append(character)
            nodes += 1
            if len(stack) > MAX_DEPTH:
                raise PodSecurityAnalysisError("JSON exceeds its depth budget")
            position += 1
        elif character in "}]":
            if not stack or (stack.pop(), character) not in {("{", "}"), ("[", "]")}:
                raise PodSecurityAnalysisError("JSON delimiters are malformed")
            position += 1
        elif character == '"':
            if len(stack) + 1 > MAX_DEPTH:
                raise PodSecurityAnalysisError("JSON scalar exceeds its depth budget")
            nodes += 1
            position += 1
            length = 0
            while position < len(text) and text[position] != '"':
                character = text[position]
                if character == "\\":
                    position += 1
                    if position >= len(text):
                        raise PodSecurityAnalysisError("JSON escape is incomplete")
                    escaped = text[position]
                    if escaped == "u":
                        digits = text[position + 1 : position + 5]
                        if len(digits) != 4 or any(
                            c not in "0123456789abcdefABCDEF" for c in digits
                        ):
                            raise PodSecurityAnalysisError("JSON escape is malformed")
                        if not 32 <= int(digits, 16) <= 126:
                            raise PodSecurityAnalysisError("JSON strings require printable ASCII")
                        position += 4
                    elif escaped not in {'"', "\\", "/"}:
                        raise PodSecurityAnalysisError("JSON strings require printable ASCII")
                elif not 32 <= ord(character) <= 126:
                    raise PodSecurityAnalysisError("JSON strings require printable ASCII")
                length += 1
                if length > MAX_STRING_LENGTH:
                    raise PodSecurityAnalysisError("JSON string exceeds its decoded length budget")
                position += 1
            if position >= len(text):
                raise PodSecurityAnalysisError("JSON string is incomplete")
            position += 1
        else:
            if len(stack) + 1 > MAX_DEPTH:
                raise PodSecurityAnalysisError("JSON scalar exceeds its depth budget")
            nodes += 1
            start = position
            while position < len(text) and text[position] not in " \t\r\n,:{}[]":
                position += 1
            token = text[start:position]
            if token not in {"true", "false", "null"}:
                if _INTEGER_TOKEN.fullmatch(token) is None or token == "-0":
                    raise PodSecurityAnalysisError("JSON scalar is outside the supported grammar")
                digits = token[1:] if token.startswith("-") else token
                maximum = str(MAX_INTEGER)
                if len(digits) > len(maximum) or (len(digits) == len(maximum) and digits > maximum):
                    raise PodSecurityAnalysisError("JSON integer exceeds its finite magnitude")
        if nodes > MAX_NODES:
            raise PodSecurityAnalysisError("JSON exceeds its aggregate node budget")
    if stack:
        raise PodSecurityAnalysisError("JSON delimiters are incomplete")
    try:
        return json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_float=_unsupported_number,
            parse_constant=_unsupported_number,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, PodSecurityAnalysisError):
            raise
        raise PodSecurityAnalysisError("JSON document is malformed") from None


def _fields(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected:
        raise PodSecurityAnalysisError(f"{label} has missing or unsupported fields")
    return value


def _reference(value: Any, label: str) -> str:
    if type(value) is not str or not value.strip():
        raise PodSecurityAnalysisError(f"{label} requires a nonblank native string")
    return value


def _nullable_bool(value: Any, label: str) -> None:
    if value is not None and type(value) is not bool:
        raise PodSecurityAnalysisError(f"{label} requires native boolean or null")


def _seccomp(value: Any) -> None:
    if value is None:
        return
    _fields(value, {"type", "localhost_profile"}, "Seccomp profile")
    _reference(value["type"], "Seccomp type")
    if value["localhost_profile"] is not None:
        _reference(value["localhost_profile"], "Localhost profile declaration")


def _capabilities(value: Any) -> None:
    if value is None:
        return
    _fields(value, {"add", "drop"}, "Capabilities")
    for name in ("add", "drop"):
        items = value[name]
        if type(items) is not list or len(items) > MAX_CAPABILITIES:
            raise PodSecurityAnalysisError("Capability array exceeds its native bound")
        seen: set[str] = set()
        for item in items:
            _reference(item, "Capability declaration")
            if item in seen:
                raise PodSecurityAnalysisError("Duplicate capability declaration")
            seen.add(item)


def _context(value: Any, *, container: bool) -> None:
    _fields(value, _CONTAINER_CONTEXT if container else _POD_CONTEXT, "Security context")
    _nullable_bool(value["run_as_non_root"], "run_as_non_root")
    uid = value["run_as_user"]
    if uid is not None and (type(uid) is not int or not 0 <= uid <= MAX_INTEGER):
        raise PodSecurityAnalysisError("run_as_user requires nonnegative native integer or null")
    _seccomp(value["seccomp_profile"])
    if container:
        _nullable_bool(value["allow_privilege_escalation"], "allow_privilege_escalation")
        _capabilities(value["capabilities"])


def _prepare(value: Any) -> tuple[dict[str, Any], list[tuple[str, dict[str, Any]]]]:
    model, _, _ = _capture(value)
    _fields(model, _MODEL_FIELDS, "Pod security model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise PodSecurityAnalysisError("Model schema version requires native integer one")
    if model["benchmark_version"] != BENCHMARK_VERSION:
        raise PodSecurityAnalysisError("Benchmark version is outside the fixed profile")
    pod = _fields(model["pod"], _POD_FIELDS, "Pod projection")
    _reference(pod["pod_ref"], "Pod reference")
    if type(pod["os_name"]) is not str or pod["os_name"] not in {"linux", "windows", "unknown"}:
        raise PodSecurityAnalysisError("OS name is outside the declared profile")
    _nullable_bool(pod["host_users"], "host_users")
    _context(pod["security_context"], container=False)
    containers: list[tuple[str, dict[str, Any]]] = []
    identities: set[str] = set()
    for role in _ROLES:
        items = pod[role]
        if type(items) is not list or len(items) > MAX_CONTAINERS:
            raise PodSecurityAnalysisError("Container array exceeds its native bound")
        if role == "containers" and not items:
            raise PodSecurityAnalysisError("At least one application container is required")
        if len(containers) + len(items) > MAX_CONTAINERS:
            raise PodSecurityAnalysisError("Total container count exceeds its bound")
        for index, item in enumerate(items):
            _fields(item, {"container_ref", "security_context"}, "Container projection")
            identity = _reference(item["container_ref"], "Container reference")
            if identity in identities:
                raise PodSecurityAnalysisError("Container references must be globally unique")
            identities.add(identity)
            _context(item["security_context"], container=True)
            containers.append((f"pod.{role}[{index}].security_context", item["security_context"]))
    return model, containers


def _unsupported(model: dict, containers: list[tuple[str, dict]]) -> list[dict[str, str]]:
    pod = model["pod"]
    result = []
    if pod["os_name"] != "linux":
        result.append({"source_path": "pod.os_name", "code": "non_linux_outside_subset"})
    if pod["host_users"] is False:
        result.append({"source_path": "pod.host_users", "code": "user_namespace_outside_subset"})
    for path, context in [("pod.security_context", pod["security_context"]), *containers]:
        profile = context["seccomp_profile"]
        if profile is None:
            continue
        kind = profile["type"]
        local = profile["localhost_profile"]
        if kind not in {"RuntimeDefault", "Localhost", "Unconfined"} or (
            (kind == "Localhost" and local is None) or (kind != "Localhost" and local is not None)
        ):
            result.append(
                {
                    "source_path": f"{path}.seccomp_profile",
                    "code": "seccomp_configuration_outside_subset",
                }
            )
    return result


class _Output:
    def __init__(self, template: dict[str, Any]) -> None:
        _, self.nodes, self.bytes = _capture(template)
        self.work = 0

    def charge_work(self, amount: int) -> None:
        self.work += amount
        if self.work > MAX_WORK:
            raise PodSecurityAnalysisError("Control evaluation exceeds its work budget")

    def append(self, destination: list, record: dict[str, Any]) -> None:
        self.charge_work(1)
        owned, nodes, size = _capture(record)
        # The empty destination array is already charged; one comma per record is conservative.
        self.nodes += nodes
        self.bytes += size + 1
        if self.nodes > MAX_NODES or self.bytes > MAX_DOCUMENT_BYTES:
            raise PodSecurityAnalysisError("Report exceeds its cumulative output budget")
        destination.append(owned)


def _derive(value: Any) -> dict[str, Any]:
    model, containers = _prepare(value)
    pod = model["pod"]
    pod_context = pod["security_context"]
    unsupported = _unsupported(model, containers)
    controls = [{"control_id": name, "outcome": "not_assessed", "checks": []} for name in _CONTROLS]
    by_name = {item["control_id"]: item for item in controls}
    summary = {
        "container_count": len(containers),
        "application_container_count": len(pod["containers"]),
        "init_container_count": len(pod["init_containers"]),
        "ephemeral_container_count": len(pod["ephemeral_containers"]),
        "evaluated_check_count": MAX_INTEGER,
        "violation_count": MAX_INTEGER,
        "violated_control_count": MAX_INTEGER,
        "work_steps": MAX_INTEGER,
    }
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "wave_id": WAVE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "benchmark_version": BENCHMARK_VERSION,
        "analysis_scope": "supplied_linux_pod_five_controls_only",
        "source_model": model,
        "model_sha256": "sha256:" + "0" * 64,
        "outcome": "x" * 64,
        "controls": controls,
        "unsupported_reasons": unsupported,
        "summary": summary,
        "exclusions": list(_EXCLUSIONS),
        "primary_sources": list(_SOURCES),
        "flags": {"offline_only": True, **dict.fromkeys(_FALSE_FLAGS, False)},
        "effects": dict.fromkeys(_EFFECTS, "none"),
        "bounds": {
            "maximum_document_bytes": MAX_DOCUMENT_BYTES,
            "maximum_nodes": MAX_NODES,
            "maximum_depth": MAX_DEPTH,
            "maximum_string_length": MAX_STRING_LENGTH,
            "maximum_containers": MAX_CONTAINERS,
            "maximum_capabilities_per_array": MAX_CAPABILITIES,
            "maximum_work_steps": MAX_WORK,
            "maximum_integer": MAX_INTEGER,
        },
        "analysis_id": "PSA-" + "0" * 32,
        "analysis_sha256": "sha256:" + "0" * 64,
    }
    output = _Output(body)

    def check(
        control: str,
        path: str,
        declared: Any,
        effective_path: str,
        effective: Any,
        satisfied: bool,
        reason: str,
    ) -> None:
        output.append(
            by_name[control]["checks"],
            {
                "source_path": path,
                "declared_value": declared,
                "effective_source_path": effective_path,
                "effective_value": effective,
                "outcome": "satisfied" if satisfied else "violated",
                "reason": reason,
            },
        )

    if not unsupported:
        root_path = "pod.security_context"
        for name in ("run_as_non_root", "run_as_user", "seccomp_profile"):
            declared = pod_context[name]
            if name == "run_as_non_root":
                valid = declared is not False
            elif name == "run_as_user":
                valid = declared is None or declared != 0
            else:
                valid = declared is None or declared["type"] in {"RuntimeDefault", "Localhost"}
            check(
                name,
                f"{root_path}.{name}",
                declared,
                f"{root_path}.{name}",
                declared,
                valid,
                "allowed_pod_declaration" if valid else "explicit_pod_value_forbidden",
            )
        for path, context in containers:
            for name in ("run_as_non_root", "run_as_user", "seccomp_profile"):
                declared = context[name]
                effective = declared if declared is not None else pod_context[name]
                effective_path = f"{path}.{name}" if declared is not None else f"{root_path}.{name}"
                if name == "run_as_non_root":
                    valid = effective is True
                    reason = "non_root_required"
                elif name == "run_as_user":
                    # This control forbids explicit zero, not a guessed image or effective UID.
                    valid = declared is None or declared != 0
                    reason = "explicit_uid_zero_forbidden"
                else:
                    valid = effective is not None and effective["type"] in {
                        "RuntimeDefault",
                        "Localhost",
                    }
                    reason = "allowed_seccomp_required"
                check(
                    name,
                    f"{path}.{name}",
                    declared,
                    effective_path,
                    effective,
                    valid,
                    "supported_declaration_satisfied" if valid else reason,
                )
            escalation = context["allow_privilege_escalation"]
            check(
                "allow_privilege_escalation",
                f"{path}.allow_privilege_escalation",
                escalation,
                f"{path}.allow_privilege_escalation",
                escalation,
                escalation is False,
                "supported_declaration_satisfied"
                if escalation is False
                else "explicit_false_required",
            )
            caps = context["capabilities"]
            for name in ("drop", "add"):
                declared = None if caps is None else caps[name]
                output.charge_work(0 if declared is None else len(declared))
                valid = (
                    declared is not None and "ALL" in declared
                    if name == "drop"
                    else declared is None or all(item == "NET_BIND_SERVICE" for item in declared)
                )
                reason = (
                    "drop_all_required" if name == "drop" else "additional_capability_forbidden"
                )
                check(
                    "capabilities",
                    f"{path}.capabilities.{name}",
                    declared,
                    f"{path}.capabilities.{name}",
                    declared,
                    valid,
                    "supported_declaration_satisfied" if valid else reason,
                )
        for item in controls:
            item["outcome"] = (
                "violated"
                if any(c["outcome"] == "violated" for c in item["checks"])
                else "satisfied"
            )
    summary["evaluated_check_count"] = sum(len(item["checks"]) for item in controls)
    summary["violation_count"] = sum(
        check["outcome"] == "violated" for item in controls for check in item["checks"]
    )
    summary["violated_control_count"] = sum(item["outcome"] == "violated" for item in controls)
    summary["work_steps"] = output.work
    body["outcome"] = (
        "unsupported"
        if unsupported
        else "violates_supported_controls"
        if summary["violation_count"]
        else "satisfies_supported_controls"
    )
    # Fixed-width digest placeholders and conservative counters were charged before retention.
    _capture(body)
    body["model_sha256"] = _digest(MODEL_DOMAIN, model)
    payload = {
        key: value for key, value in body.items() if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = _digest(REPORT_DOMAIN, payload)
    body["analysis_id"] = "PSA-" + digest[7:39].upper()
    body["analysis_sha256"] = digest
    return body


def _replay_report(value: Any) -> dict[str, Any]:
    document, _, _ = _capture(value)
    _fields(document, _REPORT_FIELDS, "Pod security analysis")
    rebuilt = _derive(document["source_model"])
    if _canonical(document) != _canonical(rebuilt):
        raise PodSecurityAnalysisError("Analysis does not exactly replay its declared source model")
    return rebuilt


class PodSecurityAnalysis:
    """Detached immutable storage with full native/source replay on every public read."""

    __slots__ = ("_document_json",)

    def __init__(self, document: Any) -> None:
        object.__setattr__(self, "_document_json", _canonical(_replay_report(document)))

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("Pod security analyses are immutable")

    @classmethod
    def from_dict(cls, document: Any) -> PodSecurityAnalysis:
        if cls is not PodSecurityAnalysis:
            raise PodSecurityAnalysisError("Exact analysis wrapper family is required")
        return cls(document)

    @classmethod
    def from_json(cls, document_json: Any) -> PodSecurityAnalysis:
        return cls.from_dict(_decode(document_json))

    def to_dict(self) -> dict[str, Any]:
        if type(self) is not PodSecurityAnalysis:
            raise PodSecurityAnalysisError("Exact analysis wrapper family is required")
        try:
            stored = object.__getattribute__(self, "_document_json")
        except AttributeError:
            raise PodSecurityAnalysisError("Analysis wrapper is incomplete") from None
        return _replay_report(_decode(stored))

    def to_json(self) -> str:
        return _canonical(self.to_dict())

    @property
    def analysis_id(self) -> str:
        return self.to_dict()["analysis_id"]

    @property
    def analysis_sha256(self) -> str:
        return self.to_dict()["analysis_sha256"]


def _owned(document: dict[str, Any]) -> PodSecurityAnalysis:
    result = object.__new__(PodSecurityAnalysis)
    object.__setattr__(result, "_document_json", _canonical(document))
    return result


def analyze_supplied_kubernetes_pod_security(model: Any) -> PodSecurityAnalysis:
    """Evaluate only the five supported supplied Linux declarations, with no callbacks."""
    return _owned(_derive(model))


def analyze_supplied_kubernetes_pod_security_bytes(*, model_bytes: Any) -> PodSecurityAnalysis:
    """Decode only bounded native ASCII JSON bytes, then apply the identical analyzer."""
    if type(model_bytes) is not bytes or len(model_bytes) > MAX_DOCUMENT_BYTES:
        raise PodSecurityAnalysisError("Model bytes require bounded native bytes")
    try:
        model_json = model_bytes.decode("ascii")
    except UnicodeDecodeError:
        raise PodSecurityAnalysisError("Model bytes require ASCII JSON") from None
    return analyze_supplied_kubernetes_pod_security(_decode(model_json))


def verify_supplied_kubernetes_pod_security_analysis(
    report: Any, *, model: Any
) -> PodSecurityAnalysis:
    """Rejoin an exact replayed report to separately supplied original declarations."""
    if type(report) is not PodSecurityAnalysis:
        raise PodSecurityAnalysisError("Exact analysis wrapper family is required")
    # Validate the separately supplied input before report replay performs any new hashing.
    original, _ = _prepare(model)
    document = report.to_dict()
    rebuilt = _derive(original)
    if _canonical(document) != _canonical(rebuilt):
        raise PodSecurityAnalysisError(
            "Analysis does not match the separately supplied original model"
        )
    return _owned(rebuilt)
