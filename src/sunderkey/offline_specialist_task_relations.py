"""Bounded unsigned conjunctions over separately replayed offline task evidence."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import offline_azure_nsg_analysis as azure
from . import offline_gcp_firewall_analysis as gcp
from . import offline_specialist_components as components
from . import offline_specialist_task as task

DOMAIN = "sunderkey.offline-specialist-task-relations.v1"
MODEL_DOMAIN = "sunderkey.offline-specialist-task-relations-model.v1"
COMPONENT_ID = "offline_specialist_task_declared_relations"
SEMANTICS_PROFILE = "unsigned-declared-premise-conjunction-dag.v1"
MAX_PREMISES = 32
MAX_HYPOTHESES = 16
MAX_DEPENDENCY_REFERENCES = 64
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 524_288
MAX_MODEL_NODES = 8_192
MAX_REPORT_NODES = 65_536
MAX_DEPTH = 16
MAX_STRING_BYTES = 512
MAX_ID_BYTES = 128
MAX_WORK = 134_217_728
MIN_INTEGER = -(1 << 63)
MAX_INTEGER = (1 << 63) - 1
MAX_TASK_BYTES = 8_388_608
MAX_TASK_NODES = 200_000
MAX_TASK_DEPTH = 80
MAX_CATALOG_BYTES = components.MAX_CATALOG_BYTES
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_SHA_PLACEHOLDER = "sha256:" + "0" * 64
_ID_PLACEHOLDER = "OTR-" + "0" * 32
_MATCH = "matches_declared_expectation"
_CONTRARY = "contradicts_declared_expectation"
_UNKNOWN = "unassessed"
_STATUSES = {_MATCH, _CONTRARY, _UNKNOWN}
_SUPPORTED = {
    gcp.COMPONENT_ID: {
        "profile_id": "AOE-GC-D14-S07",
        "analysis_prefix": "GCFA-",
        "decisions": {
            "allow_under_supplied_vpc_predicates",
            "deny_under_supplied_vpc_predicates",
        },
    },
    azure.COMPONENT_ID: {
        "profile_id": "AOE-GC-D14-S05",
        "analysis_prefix": "NSGA-",
        "decisions": {
            "allow_under_supplied_nsg_predicates",
            "deny_under_supplied_nsg_predicates",
            "not_filtered_by_declared_nsgs",
        },
    },
}
_MODEL_FIELDS = {"schema_version", "plan_id", "premises", "hypotheses"}
_PREMISE_FIELDS = {
    "premise_id",
    "job_id",
    "component_id",
    "source_model_sha256",
    "flow_id",
    "expected_decision",
}
_PREMISE_RESULT_FIELDS = _PREMISE_FIELDS | {
    "component_result_id",
    "component_result_sha256",
    "leaf_analysis_id",
    "leaf_analysis_sha256",
    "actual_decision",
    "leaf_observation",
    "status",
    "explanation",
}
_TASK_FIELDS = {
    "schema_version",
    "task_id",
    "model",
    "model_sha256",
    "catalog_id",
    "catalog_sha256",
    "jobs",
    "ownership_index",
    "job_count",
    "distinct_component_count",
    "distinct_profile_count",
    "input_provenance",
    "source_hash_profile",
    "bounds",
    "operational_effects",
    "offline_only",
    "full_candidate_assembled",
    "positive_use_approved",
    "qualification_claimed",
    "source_content_warning",
    "limitations",
    "task_result_id",
    "task_result_sha256",
}
_RESULT_FIELDS = {
    "schema_version",
    "catalog_id",
    "catalog_sha256",
    "component",
    "request_sha256",
    "input_provenance",
    "source_hash_profile",
    "analysis",
    "operational_effects",
    "full_candidate_assembled",
    "positive_use_approved",
    "result_id",
    "result_sha256",
}
_BINDING_FIELDS = {
    "task_id",
    "task_result_id",
    "task_result_sha256",
    "task_model_sha256",
    "catalog_id",
    "catalog_sha256",
    "job_count",
}
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "shared_target_proven",
        "identity_join_proven",
        "network_reachability_proven",
        "actionable_grant",
        "positive_use_approved",
        "qualification_claimed",
        "routing_approved",
        "deployment_approved",
    ),
    False,
)
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "target",
        "network",
        "provider",
        "credential",
        "process",
        "execution",
        "routing",
        "qualification",
        "deployment",
        "publication",
        "scheduling",
    ),
    "none",
)
_LIMITATIONS = [
    "Every premise and hypothesis is an unsigned caller declaration, not an observed pathway.",
    "Conjunction does not join targets, identities, tenants, addresses or network reachability.",
    "Only two fixed supplied-flow components and their exact declared decisions are supported.",
    "The original ordered plan is retained; derived displays are deterministic, not source order.",
    "Metadata exports do not verify task sources, leaf semantics or current catalog content.",
    "Current reconstruction requires the separate plan, exact task report, task model and catalog.",
    "One inherited task replay and a final catalog check use their separate existing budgets.",
    "Relation work funds its own processing and digests, not inherited algorithm or catalog work.",
    "Current source reads are development checks, not an atomic filesystem snapshot guarantee.",
    "Retained labels and observations are unsanitized and not safe publication "
    "or secret-free data.",
    "No candidate, live use, assignment, finding, scheduling or qualification approval follows.",
]
_REPORT_FIELDS = {
    "schema_version",
    "component_id",
    "semantics_profile",
    "roadmap_package_ids",
    "source_model",
    "source_model_sha256",
    "task_binding",
    "premise_observations",
    "hypothesis_observations",
    "evaluation_order",
    "summary",
    "flags",
    "effects",
    "bounds",
    "limitations",
    "analysis_id",
    "analysis_sha256",
}


class OfflineSpecialistTaskRelationsError(ValueError):
    """Closed input, finite cost, metadata or separate-current-source replay was denied."""


@dataclass(slots=True)
class _Work:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or amount > MAX_WORK - self.used:
            raise OfflineSpecialistTaskRelationsError("Relation operation work ceiling exceeded")
        self.used += amount


def _bounds() -> dict:
    return {
        "maximum_premises": MAX_PREMISES,
        "maximum_hypotheses": MAX_HYPOTHESES,
        "maximum_dependency_references": MAX_DEPENDENCY_REFERENCES,
        "maximum_model_bytes": MAX_MODEL_BYTES,
        "maximum_report_bytes": MAX_REPORT_BYTES,
        "maximum_model_nodes": MAX_MODEL_NODES,
        "maximum_report_nodes": MAX_REPORT_NODES,
        "maximum_scalar_inclusive_depth": MAX_DEPTH,
        "maximum_string_bytes": MAX_STRING_BYTES,
        "maximum_relation_work": MAX_WORK,
        "maximum_external_task_bytes": MAX_TASK_BYTES,
        "maximum_external_task_nodes": MAX_TASK_NODES,
        "maximum_external_task_depth": MAX_TASK_DEPTH,
        "maximum_external_catalog_bytes": MAX_CATALOG_BYTES,
        "maximum_inherited_task_replays": 1,
        "maximum_final_catalog_checks": 1,
        "inherited_work_accounting": "separate_existing_budgets",
    }


def _limits(kind: str) -> tuple[int, int, int, int, bool]:
    if kind == "model":
        return MAX_MODEL_BYTES, MAX_MODEL_NODES, MAX_DEPTH, MAX_STRING_BYTES, True
    if kind == "report":
        return MAX_REPORT_BYTES, MAX_REPORT_NODES, MAX_DEPTH, MAX_STRING_BYTES, True
    if kind == "catalog":
        return MAX_CATALOG_BYTES, MAX_TASK_NODES, MAX_TASK_DEPTH, MAX_TASK_BYTES, False
    return MAX_TASK_BYTES, MAX_TASK_NODES, MAX_TASK_DEPTH, MAX_TASK_BYTES, False


def _dump(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _capture(value: Any, work: _Work, kind: str) -> tuple[Any, str]:
    maximum, maximum_nodes, maximum_depth, maximum_string, ascii_only = _limits(kind)
    size = nodes = pending = 0
    active: set[int] = set()

    def reserve(amount: int) -> None:
        nonlocal size
        if amount > maximum - size:
            raise OfflineSpecialistTaskRelationsError("Canonical native byte ceiling exceeded")
        work.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes, pending
        nodes += 1
        work.charge(1)
        if nodes > maximum_nodes or depth > maximum_depth:
            raise OfflineSpecialistTaskRelationsError("Native node or depth ceiling exceeded")
        family = type(item)
        if family is str:
            if len(item) > maximum_string:
                raise OfflineSpecialistTaskRelationsError("Native string ceiling exceeded")
            escaped = 2
            for character in item:
                work.charge(1)
                number = ord(character)
                if 0xD800 <= number <= 0xDFFF or (ascii_only and not 32 <= number <= 126):
                    raise OfflineSpecialistTaskRelationsError("Unsupported native string profile")
                escaped += (
                    2
                    if character in '\\"\b\f\n\r\t'
                    else 6
                    if number < 32 or 127 <= number <= 0xFFFF
                    else 12
                    if number > 0xFFFF
                    else 1
                )
                if escaped > maximum - size:
                    raise OfflineSpecialistTaskRelationsError("Escaped native string exceeds bytes")
            reserve(escaped)
            return item
        if family is bool:
            reserve(4 if item else 5)
            return item
        if item is None:
            reserve(4)
            return None
        if family is int:
            if not MIN_INTEGER <= item <= MAX_INTEGER:
                raise OfflineSpecialistTaskRelationsError("Exact bounded signed int64 required")
            work.charge(20)
            reserve(len(str(item)))
            return item
        if family not in (dict, list):
            raise OfflineSpecialistTaskRelationsError("Exact native JSON families required")
        if id(item) in active:
            raise OfflineSpecialistTaskRelationsError("Native cycles are not supported")
        children = len(item) * (2 if family is dict else 1)
        if children > maximum_nodes - nodes - pending:
            raise OfflineSpecialistTaskRelationsError("Queued native node ceiling exceeded")
        reserve(2 + max(0, len(item) - 1) + (len(item) if family is dict else 0))
        work.charge(len(item) * max(1, len(item).bit_length()))
        pending += children
        active.add(id(item))
        try:
            if family is list:
                result = []
                for child in item:
                    pending -= 1
                    result.append(visit(child, depth + 1))
                return result
            result = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise OfflineSpecialistTaskRelationsError(
                        "Exact native object text keys required"
                    )
                pending -= 1
                owned_key = visit(key, depth + 1)
                pending -= 1
                result[owned_key] = visit(child, depth + 1)
            return result
        finally:
            active.remove(id(item))

    owned = visit(value, 1)
    work.charge(size + nodes)
    return owned, _dump(owned)


def _integer(token: str) -> int:
    if _NUMBER.fullmatch(token) is None:
        raise OfflineSpecialistTaskRelationsError("Bounded raw integer grammar required")
    negative = token.startswith("-")
    digits = token[1:] if negative else token
    limit = "9223372036854775808" if negative else "9223372036854775807"
    if len(digits) == 19 and digits > limit:
        raise OfflineSpecialistTaskRelationsError("Raw integer exceeds signed int64")
    return int(token)


def _decode(text: Any, work: _Work, kind: str) -> tuple[Any, str]:
    maximum, maximum_nodes, maximum_depth, maximum_string, ascii_only = _limits(kind)
    if type(text) is not str or not text or len(text) > maximum or not text.isascii():
        raise OfflineSpecialistTaskRelationsError("Bounded exact native ASCII JSON required")
    work.charge(len(text))
    index = nodes = canonical_size = 0
    stack: list[str] = []
    while index < len(text):
        character = text[index]
        if character in " \t\r\n":
            index += 1
            continue
        if character in ",:":
            canonical_size += 1
            index += 1
        elif character in "]}":
            if not stack or stack.pop() != ("[" if character == "]" else "{"):
                raise OfflineSpecialistTaskRelationsError("Malformed raw JSON containers")
            canonical_size += 1
            index += 1
        else:
            nodes += 1
            if nodes > maximum_nodes or len(stack) + 1 > maximum_depth:
                raise OfflineSpecialistTaskRelationsError(
                    "Predecoder node or depth ceiling exceeded"
                )
            if character in "[{":
                stack.append(character)
                canonical_size += 1
                index += 1
            elif character == '"':
                index += 1
                count = 0
                canonical_size += 2
                while True:
                    if index >= len(text):
                        raise OfflineSpecialistTaskRelationsError("Incomplete raw JSON string")
                    character = text[index]
                    if character == '"':
                        index += 1
                        break
                    work.charge(1)
                    number = ord(character)
                    if character == "\\":
                        index += 1
                        if index >= len(text):
                            raise OfflineSpecialistTaskRelationsError("Incomplete raw JSON escape")
                        marker = text[index]
                        if marker == "u":
                            digits = text[index + 1 : index + 5]
                            if len(digits) != 4 or any(
                                c not in "0123456789abcdefABCDEF" for c in digits
                            ):
                                raise OfflineSpecialistTaskRelationsError(
                                    "Invalid raw Unicode escape"
                                )
                            number = int(digits, 16)
                            index += 4
                            if 0xD800 <= number <= 0xDBFF:
                                pair = text[index + 1 : index + 7]
                                if (
                                    len(pair) != 6
                                    or not pair.startswith("\\u")
                                    or any(c not in "0123456789abcdefABCDEF" for c in pair[2:])
                                    or not 0xDC00 <= int(pair[2:], 16) <= 0xDFFF
                                ):
                                    raise OfflineSpecialistTaskRelationsError(
                                        "Invalid raw surrogate pair"
                                    )
                                number = 0x10000
                                index += 6
                            elif 0xDC00 <= number <= 0xDFFF:
                                raise OfflineSpecialistTaskRelationsError("Lone raw surrogate")
                        elif marker in '\\"/bfnrt':
                            number = ord(
                                {"b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}.get(
                                    marker, marker
                                )
                            )
                        else:
                            raise OfflineSpecialistTaskRelationsError("Invalid raw JSON escape")
                    elif number < 32:
                        raise OfflineSpecialistTaskRelationsError(
                            "Literal raw JSON control character"
                        )
                    if ascii_only and not 32 <= number <= 126:
                        raise OfflineSpecialistTaskRelationsError("Unsupported raw string profile")
                    canonical_size += (
                        2
                        if number in (8, 9, 10, 12, 13, 34, 92)
                        else 6
                        if number < 32 or 127 <= number <= 0xFFFF
                        else 12
                        if number > 0xFFFF
                        else 1
                    )
                    count += 1
                    if count > maximum_string or canonical_size > maximum:
                        raise OfflineSpecialistTaskRelationsError(
                            "Predecoder string byte ceiling exceeded"
                        )
                    index += 1
            else:
                start = index
                while index < len(text) and text[index] not in ' \t\r\n,:]}{["':
                    index += 1
                    if index - start > 20:
                        raise OfflineSpecialistTaskRelationsError(
                            "Raw scalar lexical ceiling exceeded"
                        )
                token = text[start:index]
                if token not in ("true", "false", "null"):
                    _integer(token)
                canonical_size += len(token)
        if canonical_size > maximum:
            raise OfflineSpecialistTaskRelationsError("Predecoder canonical byte ceiling exceeded")
    if stack:
        raise OfflineSpecialistTaskRelationsError("Incomplete raw JSON containers")
    # Own allocation, subsequent capture and equality work remain in this operation.
    work.charge(4 * len(text) + 2 * nodes)

    def pairs(rows: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, child in rows:
            if key in result:
                raise OfflineSpecialistTaskRelationsError("Duplicate raw JSON key")
            result[key] = child
        return result

    try:
        raw = json.loads(text, object_pairs_hook=pairs, parse_int=_integer)
    except (ValueError, RecursionError, OverflowError) as exc:
        raise OfflineSpecialistTaskRelationsError("Invalid bounded relation JSON") from exc
    return _capture(raw, work, kind)


def _bytes(content: Any, work: _Work, kind: str) -> tuple[Any, str]:
    maximum = _limits(kind)[0]
    if type(content) is not bytes or not content or len(content) > maximum:
        raise OfflineSpecialistTaskRelationsError("Bounded exact native input bytes required")
    work.charge(len(content))
    try:
        text = content.decode("ascii")
    except UnicodeDecodeError as exc:
        raise OfflineSpecialistTaskRelationsError("ASCII relation bytes required") from exc
    return _decode(text, work, kind)


def _object(value: Any, fields: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != fields:
        raise OfflineSpecialistTaskRelationsError(f"Exact closed {label} fields required")


def _identifier(value: Any) -> None:
    if type(value) is not str or len(value) > MAX_ID_BYTES or _ID.fullmatch(value) is None:
        raise OfflineSpecialistTaskRelationsError("Bounded native ASCII identifier required")


def _sha(value: Any) -> None:
    if type(value) is not str or _SHA.fullmatch(value) is None:
        raise OfflineSpecialistTaskRelationsError("Exact lowercase native digest required")


def _address_pair(identifier: Any, digest: Any, prefix: str) -> None:
    _sha(digest)
    if type(identifier) is not str or identifier != prefix + digest[7:39].upper():
        raise OfflineSpecialistTaskRelationsError("Declared content address pair is inconsistent")


def _same(first: Any, second: Any, work: _Work, kind: str = "report") -> None:
    _first, first_text = _capture(first, work, kind)
    _second, second_text = _capture(second, work, kind)
    work.charge(len(first_text) + len(second_text))
    if first_text != second_text:
        raise OfflineSpecialistTaskRelationsError("Exact canonical declared projection differs")


def _plan(value: Any, work: _Work) -> tuple[dict, str, list[str]]:
    if type(value) is not dict:
        raise OfflineSpecialistTaskRelationsError("Exact native relation model object required")
    model, text = _capture(value, work, "model")
    _object(model, _MODEL_FIELDS, "relation model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise OfflineSpecialistTaskRelationsError("Exact native relation schema 1 required")
    _identifier(model["plan_id"])
    premises, hypotheses = model["premises"], model["hypotheses"]
    if type(premises) is not list or not 1 <= len(premises) <= MAX_PREMISES:
        raise OfflineSpecialistTaskRelationsError("Bounded nonempty native premises required")
    if type(hypotheses) is not list or not 1 <= len(hypotheses) <= MAX_HYPOTHESES:
        raise OfflineSpecialistTaskRelationsError("Bounded nonempty native hypotheses required")
    premise_ids = set()
    for premise in premises:
        work.charge(16)
        _object(premise, _PREMISE_FIELDS, "premise")
        for name in ("premise_id", "job_id", "flow_id"):
            _identifier(premise[name])
        if premise["premise_id"] in premise_ids:
            raise OfflineSpecialistTaskRelationsError("Duplicate premise identity")
        premise_ids.add(premise["premise_id"])
        selected = premise["component_id"]
        if type(selected) is not str or selected not in _SUPPORTED:
            raise OfflineSpecialistTaskRelationsError(
                "Only the two fixed flow components supported"
            )
        _sha(premise["source_model_sha256"])
        if (
            type(premise["expected_decision"]) is not str
            or premise["expected_decision"] not in _SUPPORTED[selected]["decisions"]
        ):
            raise OfflineSpecialistTaskRelationsError(
                "Exact supported component expectation required"
            )
    by_id = {}
    references = 0
    for hypothesis in hypotheses:
        work.charge(8)
        _object(hypothesis, {"hypothesis_id", "dependencies"}, "hypothesis")
        identifier = hypothesis["hypothesis_id"]
        _identifier(identifier)
        if identifier in by_id:
            raise OfflineSpecialistTaskRelationsError("Duplicate hypothesis identity")
        by_id[identifier] = hypothesis
        dependencies = hypothesis["dependencies"]
        if (
            type(dependencies) is not list
            or not 1 <= len(dependencies) <= MAX_DEPENDENCY_REFERENCES
        ):
            raise OfflineSpecialistTaskRelationsError(
                "Nonempty bounded typed dependencies required"
            )
        seen = set()
        for reference in dependencies:
            references += 1
            work.charge(8)
            if references > MAX_DEPENDENCY_REFERENCES:
                raise OfflineSpecialistTaskRelationsError("Aggregate dependency ceiling exceeded")
            _object(reference, {"kind", "id"}, "dependency")
            if type(reference["kind"]) is not str or reference["kind"] not in {
                "premise",
                "hypothesis",
            }:
                raise OfflineSpecialistTaskRelationsError("Exact dependency namespace required")
            _identifier(reference["id"])
            identity = (reference["kind"], reference["id"])
            if identity in seen:
                raise OfflineSpecialistTaskRelationsError("Duplicate scoped dependency")
            seen.add(identity)
    for hypothesis in hypotheses:
        for reference in hypothesis["dependencies"]:
            known = premise_ids if reference["kind"] == "premise" else by_id
            if reference["id"] not in known:
                raise OfflineSpecialistTaskRelationsError("Missing scoped dependency")
    order = []
    resolved = set()
    while len(order) < len(by_id):
        work.charge(len(by_id) * (MAX_DEPENDENCY_REFERENCES + MAX_ID_BYTES))
        ready = sorted(
            identifier
            for identifier, hypothesis in by_id.items()
            if identifier not in resolved
            and all(
                reference["kind"] == "premise" or reference["id"] in resolved
                for reference in hypothesis["dependencies"]
            )
        )
        if not ready:
            raise OfflineSpecialistTaskRelationsError("Hypothesis dependency cycle")
        order.extend(ready)
        resolved.update(ready)
    return model, text, order


def parse_offline_specialist_task_relations_model(content: Any) -> dict:
    """Detach an exact bounded closed plan without parent, catalog, source or hash work."""
    work = _Work()
    return _plan(_bytes(content, work, "model")[0], work)[0]


def _wrapper_text(value: Any, family: type, work: _Work, kind: str) -> tuple[dict, str]:
    if type(value) is not family:
        raise OfflineSpecialistTaskRelationsError("Exact complete external wrapper family required")
    text = getattr(value, "document_json", None)
    document, canonical = _decode(text, work, kind)
    work.charge(len(text) + len(canonical))
    if text != canonical:
        raise OfflineSpecialistTaskRelationsError("External wrapper must retain canonical JSON")
    return document, canonical


def _task_inputs(
    model: Any, report: Any, catalog: Any, work: _Work
) -> tuple[dict, str, dict, str, dict, str]:
    original, original_text = _capture(model, work, "task")
    _object(original, {"schema_version", "task_id", "jobs"}, "original task")
    if type(original["schema_version"]) is not int or original["schema_version"] != 1:
        raise OfflineSpecialistTaskRelationsError("Exact original task schema 1 required")
    _identifier(original["task_id"])
    jobs = original["jobs"]
    if type(jobs) is not list or not 1 <= len(jobs) <= task.MAX_JOBS:
        raise OfflineSpecialistTaskRelationsError("Bounded original task jobs required")
    seen = set()
    envelope = {
        "schema_version",
        "profile_id",
        "environment",
        "action_tier",
        "dry_run",
        "credential_refs",
        "resources",
        "payload",
    }
    for job in jobs:
        _object(job, {"job_id", "request"}, "original job")
        _identifier(job["job_id"])
        if job["job_id"] in seen:
            raise OfflineSpecialistTaskRelationsError("Duplicate original task job")
        seen.add(job["job_id"])
        request = job["request"]
        if type(request) is not dict or request.keys() not in (
            envelope,
            envelope | {"component_id"},
        ):
            raise OfflineSpecialistTaskRelationsError("Closed original request envelope required")
        if (
            type(request["schema_version"]) is not int
            or request["schema_version"] != 1
            or type(request["dry_run"]) is not bool
            or request["dry_run"] is not True
        ):
            raise OfflineSpecialistTaskRelationsError("Native inert original envelope required")
        _identifier(request["profile_id"])
        if (
            type(request["action_tier"]) is not str
            or request["action_tier"] != "R0"
            or type(request["environment"]) is not str
            or request["environment"] not in {"synthetic", "supplied_inert_data"}
        ):
            raise OfflineSpecialistTaskRelationsError("Declared inert request scope required")
        _same(request["credential_refs"], [], work, "task")
        _same(
            request["resources"],
            {"network": [], "filesystem": [], "process": [], "credential": []},
            work,
            "task",
        )
        if type(request["payload"]) is not dict:
            raise OfflineSpecialistTaskRelationsError("Exact original payload object required")
    document, report_text = _wrapper_text(report, task.OfflineSpecialistTaskResult, work, "task")
    _object(document, _TASK_FIELDS, "external task report")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise OfflineSpecialistTaskRelationsError("Exact external task report schema required")
    for name in ("job_count", "distinct_component_count", "distinct_profile_count"):
        if type(document[name]) is not int or not 1 <= document[name] <= task.MAX_JOBS:
            raise OfflineSpecialistTaskRelationsError("Native external task counters required")
    if (
        type(document["task_id"]) is not str
        or document["task_id"] != original["task_id"]
        or document["job_count"] != len(jobs)
    ):
        raise OfflineSpecialistTaskRelationsError("External task identity or job count differs")
    for name, expected in (
        ("offline_only", True),
        ("full_candidate_assembled", False),
        ("positive_use_approved", False),
        ("qualification_claimed", False),
    ):
        if type(document[name]) is not bool or document[name] is not expected:
            raise OfflineSpecialistTaskRelationsError(
                "Native nonpromoting external task flags required"
            )
    _same(document["model"], original, work, "task")
    _address_pair(document["task_result_id"], document["task_result_sha256"], "OST-")
    _sha(document["model_sha256"])
    current, catalog_text = _wrapper_text(
        catalog, components.OfflineSpecialistComponentCatalog, work, "catalog"
    )
    if type(current) is not dict or "catalog_id" not in current or "catalog_sha256" not in current:
        raise OfflineSpecialistTaskRelationsError("External catalog identity is missing")
    _address_pair(current["catalog_id"], current["catalog_sha256"], "OSC-")
    if (
        document["catalog_id"] != current["catalog_id"]
        or document["catalog_sha256"] != current["catalog_sha256"]
    ):
        raise OfflineSpecialistTaskRelationsError("Original task and supplied catalog differ")
    return original, original_text, document, report_text, current, catalog_text


def _join(plan: dict, original: dict, document: dict, work: _Work) -> dict[str, tuple[dict, dict]]:
    work.charge(16 * (len(original["jobs"]) + len(plan["premises"])))
    requests = {row["job_id"]: row["request"] for row in original["jobs"]}
    rows = document["jobs"]
    if type(rows) is not list or len(rows) != len(requests):
        raise OfflineSpecialistTaskRelationsError("Exact external task job set required")
    results = {}
    for row, identifier in zip(rows, sorted(requests), strict=True):
        _object(row, {"job_id", "result"}, "external task job")
        if type(row["job_id"]) is not str or row["job_id"] != identifier:
            raise OfflineSpecialistTaskRelationsError("External task job identity/order differs")
        results[identifier] = row["result"]
    selected = {}
    for premise in plan["premises"]:
        work.charge(32)
        job_id, component_id = premise["job_id"], premise["component_id"]
        if job_id not in requests:
            raise OfflineSpecialistTaskRelationsError("Premise original job is missing")
        request, result = requests[job_id], results[job_id]
        expected_profile = _SUPPORTED[component_id]["profile_id"]
        selector = request.get(
            "component_id", components.PROFILE_DEFAULT_COMPONENTS.get(request["profile_id"])
        )
        if (
            request["profile_id"] != expected_profile
            or type(selector) is not str
            or selector != component_id
        ):
            raise OfflineSpecialistTaskRelationsError(
                "Premise component is not owned by its original job"
            )
        _object(request["payload"], {"model"}, "fixed flow payload")
        _object(result, _RESULT_FIELDS, "external component result")
        if (
            type(result["schema_version"]) is not int
            or result["schema_version"] != 1
            or result["catalog_id"] != document["catalog_id"]
            or result["catalog_sha256"] != document["catalog_sha256"]
        ):
            raise OfflineSpecialistTaskRelationsError(
                "External component schema or catalog differs"
            )
        descriptor = result["component"]
        if (
            type(descriptor) is not dict
            or descriptor.get("component_id") != component_id
            or descriptor.get("profile_id") != expected_profile
        ):
            raise OfflineSpecialistTaskRelationsError("Premise external component identity differs")
        analysis = result["analysis"]
        if type(analysis) is not dict or analysis.get("component_id") != component_id:
            raise OfflineSpecialistTaskRelationsError("Premise external leaf identity differs")
        if type(analysis.get("schema_version")) is not int or analysis["schema_version"] != 1:
            raise OfflineSpecialistTaskRelationsError("Native leaf schema required")
        _same(analysis.get("source_model"), request["payload"]["model"], work, "task")
        _sha(analysis.get("source_model_sha256"))
        if analysis["source_model_sha256"] != premise["source_model_sha256"]:
            raise OfflineSpecialistTaskRelationsError("Premise exact leaf source pin differs")
        source_flows = (
            request["payload"]["model"].get("flows")
            if type(request["payload"]["model"]) is dict
            else None
        )
        observations = analysis.get("flow_observations")
        if type(source_flows) is not list or type(observations) is not list:
            raise OfflineSpecialistTaskRelationsError(
                "Original flow and observation collections required"
            )
        work.charge(4 * (len(source_flows) + len(observations)))
        source_ids = [row.get("flow_id") for row in source_flows if type(row) is dict]
        found = [
            row
            for row in observations
            if type(row) is dict and row.get("flow_id") == premise["flow_id"]
        ]
        if source_ids.count(premise["flow_id"]) != 1 or len(found) != 1:
            raise OfflineSpecialistTaskRelationsError(
                "Premise exact original flow is missing or ambiguous"
            )
        selected[premise["premise_id"]] = result, found[0]
    return selected


def _status(actual: str, expected: str) -> tuple[str, str]:
    if actual == _UNKNOWN:
        return _UNKNOWN, "leaf_decision_unassessed"
    if actual == expected:
        return _MATCH, "exact_supported_decision_matches"
    return _CONTRARY, "exact_supported_decision_differs"


def _binding(document: dict) -> dict:
    return {
        "task_id": document["task_id"],
        "task_result_id": document["task_result_id"],
        "task_result_sha256": document["task_result_sha256"],
        "task_model_sha256": document["model_sha256"],
        "catalog_id": document["catalog_id"],
        "catalog_sha256": document["catalog_sha256"],
        "job_count": document["job_count"],
    }


def _binding_shape(value: Any) -> None:
    _object(value, _BINDING_FIELDS, "task binding")
    _identifier(value["task_id"])
    _address_pair(value["task_result_id"], value["task_result_sha256"], "OST-")
    _address_pair(value["catalog_id"], value["catalog_sha256"], "OSC-")
    _sha(value["task_model_sha256"])
    if type(value["job_count"]) is not int or not 1 <= value["job_count"] <= task.MAX_JOBS:
        raise OfflineSpecialistTaskRelationsError("Native bounded task binding count required")


def _observation_shape(
    observation: Any, component_id: str, flow_id: str, decision: str, work: _Work
) -> None:
    fields = (
        {
            "flow_id",
            "network_id",
            "target_id",
            "direction",
            "decision",
            "reason",
            "candidate_priority",
            "matched_rules",
            "possible_rules",
            "winning_rule_ids",
            "winning_witnesses_complete",
        }
        if component_id == gcp.COMPONENT_ID
        else {"flow_id", "direction", "layer_order", "layers", "decision", "uncertainty"}
    )
    _object(observation, fields, "retained leaf observation")
    if (
        type(observation["flow_id"]) is not str
        or observation["flow_id"] != flow_id
        or type(observation["decision"]) is not str
        or observation["decision"] != decision
    ):
        raise OfflineSpecialistTaskRelationsError("Retained flow and decision join differs")
    if component_id == gcp.COMPONENT_ID:
        for name in ("network_id", "target_id"):
            _identifier(observation[name])
        if (
            type(observation["direction"]) is not str
            or observation["direction"] not in {"INGRESS", "EGRESS"}
            or type(observation["reason"]) is not str
        ):
            raise OfflineSpecialistTaskRelationsError("Native retained flow metadata required")
        if type(observation["winning_witnesses_complete"]) is not bool:
            raise OfflineSpecialistTaskRelationsError("Native retained witness flag required")
        priority = observation["candidate_priority"]
        if priority is not None and (type(priority) is not int or not 0 <= priority <= 65535):
            raise OfflineSpecialistTaskRelationsError("Native retained priority required")
        for name in ("matched_rules", "possible_rules", "winning_rule_ids"):
            if type(observation[name]) is not list or len(observation[name]) > gcp.MAX_RULES:
                raise OfflineSpecialistTaskRelationsError("Bounded retained witnesses required")
            work.charge(16 * len(observation[name]))
            for witness in observation[name]:
                if name == "winning_rule_ids":
                    _identifier(witness)
                    continue
                _object(
                    witness,
                    {"rule_id", "priority", "action", "reasons"}
                    if name == "possible_rules"
                    else {"rule_id", "priority", "action"},
                    "retained witness",
                )
                _identifier(witness["rule_id"])
                if (
                    type(witness["priority"]) is not int
                    or not 0 <= witness["priority"] <= 65535
                    or type(witness["action"]) is not str
                    or witness["action"] not in {"allow", "deny"}
                ):
                    raise OfflineSpecialistTaskRelationsError(
                        "Native retained witness primitives required"
                    )
                if name == "possible_rules" and (
                    type(witness["reasons"]) is not list
                    or not 1 <= len(witness["reasons"]) <= 2
                    or any(type(reason) is not str for reason in witness["reasons"])
                ):
                    raise OfflineSpecialistTaskRelationsError(
                        "Native retained witness reasons required"
                    )
    else:
        if (
            type(observation["layers"]) is not list
            or len(observation["layers"]) != 2
            or type(observation["layer_order"]) is not list
            or observation["layer_order"] not in (["subnet", "nic"], ["nic", "subnet"])
            or type(observation["uncertainty"]) is not list
            or len(observation["uncertainty"]) > 2
        ):
            raise OfflineSpecialistTaskRelationsError("Native retained layer metadata required")
        if (
            type(observation["direction"]) is not str
            or observation["direction"] not in {"Inbound", "Outbound"}
            or any(type(reason) is not str for reason in observation["uncertainty"])
        ):
            raise OfflineSpecialistTaskRelationsError("Native retained layer metadata required")
        work.charge(32 * len(observation["layers"]))
        for layer in observation["layers"]:
            _object(
                layer,
                {
                    "layer",
                    "nsg_id",
                    "decision",
                    "reason",
                    "candidate_rule_id",
                    "candidate_priority",
                    "candidate_declared_access",
                },
                "retained layer",
            )
            if (
                type(layer["layer"]) is not str
                or layer["layer"] not in {"subnet", "nic"}
                or type(layer["decision"]) is not str
                or layer["decision"] not in {"allow", "deny", "unassessed", "not_attached"}
                or type(layer["reason"]) is not str
            ):
                raise OfflineSpecialistTaskRelationsError(
                    "Native retained layer primitives required"
                )
            for name in ("nsg_id", "candidate_rule_id"):
                if layer[name] is not None:
                    _identifier(layer[name])
            priority = layer["candidate_priority"]
            if priority is not None and (type(priority) is not int or not 100 <= priority <= 65535):
                raise OfflineSpecialistTaskRelationsError("Native retained layer priority required")
            access = layer["candidate_declared_access"]
            if access is not None and (type(access) is not str or access not in {"Allow", "Deny"}):
                raise OfflineSpecialistTaskRelationsError("Native retained layer access required")


def _premise_shape(row: Any, premise: dict, work: _Work) -> None:
    _object(row, _PREMISE_RESULT_FIELDS, "premise observation")
    _same({key: row[key] for key in _PREMISE_FIELDS}, premise, work)
    _address_pair(row["component_result_id"], row["component_result_sha256"], "OSR-")
    _address_pair(
        row["leaf_analysis_id"],
        row["leaf_analysis_sha256"],
        _SUPPORTED[premise["component_id"]]["analysis_prefix"],
    )
    actual = row["actual_decision"]
    if type(actual) is not str or actual not in _SUPPORTED[premise["component_id"]]["decisions"] | {
        _UNKNOWN
    }:
        raise OfflineSpecialistTaskRelationsError("Exact retained component decision required")
    _observation_shape(
        row["leaf_observation"], premise["component_id"], premise["flow_id"], actual, work
    )
    status, explanation = _status(actual, premise["expected_decision"])
    if (
        type(row["status"]) is not str
        or row["status"] != status
        or type(row["explanation"]) is not str
        or row["explanation"] != explanation
    ):
        raise OfflineSpecialistTaskRelationsError(
            "Premise status or explanation contradicts declarations"
        )


def _body(plan: dict, binding: dict, premises: list[dict], order: list[str], work: _Work) -> dict:
    _binding_shape(binding)
    if type(premises) is not list or len(premises) != len(plan["premises"]):
        raise OfflineSpecialistTaskRelationsError("Exact premise observation set required")
    work.charge(16 * len(premises) + MAX_ID_BYTES * len(plan["hypotheses"]))
    sorted_original = sorted(plan["premises"], key=lambda row: row["premise_id"])
    statuses = {}
    for row, premise in zip(premises, sorted_original, strict=True):
        _premise_shape(row, premise, work)
        statuses[("premise", row["premise_id"])] = row["status"]
    original_hypotheses = {row["hypothesis_id"]: row for row in plan["hypotheses"]}
    hypotheses = {}
    for identifier in order:
        original = original_hypotheses[identifier]
        work.charge(16 * len(original["dependencies"]) + MAX_ID_BYTES)
        dependencies = [
            {**reference, "status": statuses[(reference["kind"], reference["id"])]}
            for reference in sorted(
                original["dependencies"], key=lambda row: (row["kind"], row["id"])
            )
        ]
        dependency_statuses = {row["status"] for row in dependencies}
        if _CONTRARY in dependency_statuses:
            status, explanation = _CONTRARY, "dependency_contradiction"
        elif _UNKNOWN in dependency_statuses:
            status, explanation = _UNKNOWN, "dependency_unassessed"
        else:
            status, explanation = _MATCH, "all_dependencies_match"
        hypotheses[identifier] = {
            "hypothesis_id": identifier,
            "dependencies": dependencies,
            "status": status,
            "explanation": explanation,
        }
        statuses[("hypothesis", identifier)] = status

    def counts(rows: list[dict]) -> dict:
        return {
            "total": len(rows),
            **{
                status: sum(row["status"] == status for row in rows) for status in sorted(_STATUSES)
            },
        }

    displayed_hypotheses = [hypotheses[identifier] for identifier in sorted(hypotheses)]
    return {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "semantics_profile": SEMANTICS_PROFILE,
        "roadmap_package_ids": ["A2.4", "A2.13", "A7.4"],
        "source_model": plan,
        "source_model_sha256": _SHA_PLACEHOLDER,
        "task_binding": binding,
        "premise_observations": premises,
        "hypothesis_observations": displayed_hypotheses,
        "evaluation_order": order,
        "summary": {
            "premises": counts(premises),
            "hypotheses": counts(displayed_hypotheses),
            "dependency_references": sum(len(row["dependencies"]) for row in displayed_hypotheses),
        },
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "bounds": _bounds(),
        "limitations": list(_LIMITATIONS),
        "analysis_id": _ID_PLACEHOLDER,
        "analysis_sha256": _SHA_PLACEHOLDER,
    }


def _final_catalog_check(document: dict, repository_root: str | Path) -> None:
    try:
        components.OfflineSpecialistComponentCatalog.from_dict(
            document, repository_root=repository_root
        )
    except components.OfflineSpecialistComponentError as exc:
        raise OfflineSpecialistTaskRelationsError(
            "Final current catalog source validation failed"
        ) from exc


def _hash(domain: str, text: str) -> str:
    return "sha256:" + hashlib.sha256((domain + "\n" + text).encode("ascii")).hexdigest()


def _seal(
    body: dict,
    source_text: str,
    work: _Work,
    supplied: str | None = None,
    *,
    catalog_document: dict | None = None,
    repository_root: str | Path | None = None,
) -> tuple[dict, str]:
    owned, placeholder_text = _capture(body, work, "report")
    unsigned = {
        key: value for key, value in owned.items() if key not in {"analysis_id", "analysis_sha256"}
    }
    _unsigned, unsigned_text = _capture(unsigned, work, "report")
    # Fixed-width placeholders fund every own final pass before either relation digest.
    work.charge(
        3 * len(source_text)
        + 4 * len(unsigned_text)
        + len(placeholder_text)
        + 3 * (len(DOMAIN) + len(MODEL_DOMAIN) + 2)
    )
    if supplied is not None:
        work.charge(len(supplied) + len(placeholder_text))
    if catalog_document is not None:
        _final_catalog_check(catalog_document, repository_root)
    source_digest = _hash(MODEL_DOMAIN, source_text)
    owned["source_model_sha256"] = source_digest
    unsigned["source_model_sha256"] = source_digest
    digest = _hash(DOMAIN, _dump(unsigned))
    owned["analysis_id"] = "OTR-" + digest[7:39].upper()
    owned["analysis_sha256"] = digest
    text = _dump(owned)
    if supplied is not None and supplied != text:
        raise OfflineSpecialistTaskRelationsError(
            "Relation report differs from complete original derivation"
        )
    return owned, text


def _derive(
    model: Any,
    *,
    task_report: Any,
    task_model: Any,
    catalog: Any,
    repository_root: str | Path,
    work: _Work,
    supplied: str | None = None,
) -> tuple[dict, str]:
    plan, source_text, order = _plan(model, work)
    original, _original_text, document, original_report_text, catalog_document, catalog_text = (
        _task_inputs(task_model, task_report, catalog, work)
    )
    _join(plan, original, document, work)
    delivered_model, _text = _capture(original, work, "task")
    delivered_report = task.OfflineSpecialistTaskResult._owned(original_report_text)
    delivered_catalog = components.OfflineSpecialistComponentCatalog(catalog_text)
    try:
        verified = task.verify_offline_specialist_task(
            delivered_report,
            model=delivered_model,
            catalog=delivered_catalog,
            repository_root=repository_root,
        )
    except components.OfflineSpecialistComponentError as exc:
        raise OfflineSpecialistTaskRelationsError(
            "Original task/current source replay failed"
        ) from exc
    current, current_text = _wrapper_text(verified, task.OfflineSpecialistTaskResult, work, "task")
    work.charge(len(current_text) + len(original_report_text))
    if current_text != original_report_text:
        raise OfflineSpecialistTaskRelationsError("Full returned task report differs from original")
    _same(delivered_model, original, work, "task")
    _delivered_document, delivered_report_text = _wrapper_text(
        delivered_report, task.OfflineSpecialistTaskResult, work, "task"
    )
    _delivered_catalog_document, delivered_catalog_text = _wrapper_text(
        delivered_catalog, components.OfflineSpecialistComponentCatalog, work, "catalog"
    )
    work.charge(
        len(delivered_report_text)
        + len(original_report_text)
        + len(delivered_catalog_text)
        + len(catalog_text)
    )
    if delivered_report_text != original_report_text or delivered_catalog_text != catalog_text:
        raise OfflineSpecialistTaskRelationsError("Owned external delivery context changed")
    selected = _join(plan, original, current, work)
    premises = []
    for premise in sorted(plan["premises"], key=lambda row: row["premise_id"]):
        result, observation = selected[premise["premise_id"]]
        analysis = result["analysis"]
        actual = observation.get("decision")
        if type(actual) is not str or actual not in _SUPPORTED[premise["component_id"]][
            "decisions"
        ] | {_UNKNOWN}:
            raise OfflineSpecialistTaskRelationsError(
                "Verified leaf decision is outside fixed relation profile"
            )
        status, explanation = _status(actual, premise["expected_decision"])
        row = {
            **premise,
            "component_result_id": result["result_id"],
            "component_result_sha256": result["result_sha256"],
            "leaf_analysis_id": analysis["analysis_id"],
            "leaf_analysis_sha256": analysis["analysis_sha256"],
            "actual_decision": actual,
            "leaf_observation": observation,
            "status": status,
            "explanation": explanation,
        }
        _row, row_text = _capture(row, work, "report")
        work.charge(len(row_text))
        premises.append(_row)
        _capture({"source_model": plan, "premise_observations": premises}, work, "report")
    body = _body(plan, _binding(current), premises, order, work)
    return _seal(
        body,
        source_text,
        work,
        supplied,
        catalog_document=catalog_document,
        repository_root=repository_root,
    )


def _report_shape(document: dict, work: _Work) -> tuple[dict, str, list[str]]:
    _object(document, _REPORT_FIELDS, "relation report")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise OfflineSpecialistTaskRelationsError("Exact native report schema 1 required")
    _binding_shape(document["task_binding"])
    _address_pair(document["analysis_id"], document["analysis_sha256"], "OTR-")
    _sha(document["source_model_sha256"])
    _same(document["flags"], _FLAGS, work)
    _same(document["effects"], _EFFECTS, work)
    return _plan(document["source_model"], work)


def _storage(report: Any, work: _Work) -> tuple[dict, str]:
    if type(report) is not OfflineSpecialistTaskRelations:
        raise OfflineSpecialistTaskRelationsError("Exact native complete relation wrapper required")
    text = getattr(report, "document_json", None)
    document, canonical = _decode(text, work, "report")
    work.charge(len(canonical) + len(text))
    if text != canonical:
        raise OfflineSpecialistTaskRelationsError("Relation wrapper must retain canonical JSON")
    return document, canonical


def _metadata(report: Any, work: _Work) -> tuple[dict, str]:
    document, supplied = _storage(report, work)
    plan, source_text, order = _report_shape(document, work)
    body = _body(plan, document["task_binding"], document["premise_observations"], order, work)
    return _seal(body, source_text, work, supplied)


def _reconstruct(
    document: Any,
    model: Any,
    *,
    task_report: Any,
    task_model: Any,
    catalog: Any,
    repository_root: str | Path,
    work: _Work,
) -> tuple[dict, str]:
    owned, supplied = _capture(document, work, "report")
    plan, _source_text, order = _report_shape(owned, work)
    separate, _separate_text, _separate_order = _plan(model, work)
    _same(plan, separate, work, "model")
    metadata = _body(plan, owned["task_binding"], owned["premise_observations"], order, work)
    placeholders = {
        **owned,
        "source_model_sha256": _SHA_PLACEHOLDER,
        "analysis_id": _ID_PLACEHOLDER,
        "analysis_sha256": _SHA_PLACEHOLDER,
    }
    _same(metadata, placeholders, work)
    return _derive(
        separate,
        task_report=task_report,
        task_model=task_model,
        catalog=catalog,
        repository_root=repository_root,
        work=work,
        supplied=supplied,
    )


@dataclass(frozen=True, slots=True, init=False)
class OfflineSpecialistTaskRelations:
    """Detached relation metadata; only explicit original/current replay verifies use."""

    document_json: str

    def __init__(self, _document_json: Any = None) -> None:
        raise OfflineSpecialistTaskRelationsError(
            "Use derivation or separate-current-source parsers"
        )

    @classmethod
    def _owned(cls, text: str) -> OfflineSpecialistTaskRelations:
        if cls is not OfflineSpecialistTaskRelations:
            raise OfflineSpecialistTaskRelationsError("Exact native relation family required")
        result = object.__new__(cls)
        object.__setattr__(result, "document_json", text)
        return result

    @classmethod
    def from_dict(
        cls,
        document: Any,
        *,
        model: Any,
        task_report: Any,
        task_model: Any,
        catalog: Any,
        repository_root: str | Path,
    ) -> OfflineSpecialistTaskRelations:
        if cls is not OfflineSpecialistTaskRelations:
            raise OfflineSpecialistTaskRelationsError("Exact native relation family required")
        _document, text = _reconstruct(
            document,
            model,
            task_report=task_report,
            task_model=task_model,
            catalog=catalog,
            repository_root=repository_root,
            work=_Work(),
        )
        return cls._owned(text)

    @classmethod
    def from_json(
        cls,
        document_json: Any,
        *,
        model: Any,
        task_report: Any,
        task_model: Any,
        catalog: Any,
        repository_root: str | Path,
    ) -> OfflineSpecialistTaskRelations:
        if cls is not OfflineSpecialistTaskRelations:
            raise OfflineSpecialistTaskRelationsError("Exact native relation family required")
        work = _Work()
        document, _text = _decode(document_json, work, "report")
        _document, text = _reconstruct(
            document,
            model,
            task_report=task_report,
            task_model=task_model,
            catalog=catalog,
            repository_root=repository_root,
            work=work,
        )
        return cls._owned(text)

    def to_dict(self) -> dict:
        return _metadata(self, _Work())[0]

    def to_json(self) -> str:
        return _metadata(self, _Work())[1]


def analyze_offline_specialist_task_relations(
    model: Any, *, task_report: Any, task_model: Any, catalog: Any, repository_root: str | Path
) -> OfflineSpecialistTaskRelations:
    _document, text = _derive(
        model,
        task_report=task_report,
        task_model=task_model,
        catalog=catalog,
        repository_root=repository_root,
        work=_Work(),
    )
    return OfflineSpecialistTaskRelations._owned(text)


def analyze_offline_specialist_task_relations_bytes(
    *,
    model_bytes: Any,
    task_report: Any,
    task_model: Any,
    catalog: Any,
    repository_root: str | Path,
) -> OfflineSpecialistTaskRelations:
    work = _Work()
    model, _text = _bytes(model_bytes, work, "model")
    _document, text = _derive(
        model,
        task_report=task_report,
        task_model=task_model,
        catalog=catalog,
        repository_root=repository_root,
        work=work,
    )
    return OfflineSpecialistTaskRelations._owned(text)


def verify_offline_specialist_task_relations(
    report: Any,
    *,
    model: Any,
    task_report: Any,
    task_model: Any,
    catalog: Any,
    repository_root: str | Path,
) -> OfflineSpecialistTaskRelations:
    work = _Work()
    document, _text = _storage(report, work)
    _document, text = _reconstruct(
        document,
        model,
        task_report=task_report,
        task_model=task_model,
        catalog=catalog,
        repository_root=repository_root,
        work=work,
    )
    return OfflineSpecialistTaskRelations._owned(text)


def task_fixture() -> dict:
    """Fresh two-job inert source models; no catalog, task result or algorithm is produced."""

    def request(profile: str, component: str, model: dict) -> dict:
        return {
            "schema_version": 1,
            "profile_id": profile,
            "component_id": component,
            "environment": "synthetic",
            "action_tier": "R0",
            "dry_run": True,
            "credential_refs": [],
            "resources": {"network": [], "filesystem": [], "process": [], "credential": []},
            "payload": {"model": model},
        }

    return {
        "schema_version": 1,
        "task_id": "synthetic.declared-flow-premises",
        "jobs": [
            {
                "job_id": "gcp",
                "request": request("AOE-GC-D14-S07", gcp.COMPONENT_ID, gcp.component_fixture()),
            },
            {
                "job_id": "azure",
                "request": request("AOE-GC-D14-S05", azure.COMPONENT_ID, azure.component_fixture()),
            },
        ],
    }


def component_fixture() -> dict:
    """Fresh catalog-independent plan; stable leaf source pins are not source authenticity."""

    def premise(
        identifier: str, job: str, component: str, digest: str, flow: str, expected: str
    ) -> dict:
        return {
            "premise_id": identifier,
            "job_id": job,
            "component_id": component,
            "source_model_sha256": digest,
            "flow_id": flow,
            "expected_decision": expected,
        }

    return {
        "schema_version": 1,
        "plan_id": "synthetic.declared-flow-conjunctions",
        "premises": [
            premise(
                "gcp.ingress",
                "gcp",
                gcp.COMPONENT_ID,
                "sha256:5c9cfab6bd6d73292c098d1e5440967ac6ff73a48964e9c557c4e8b26e8c9806",
                "synthetic-ingress",
                "allow_under_supplied_vpc_predicates",
            ),
            premise(
                "azure.inbound",
                "azure",
                azure.COMPONENT_ID,
                "sha256:5b86106d482a0ab104104c983cc0554addc26651b8d1d34bd743d3249438cbad",
                "synthetic-inbound",
                "allow_under_supplied_nsg_predicates",
            ),
            premise(
                "gcp.egress",
                "gcp",
                gcp.COMPONENT_ID,
                "sha256:5c9cfab6bd6d73292c098d1e5440967ac6ff73a48964e9c557c4e8b26e8c9806",
                "synthetic-egress",
                "deny_under_supplied_vpc_predicates",
            ),
            premise(
                "azure.outbound",
                "azure",
                azure.COMPONENT_ID,
                "sha256:5b86106d482a0ab104104c983cc0554addc26651b8d1d34bd743d3249438cbad",
                "synthetic-outbound",
                "allow_under_supplied_nsg_predicates",
            ),
        ],
        "hypotheses": [
            {
                "hypothesis_id": "known",
                "dependencies": [
                    {"kind": "premise", "id": "gcp.ingress"},
                    {"kind": "premise", "id": "azure.inbound"},
                ],
            },
            {
                "hypothesis_id": "unknown",
                "dependencies": [
                    {"kind": "premise", "id": "gcp.egress"},
                    {"kind": "premise", "id": "azure.outbound"},
                ],
            },
            {
                "hypothesis_id": "overall",
                "dependencies": [
                    {"kind": "hypothesis", "id": "known"},
                    {"kind": "hypothesis", "id": "unknown"},
                ],
            },
        ],
    }


__all__ = [
    "OfflineSpecialistTaskRelations",
    "OfflineSpecialistTaskRelationsError",
    "analyze_offline_specialist_task_relations",
    "analyze_offline_specialist_task_relations_bytes",
    "verify_offline_specialist_task_relations",
    "parse_offline_specialist_task_relations_model",
    "component_fixture",
    "task_fixture",
]
