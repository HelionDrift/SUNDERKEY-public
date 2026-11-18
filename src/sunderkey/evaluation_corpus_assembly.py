"""Deterministic evaluation corpus assembly and contamination checks.

This module accepts caller-supplied records in memory. It does not discover or
read files, contact a provider, invoke a model, execute a subprocess, access a
target, authorize an action, or produce a qualification result.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any

SCHEMA_VERSION = 1
MANIFEST_VERSION = "1.0.0"
CONTRACT_DOMAIN = "sunderkey.evaluation-corpus-assembly.v1"

CORPUS_PARTITIONS = (
    "public",
    "private_holdout",
    "adversarial_safety",
    "regression",
    "pilot",
)
HOLDOUT_PARTITIONS = frozenset({"private_holdout", "adversarial_safety"})

NO_EFFECTS = {
    "authority": "none",
    "evaluation_execution": "none",
    "model_calls": "none",
    "network": "none",
    "provider_calls": "none",
    "qualification": "none",
    "routing": "none",
    "target_access": "none",
}

LIMITATIONS = (
    "receipt_does_not_authorize_corpus_access_or_evaluation",
    "hashed_shingle_similarity_is_an_indicator_not_a_semantic_judgment",
    "caller_is_responsible_for_source_and_provenance_digest_truthfulness",
    "receipt_does_not_store_or_recover_corpus_content",
)

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[+.-][A-Za-z0-9][A-Za-z0-9.-]*)?\Z")
TOKEN_RE = re.compile(r"[A-Za-z0-9]+")
MOVING_VERSIONS = frozenset({"current", "head", "latest", "main", "master", "tip"})


class EvaluationCorpusAssemblyError(ValueError):
    """Raised when corpus assembly or receipt verification fails closed."""


def canonical_json(value: Any) -> str:
    """Return canonical printable ASCII JSON after bounded type validation."""

    _validate_json_value(value, "value")
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise EvaluationCorpusAssemblyError("value cannot be serialized") from exc


def canonical_sha256(value: Any) -> str:
    """Return a SHA-256 digest over canonical JSON."""

    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _validate_json_value(value: Any, label: str, *, depth: int = 0) -> None:
    if depth > 12:
        raise EvaluationCorpusAssemblyError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{label}[{index}]", depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise EvaluationCorpusAssemblyError(f"{label} contains a non-string key")
            _validate_json_value(item, f"{label}.{key}", depth=depth + 1)
        return
    raise EvaluationCorpusAssemblyError(f"{label} contains an unsupported value")


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvaluationCorpusAssemblyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _exact_fields(raw: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise EvaluationCorpusAssemblyError(f"{label} fields do not match the contract")
    return raw


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise EvaluationCorpusAssemblyError(f"{label} must be a safe identifier")
    return value


def _version(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or VERSION_RE.fullmatch(value) is None
        or value.lower() in MOVING_VERSIONS
    ):
        raise EvaluationCorpusAssemblyError(f"{label} must be an exact immutable version")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise EvaluationCorpusAssemblyError(f"{label} must be a sha256 digest")
    return value


def _bounded_int(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise EvaluationCorpusAssemblyError(
            f"{label} must be an integer from {minimum} through {maximum}"
        )
    return value


@dataclass(frozen=True)
class CorpusAssemblyBudgets:
    """Hard resource ceilings for a single deterministic assembly operation."""

    maximum_records: int = 2_000
    maximum_total_content_bytes: int = 32 * 1024 * 1024
    maximum_content_bytes_per_record: int = 256 * 1024
    maximum_tokens_per_record: int = 4_096
    maximum_pair_comparisons: int = 2_000_000
    maximum_findings: int = 50_000
    maximum_fingerprint_components: int = 512
    near_duplicate_threshold_basis_points: int = 8_000

    def __post_init__(self) -> None:
        ceilings = {
            "maximum_records": (self.maximum_records, 1, 100_000),
            "maximum_total_content_bytes": (
                self.maximum_total_content_bytes,
                1,
                2**40,
            ),
            "maximum_content_bytes_per_record": (
                self.maximum_content_bytes_per_record,
                1,
                2**30,
            ),
            "maximum_tokens_per_record": (self.maximum_tokens_per_record, 3, 1_000_000),
            "maximum_pair_comparisons": (
                self.maximum_pair_comparisons,
                1,
                5_000_000_000,
            ),
            "maximum_findings": (self.maximum_findings, 1, 5_000_000),
            "maximum_fingerprint_components": (
                self.maximum_fingerprint_components,
                1,
                65_536,
            ),
            "near_duplicate_threshold_basis_points": (
                self.near_duplicate_threshold_basis_points,
                1,
                10_000,
            ),
        }
        for label, (value, minimum, maximum) in ceilings.items():
            _bounded_int(value, label, minimum=minimum, maximum=maximum)
        if self.maximum_content_bytes_per_record > self.maximum_total_content_bytes:
            raise EvaluationCorpusAssemblyError(
                "maximum_content_bytes_per_record cannot exceed the total byte budget"
            )

    @classmethod
    def from_dict(cls, raw: Any) -> CorpusAssemblyBudgets:
        fields = {
            "maximum_records",
            "maximum_total_content_bytes",
            "maximum_content_bytes_per_record",
            "maximum_tokens_per_record",
            "maximum_pair_comparisons",
            "maximum_findings",
            "maximum_fingerprint_components",
            "near_duplicate_threshold_basis_points",
        }
        values = _exact_fields(raw, fields, "budgets")
        return cls(**{field: values[field] for field in fields})

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


@dataclass(frozen=True)
class CorpusInputRecord:
    """One caller-supplied local corpus record."""

    record_id: str
    record_version: str
    partition: str
    source_id: str
    source_version: str
    source_sha256: str
    provenance_sha256: str
    content: str

    def __post_init__(self) -> None:
        _identifier(self.record_id, "record_id")
        _version(self.record_version, "record_version")
        if self.partition not in CORPUS_PARTITIONS:
            raise EvaluationCorpusAssemblyError("partition is not recognized")
        _identifier(self.source_id, "source_id")
        _version(self.source_version, "source_version")
        _sha256(self.source_sha256, "source_sha256")
        _sha256(self.provenance_sha256, "provenance_sha256")
        if not isinstance(self.content, str) or not self.content:
            raise EvaluationCorpusAssemblyError("content must be nonempty caller-supplied text")

    @classmethod
    def from_dict(cls, raw: Any) -> CorpusInputRecord:
        fields = {
            "record_id",
            "record_version",
            "partition",
            "source_id",
            "source_version",
            "source_sha256",
            "provenance_sha256",
            "content",
        }
        values = _exact_fields(raw, fields, "input record")
        return cls(**{field: values[field] for field in fields})


@dataclass(frozen=True)
class EvaluationCorpusAssemblyReceipt:
    """Validated, content-addressed assembly receipt."""

    manifest_id: str
    manifest_sha256: str
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json, object_pairs_hook=_strict_json_object)

    @classmethod
    def from_dict(cls, raw: Any) -> EvaluationCorpusAssemblyReceipt:
        document = _verify_receipt_document(raw)
        return cls(
            manifest_id=document["manifest_id"],
            manifest_sha256=document["manifest_sha256"],
            document_json=canonical_json(document),
        )

    @classmethod
    def from_json(cls, payload: str) -> EvaluationCorpusAssemblyReceipt:
        if not isinstance(payload, str):
            raise EvaluationCorpusAssemblyError("receipt JSON must be text")
        try:
            raw = json.loads(payload, object_pairs_hook=_strict_json_object)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise EvaluationCorpusAssemblyError("receipt JSON is invalid") from exc
        return cls.from_dict(raw)


def _normalized_tokens(content: str, maximum_tokens: int) -> tuple[str, ...]:
    tokens = tuple(match.group(0).lower() for match in TOKEN_RE.finditer(content))
    if len(tokens) < 3:
        raise EvaluationCorpusAssemblyError(
            "content must contain at least three alphanumeric tokens"
        )
    if len(tokens) > maximum_tokens:
        raise EvaluationCorpusAssemblyError("content exceeds the token budget")
    return tokens


def _fingerprint_components(tokens: tuple[str, ...], maximum_components: int) -> tuple[str, ...]:
    components = {
        "sha256:"
        + hashlib.sha256(
            ("sunderkey.corpus-shingle.v1\0" + tokens[index] + "\0" + tokens[index + 1]).encode(
                "utf-8"
            )
        ).hexdigest()
        for index in range(len(tokens) - 1)
    }
    return tuple(sorted(components)[:maximum_components])


def _record_manifest(record: CorpusInputRecord, budgets: CorpusAssemblyBudgets) -> dict[str, Any]:
    content_bytes = record.content.encode("utf-8")
    if len(content_bytes) > budgets.maximum_content_bytes_per_record:
        raise EvaluationCorpusAssemblyError("content exceeds the per-record byte budget")
    tokens = _normalized_tokens(record.content, budgets.maximum_tokens_per_record)
    components = _fingerprint_components(tokens, budgets.maximum_fingerprint_components)
    body = {
        "record_id": record.record_id,
        "record_version": record.record_version,
        "partition": record.partition,
        "source_id": record.source_id,
        "source_version": record.source_version,
        "source_sha256": record.source_sha256,
        "provenance_sha256": record.provenance_sha256,
        "content_sha256": "sha256:" + hashlib.sha256(content_bytes).hexdigest(),
        "content_bytes": len(content_bytes),
        "token_count": len(tokens),
        "fingerprint_component_sha256s": list(components),
    }
    body["fingerprint_sha256"] = canonical_sha256(
        {
            "domain": "sunderkey.corpus-fingerprint.v1",
            "components": body["fingerprint_component_sha256s"],
        }
    )
    return body


def _pair_identity(prefix: str, domain: str, body: dict[str, Any]) -> dict[str, Any]:
    digest = canonical_sha256({"domain": domain, "record": body})
    return {f"{prefix.lower()}_id": f"{prefix}-{digest[7:39].upper()}", **body}


def _pair_partitions(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return left["partition"] != right["partition"]


def _holdout_pair(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return _pair_partitions(left, right) and bool(
        {left["partition"], right["partition"]} & HOLDOUT_PARTITIONS
    )


def _similarity(left: Mapping[str, Any], right: Mapping[str, Any]) -> tuple[int, int, int]:
    left_components = set(left["fingerprint_component_sha256s"])
    right_components = set(right["fingerprint_component_sha256s"])
    matching = len(left_components & right_components)
    union = len(left_components | right_components)
    basis_points = matching * 10_000 // union if union else 0
    return basis_points, matching, union


def _indicator_sets(
    records: Sequence[Mapping[str, Any]], budgets: CorpusAssemblyBudgets
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    exact: list[dict[str, Any]] = []
    near: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for left_index, left in enumerate(records):
        for right in records[left_index + 1 :]:
            common = {
                "left_record_id": left["record_id"],
                "left_partition": left["partition"],
                "right_record_id": right["record_id"],
                "right_partition": right["partition"],
            }
            exact_match = left["content_sha256"] == right["content_sha256"]
            if exact_match:
                body = {**common, "content_sha256": left["content_sha256"]}
                exact.append(_pair_identity("ECD", "sunderkey.corpus-exact-duplicate.v1", body))
            else:
                similarity, matching, union = _similarity(left, right)
                if similarity >= budgets.near_duplicate_threshold_basis_points:
                    body = {
                        **common,
                        "matching_component_count": matching,
                        "union_component_count": union,
                        "similarity_basis_points": similarity,
                        "threshold_basis_points": (budgets.near_duplicate_threshold_basis_points),
                    }
                    near.append(_pair_identity("NCD", "sunderkey.corpus-near-duplicate.v1", body))

            if not _holdout_pair(left, right):
                continue
            reasons: list[tuple[str, str]] = []
            if exact_match:
                reasons.append(("exact_content_overlap", left["content_sha256"]))
            elif (
                near
                and near[-1]["left_record_id"] == left["record_id"]
                and near[-1]["right_record_id"] == right["record_id"]
            ):
                reasons.append(("near_content_overlap", near[-1]["ncd_id"]))
            if left["source_sha256"] == right["source_sha256"]:
                reasons.append(("source_overlap", left["source_sha256"]))
            if left["provenance_sha256"] == right["provenance_sha256"]:
                reasons.append(("provenance_overlap", left["provenance_sha256"]))
            for kind, evidence_sha256 in reasons:
                finding_body = {
                    **common,
                    "finding_kind": kind,
                    "evidence_sha256": (
                        evidence_sha256
                        if evidence_sha256.startswith("sha256:")
                        else canonical_sha256(evidence_sha256)
                    ),
                    "disposition": "requires_independent_review",
                    "qualification_effect": "none",
                }
                findings.append(
                    _pair_identity("ECF", "sunderkey.corpus-contamination-finding.v1", finding_body)
                )
                if len(findings) > budgets.maximum_findings:
                    raise EvaluationCorpusAssemblyError("contamination findings exceed budget")
    return exact, near, findings


def _partition_summaries(records: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    by_partition: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for record in records:
        by_partition[record["partition"]].append(record)
    summaries: list[dict[str, Any]] = []
    for partition in CORPUS_PARTITIONS:
        members = by_partition[partition]
        bindings = [
            {
                "content_sha256": item["content_sha256"],
                "record_id": item["record_id"],
                "record_version": item["record_version"],
            }
            for item in members
        ]
        summaries.append(
            {
                "partition": partition,
                "record_count": len(members),
                "record_ids": [item["record_id"] for item in members],
                "membership_sha256": canonical_sha256(
                    {
                        "domain": "sunderkey.corpus-partition-membership.v1",
                        "partition": partition,
                        "bindings": bindings,
                    }
                ),
            }
        )
    return summaries


def _holdout_checks(
    records: Sequence[Mapping[str, Any]],
    exact: Sequence[Mapping[str, Any]],
    near: Sequence[Mapping[str, Any]],
    findings: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    del records
    checks: list[dict[str, Any]] = []
    for left_index, left_partition in enumerate(CORPUS_PARTITIONS):
        for right_partition in CORPUS_PARTITIONS[left_index + 1 :]:
            if not ({left_partition, right_partition} & HOLDOUT_PARTITIONS):
                continue
            pair = {left_partition, right_partition}
            exact_count = sum(
                {item["left_partition"], item["right_partition"]} == pair for item in exact
            )
            near_count = sum(
                {item["left_partition"], item["right_partition"]} == pair for item in near
            )
            pair_findings = [
                item
                for item in findings
                if {item["left_partition"], item["right_partition"]} == pair
            ]
            source_count = sum(item["finding_kind"] == "source_overlap" for item in pair_findings)
            provenance_count = sum(
                item["finding_kind"] == "provenance_overlap" for item in pair_findings
            )
            checks.append(
                {
                    "left_partition": left_partition,
                    "right_partition": right_partition,
                    "exact_duplicate_count": exact_count,
                    "near_duplicate_count": near_count,
                    "source_overlap_count": source_count,
                    "provenance_overlap_count": provenance_count,
                    "status": "contaminated" if pair_findings else "clean",
                }
            )
    return checks


def _receipt_body(
    *,
    corpus_id: str,
    corpus_version: str,
    budgets: CorpusAssemblyBudgets,
    records: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    exact, near, findings = _indicator_sets(records, budgets)
    holdout_checks = _holdout_checks(records, exact, near, findings)
    return {
        "schema_version": SCHEMA_VERSION,
        "manifest_version": MANIFEST_VERSION,
        "corpus_id": corpus_id,
        "corpus_version": corpus_version,
        "assembly_status": "contamination_detected" if findings else "clean",
        "budgets": budgets.to_dict(),
        "partitions": _partition_summaries(records),
        "records": list(records),
        "exact_duplicate_indicators": exact,
        "near_duplicate_indicators": near,
        "holdout_separation_checks": holdout_checks,
        "contamination_findings": findings,
        "summary": {
            "record_count": len(records),
            "pair_comparison_count": len(records) * (len(records) - 1) // 2,
            "exact_duplicate_count": len(exact),
            "near_duplicate_count": len(near),
            "contamination_finding_count": len(findings),
            "holdout_check_count": len(holdout_checks),
        },
        "effects": dict(NO_EFFECTS),
        "limitations": list(LIMITATIONS),
    }


def _address_receipt(body: dict[str, Any]) -> dict[str, Any]:
    digest = canonical_sha256({"domain": CONTRACT_DOMAIN, "manifest": body})
    return {
        "manifest_id": f"ECM-{digest[7:39].upper()}",
        "manifest_sha256": digest,
        **body,
    }


def assemble_evaluation_corpus(
    *,
    corpus_id: str,
    corpus_version: str,
    records: Sequence[CorpusInputRecord | Mapping[str, Any]],
    budgets: CorpusAssemblyBudgets | None = None,
) -> EvaluationCorpusAssemblyReceipt:
    """Assemble a content-addressed manifest from caller-supplied records."""

    safe_corpus_id = _identifier(corpus_id, "corpus_id")
    safe_corpus_version = _version(corpus_version, "corpus_version")
    limits = budgets or CorpusAssemblyBudgets()
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        raise EvaluationCorpusAssemblyError("records must be a sequence")
    if not 1 <= len(records) <= limits.maximum_records:
        raise EvaluationCorpusAssemblyError("record count exceeds the configured budget")
    pair_count = len(records) * (len(records) - 1) // 2
    if pair_count > limits.maximum_pair_comparisons:
        raise EvaluationCorpusAssemblyError("pair comparisons exceed the configured budget")

    input_records = [
        item if isinstance(item, CorpusInputRecord) else CorpusInputRecord.from_dict(item)
        for item in records
    ]
    identifiers = [item.record_id for item in input_records]
    if len(identifiers) != len(set(identifiers)):
        raise EvaluationCorpusAssemblyError("record IDs must be unique")
    partitions = {item.partition for item in input_records}
    if partitions != set(CORPUS_PARTITIONS):
        raise EvaluationCorpusAssemblyError("records must cover every required partition")

    manifests = sorted(
        (_record_manifest(item, limits) for item in input_records),
        key=lambda item: item["record_id"],
    )
    total_bytes = sum(item["content_bytes"] for item in manifests)
    if total_bytes > limits.maximum_total_content_bytes:
        raise EvaluationCorpusAssemblyError("content exceeds the total byte budget")
    document = _address_receipt(
        _receipt_body(
            corpus_id=safe_corpus_id,
            corpus_version=safe_corpus_version,
            budgets=limits,
            records=manifests,
        )
    )
    return EvaluationCorpusAssemblyReceipt.from_dict(document)


def _validate_record_manifest(raw: Any) -> dict[str, Any]:
    fields = {
        "record_id",
        "record_version",
        "partition",
        "source_id",
        "source_version",
        "source_sha256",
        "provenance_sha256",
        "content_sha256",
        "content_bytes",
        "token_count",
        "fingerprint_component_sha256s",
        "fingerprint_sha256",
    }
    item = _exact_fields(raw, fields, "record manifest")
    record = dict(item)
    _identifier(record["record_id"], "record_id")
    _version(record["record_version"], "record_version")
    if record["partition"] not in CORPUS_PARTITIONS:
        raise EvaluationCorpusAssemblyError("partition is not recognized")
    _identifier(record["source_id"], "source_id")
    _version(record["source_version"], "source_version")
    for label in (
        "source_sha256",
        "provenance_sha256",
        "content_sha256",
        "fingerprint_sha256",
    ):
        _sha256(record[label], label)
    _bounded_int(record["content_bytes"], "content_bytes", minimum=1, maximum=2**30)
    _bounded_int(record["token_count"], "token_count", minimum=3, maximum=1_000_000)
    components = record["fingerprint_component_sha256s"]
    if (
        not isinstance(components, list)
        or not components
        or len(components) != len(set(components))
        or components != sorted(components)
    ):
        raise EvaluationCorpusAssemblyError(
            "fingerprint components must be a nonempty sorted unique list"
        )
    for component in components:
        _sha256(component, "fingerprint component")
    expected_fingerprint = canonical_sha256(
        {"domain": "sunderkey.corpus-fingerprint.v1", "components": components}
    )
    if record["fingerprint_sha256"] != expected_fingerprint:
        raise EvaluationCorpusAssemblyError("fingerprint content address does not match")
    return record


def _verify_receipt_document(raw: Any) -> dict[str, Any]:
    fields = {
        "manifest_id",
        "manifest_sha256",
        "schema_version",
        "manifest_version",
        "corpus_id",
        "corpus_version",
        "assembly_status",
        "budgets",
        "partitions",
        "records",
        "exact_duplicate_indicators",
        "near_duplicate_indicators",
        "holdout_separation_checks",
        "contamination_findings",
        "summary",
        "effects",
        "limitations",
    }
    document = dict(_exact_fields(raw, fields, "receipt"))
    if type(document["schema_version"]) is not int or document["schema_version"] != SCHEMA_VERSION:
        raise EvaluationCorpusAssemblyError("schema_version is not supported")
    if document["manifest_version"] != MANIFEST_VERSION:
        raise EvaluationCorpusAssemblyError("manifest_version is not supported")
    _identifier(document["corpus_id"], "corpus_id")
    _version(document["corpus_version"], "corpus_version")
    budgets = CorpusAssemblyBudgets.from_dict(document["budgets"])
    records_raw = document["records"]
    if not isinstance(records_raw, list) or not records_raw:
        raise EvaluationCorpusAssemblyError("records must be a nonempty list")
    records = [_validate_record_manifest(item) for item in records_raw]
    if records != sorted(records, key=lambda item: item["record_id"]):
        raise EvaluationCorpusAssemblyError("records must be sorted by record_id")
    record_ids = [item["record_id"] for item in records]
    if len(record_ids) != len(set(record_ids)):
        raise EvaluationCorpusAssemblyError("record IDs must be unique")
    if {item["partition"] for item in records} != set(CORPUS_PARTITIONS):
        raise EvaluationCorpusAssemblyError("records must cover every required partition")
    if len(records) > budgets.maximum_records:
        raise EvaluationCorpusAssemblyError("record count exceeds the configured budget")
    if sum(item["content_bytes"] for item in records) > budgets.maximum_total_content_bytes:
        raise EvaluationCorpusAssemblyError("content exceeds the total byte budget")
    if any(
        item["content_bytes"] > budgets.maximum_content_bytes_per_record
        or item["token_count"] > budgets.maximum_tokens_per_record
        or len(item["fingerprint_component_sha256s"]) > budgets.maximum_fingerprint_components
        for item in records
    ):
        raise EvaluationCorpusAssemblyError("record exceeds the receipt budgets")
    pair_count = len(records) * (len(records) - 1) // 2
    if pair_count > budgets.maximum_pair_comparisons:
        raise EvaluationCorpusAssemblyError("pair comparisons exceed the configured budget")

    expected_body = _receipt_body(
        corpus_id=document["corpus_id"],
        corpus_version=document["corpus_version"],
        budgets=budgets,
        records=records,
    )
    expected = _address_receipt(expected_body)
    if canonical_json(document) != canonical_json(expected):
        raise EvaluationCorpusAssemblyError("receipt content or content address does not match")
    return document


def verify_evaluation_corpus_receipt(
    receipt: EvaluationCorpusAssemblyReceipt | Mapping[str, Any] | str,
) -> EvaluationCorpusAssemblyReceipt:
    """Verify exact fields, invariants, derived checks, and the content address."""

    if isinstance(receipt, EvaluationCorpusAssemblyReceipt):
        return EvaluationCorpusAssemblyReceipt.from_json(receipt.document_json)
    if isinstance(receipt, str):
        return EvaluationCorpusAssemblyReceipt.from_json(receipt)
    return EvaluationCorpusAssemblyReceipt.from_dict(receipt)
