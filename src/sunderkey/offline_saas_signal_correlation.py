"""Correlate bounded supplied SaaS domain signals without discovery I/O."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_saas_signal_correlation"
PROFILE_ID = "AOE-GA-D01-S06"
CAPABILITY_ID = "army.ga.d01.s06"
VECTOR_ID = "AV-GA-D01-S06-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D01-S06"
WAVE_ID = "IW2-006"
COMMANDER_ID = "AOE-GA-D01-CMD"
GROUP_OWNER_ID = "AOE-HQ-03"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:dbbabc7358155937d853835169b4bad229ae2561547f26877db5799db390aa82"
SEMANTICS_PROFILE = "supplied-saas-signal-correlation-v1"
DOMAIN = "sunderkey.offline-saas-signal-correlation.v1"
MAX_SIGNALS = 512
MAX_CATALOG_DOMAINS = 256
MAX_DOCUMENT_BYTES = 262_144
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_KINDS = frozenset({"idp_app", "dns_alias", "expense_vendor", "egress_domain", "managed_catalog"})
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "credential",
        "dns",
        "execution",
        "filesystem",
        "network",
        "provider",
        "publication",
        "qualification",
        "target",
    ),
    "none",
)


class SaasSignalCorrelationError(ValueError):
    """A supplied signal model or replay document was refused."""


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise SaasSignalCorrelationError(f"{label} fields are invalid")


def _identifier(value: Any, label: str) -> None:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise SaasSignalCorrelationError(f"{label} identifier is invalid")


def _domain(value: Any) -> None:
    if type(value) is not str or not 1 <= len(value) <= 253:
        raise SaasSignalCorrelationError("Domain text is invalid")
    labels = value.split(".")
    if len(labels) < 2 or any(_LABEL.fullmatch(label) is None for label in labels):
        raise SaasSignalCorrelationError("Canonical ASCII domain is required")
    if labels[-1].isdigit():
        raise SaasSignalCorrelationError("IP literals are not domain signals")


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise SaasSignalCorrelationError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise SaasSignalCorrelationError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise SaasSignalCorrelationError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise SaasSignalCorrelationError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise SaasSignalCorrelationError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise SaasSignalCorrelationError("Native JSON text keys are required")
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            else:
                for child in item:
                    visit(child, depth + 1)
        finally:
            active.remove(id(item))

    visit(value, 1)
    encoded = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise SaasSignalCorrelationError("Document byte bound exceeded")
    return encoded


def _plan(model: Any) -> tuple[dict, list[dict], set[str]]:
    _fields(model, {"schema_version", "semantics_profile", "signals", "catalog_domains"}, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise SaasSignalCorrelationError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise SaasSignalCorrelationError("Semantics profile is invalid")
    signals = model["signals"]
    domains = model["catalog_domains"]
    if type(signals) is not list or not 1 <= len(signals) <= MAX_SIGNALS:
        raise SaasSignalCorrelationError("Signal count is invalid")
    if type(domains) is not list or len(domains) > MAX_CATALOG_DOMAINS:
        raise SaasSignalCorrelationError("Catalog domain count is invalid")
    catalog: set[str] = set()
    for domain in domains:
        _domain(domain)
        if domain in catalog:
            raise SaasSignalCorrelationError("Duplicate supplied catalog domain")
        catalog.add(domain)
    ids: set[str] = set()
    signatures: set[tuple[str, str, str]] = set()
    for signal in signals:
        _fields(signal, {"signal_id", "kind", "domain", "source_id"}, "signal")
        _identifier(signal["signal_id"], "signal")
        _identifier(signal["source_id"], "source")
        _domain(signal["domain"])
        if type(signal["kind"]) is not str or signal["kind"] not in _KINDS:
            raise SaasSignalCorrelationError("Signal kind is invalid")
        signature = (signal["kind"], signal["domain"], signal["source_id"])
        if signal["signal_id"] in ids or signature in signatures:
            raise SaasSignalCorrelationError("Duplicate supplied signal")
        ids.add(signal["signal_id"])
        signatures.add(signature)
    return json.loads(_canonical(model)), signals, catalog


def _derive(model: Any) -> dict:
    plan, signals, catalog = _plan(model)
    groups: dict[str, list[dict]] = {}
    for signal in signals:
        groups.setdefault(signal["domain"], []).append(signal)
    observations = []
    for domain, rows in sorted(groups.items()):
        kinds = sorted({row["kind"] for row in rows})
        observations.append(
            {
                "domain": domain,
                "catalog_status": (
                    "listed_in_supplied_catalog"
                    if domain in catalog
                    else "not_listed_in_supplied_catalog"
                ),
                "corroboration_status": (
                    "multiple_supplied_signal_kinds"
                    if len(kinds) > 1
                    else "single_supplied_signal_kind"
                ),
                "signal_kinds": kinds,
                "signal_ids": sorted(row["signal_id"] for row in rows),
                "source_ids": sorted({row["source_id"] for row in rows}),
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": plan,
        "observations": observations,
        "flags": {
            "signal_sources_authenticated": False,
            "catalog_authority_proven": False,
            "domain_ownership_proven": False,
            "saas_use_proven": False,
            "unauthorized_use_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Signals and catalog labels are caller-supplied and unauthenticated.",
            "Only exact canonical ASCII domain text is joined; suffixes are not inferred.",
            "A catalog miss is not proof of unauthorized or shadow-IT use.",
            "No DNS, IdP, billing, egress, SaaS or target system is queried.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "SSC-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class SaasSignalAnalysis:
    """Replay-checked supplied domain correlation without discovery authority."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise SaasSignalCorrelationError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise SaasSignalCorrelationError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_saas_signals(model: Any) -> SaasSignalAnalysis:
    """Join exact supplied domains without inferring real SaaS use."""
    return SaasSignalAnalysis(_derive(model))


def verify_supplied_saas_signals(report: Any, *, model: Any) -> SaasSignalAnalysis:
    """Independently rederive the current supplied model result."""
    if type(report) is not SaasSignalAnalysis:
        raise SaasSignalCorrelationError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise SaasSignalCorrelationError("Report differs from supplied model replay")
    return SaasSignalAnalysis(expected)


__all__ = [
    "COMPONENT_ID",
    "PROFILE_ID",
    "SaasSignalAnalysis",
    "SaasSignalCorrelationError",
    "analyze_supplied_saas_signals",
    "verify_supplied_saas_signals",
]
