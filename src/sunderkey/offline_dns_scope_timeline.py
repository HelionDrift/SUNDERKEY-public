"""Compare supplied DNS answer scopes without resolving a hostname."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_dns_scope_timeline"
PROFILE_ID = "AOE-GE-D23-S06"
CAPABILITY_ID = "army.ge.d23.s06"
VECTOR_ID = "AV-GE-D23-S06-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D23-S06"
WAVE_ID = "IW2-020"
COMMANDER_ID = "AOE-GE-D23-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:18684c8066ea1f9ee15b56b7436ec465b71287986a4afbaed11878dbd3ed7609"
SEMANTICS_PROFILE = "supplied-dns-scope-timeline-v1"
DOMAIN = "sunderkey.offline-dns-scope-timeline.v1"
MAX_SNAPSHOTS = 64
MAX_ADDRESSES = 16
MAX_DOCUMENT_BYTES = 65_536
MAX_NATIVE_NODES = 4_096
MAX_NATIVE_DEPTH = 10
MAX_STRING_LENGTH = 253
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_INTERNAL = frozenset(("private", "loopback", "link_local"))
_EFFECTS = dict.fromkeys(
    (
        "authority", "credential", "dns", "execution", "network",
        "publication", "qualification", "target",
    ),
    "none",
)


class DnsScopeTimelineError(ValueError):
    """A supplied DNS timeline or replay report was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise DnsScopeTimelineError("Native structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise DnsScopeTimelineError("Native string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not 0 <= item <= 1_000_000_000:
                raise DnsScopeTimelineError("Native integer bound exceeded")
            return
        if family not in (dict, list):
            raise DnsScopeTimelineError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise DnsScopeTimelineError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise DnsScopeTimelineError("Native JSON text keys are required")
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
        raise DnsScopeTimelineError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise DnsScopeTimelineError(f"{label} fields are invalid")


def _address(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    address = ipaddress.ip_address(text)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _model(value: Any) -> dict:
    model = json.loads(_canonical(value))
    _fields(model, {"schema_version", "semantics_profile", "hostname", "snapshots"}, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise DnsScopeTimelineError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise DnsScopeTimelineError("Semantics profile is invalid")
    hostname = model["hostname"]
    if (
        type(hostname) is not str
        or len(hostname) > MAX_STRING_LENGTH
        or len(hostname.split(".")) < 2
        or any(_LABEL.fullmatch(label) is None for label in hostname.split("."))
    ):
        raise DnsScopeTimelineError("Only canonical ASCII DNS hostnames are accepted")
    snapshots = model["snapshots"]
    if type(snapshots) is not list or not 2 <= len(snapshots) <= MAX_SNAPSHOTS:
        raise DnsScopeTimelineError("Snapshot count is invalid")
    seen_ids: set[str] = set()
    prior_sequence = -1
    for snapshot in snapshots:
        _fields(snapshot, {"snapshot_id", "sequence", "addresses"}, "snapshot")
        snapshot_id = snapshot["snapshot_id"]
        if type(snapshot_id) is not str or _ID.fullmatch(snapshot_id) is None:
            raise DnsScopeTimelineError("Snapshot identifier is invalid")
        if snapshot_id in seen_ids:
            raise DnsScopeTimelineError("Snapshot identifier is duplicated")
        seen_ids.add(snapshot_id)
        sequence = snapshot["sequence"]
        if type(sequence) is not int or sequence <= prior_sequence:
            raise DnsScopeTimelineError("Sequences must strictly increase")
        prior_sequence = sequence
        addresses = snapshot["addresses"]
        if type(addresses) is not list or not 1 <= len(addresses) <= MAX_ADDRESSES:
            raise DnsScopeTimelineError("Address count is invalid")
        seen_addresses: set[str] = set()
        for address in addresses:
            if type(address) is not str or "%" in address:
                raise DnsScopeTimelineError("Address must be an unscoped IP literal")
            try:
                canonical = str(_address(address))
            except ValueError as exc:
                raise DnsScopeTimelineError("Address is not an IP literal") from exc
            if canonical in seen_addresses:
                raise DnsScopeTimelineError("Canonical address is duplicated")
            seen_addresses.add(canonical)
    return model


def _scope(text: str) -> tuple[str, str]:
    address = _address(text)
    if address.is_loopback:
        scope = "loopback"
    elif address.is_link_local:
        scope = "link_local"
    elif address.is_private:
        scope = "private"
    elif address.is_global:
        scope = "global"
    else:
        scope = "other_non_global"
    return str(address), scope


def _transition(previous: set[str], current: set[str]) -> str:
    if previous == {"global"} and current <= _INTERNAL:
        return "candidate_global_to_internal_shift"
    if "global" in previous and current & _INTERNAL:
        return "unknown_mixed_answer_shift"
    return "no_declared_global_to_internal_shift"


def _derive(value: Any) -> dict:
    model = _model(value)
    observations = []
    transitions = []
    for snapshot in model["snapshots"]:
        answers = []
        for address in snapshot["addresses"]:
            canonical, scope = _scope(address)
            answers.append({"address": canonical, "scope": scope})
        scopes = sorted({answer["scope"] for answer in answers})
        observations.append(
            {
                "snapshot_id": snapshot["snapshot_id"],
                "sequence": snapshot["sequence"],
                "answers": answers,
                "scope_set": scopes,
            }
        )
        if len(observations) > 1:
            previous = observations[-2]
            transitions.append(
                {
                    "from_snapshot_id": previous["snapshot_id"],
                    "to_snapshot_id": snapshot["snapshot_id"],
                    "disposition": _transition(set(previous["scope_set"]), set(scopes)),
                }
            )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": model,
        "observations": observations,
        "transitions": transitions,
        "flags": {
            "dns_resolution_performed": False,
            "resolver_provenance_verified": False,
            "application_fetch_verified": False,
            "rebind_or_ssrf_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Hostname, sequence, and IP answers are caller-supplied declarations.",
            "Address scope is a finite standard-library classification, not resolver behavior.",
            "A candidate transition does not prove DNS rebinding, SSRF, "
            "cache timing, or application access.",
            "No DNS query, URL fetch, credential use, network call, or target interaction occurs.",
        ],
    }
    digest = "sha256:" + hashlib.sha256(
        (DOMAIN + "\n" + _canonical(body)).encode("ascii")
    ).hexdigest()
    return json.loads(
        _canonical(
            {**body, "analysis_id": "DST-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class DnsScopeTimeline:
    """Immutable report replayed from supplied DNS answer declarations."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise DnsScopeTimelineError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise DnsScopeTimelineError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_dns_scope_timeline(model: Any) -> DnsScopeTimeline:
    """Classify only supplied address-scope transitions for one hostname."""
    return DnsScopeTimeline(_derive(model))


def verify_supplied_dns_scope_timeline(report: Any, *, model: Any) -> DnsScopeTimeline:
    if type(report) is not DnsScopeTimeline:
        raise DnsScopeTimelineError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise DnsScopeTimelineError("Report differs from supplied model replay")
    return DnsScopeTimeline(expected)
