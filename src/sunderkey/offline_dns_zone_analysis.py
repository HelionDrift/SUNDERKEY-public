"""Bounded name-tree lookup over one unauthenticated, explicitly supplied zone."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any

COMPONENT_ID = "dns_supplied_zone_lookup"
PROFILE_ID = "AOE-GA-D01-S03"
CAPABILITY_ID = "army.ga.d01.s03"
VECTOR_ID = "AV-GA-D01-S03-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D01-S03"
WAVE_ID = "IW2-003"
COMMANDER_ID = "AOE-GA-D01-CMD"
GROUP_OWNER_ID = "AOE-HQ-03"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:d242f5ad785667eda0f2669fef8f3e92f75e473fb39ac939fdc8aedd324f6dae"
SEMANTICS_PROFILE = "single-declared-zone-lookup-v1"
DOMAIN = "sunderkey.offline-dns-zone-analysis.v1"
MODEL_DOMAIN = "sunderkey.offline-dns-zone-model.v1"
MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_NATIVE_NODES = 32768
MAX_NATIVE_DEPTH = 16
MAX_STRING_BYTES = 512
MAX_RRSETS = 1024
MAX_ORDINARY_OWNERS = 1024
MAX_DELEGATIONS = 128
MAX_RDATA = 16
MAX_QUERIES = 64
MAX_LABELS = 32
MAX_TEXT_NAME_BYTES = 253
MAX_DNS_WIRE_NAME_BYTES = 255
MAX_ALIAS_HOPS = 32
MAX_TREE_NODES = 16384
MAX_WORK = 262144
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\Z")
_QUERY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PLACEHOLDER = "sha256:" + "0" * 64
_MODEL_FIELDS = {"schema_version", "semantics_profile", "zone", "queries"}
_ORDINARY_TYPES = frozenset({"TXT", "MX", "SRV", "PTR", "CAA", "SOA", "NS"})
_QTYPE = frozenset({"A", "AAAA", "CNAME"})
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "target",
        "execution",
        "routing",
        "qualification",
        "deployment",
        "network",
        "provider",
        "credential",
        "process",
        "dns",
    ),
    "none",
)
_FLAGS = {
    "source_authenticated": False,
    "real_zone_validity_proven": False,
    "actual_completeness_proven": False,
    "authoritative_negative_answer_proven": False,
    "live_resolution_proven": False,
    "target_existence_proven": False,
    "takeover_proven": False,
    "live_use_approved": False,
    "qualification_claimed": False,
}
_BOUNDS = {
    "document_bytes": MAX_DOCUMENT_BYTES,
    "native_nodes": MAX_NATIVE_NODES,
    "native_depth": MAX_NATIVE_DEPTH,
    "string_bytes": MAX_STRING_BYTES,
    "rrsets": MAX_RRSETS,
    "ordinary_data_owners": MAX_ORDINARY_OWNERS,
    "delegations": MAX_DELEGATIONS,
    "values_per_rrset_or_delegation": MAX_RDATA,
    "queries": MAX_QUERIES,
    "labels_per_name": MAX_LABELS,
    "text_name_bytes_subset": MAX_TEXT_NAME_BYTES,
    "dns_wire_name_bytes": MAX_DNS_WIRE_NAME_BYTES,
    "alias_hops": MAX_ALIAS_HOPS,
    "derived_tree_nodes": MAX_TREE_NODES,
    "work_steps": MAX_WORK,
}
_LIMITATIONS = (
    "All source records, actual data ownership and completeness are caller assertions.",
    "Only one declared IN-class zone and A, AAAA and CNAME queries are modeled.",
    "Ordinary-data owner declarations preserve existence, not ordinary RDATA validity.",
    "Apex role and declared completeness do not prove a valid SOA/NS zone or DNS authority.",
    "The lowercase ASCII LDH/underscore/asterisk textual subset is not all binary DNS names.",
    "Below-cut rows are retained as supplied observations and never this zone's answers.",
    "External aliases, cuts, loops and traversal limits are not resolved addresses "
    "or takeover proof.",
    "No zonefile or wire parsing, recursion, cache freshness, DNSSEC, DNAME "
    "or wildcard NS is modeled.",
    "No provider synthesis, discovery, registrar ownership, credentials or target requests occur.",
    "Source integrity and deterministic replay do not authenticate data or permit live use.",
)


class DnsZoneAnalysisError(ValueError):
    """The supplied subset is malformed, unbounded or does not replay exactly."""


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _hash(domain: str, value: Any) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            domain.encode("ascii") + b"\n" + _canonical(value).encode("ascii")
        ).hexdigest()
    )


def _capture_cost(value: Any) -> tuple[Any, int, int]:
    """Charge repeated nodes, punctuation and escapes before copying or hashing."""
    nodes = size = 0
    active: set[int] = set()

    def charge(count: int) -> None:
        nonlocal size
        size += count
        if size > MAX_DOCUMENT_BYTES:
            raise DnsZoneAnalysisError("Document exceeds its aggregate byte bound")

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        if depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise DnsZoneAnalysisError("Document exceeds native node or depth bounds")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES:
                raise DnsZoneAnalysisError("String exceeds its supported byte bound")
            charge(2 + len(item))
            for char in item:
                if not 32 <= ord(char) <= 126:
                    raise DnsZoneAnalysisError("Strings must be printable ASCII")
                if char in '\\"':
                    charge(1)
            return item
        if kind is bool:
            charge(4 if item else 5)
            return item
        if item is None:
            charge(4)
            return None
        if kind is int:
            if item.bit_length() > 63:
                raise DnsZoneAnalysisError("Integer exceeds signed63 magnitude")
            charge(len(str(item)))
            return item
        if kind not in {dict, list}:
            raise DnsZoneAnalysisError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise DnsZoneAnalysisError("Cyclic native inputs are refused")
        child_count = len(item) * (2 if kind is dict else 1)
        if child_count > MAX_NATIVE_NODES - nodes:
            raise DnsZoneAnalysisError("Collection exceeds the remaining node budget")
        charge(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
        active.add(id(item))
        try:
            if kind is list:
                return [visit(child, depth + 1) for child in item]
            result = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise DnsZoneAnalysisError("Object keys must be exact native strings")
                result[visit(key, depth + 1)] = visit(child, depth + 1)
            return result
        finally:
            active.remove(id(item))

    return visit(value, 1), size, nodes


def _capture(value: Any) -> Any:
    return _capture_cost(value)[0]


def _decode(text: Any) -> Any:
    """Bound raw strings, scalar depth, nodes and integer conversion before json.loads."""
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES or not text.isascii():
        raise DnsZoneAnalysisError("JSON must be bounded native ASCII text")
    index = depth = nodes = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            if depth + 1 > MAX_NATIVE_DEPTH:
                raise DnsZoneAnalysisError("JSON scalar exceeds the pre-decoder depth bound")
            nodes += 1
            length = 0
            index += 1
            closed = False
            while index < len(text):
                char = text[index]
                if char == '"':
                    index += 1
                    closed = True
                    break
                if char == "\\":
                    index += 1
                    if index >= len(text):
                        raise DnsZoneAnalysisError("Incomplete JSON escape")
                    escape = text[index]
                    if escape == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            c not in "0123456789abcdefABCDEF" for c in digits
                        ):
                            raise DnsZoneAnalysisError("Invalid JSON Unicode escape")
                        if not 32 <= int(digits, 16) <= 126:
                            raise DnsZoneAnalysisError("JSON is outside printable ASCII")
                        index += 5
                    elif escape in '\\"/':
                        index += 1
                    else:
                        raise DnsZoneAnalysisError("Unsupported JSON string escape")
                else:
                    if not 32 <= ord(char) <= 126:
                        raise DnsZoneAnalysisError("JSON is outside printable ASCII")
                    index += 1
                length += 1
                if length > MAX_STRING_BYTES:
                    raise DnsZoneAnalysisError("JSON string exceeds its bound")
            if not closed:
                raise DnsZoneAnalysisError("Incomplete JSON string")
        elif char in "[{":
            depth += 1
            nodes += 1
            index += 1
        elif char in "]}":
            depth -= 1
            index += 1
        elif char in " \t\r\n,:":
            index += 1
        else:
            if depth + 1 > MAX_NATIVE_DEPTH:
                raise DnsZoneAnalysisError("JSON scalar exceeds the pre-decoder depth bound")
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}{["':
                index += 1
            token = text[start:index]
            nodes += 1
            if token not in {"true", "false", "null"} and (
                _INTEGER.fullmatch(token) is None or int(token).bit_length() > 63
            ):
                raise DnsZoneAnalysisError("JSON number is outside the integer subset")
        if depth < 0 or depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise DnsZoneAnalysisError("JSON exceeds pre-decoder node or depth bounds")
    if depth:
        raise DnsZoneAnalysisError("Incomplete JSON structure")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                raise DnsZoneAnalysisError("Duplicate JSON object member")
            result[key] = value
        return result

    def unsupported(_: str) -> None:
        raise DnsZoneAnalysisError("Fractional and nonfinite JSON numbers are unsupported")

    try:
        document = json.loads(
            text, object_pairs_hook=pairs, parse_float=unsupported, parse_constant=unsupported
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, DnsZoneAnalysisError):
            raise
        raise DnsZoneAnalysisError("Malformed JSON document") from exc
    return _capture(document)


def _fields(value: Any, expected: set[str], label: str) -> dict:
    if type(value) is not dict or value.keys() != expected:
        raise DnsZoneAnalysisError(f"{label} has missing or unsupported fields")
    return value


def _list(value: Any, maximum: int, label: str, *, nonempty: bool = False) -> list:
    if type(value) is not list or len(value) > maximum or (nonempty and not value):
        raise DnsZoneAnalysisError(f"{label} exceeds its supported native collection bound")
    return value


def _name(value: Any) -> tuple[str, ...]:
    if type(value) is not str or not value.endswith(".") or len(value) > MAX_TEXT_NAME_BYTES:
        raise DnsZoneAnalysisError("Name is outside the absolute textual subset")
    labels = tuple(value[:-1].split("."))
    if not 1 <= len(labels) <= MAX_LABELS:
        raise DnsZoneAnalysisError("Name exceeds the label bound")
    if any(part != "*" and _LABEL.fullmatch(part) is None for part in labels):
        raise DnsZoneAnalysisError("Name is outside lowercase LDH/underscore/asterisk labels")
    wire_bytes = 1 + sum(1 + len(part) for part in labels)
    if wire_bytes > MAX_DNS_WIRE_NAME_BYTES:
        raise DnsZoneAnalysisError("Name exceeds the DNS wire length bound")
    return tuple(reversed(labels))


def _within(name: tuple[str, ...], apex: tuple[str, ...]) -> bool:
    return len(name) >= len(apex) and name[: len(apex)] == apex


def _text(labels: tuple[str, ...]) -> str:
    return ".".join(reversed(labels)) + "."


def _validate_model(model: Any) -> dict:
    owned = _capture(model)
    _fields(owned, _MODEL_FIELDS, "Model")
    if type(owned["schema_version"]) is not int or owned["schema_version"] != 1:
        raise DnsZoneAnalysisError("schema_version must be the native integer 1")
    if type(owned["semantics_profile"]) is not str or (
        owned["semantics_profile"] != SEMANTICS_PROFILE
    ):
        raise DnsZoneAnalysisError("Unsupported semantics profile")
    zone = _fields(
        owned["zone"],
        {"apex", "complete", "rrsets", "ordinary_data_owners", "delegations"},
        "Zone",
    )
    apex = _name(zone["apex"])
    if "*" in apex:
        raise DnsZoneAnalysisError("A wildcard apex is outside this single-zone subset")
    if type(zone["complete"]) is not bool:
        raise DnsZoneAnalysisError("Zone completeness must be an exact native boolean")
    keys: set[tuple[str, str]] = set()
    owner_types: dict[str, set[str]] = {}
    for rrset in _list(zone["rrsets"], MAX_RRSETS, "RRsets"):
        _fields(rrset, {"owner", "rrtype", "rdata"}, "RRset")
        if not _within(_name(rrset["owner"]), apex):
            raise DnsZoneAnalysisError("RRset owner is outside the supplied zone")
        rrtype = rrset["rrtype"]
        if type(rrtype) is not str or rrtype not in _QTYPE:
            raise DnsZoneAnalysisError("RRset type is outside A/AAAA/CNAME")
        key = (rrset["owner"], rrtype)
        if key in keys:
            raise DnsZoneAnalysisError("Duplicate owner/type RRset")
        keys.add(key)
        owner_types.setdefault(rrset["owner"], set()).add(rrtype)
        values = _list(rrset["rdata"], MAX_RDATA, "RRset rdata", nonempty=True)
        if any(type(value) is not str for value in values):
            raise DnsZoneAnalysisError("RRset rdata must contain exact native strings")
        if len(set(values)) != len(values):
            raise DnsZoneAnalysisError("RRset rdata must be unique")
        if rrtype == "CNAME":
            if len(values) != 1:
                raise DnsZoneAnalysisError("CNAME requires exactly one target")
            _name(values[0])
            if rrset["owner"] == zone["apex"]:
                raise DnsZoneAnalysisError("Apex CNAME is unsupported in this single-zone subset")
        else:
            for value in values:
                if type(value) is not str or "%" in value:
                    raise DnsZoneAnalysisError("Address RDATA must be a canonical native string")
                try:
                    address = ipaddress.ip_address(value)
                except ValueError as exc:
                    raise DnsZoneAnalysisError("Malformed address RDATA") from exc
                if address.version != (4 if rrtype == "A" else 6) or str(address) != value:
                    raise DnsZoneAnalysisError("Address RDATA family or canonical spelling differs")
    ordinary_names: set[str] = set()
    for owner in _list(zone["ordinary_data_owners"], MAX_ORDINARY_OWNERS, "Ordinary owners"):
        _fields(owner, {"owner", "rrtypes"}, "Ordinary owner")
        if not _within(_name(owner["owner"]), apex) or owner["owner"] in ordinary_names:
            raise DnsZoneAnalysisError("Ordinary owner is foreign or duplicated")
        ordinary_names.add(owner["owner"])
        types = _list(owner["rrtypes"], len(_ORDINARY_TYPES), "Ordinary rrtypes", nonempty=True)
        if any(type(value) is not str or value not in _ORDINARY_TYPES for value in types):
            raise DnsZoneAnalysisError("Ordinary types are outside the declared passive subset")
        if len(set(types)) != len(types):
            raise DnsZoneAnalysisError("Ordinary types must be unique")
        if owner["owner"] != zone["apex"] and any(t in {"SOA", "NS"} for t in types):
            raise DnsZoneAnalysisError("SOA/NS ordinary declarations are apex-only")
        owner_types.setdefault(owner["owner"], set()).update(types)
    cuts: list[tuple[str, ...]] = []
    for delegation in _list(zone["delegations"], MAX_DELEGATIONS, "Delegations"):
        _fields(delegation, {"owner", "nameservers"}, "Delegation")
        cut = _name(delegation["owner"])
        if not _within(cut, apex) or len(cut) == len(apex) or "*" in cut:
            raise DnsZoneAnalysisError("Cut must be a nonwildcard strict descendant")
        if any(_within(cut, prior) or _within(prior, cut) for prior in cuts):
            raise DnsZoneAnalysisError("Delegation cuts must be unique and nonoverlapping")
        cuts.append(cut)
        servers = _list(delegation["nameservers"], MAX_RDATA, "Nameservers", nonempty=True)
        for server in servers:
            _name(server)
        if len(set(servers)) != len(servers):
            raise DnsZoneAnalysisError("Nameservers must be unique")
        owner_types.setdefault(delegation["owner"], set()).add("NS")
    if any("CNAME" in types and len(types) != 1 for types in owner_types.values()):
        raise DnsZoneAnalysisError("CNAME owner cannot have other modeled or ordinary data")
    query_ids: set[str] = set()
    for query in _list(owned["queries"], MAX_QUERIES, "Queries", nonempty=True):
        _fields(query, {"query_id", "qname", "qtype"}, "Query")
        query_id = query["query_id"]
        if type(query_id) is not str or _QUERY_ID.fullmatch(query_id) is None:
            raise DnsZoneAnalysisError("query_id is outside the supported native spelling")
        if query_id in query_ids:
            raise DnsZoneAnalysisError("query_id must be unique")
        query_ids.add(query_id)
        _name(query["qname"])
        if type(query["qtype"]) is not str or query["qtype"] not in _QTYPE:
            raise DnsZoneAnalysisError("Query type is outside A/AAAA/CNAME")
    return owned


@dataclass(slots=True)
class _Work:
    count: int = 0

    def charge(self, amount: int = 1) -> None:
        self.count += amount
        if self.count > MAX_WORK:
            raise DnsZoneAnalysisError("Derived work budget exhausted; no conclusions published")


@dataclass(slots=True)
class _Node:
    children: dict[str, _Node] = field(default_factory=dict)
    rrsets: dict[str, tuple[int, dict]] = field(default_factory=dict)
    cut: tuple[int, dict] | None = None
    owns_ordinary_data: bool = False


class _Tree:
    def __init__(self, apex: tuple[str, ...], work: _Work) -> None:
        self.apex = apex
        self.work = work
        self.node_count = 1
        self.root = _Node()
        self.ignored_rrsets: list[int] = []
        self.ignored_ordinary: list[int] = []

    def insert(self, name: tuple[str, ...]) -> _Node | None:
        node = self.root
        for label in name[len(self.apex) :]:
            self.work.charge()
            if node.cut is not None:
                return None
            if label not in node.children:
                if self.node_count >= MAX_TREE_NODES:
                    raise DnsZoneAnalysisError("Derived tree node bound exhausted")
                self.node_count += 1
                node.children[label] = _Node()
            node = node.children[label]
        return None if node.cut is not None else node

    def load(self, zone: dict) -> None:
        for index, cut in enumerate(zone["delegations"]):
            self.work.charge(1 + len(cut["nameservers"]))
            node = self.insert(_name(cut["owner"]))
            if node is None:
                raise DnsZoneAnalysisError("Overlapping cut in derived tree")
            node.cut = (index, cut)
        for index, rrset in enumerate(zone["rrsets"]):
            self.work.charge(1 + len(rrset["rdata"]))
            node = self.insert(_name(rrset["owner"]))
            if node is None:
                self.ignored_rrsets.append(index)
            else:
                node.rrsets[rrset["rrtype"]] = (index, rrset)
        for index, owner in enumerate(zone["ordinary_data_owners"]):
            self.work.charge(1 + len(owner["rrtypes"]))
            node = self.insert(_name(owner["owner"]))
            if node is None:
                self.ignored_ordinary.append(index)
            else:
                node.owns_ordinary_data = True

    def locate(self, name: tuple[str, ...]) -> tuple[str, _Node | None, str | None, str | None]:
        """Return cut, exact, one wildcard source or absent, never a higher fallback."""
        node = self.root
        walked = self.apex
        for label in name[len(self.apex) :]:
            self.work.charge()
            if node.cut is not None:
                return "cut", node, _text(walked), None
            if label not in node.children:
                self.work.charge()
                wildcard = node.children.get("*")
                return (
                    "wildcard" if wildcard is not None else "absent",
                    wildcard,
                    _text(walked),
                    _text(walked + ("*",)) if wildcard is not None else None,
                )
            node = node.children[label]
            walked += (label,)
        if node.cut is not None:
            return "cut", node, _text(walked), None
        return "exact", node, _text(walked), None


class _OutputBudget:
    def __init__(self, base: dict) -> None:
        _, self.size, self.nodes = _capture_cost(base)

    def charge(self, size: int, nodes: int) -> None:
        self.size += size
        self.nodes += nodes
        if self.size > MAX_DOCUMENT_BYTES or self.nodes > MAX_NATIVE_NODES:
            raise DnsZoneAnalysisError("Cumulative report cost exhausted before retention or hash")

    def trace(self, value: dict) -> tuple[dict, int, int]:
        captured, size, nodes = _capture_cost(value)
        self.charge(size, nodes)
        return captured, size, nodes

    def result(self, value: dict, reserved_size: int, reserved_nodes: int) -> dict:
        captured, size, nodes = _capture_cost(value)
        self.charge(size - reserved_size + 1, nodes - reserved_nodes)
        return captured


def _query(tree: _Tree, query: dict, complete: bool, output: _OutputBudget) -> dict:
    current = query["qname"]
    traces: list[dict] = []
    seen: set[str] = set()
    reserved_size = reserved_nodes = 0

    def finish(
        outcome: str,
        basis: str,
        *,
        mode: str | None = None,
        closest: str | None = None,
        synthesis: str | None = None,
        rrset_index: int | None = None,
        rdata: list[str] | None = None,
        delegation: tuple[int, dict] | None = None,
    ) -> dict:
        result = {
            "query_id": query["query_id"],
            "qname": query["qname"],
            "qtype": query["qtype"],
            "terminal_name": current,
            "outcome": outcome,
            "basis": basis,
            "lookup_mode": mode,
            "closest_encloser": closest,
            "source_of_synthesis": synthesis,
            "rrset_index": rrset_index,
            "rdata": [] if rdata is None else rdata,
            "delegation_index": None if delegation is None else delegation[0],
            "delegation_owner": None if delegation is None else delegation[1]["owner"],
            "nameservers": [] if delegation is None else delegation[1]["nameservers"],
            "alias_trace": traces,
        }
        return output.result(result, reserved_size, reserved_nodes)

    if not complete:
        return finish("incomplete", "projection_declared_incomplete")
    while True:
        tree.work.charge()
        labels = _name(current)
        if not _within(labels, tree.apex):
            return finish("incomplete", "name_outside_supplied_zone")
        if current in seen:
            return finish("incomplete", "alias_loop_in_supplied_projection")
        seen.add(current)
        mode, node, closest, synthesis = tree.locate(labels)
        if mode == "cut":
            if node is None or node.cut is None:
                raise DnsZoneAnalysisError("Derived cut invariant failed")
            return finish(
                "referral_in_supplied_projection",
                "delegation_precedes_data_and_synthesis",
                mode=mode,
                closest=closest,
                delegation=node.cut,
            )
        if node is None:
            return finish(
                "name_absent_in_supplied_projection",
                "closest_encloser_has_no_wildcard_source",
                mode=mode,
                closest=closest,
            )
        answer = node.rrsets.get(query["qtype"])
        if answer is not None:
            return finish(
                "answer_in_supplied_projection",
                "requested_rrset_present",
                mode=mode,
                closest=closest,
                synthesis=synthesis,
                rrset_index=answer[0],
                rdata=answer[1]["rdata"],
            )
        alias = node.rrsets.get("CNAME")
        if alias is None or query["qtype"] == "CNAME":
            return finish(
                "no_data_in_supplied_projection",
                "existing_name_or_wildcard_has_no_requested_rrset",
                mode=mode,
                closest=closest,
                synthesis=synthesis,
            )
        if len(traces) >= MAX_ALIAS_HOPS:
            return finish(
                "incomplete",
                "alias_traversal_bound_exhausted",
                mode=mode,
                closest=closest,
                synthesis=synthesis,
            )
        trace, size, nodes = output.trace(
            {
                "name": current,
                "target": alias[1]["rdata"][0],
                "rrset_index": alias[0],
                "lookup_mode": mode,
                "closest_encloser": closest,
                "source_of_synthesis": synthesis,
            }
        )
        reserved_size += size
        reserved_nodes += nodes
        traces.append(trace)
        current = alias[1]["rdata"][0]


def _derive(model: dict) -> dict:
    work = _Work()
    tree = _Tree(_name(model["zone"]["apex"]), work)
    tree.load(model["zone"])
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_id": COMMANDER_ID,
        "group_owner_id": GROUP_OWNER_ID,
        "independent_validator_id": INDEPENDENT_VALIDATOR_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "semantics_profile": SEMANTICS_PROFILE,
        "source_model": model,
        "source_model_sha256": _PLACEHOLDER,
        "declared_projection_complete": model["zone"]["complete"],
        "ignored_below_cut_rrset_indexes": tree.ignored_rrsets,
        "ignored_below_cut_ordinary_owner_indexes": tree.ignored_ordinary,
        "tree_node_count": tree.node_count,
        "work_steps": MAX_WORK,
        "query_results": [],
        "bounds": dict(_BOUNDS),
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "limitations": list(_LIMITATIONS),
        "analysis_id": "DZA-" + "0" * 32,
        "analysis_sha256": _PLACEHOLDER,
    }
    output = _OutputBudget(body)
    for query in model["queries"]:
        body["query_results"].append(_query(tree, query, model["zone"]["complete"], output))
    body["work_steps"] = work.count
    _capture(body)
    body["source_model_sha256"] = _hash(MODEL_DOMAIN, model)
    del body["analysis_id"]
    del body["analysis_sha256"]
    digest = _hash(DOMAIN, body)
    body["analysis_id"] = "DZA-" + digest[7:39].upper()
    body["analysis_sha256"] = digest
    return body


def _replay(document: Any) -> dict:
    supplied = _capture(document)
    fields = {
        "schema_version",
        "component_id",
        "profile_id",
        "capability_id",
        "vector_id",
        "work_package_id",
        "wave_id",
        "commander_id",
        "group_owner_id",
        "independent_validator_id",
        "blueprint_sha256",
        "semantics_profile",
        "source_model",
        "source_model_sha256",
        "declared_projection_complete",
        "ignored_below_cut_rrset_indexes",
        "ignored_below_cut_ordinary_owner_indexes",
        "tree_node_count",
        "work_steps",
        "query_results",
        "bounds",
        "flags",
        "effects",
        "limitations",
        "analysis_id",
        "analysis_sha256",
    }
    _fields(supplied, fields, "Analysis")
    if type(supplied["analysis_sha256"]) is not str or (
        _DIGEST.fullmatch(supplied["analysis_sha256"]) is None
    ):
        raise DnsZoneAnalysisError("Analysis digest is malformed")
    expected = _derive(_validate_model(supplied["source_model"]))
    if _canonical(supplied) != _canonical(expected):
        raise DnsZoneAnalysisError("Analysis does not replay exactly from its supplied source")
    return expected


@dataclass(frozen=True, slots=True, init=False)
class DnsZoneAnalysis:
    """Detached canonical observation, not authenticated DNS evidence or authority."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        object.__setattr__(self, "_document_json", _canonical(_replay(document)))

    @classmethod
    def from_dict(cls, document: Any) -> DnsZoneAnalysis:
        return cls(document)

    @classmethod
    def from_json(cls, content: Any) -> DnsZoneAnalysis:
        return cls(_decode(content))

    def to_dict(self) -> dict:
        return _replay(_decode(getattr(self, "_document_json", None)))

    def to_json(self) -> str:
        return _canonical(self.to_dict())

    @property
    def analysis_id(self) -> str:
        return self.to_dict()["analysis_id"]

    @property
    def analysis_sha256(self) -> str:
        return self.to_dict()["analysis_sha256"]


def analyze_supplied_dns_zone(model: Any) -> DnsZoneAnalysis:
    """Evaluate only the finite supplied name-tree projection, without any I/O."""
    return DnsZoneAnalysis(_derive(_validate_model(model)))


def analyze_supplied_dns_zone_bytes(*, model_bytes: Any) -> DnsZoneAnalysis:
    """Decode bounded exact native ASCII JSON bytes before supplied-model analysis."""
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_DOCUMENT_BYTES:
        raise DnsZoneAnalysisError("Model bytes must be bounded exact native bytes")
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise DnsZoneAnalysisError("Model bytes must contain ASCII JSON") from exc
    return analyze_supplied_dns_zone(_decode(text))


def verify_supplied_dns_zone_analysis(report: Any, *, model: Any) -> DnsZoneAnalysis:
    """Re-derive from separately supplied originals; integrity is not DNS authentication."""
    original = _validate_model(model)
    if type(report) is not DnsZoneAnalysis:
        raise DnsZoneAnalysisError("Report must be the exact native analysis family")
    supplied = report.to_dict()
    expected = _derive(original)
    if _canonical(supplied) != _canonical(expected):
        raise DnsZoneAnalysisError("Analysis is not bound to the separately supplied original")
    return DnsZoneAnalysis(expected)


__all__ = [
    "DnsZoneAnalysis",
    "DnsZoneAnalysisError",
    "analyze_supplied_dns_zone",
    "analyze_supplied_dns_zone_bytes",
    "verify_supplied_dns_zone_analysis",
]
