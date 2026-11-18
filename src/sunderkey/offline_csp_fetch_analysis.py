"""Finite supplied CSP external-fetch predicates, without browser or network effects."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "csp_supplied_external_fetch_predicates"
PROFILE_ID = "AOE-GB-D05-S14"
CAPABILITY_ID = "army.gb.d05.s14"
VECTOR_ID = "AV-GB-D05-S14-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D05-S14"
WAVE_ID = "IW2-014"
COMMANDER_ID = "AOE-GB-D05-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:519eecb0d32d95081a3bb2e04dc431d5ce71a47f1f65247f6f5e8d875a1fff43"
STANDARD_PROFILE = "csp3-wd-20260916-pathless-http-dns-fetch.v1"
DOMAIN = "sunderkey.offline-csp-fetch-analysis.v1"
MODEL_DOMAIN = "sunderkey.offline-csp-fetch-model.v1"
MAX_MODEL_BYTES = 262_144
MAX_REPORT_BYTES = 1_048_576
MAX_MODEL_NODES = 8192
MAX_REPORT_NODES = 65_536
MAX_MODEL_DEPTH = 16
MAX_REPORT_DEPTH = 20
MAX_STRING_BYTES = 8192
MAX_POLICIES = 16
MAX_QUERIES = 128
MAX_DIRECTIVES_PER_POLICY = 64
MAX_SOURCES_PER_DIRECTIVE = 64
MAX_TOTAL_SOURCES = 2048
MAX_SOURCE_BYTES = 512
MAX_REDIRECT_COUNT = 128
MAX_WORK = 16_777_216
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1
_SPACE = "\t\n\f\r "
_SPLIT_SPACE = re.compile(r"[\t\n\f\r ]+")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_DIRECTIVE = re.compile(r"[a-z0-9-]{1,128}\Z")
_DIGITS = re.compile(r"[0-9]{1,5}\Z")
_FETCH = {"image": "img-src", "font": "font-src", "media": "media-src", "connect": "connect-src"}
_SUPPORTED_DIRECTIVES = {"default-src", *_FETCH.values()}
_PLACEHOLDER = "sha256:" + "0" * 64
_ID_PLACEHOLDER = "CFA-" + "0" * 32
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "browser",
        "credential",
        "execution",
        "network",
        "process",
        "provider",
        "publication",
        "qualification",
        "routing",
        "target",
    ),
    "none",
)
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "policy_delivery_verified",
        "browser_behavior_verified",
        "full_csp_semantics_verified",
        "xss_safety_proven",
        "csp_bypass_proven",
        "live_fetch_approved",
        "current_authority_verified",
        "qualification_claimed",
    ),
    False,
)
_BOUNDS = {
    "model_bytes": MAX_MODEL_BYTES,
    "report_bytes": MAX_REPORT_BYTES,
    "model_nodes": MAX_MODEL_NODES,
    "report_nodes": MAX_REPORT_NODES,
    "model_depth": MAX_MODEL_DEPTH,
    "report_depth": MAX_REPORT_DEPTH,
    "string_bytes": MAX_STRING_BYTES,
    "policies": MAX_POLICIES,
    "queries": MAX_QUERIES,
    "directives_per_policy": MAX_DIRECTIVES_PER_POLICY,
    "sources_per_directive": MAX_SOURCES_PER_DIRECTIVE,
    "total_sources": MAX_TOTAL_SOURCES,
    "source_bytes": MAX_SOURCE_BYTES,
    "redirect_count": MAX_REDIRECT_COUNT,
    "cumulative_work_per_operation": MAX_WORK,
}
_LIMITATIONS = (
    "Origins, URLs, policies, completeness and redirect counts are caller declarations.",
    "Only pathless HTTP(S) DNS-host source predicates for image/font/media/connect are computed.",
    "Structured URL ports are already normalized; null denotes the scheme default port.",
    "Unsupported selected expressions or directives withhold that policy conclusion.",
    "An unresolved enforced policy withholds the overall supplied-predicate conclusion.",
    "Report-only observations do not restrict the overall enforced-policy predicate.",
    "Redirects, paths, opaque origins, IP/IDNA normalization and policy-driven upgrades "
    "are unassessed.",
    "Inline/script/style, nonces, hashes, strict-dynamic and full CSP semantics are unassessed.",
    "No browser, response, policy delivery, fetch permission, bypass or XSS-safety claim is made.",
    "Source digests bind canonical supplied declarations, not acquisition or authenticated truth.",
    "The embedded original policies and hosts are not sanitized for publication.",
    "No credentials, network, process, provider, current authority or qualification "
    "is established.",
)


class CspFetchAnalysisError(ValueError):
    """The closed supplied profile, cost bound or exact semantic replay was rejected."""


@dataclass(slots=True)
class _Budget:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount > MAX_WORK - self.used:
            raise CspFetchAnalysisError("Cumulative operation work budget exceeded")
        self.used += amount


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _capture(value: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int, int]:
    """Own exact native occurrences after charging punctuation, escaping and pending nodes."""
    size = nodes = 0
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    depth_limit = MAX_REPORT_DEPTH if report else MAX_MODEL_DEPTH
    active: set[int] = set()

    def take(amount: int) -> None:
        nonlocal size
        if amount > byte_limit - size:
            raise CspFetchAnalysisError("Escaped document byte budget exceeded")
        budget.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes
        budget.charge(1)
        nodes += 1
        if nodes > node_limit or depth > depth_limit:
            raise CspFetchAnalysisError("Native node/depth budget exceeded")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES:
                raise CspFetchAnalysisError("Native string budget exceeded")
            take(len(item) + 2)
            for char in item:
                if not (32 <= ord(char) <= 126 or char in _SPACE):
                    raise CspFetchAnalysisError("ASCII policy/JSON string subset required")
                if char in '\\"\t\n\f\r':
                    take(1)
            return item
        if kind is bool:
            take(4 if item else 5)
            return item
        if item is None:
            take(4)
            return None
        if kind is int:
            if item.bit_length() > 64 or not MIN_INTEGER <= item <= MAX_INTEGER:
                raise CspFetchAnalysisError("Signed 64-bit native integers required")
            budget.charge(20)
            take(len(str(item)))
            return item
        if kind not in (dict, list):
            raise CspFetchAnalysisError("Exact native integer-only JSON families required")
        if id(item) in active:
            raise CspFetchAnalysisError("Cyclic native input")
        count = len(item)
        children = count * (2 if kind is dict else 1)
        if children > node_limit - nodes:
            raise CspFetchAnalysisError("Collection exceeds remaining node budget")
        take(2 + max(0, count - 1) + (count if kind is dict else 0))
        active.add(id(item))
        try:
            if kind is list:
                return [visit(child, depth + 1) for child in item]
            owned = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise CspFetchAnalysisError("Exact native string object keys required")
                owned[visit(key, depth + 1)] = visit(child, depth + 1)
            return owned
        finally:
            active.remove(id(item))

    return visit(value, 1), size, nodes


def _integer(text: str) -> int:
    negative = text.startswith("-")
    digits = text[1:] if negative else text
    if (
        not digits
        or len(digits) > 19
        or any(not "0" <= c <= "9" for c in digits)
        or (len(digits) > 1 and digits[0] == "0")
    ):
        raise CspFetchAnalysisError("Bounded raw integer grammar required")
    limit = "9223372036854775808" if negative else "9223372036854775807"
    if len(digits) == 19 and digits > limit:
        raise CspFetchAnalysisError("Raw signed 64-bit integer bound exceeded")
    return int(text)


def _raw_string(text: str, start: int) -> int:
    index = start + 1
    count = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            return index + 1
        if char == "\\":
            index += 1
            if index >= len(text):
                raise CspFetchAnalysisError("Incomplete JSON escape")
            escape = text[index]
            if escape == "u":
                digits = text[index + 1 : index + 5]
                if len(digits) != 4 or any(c not in "0123456789abcdefABCDEF" for c in digits):
                    raise CspFetchAnalysisError("Malformed Unicode escape")
                decoded = int(digits, 16)
                if not (32 <= decoded <= 126 or decoded in (9, 10, 12, 13)):
                    raise CspFetchAnalysisError("Raw strings outside supported ASCII subset")
                index += 4
            elif escape not in '\\"/tnfr':
                raise CspFetchAnalysisError("Unsupported JSON string escape")
        elif not 32 <= ord(char) <= 126:
            raise CspFetchAnalysisError("Raw strings require valid ASCII JSON spelling")
        count += 1
        if count > MAX_STRING_BYTES:
            raise CspFetchAnalysisError("Raw decoded string budget exceeded")
        index += 1
    raise CspFetchAnalysisError("Unterminated JSON string")


def _decode(text: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int, int]:
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    depth_limit = MAX_REPORT_DEPTH if report else MAX_MODEL_DEPTH
    if type(text) is not str or not text or len(text) > byte_limit:
        raise CspFetchAnalysisError("Bounded exact native ASCII JSON required")
    budget.charge(len(text))
    if not text.isascii():
        raise CspFetchAnalysisError("ASCII JSON subset required")
    index = nodes = 0
    stack: list[str] = []
    while index < len(text):
        char = text[index]
        if char in " \t\r\n,:":
            index += 1
            continue
        if char in "]}":
            if not stack or stack.pop() != ("[" if char == "]" else "{"):
                raise CspFetchAnalysisError("Malformed raw JSON containers")
            index += 1
            continue
        nodes += 1
        if nodes > node_limit or len(stack) + 1 > depth_limit:
            raise CspFetchAnalysisError("Pre-decoder node/depth budget exceeded")
        if char in "[{":
            stack.append(char)
            index += 1
        elif char == '"':
            index = _raw_string(text, index)
        else:
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}{["':
                index += 1
                if index - start > 20:
                    raise CspFetchAnalysisError("Raw scalar lexical budget exceeded")
            token = text[start:index]
            if token not in ("true", "false", "null"):
                _integer(token)
    if stack:
        raise CspFetchAnalysisError("Unterminated raw JSON containers")

    def pairs(rows: list[tuple[str, Any]]) -> dict:
        owned = {}
        for key, value in rows:
            if key in owned:
                raise CspFetchAnalysisError("Duplicate JSON member")
            owned[key] = value
        return owned

    try:
        decoded = json.loads(text, object_pairs_hook=pairs, parse_int=_integer)
    except (ValueError, RecursionError, OverflowError) as exc:
        raise CspFetchAnalysisError("Invalid bounded JSON") from exc
    return _capture(decoded, budget, report=report)


def _fields(value: Any, fields: set[str], label: str) -> dict:
    if type(value) is not dict or value.keys() != fields:
        raise CspFetchAnalysisError(f"{label} requires exact closed fields")
    return value


def _dns(host: str) -> bool:
    # A declared DNS text profile, not URL/IDNA/IP normalization.
    return (
        1 <= len(host) <= 253
        and not host.endswith(".")
        and not all(c in "0123456789." for c in host)
        and all(_DNS_LABEL.fullmatch(label) is not None for label in host.split("."))
    )


def _url(value: Any) -> None:
    _fields(value, {"scheme", "host", "port"}, "URL/origin")
    scheme, host, port = value["scheme"], value["host"], value["port"]
    if type(scheme) is not str or scheme not in ("http", "https"):
        raise CspFetchAnalysisError("Declared canonical HTTP(S) scheme required")
    if type(host) is not str or not _dns(host) or host.lower() != host:
        raise CspFetchAnalysisError("Declared lowercase ASCII DNS host required")
    if port is not None and (
        type(port) is not int or not 1 <= port <= 65535 or port == (80 if scheme == "http" else 443)
    ):
        raise CspFetchAnalysisError(
            "Declared URL-normalized null/default or nondefault port required"
        )


def _validate(model: Any, budget: _Budget) -> None:
    _fields(
        model,
        {"schema_version", "protected_origin", "policy_list_complete", "policies", "queries"},
        "Model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise CspFetchAnalysisError("Exact native schema version 1 required")
    _url(model["protected_origin"])
    if type(model["policy_list_complete"]) is not bool:
        raise CspFetchAnalysisError("Exact declared completeness boolean required")
    for name, count, fields, key in (
        ("policies", MAX_POLICIES, {"policy_id", "disposition", "serialized_policy"}, "policy_id"),
        ("queries", MAX_QUERIES, {"query_id", "destination", "url", "redirect_count"}, "query_id"),
    ):
        rows = model[name]
        if type(rows) is not list or len(rows) > count:
            raise CspFetchAnalysisError("Bounded exact native policy/query arrays required")
        seen = set()
        for row in rows:
            budget.charge(1)
            _fields(row, fields, name)
            identifier = row[key]
            if (
                type(identifier) is not str
                or _REF.fullmatch(identifier) is None
                or identifier in seen
            ):
                raise CspFetchAnalysisError("Distinct bounded policy/query identifiers required")
            seen.add(identifier)
            if name == "policies":
                if type(row["disposition"]) is not str or row["disposition"] not in (
                    "enforce",
                    "report",
                ):
                    raise CspFetchAnalysisError("Exact enforce/report disposition required")
                if type(row["serialized_policy"]) is not str:
                    raise CspFetchAnalysisError("Exact serialized policy string required")
            else:
                if type(row["destination"]) is not str or row["destination"] not in _FETCH:
                    raise CspFetchAnalysisError(
                        "Only image/font/media/connect declarations supported"
                    )
                _url(row["url"])
                redirect = row["redirect_count"]
                if type(redirect) is not int or not 0 <= redirect <= MAX_REDIRECT_COUNT:
                    raise CspFetchAnalysisError("Bounded native declared redirect count required")


@dataclass(frozen=True, slots=True)
class _Source:
    text: str
    kind: str
    scheme: str | None = None
    host: str | None = None
    port: str | None = None


def _source(text: str, budget: _Budget) -> _Source:
    budget.charge(2 * len(text) + 1)
    if len(text) > MAX_SOURCE_BYTES:
        raise CspFetchAnalysisError("Source-expression software byte limit exceeded")
    lower = text.lower()
    if lower in ("'self'", "'none'"):
        return _Source(text, lower[1:-1])
    if text == "*":
        return _Source(text, "any")
    if lower in ("http:", "https:"):
        return _Source(text, "scheme", lower[:-1])
    scheme = None
    authority = lower
    if "://" in lower:
        scheme, authority = lower.split("://", 1)
        if scheme not in ("http", "https"):
            return _Source(text, "unsupported")
    if any(c in authority for c in "/?#@"):
        return _Source(text, "unsupported")
    port = None
    if ":" in authority:
        authority, port = authority.rsplit(":", 1)
        if port != "*" and (_DIGITS.fullmatch(port) is None or not 1 <= int(port) <= 65535):
            return _Source(text, "unsupported")
    host = authority
    base = host[2:] if host.startswith("*.") else host
    if host != "*" and not _dns(base):
        return _Source(text, "unsupported")
    return _Source(text, "host", scheme, host, port)


@dataclass(slots=True)
class _Policy:
    declaration: dict
    directives: dict[str, list[_Source]]
    observation: dict
    unsupported: bool


@dataclass(slots=True)
class _Retained:
    size: int
    nodes: int
    budget: _Budget

    def row(self, value: dict) -> dict:
        owned, size, nodes = _capture(value, self.budget, report=True)
        if size + 1 > MAX_REPORT_BYTES - self.size or nodes > MAX_REPORT_NODES - self.nodes:
            raise CspFetchAnalysisError("Cumulative retained report budget exceeded")
        self.size += size + 1
        self.nodes += nodes
        return owned


def _policies(model: dict, budget: _Budget, retained: _Retained) -> list[_Policy]:
    parsed = []
    total_sources = 0
    for row in model["policies"]:
        serialized = row["serialized_policy"]
        # Reserve scans and potential splits before constructing token arrays.
        budget.charge(4 * len(serialized) + 1)
        if serialized.count(";") + 1 > MAX_DIRECTIVES_PER_POLICY:
            raise CspFetchAnalysisError("Serialized directive segment limit exceeded")
        directives: dict[str, list[_Source]] = {}
        observations = []
        duplicates = []
        seen = set()
        unsupported = False
        for segment in serialized.split(";"):
            stripped = segment.strip(_SPACE)
            if not stripped:
                continue
            # Bound before splitting; unused duplicate values still incur input cost.
            gaps = sum(
                char in _SPACE and stripped[index - 1] not in _SPACE
                for index, char in enumerate(stripped)
                if index
            )
            if gaps > MAX_SOURCES_PER_DIRECTIVE:
                raise CspFetchAnalysisError("Serialized source count limit exceeded")
            words = _SPLIT_SPACE.split(stripped)
            name = words[0].lower()
            if len(name) > 128:
                raise CspFetchAnalysisError("Directive-name software byte limit exceeded")
            if name in seen:
                duplicates.append(name)
                continue
            seen.add(name)
            values = words[1:]
            if len(values) > MAX_SOURCES_PER_DIRECTIVE:
                raise CspFetchAnalysisError("Sources per directive limit exceeded")
            total_sources += len(values)
            if total_sources > MAX_TOTAL_SOURCES:
                raise CspFetchAnalysisError("Aggregate source-expression limit exceeded")
            supported = name in _SUPPORTED_DIRECTIVES and _DIRECTIVE.fullmatch(name) is not None
            sources = [_source(value, budget) for value in values]
            if not supported:
                unsupported = True
            observations.append(
                {
                    "name": name,
                    "supported_directive": supported,
                    "source_expressions": [
                        {"expression": source.text, "supported": source.kind != "unsupported"}
                        for source in sources
                    ],
                }
            )
            if supported:
                directives[name] = sources
        observation = retained.row(
            {
                "policy_id": row["policy_id"],
                "disposition": row["disposition"],
                "directives": observations,
                "ignored_duplicate_directives": duplicates,
                "unsupported_directive_present": unsupported,
            }
        )
        parsed.append(_Policy(row, directives, observation, unsupported))
    return parsed


def _matches(source: _Source, url: dict, origin: dict, budget: _Budget) -> bool:
    budget.charge(len(source.text) + len(url["host"]) + len(origin["host"]) + 16)
    if source.kind == "any":
        return True
    if source.kind == "none":
        return False
    if source.kind == "self":
        # Structured URLs carry normalized default ports as null.
        same = origin == url
        compatible_port = origin["port"] == url["port"]
        secure_destination = url["scheme"] == "https"
        insecure_pair = origin["scheme"] == "http" and url["scheme"] == "http"
        return same or (
            origin["host"] == url["host"]
            and compatible_port
            and (secure_destination or insecure_pair)
        )
    scheme = source.scheme or origin["scheme"]
    scheme_match = scheme == url["scheme"] or (scheme == "http" and url["scheme"] == "https")
    if source.kind == "scheme":
        return scheme_match
    if source.kind != "host" or not scheme_match:
        return False
    host = source.host
    if host is None:
        raise CspFetchAnalysisError("Incomplete private source projection")
    host_match = host == "*" or (
        url["host"].endswith(host[1:]) if host.startswith("*.") else host == url["host"]
    )
    if source.port == "*":
        port_match = True
    elif source.port is None:
        port_match = url["port"] is None
    else:
        effective = (
            url["port"] if url["port"] is not None else (80 if url["scheme"] == "http" else 443)
        )
        port_match = int(source.port) == effective
    return host_match and port_match


def _logic(model: dict, size: int, nodes: int, budget: _Budget) -> dict:
    retained = _Retained(size, nodes, budget)
    policies = _policies(model, budget, retained)
    observations = []
    counts = {"allowed_supplied_subset": 0, "blocked_supplied_subset": 0, "unassessed": 0}
    for query in model["queries"]:
        results = []
        enforced_results = []
        for policy in policies:
            budget.charge(1)
            effective = _FETCH[query["destination"]]
            selected = (
                effective
                if effective in policy.directives
                else ("default-src" if "default-src" in policy.directives else None)
            )
            sources = policy.directives[selected] if selected is not None else []
            matched = [
                source.text
                for source in sources
                if source.kind != "unsupported"
                and _matches(source, query["url"], model["protected_origin"], budget)
            ]
            reasons = []
            if query["redirect_count"]:
                reasons.append("redirect_semantics_unassessed")
            if policy.unsupported:
                reasons.append("unsupported_directive_semantics")
            if any(source.kind == "unsupported" for source in sources):
                reasons.append("unsupported_selected_source_expression")
            subset = "match" if selected is None or matched else "no_match"
            decision = "unassessed" if reasons else subset
            if policy.declaration["disposition"] == "enforce":
                enforced_results.append(decision)
            results.append(
                {
                    "policy_id": policy.declaration["policy_id"],
                    "disposition": policy.declaration["disposition"],
                    "effective_directive": effective,
                    "selected_directive": selected,
                    "supported_source_list_observation": subset,
                    "matched_source_expressions": matched,
                    "decision": decision,
                    "uncertainties": reasons,
                }
            )
        reasons = []
        if not model["policy_list_complete"]:
            reasons.append("declared_policy_list_incomplete")
        if query["redirect_count"]:
            reasons.append("redirect_semantics_unassessed")
        if "unassessed" in enforced_results:
            reasons.append("enforced_policy_semantics_unassessed")
        decision = (
            "unassessed"
            if reasons
            else "blocked_supplied_subset"
            if "no_match" in enforced_results
            else "allowed_supplied_subset"
        )
        counts[decision] += 1
        observations.append(
            retained.row(
                {
                    "query_id": query["query_id"],
                    "destination": query["destination"],
                    "policy_observations": results,
                    "decision": decision,
                    "uncertainties": reasons,
                }
            )
        )
    return {
        "policy_observations": [policy.observation for policy in policies],
        "query_observations": observations,
        "summary": {"query_count": len(observations), **counts},
    }


def _digest(domain: str, body: Any) -> str:
    return (
        "sha256:" + hashlib.sha256((domain + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )


@dataclass(slots=True)
class _Plan:
    document: dict
    size: int


def _plan(model: Any, budget: _Budget) -> _Plan:
    owned, size, nodes = _capture(model, budget)
    _validate(owned, budget)
    logic = _logic(owned, size, nodes, budget)
    document = {
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
        "standard_profile": STANDARD_PROFILE,
        "source_model": owned,
        "source_model_sha256": _PLACEHOLDER,
        "analysis_id": _ID_PLACEHOLDER,
        "analysis_sha256": _PLACEHOLDER,
        "effects": _EFFECTS,
        "flags": _FLAGS,
        "bounds": _BOUNDS,
        "limitations": list(_LIMITATIONS),
        **logic,
    }
    document, report_size, _ = _capture(document, budget, report=True)
    # Reserve all canonicalization, equality, encoding and addressing work before any digest.
    budget.charge(4 * report_size + 2 * size + len(DOMAIN) + len(MODEL_DOMAIN) + 2)
    return _Plan(document, report_size)


def _materialize(plan: _Plan) -> str:
    document = plan.document
    document["source_model_sha256"] = _digest(MODEL_DOMAIN, document["source_model"])
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = _digest(DOMAIN, body)
    document["analysis_sha256"] = digest
    document["analysis_id"] = "CFA-" + digest[7:39].upper()
    return _canonical(document)


def _replay_plan(text: Any, budget: _Budget) -> tuple[dict, _Plan, int]:
    document, size, _ = _decode(text, budget, report=True)
    if type(document) is not dict or "source_model" not in document:
        raise CspFetchAnalysisError("Report requires its complete embedded source model")
    plan = _plan(document["source_model"], budget)
    budget.charge(2 * size + plan.size)
    return document, plan, size


def _compare_replay(text: str, document: dict, expected: str) -> None:
    actual = _canonical(document)
    if actual != expected or text != actual:
        raise CspFetchAnalysisError("Canonical report does not replay its embedded source")


def _replay(text: Any, budget: _Budget) -> dict:
    document, plan, _ = _replay_plan(text, budget)
    _compare_replay(text, document, _materialize(plan))
    return document


@dataclass(frozen=True, slots=True)
class CspFetchAnalysis:
    """Owned supplied predicates, not browser enforcement or an authorized fetch."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not CspFetchAnalysis:
            raise CspFetchAnalysisError("Exact native report family required")
        _replay(self.document_json, _Budget())

    @classmethod
    def from_dict(cls, document: Any) -> CspFetchAnalysis:
        if cls is not CspFetchAnalysis:
            raise CspFetchAnalysisError("Exact native report family required")
        budget = _Budget()
        owned, size, _ = _capture(document, budget, report=True)
        budget.charge(size)
        text = _canonical(owned)
        _replay(text, budget)
        return _owned(text)

    @classmethod
    def from_json(cls, document_json: Any) -> CspFetchAnalysis:
        if cls is not CspFetchAnalysis:
            raise CspFetchAnalysisError("Exact native report family required")
        _replay(document_json, _Budget())
        return _owned(document_json)

    def to_dict(self) -> dict:
        if type(self) is not CspFetchAnalysis or not hasattr(self, "document_json"):
            raise CspFetchAnalysisError("Exact complete report wrapper required")
        return _replay(self.document_json, _Budget())

    def to_json(self) -> str:
        self.to_dict()
        return self.document_json


def _owned(text: str) -> CspFetchAnalysis:
    result = object.__new__(CspFetchAnalysis)
    object.__setattr__(result, "document_json", text)
    return result


def analyze_supplied_csp_fetch(model: Any) -> CspFetchAnalysis:
    """Analyze only exact supplied predicates without executing or fetching anything."""
    return _owned(_materialize(_plan(model, _Budget())))


def analyze_supplied_csp_fetch_bytes(*, model_bytes: Any) -> CspFetchAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise CspFetchAnalysisError("Bounded exact native model bytes required")
    budget = _Budget()
    budget.charge(len(model_bytes))
    if not model_bytes.isascii():
        raise CspFetchAnalysisError("ASCII JSON subset required")
    model, _, _ = _decode(model_bytes.decode("ascii"), budget)
    return _owned(_materialize(_plan(model, budget)))


def verify_supplied_csp_fetch_analysis(report: Any, *, model: Any) -> CspFetchAnalysis:
    if type(report) is not CspFetchAnalysis or not hasattr(report, "document_json"):
        raise CspFetchAnalysisError("Exact complete report wrapper required")
    budget = _Budget()
    actual, embedded, size = _replay_plan(report.document_json, budget)
    original = _plan(model, budget)
    budget.charge(size + original.size)
    expected = _materialize(embedded)
    original_expected = _materialize(original)
    _compare_replay(report.document_json, actual, expected)
    if _canonical(actual) != original_expected:
        raise CspFetchAnalysisError("Report does not match separately supplied original model")
    return _owned(original_expected)


def component_fixture() -> dict:
    """Fresh inert synthetic declarations, not delivered policies or an observed browser."""
    return {
        "schema_version": 1,
        "protected_origin": {"scheme": "http", "host": "app.example.test", "port": None},
        "policy_list_complete": True,
        "policies": [
            {
                "policy_id": "enforced.baseline",
                "disposition": "enforce",
                "serialized_policy": "default-src 'none'; img-src 'self' https://*.example.test; "
                "connect-src https:",
            },
            {
                "policy_id": "report.candidate",
                "disposition": "report",
                "serialized_policy": "default-src 'none'",
            },
        ],
        "queries": [
            {
                "query_id": "image.same-upgrade",
                "destination": "image",
                "redirect_count": 0,
                "url": {"scheme": "https", "host": "app.example.test", "port": None},
            },
            {
                "query_id": "font.denied",
                "destination": "font",
                "redirect_count": 0,
                "url": {"scheme": "https", "host": "fonts.example.test", "port": None},
            },
            {
                "query_id": "connect.external",
                "destination": "connect",
                "redirect_count": 0,
                "url": {"scheme": "https", "host": "api.other.test", "port": None},
            },
        ],
    }
