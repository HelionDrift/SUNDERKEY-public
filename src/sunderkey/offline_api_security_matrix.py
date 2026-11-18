"""Plan API security-declaration differentials without target interaction."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from .service_contract_extractor import (
    ServiceContractEndpointBundle,
    ServiceContractExtractionError,
)

DOMAIN = "sunderkey.offline-api-security-matrix.v1"
MAX_PRINCIPALS = 32
MAX_ENDPOINTS = 512
MAX_PAIRS = 4096
MAX_ASSERTION_BYTES = 65536
PRINCIPAL_RE = re.compile(r"principalref:[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z")
NO_EFFECTS = {
    "authorization": "none",
    "credential_resolution": "none",
    "execution": "none",
    "finding_publication": "none",
    "network": "none",
    "qualification": "none",
    "target_interaction": "none",
}


class OfflineApiSecurityMatrixError(ValueError):
    """Raised when a declared API differential cannot be planned safely."""


def _canonical(value: Any) -> str:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise OfflineApiSecurityMatrixError("matrix input is not JSON data") from exc


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _label(value: Any, name: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 256
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise OfflineApiSecurityMatrixError(f"{name} is invalid")
    return value


def _principals(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, (list, tuple)) or not 1 <= len(raw) <= MAX_PRINCIPALS:
        raise OfflineApiSecurityMatrixError("principal assertion count is invalid")
    normalized: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, Mapping) or set(item) != {"principal_ref", "grants"}:
            raise OfflineApiSecurityMatrixError("principal assertion fields are invalid")
        principal_ref = item["principal_ref"]
        if not isinstance(principal_ref, str) or PRINCIPAL_RE.fullmatch(principal_ref) is None:
            raise OfflineApiSecurityMatrixError("principal reference is invalid")
        grants = item["grants"]
        if not isinstance(grants, list) or len(grants) > 32:
            raise OfflineApiSecurityMatrixError("principal grants are invalid")
        normalized_grants = []
        for grant in grants:
            if not isinstance(grant, Mapping) or set(grant) != {"scheme", "scopes"}:
                raise OfflineApiSecurityMatrixError("principal grant fields are invalid")
            scheme = _label(grant["scheme"], "scheme")
            scopes = grant["scopes"]
            if not isinstance(scopes, list) or len(scopes) > 128:
                raise OfflineApiSecurityMatrixError("principal grant scopes are invalid")
            checked_scopes = [_label(scope, "scope") for scope in scopes]
            if checked_scopes != sorted(set(checked_scopes)):
                raise OfflineApiSecurityMatrixError(
                    "principal grant scopes are not sorted and unique"
                )
            normalized_grants.append({"scheme": scheme, "scopes": checked_scopes})
        names = [grant["scheme"] for grant in normalized_grants]
        if names != sorted(set(names)):
            raise OfflineApiSecurityMatrixError("principal grants are not sorted and unique")
        normalized.append({"principal_ref": principal_ref, "grants": normalized_grants})
    refs = [item["principal_ref"] for item in normalized]
    if refs != sorted(set(refs)):
        raise OfflineApiSecurityMatrixError("principals are not sorted and unique")
    if len(_canonical(normalized).encode("ascii")) > MAX_ASSERTION_BYTES:
        raise OfflineApiSecurityMatrixError("principal assertions exceed their size limit")
    return normalized


def _matches(requirement: Mapping[str, Any], grants: Mapping[str, set[str]]) -> bool:
    return all(
        scheme["name"] in grants
        and set(scheme["scopes"]) <= grants[scheme["name"]]
        for scheme in requirement["schemes"]
    )


def build_offline_api_security_matrix(
    *,
    bundle: ServiceContractEndpointBundle,
    principal_assertions: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Find declared positive and negative controls, not authorized actions."""

    if not isinstance(bundle, ServiceContractEndpointBundle):
        raise OfflineApiSecurityMatrixError("typed service contract bundle is required")
    try:
        checked = ServiceContractEndpointBundle.from_dict(bundle.to_dict())
    except ServiceContractExtractionError as exc:
        raise OfflineApiSecurityMatrixError("service contract bundle is invalid") from exc
    if checked.document_kind not in {"openapi", "swagger"}:
        raise OfflineApiSecurityMatrixError("HTTP API contract is required")
    if len(checked.endpoints) > MAX_ENDPOINTS:
        raise OfflineApiSecurityMatrixError("endpoint count exceeds matrix limit")
    principals = _principals(principal_assertions)
    rows = []
    total_pairs = 0
    for endpoint in checked.endpoints:
        requirements = endpoint.security_requirements
        if not requirements:
            matches = [
                {"principal_ref": principal["principal_ref"], "declaration_match": None}
                for principal in principals
            ]
            status = "no_security_requirement_declared"
            pairs: list[dict[str, str]] = []
        else:
            matches = []
            positive = []
            negative = []
            for principal in principals:
                grants = {
                    grant["scheme"]: set(grant["scopes"])
                    for grant in principal["grants"]
                }
                matched = any(_matches(requirement, grants) for requirement in requirements)
                matches.append({
                    "principal_ref": principal["principal_ref"],
                    "declaration_match": matched,
                })
                (positive if matched else negative).append(principal["principal_ref"])
            pairs = [
                {"matching_principal_ref": accepted, "nonmatching_principal_ref": denied}
                for accepted in positive
                for denied in negative
            ]
            total_pairs += len(pairs)
            if total_pairs > MAX_PAIRS:
                raise OfflineApiSecurityMatrixError("differential pair count exceeds limit")
            status = (
                "differential_pair_available" if pairs else
                "all_principals_match_declaration" if positive else
                "no_principal_matches_declaration"
            )
        rows.append({
            "endpoint_sha256": endpoint.endpoint_sha256,
            "method": endpoint.method,
            "security_requirements": [dict(item) for item in requirements],
            "declaration_status": status,
            "principal_matches": matches,
            "differential_pairs": pairs,
        })
    body = {
        "schema_version": 1,
        "bundle_sha256": checked.bundle_sha256,
        "assertions_sha256": _digest(principals),
        "endpoint_count": len(rows),
        "principal_count": len(principals),
        "differential_pair_count": total_pairs,
        "rows": rows,
        "interpretation": "declaration_only_unverified_hypothesis",
        "assertion_assurance": "caller_supplied_unsigned",
        "scheme_definition_assurance": "not_verified",
        "target_authorization_verified": False,
        "positive_use_approved": False,
        "effects": dict(NO_EFFECTS),
    }
    return {**body, "matrix_sha256": _digest({"domain": DOMAIN, "body": body})}


def verify_offline_api_security_matrix(
    *,
    bundle: ServiceContractEndpointBundle,
    principal_assertions: Sequence[Mapping[str, Any]],
    document: Mapping[str, Any],
) -> dict[str, Any]:
    expected = build_offline_api_security_matrix(
        bundle=bundle, principal_assertions=principal_assertions
    )
    if not isinstance(document, Mapping) or _canonical(document) != _canonical(expected):
        raise OfflineApiSecurityMatrixError("security matrix does not match inputs")
    return expected


__all__ = [
    "OfflineApiSecurityMatrixError",
    "build_offline_api_security_matrix",
    "verify_offline_api_security_matrix",
]
