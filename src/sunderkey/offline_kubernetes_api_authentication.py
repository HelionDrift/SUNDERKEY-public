"""Inert comparison of supplied Kubernetes API authentication declarations."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "kubernetes_supplied_api_authentication_context"
PROFILE_ID = "AOE-GC-D15-S03"
CAPABILITY_ID = "army.gc.d15.s03"
VECTOR_ID = "AV-GC-D15-S03-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D15-S03"
WAVE_ID = "IW2-005"
COMMANDER_ID = "AOE-GC-D15-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:197e94b29f1a32b8c78b400123eb37cc64782cfc594e8effa2b31bfaec91e498"
DOMAIN = "sunderkey.offline-kubernetes-api-authentication.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_CREDENTIALS = 64
MAX_REQUESTS = 128
_REF = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")
EFFECTS = dict.fromkeys(
    ("authority", "credential", "execution", "filesystem", "network", "process",
     "provider", "qualification", "target"), "none"
)


class KubernetesApiAuthenticationError(ValueError):
    """Invalid supplied authentication declaration or failed original replay."""


def _ref(value: Any, label: str) -> str:
    if type(value) is not str or _REF.fullmatch(value) is None:
        raise KubernetesApiAuthenticationError(f"{label} must be a bounded reference ID")
    return value


def _optional_ref(value: Any, label: str) -> str | None:
    return None if value is None else _ref(value, label)


def _rows(value: Any, maximum: int, key: str, label: str) -> list[dict]:
    rows = core.bounded_list(value, maximum, label)
    identifiers = [_ref(row[key], key) for row in rows if type(row) is dict and key in row]
    if len(identifiers) != len(rows) or identifiers != sorted(set(identifiers)):
        raise KubernetesApiAuthenticationError(f"{label} IDs must be sorted and unique")
    return rows


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "credentials", "requests"},
        "authentication model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise KubernetesApiAuthenticationError("Schema version 1 required")
    _ref(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    credentials = _rows(model["credentials"], MAX_CREDENTIALS, "credential_id", "credentials")
    requests = _rows(model["requests"], MAX_REQUESTS, "request_id", "requests")
    for item in credentials:
        core.exact(
            item,
            {"credential_id", "credential_kind", "principal_id", "audience_id",
             "validity", "metadata_complete"},
            "credential metadata",
        )
        core.choice(item["credential_kind"], {"service_account_token", "client_certificate"},
                    "credential kind")
        _ref(item["principal_id"], "principal ID")
        _optional_ref(item["audience_id"], "audience ID")
        if item["credential_kind"] == "client_certificate" and item["audience_id"] is not None:
            raise KubernetesApiAuthenticationError(
                "Client certificate cannot declare token audience"
            )
        core.choice(item["validity"], {"valid", "expired", "unknown"}, "validity")
        core.boolean(item["metadata_complete"], "credential metadata completeness")
    for item in requests:
        core.exact(
            item,
            {"request_id", "credential_id", "expected_principal_id", "audience_id",
             "supplied_outcome", "context_complete", "observation_complete"},
            "API request declaration",
        )
        _ref(item["credential_id"], "credential ID")
        _ref(item["expected_principal_id"], "expected principal ID")
        _optional_ref(item["audience_id"], "request audience ID")
        core.choice(item["supplied_outcome"], {"authenticated", "rejected", "unknown"},
                    "supplied outcome")
        core.boolean(item["context_complete"], "request context completeness")
        core.boolean(item["observation_complete"], "observation completeness")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    credentials = {row["credential_id"]: row for row in model["credentials"]}
    rows = []
    for request in model["requests"]:
        credential = credentials.get(request["credential_id"])
        reason = None
        expected = None
        if (
            model["inventory_complete"] and credential is not None
            and credential["metadata_complete"] and request["context_complete"]
            and request["observation_complete"]
        ):
            if credential["validity"] == "expired":
                reason = "declared_expired_credential"
                expected = "rejected"
            elif credential["validity"] == "valid":
                if (
                    credential["credential_kind"] == "service_account_token"
                    and credential["audience_id"] is not None
                    and request["audience_id"] is not None
                    and credential["audience_id"] != request["audience_id"]
                ):
                    reason = "declared_audience_mismatch"
                elif credential["principal_id"] != request["expected_principal_id"]:
                    reason = "declared_principal_mismatch"
        candidate = expected == "rejected" and request["supplied_outcome"] == "authenticated"
        rows.append({
            "request_id": request["request_id"],
            "credential_id": request["credential_id"],
            "expected_authentication": expected,
            "reason": reason,
            "disposition": "candidate_declared_authentication_mismatch" if candidate else "unknown",
        })
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(source_text.encode("ascii")),
        "credential_count": len(model["credentials"]),
        "request_count": len(rows),
        "request_rows": rows,
        "candidate_count": sum(row["disposition"].startswith("candidate") for row in rows),
        "unknown_count": sum(row["disposition"] == "unknown" for row in rows),
        "source_authenticated": False,
        "api_contacted": False,
        "credential_bytes_accepted": False,
        "token_validated": False,
        "authentication_performed": False,
        "finding_claimed": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "All credential metadata, request context and outcomes are caller declarations.",
            "No raw token, private key, certificate or kubeconfig bytes are accepted.",
            "Only a declared expired credential yields a candidate rejection.",
            "Principal and single-audience differences remain unknown context differences.",
            "A candidate is a declaration mismatch, not a verified authentication bypass.",
            "No Kubernetes API, credential provider, network, process or target is contacted.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="KAA-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class KubernetesApiAuthenticationReport:
    """Detached report requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise KubernetesApiAuthenticationError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> KubernetesApiAuthenticationReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_kubernetes_api_authentication(model: Any) -> KubernetesApiAuthenticationReport:
    return KubernetesApiAuthenticationReport._owned(_derive(model))


def analyze_supplied_kubernetes_api_authentication_bytes(
    *, model_bytes: bytes
) -> KubernetesApiAuthenticationReport:
    return analyze_supplied_kubernetes_api_authentication(
        core.decode(model_bytes, maximum=MAX_MODEL_BYTES)
    )


def verify_supplied_kubernetes_api_authentication(
    report: Any, *, model: Any
) -> KubernetesApiAuthenticationReport:
    if type(report) is not KubernetesApiAuthenticationReport:
        raise KubernetesApiAuthenticationError("Exact native report family required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise KubernetesApiAuthenticationError("Report differs from original model")
    return KubernetesApiAuthenticationReport._owned(expected)


def verify_supplied_kubernetes_api_authentication_bytes(
    report_bytes: bytes, *, model: Any
) -> KubernetesApiAuthenticationReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise KubernetesApiAuthenticationError("Exported report differs from original model")
    return KubernetesApiAuthenticationReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-api-auth",
        "inventory_complete": True,
        "credentials": [{
            "credential_id": "sa-token-ref", "credential_kind": "service_account_token",
            "principal_id": "team-a-sa", "audience_id": "api-a", "validity": "expired",
            "metadata_complete": True,
        }],
        "requests": [{
            "request_id": "declared-expired-credential", "credential_id": "sa-token-ref",
            "expected_principal_id": "team-a-sa", "audience_id": "api-a",
            "supplied_outcome": "authenticated", "context_complete": True,
            "observation_complete": True,
        }],
    }


__all__ = [
    "KubernetesApiAuthenticationError", "KubernetesApiAuthenticationReport",
    "analyze_supplied_kubernetes_api_authentication",
    "analyze_supplied_kubernetes_api_authentication_bytes",
    "verify_supplied_kubernetes_api_authentication",
    "verify_supplied_kubernetes_api_authentication_bytes", "component_fixture",
]
