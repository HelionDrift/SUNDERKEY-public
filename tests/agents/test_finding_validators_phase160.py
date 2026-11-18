"""Phase 160 deterministic finding validator SDK tests."""

from __future__ import annotations

import ast
import json
import re
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.finding_validators import (
    DEFAULT_REGISTRY,
    AuthorizationDifferentialValidator,
    EvidenceRecord,
    FindingValidationError,
    FindingValidationLimits,
    FindingValidationRequest,
    FindingValidationResult,
    InputReflectionContextValidator,
    ValidatorDescriptor,
    build_default_registry,
    validate_finding,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "finding-validation-result-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "finding_validators.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "finding-validator-sdk.md",
)
SCOPE = "scope.phase160.fixture"
TECHNIQUE = "AT3-GB-D06-S09-01"


def evidence(
    evidence_id: str,
    content: bytes,
    *,
    role: str = "response",
    status: int | None = 200,
    headers=(),
    **attributes,
) -> EvidenceRecord:
    return EvidenceRecord.from_bytes(
        evidence_id,
        content,
        role=role,
        status_code=status,
        headers=headers,
        media_type="text/html",
        attributes=attributes,
    )


def request(validator_id: str, records, **kwargs) -> FindingValidationRequest:
    version = (
        AuthorizationDifferentialValidator.descriptor.version
        if validator_id == AuthorizationDifferentialValidator.descriptor.validator_id
        else "1.0.0"
    )
    return FindingValidationRequest(
        scope_id=SCOPE,
        technique_id=TECHNIQUE,
        validator_id=validator_id,
        validator_version=kwargs.pop("validator_version", version),
        evidence=tuple(records),
        **kwargs,
    )


class FindingValidatorPhase160Tests(unittest.TestCase):
    def test_authorization_differential_is_deterministic_and_schema_valid(self) -> None:
        allowed = evidence(
            "auth-owner",
            b'{"record":"same"}',
            principal_id="principal.owner",
            object_id="object.7",
            action="read",
            expected_access=True,
        )
        denied_principal = evidence(
            "auth-other",
            b'{"record":"same"}',
            principal_id="principal.other",
            object_id="object.7",
            action="read",
            expected_access=False,
        )
        validation = request(
            AuthorizationDifferentialValidator.descriptor.validator_id,
            (allowed, denied_principal),
            finding_impact="high",
        )
        first = DEFAULT_REGISTRY.validate(validation)
        second = DEFAULT_REGISTRY.validate(validation)
        self.assertEqual(first.document_json, second.document_json)
        self.assertEqual(first.state, "verified")
        self.assertGreaterEqual(len(first.observed_signals), 2)
        self.assertEqual(
            first.evidence_hashes,
            tuple(sorted({allowed.evidence_sha256, denied_principal.evidence_sha256})),
        )
        self.assertEqual(first.to_dict()["effects"]["network"], "none")
        if Draft202012Validator is not None:
            schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(first.to_dict())

    def test_negative_authorization_evidence_remains_distinct(self) -> None:
        owner = evidence(
            "owner-response",
            b"record",
            principal_id="owner",
            object_id="object.9",
            action="read",
            expected_access=True,
        )
        other = evidence(
            "other-response",
            b"denied",
            status=403,
            principal_id="other",
            object_id="object.9",
            action="read",
            expected_access=False,
        )
        result = DEFAULT_REGISTRY.validate(
            request(AuthorizationDifferentialValidator.descriptor.validator_id, (owner, other))
        )
        self.assertEqual(result.state, "negative")
        self.assertNotEqual(result.state, "inconclusive")

    def test_result_tampering_and_evidence_substitution_fail(self) -> None:
        record = evidence("canary-1", b"opaque-canary-77", source_id="source.a")
        result = validate_finding(
            scope_id=SCOPE,
            technique_id=TECHNIQUE,
            validator_id="validator.web.canary-observation",
            validator_version="1.0.0",
            evidence=(record,),
            canary_ids=("opaque-canary-77",),
        )
        changed = result.to_dict()
        changed["confidence"] = 1.0
        with self.assertRaisesRegex(FindingValidationError, "hash"):
            FindingValidationResult.from_dict(changed)
        with self.assertRaisesRegex(FindingValidationError, "hash"):
            EvidenceRecord.from_bytes(
                "substitution",
                b"different",
                content_sha256=record.content_sha256,
            )
        relabeled = EvidenceRecord.from_bytes(
            record.evidence_id,
            record.content,
            status_code=record.status_code,
            attributes={"source_id": "source.substituted"},
        )
        self.assertNotEqual(record.evidence_sha256, relabeled.evidence_sha256)
        with self.assertRaisesRegex(FindingValidationError, "record hash"):
            EvidenceRecord.from_bytes(
                record.evidence_id,
                record.content,
                status_code=record.status_code,
                attributes={"source_id": "source.substituted"},
                evidence_sha256=record.evidence_sha256,
            )
        with self.assertRaisesRegex(FindingValidationError, "expected evidence"):
            request(
                "validator.web.canary-observation",
                (record,),
                canary_ids=("opaque-canary-77",),
                expected_evidence_hashes=("sha256:" + "0" * 64,),
            )

    def test_secret_values_are_not_emitted(self) -> None:
        secret = "Bearer " + "this-is-a-sensitive-access-value"
        record = evidence(
            "sensitive-response",
            f"response {secret}".encode(),
            headers=(("Authorization", secret), ("Set-Cookie", "sid=private-value; HttpOnly")),
        )
        result = validate_finding(
            scope_id=SCOPE,
            technique_id=TECHNIQUE,
            validator_id="validator.web.security-header-cookie-policy",
            validator_version="1.0.0",
            evidence=(record,),
        )
        self.assertNotIn(secret, result.document_json)
        self.assertNotIn("private-value", result.document_json)
        self.assertNotIn("authorization", result.document_json.lower())

    def test_oversized_evidence_and_reduced_limits_fail(self) -> None:
        with self.assertRaisesRegex(FindingValidationError, "hard byte"):
            evidence("too-large", b"x" * (1_048_576 + 1))
        first = evidence("small-a", b"1234")
        second = evidence("small-b", b"5678")
        with self.assertRaisesRegex(FindingValidationError, "total byte"):
            request(
                "validator.web.canary-observation",
                (first, second),
                canary_ids=("canary-safe",),
                limits=FindingValidationLimits(max_total_evidence_bytes=7),
            )

    def test_ambiguous_status_and_false_positive_controls(self) -> None:
        marker = "reflect-marker-17"
        request_record = evidence(
            "reflection-request",
            f"value={marker}".encode(),
            role="request",
            status=None,
        )
        response = evidence(
            "reflection-response",
            f"<script>const value='{marker}'</script>".encode(),
            status=None,
        )
        result = DEFAULT_REGISTRY.validate(
            request(
                InputReflectionContextValidator.descriptor.validator_id,
                (request_record, response),
                markers=(marker,),
                finding_impact="high",
            )
        )
        self.assertEqual(result.state, "abstained")

        response = evidence(
            "reflection-response-typed",
            f"<script>const value='{marker}'</script>".encode(),
        )
        without_control = DEFAULT_REGISTRY.validate(
            request(
                InputReflectionContextValidator.descriptor.validator_id,
                (request_record, response),
                markers=(marker,),
                finding_impact="high",
            )
        )
        self.assertEqual(without_control.state, "hypothesis")
        self.assertFalse(without_control.corroboration_satisfied)

    def test_canary_needs_independent_sources_and_never_grants_authority(self) -> None:
        canary = "canary-observation-44"
        one = evidence("canary-a", f"seen:{canary}".encode(), source_id="sensor.a")
        partial = DEFAULT_REGISTRY.validate(
            request(
                "validator.web.canary-observation",
                (one,),
                canary_ids=(canary,),
                finding_impact="critical",
            )
        )
        self.assertEqual(partial.state, "hypothesis")
        self.assertNotIn(canary, partial.document_json)
        self.assertEqual(partial.to_dict()["effects"]["authority"], "none")

        two = evidence("canary-b", f"copy:{canary}:two".encode(), source_id="sensor.b")
        verified = DEFAULT_REGISTRY.validate(
            request(
                "validator.web.canary-observation",
                (one, two),
                canary_ids=(canary,),
                finding_impact="critical",
            )
        )
        self.assertEqual(verified.state, "verified")

    def test_error_header_cookie_and_redirect_validators(self) -> None:
        baseline = evidence(
            "baseline",
            b'{"ok":true}',
            variant="baseline",
            comparison_id="comparison.1",
        )
        probe = evidence(
            "probe",
            b"Database error SQLSTATE at /safe/path line 4",
            status=500,
            variant="probe",
            comparison_id="comparison.1",
        )
        error_result = DEFAULT_REGISTRY.validate(
            request("validator.api.error-oracle-differential", (baseline, probe))
        )
        self.assertEqual(error_result.state, "verified")

        policy = evidence(
            "policy",
            b"ok",
            headers=(("X-Content-Type-Options", "nosniff"), ("Set-Cookie", "id=x")),
        )
        policy_result = DEFAULT_REGISTRY.validate(
            request("validator.web.security-header-cookie-policy", (policy,))
        )
        self.assertEqual(policy_result.state, "verified")
        self.assertNotIn("id=x", policy_result.document_json)

        redirect = evidence(
            "redirect",
            b"",
            status=302,
            headers=(("Location", "http://outside.example/path"),),
            request_url="https://inside.example/start",
        )
        redirect_result = DEFAULT_REGISTRY.validate(
            request("validator.web.redirect-boundary", (redirect,))
        )
        self.assertEqual(redirect_result.state, "verified")
        self.assertNotIn("outside.example", redirect_result.document_json)

    def test_restoration_binding_changes_verified_result(self) -> None:
        owner = evidence(
            "restore-owner",
            b"same",
            principal_id="owner",
            object_id="object.restore",
            action="read",
            expected_access=True,
        )
        other = evidence(
            "restore-other",
            b"same",
            principal_id="other",
            object_id="object.restore",
            action="read",
            expected_access=False,
        )
        missing = DEFAULT_REGISTRY.validate(
            request(
                "validator.web.authorization-differential",
                (owner, other),
                restoration_required=True,
                options={"restored_object_id": "object.restore"},
            )
        )
        self.assertEqual(missing.state, "inconclusive")
        self.assertEqual(missing.restoration, "missing")

        restoration = evidence(
            "restoration",
            b"restored-state-record",
            role="restoration",
            status=None,
            restoration_status="verified",
            restored_object_id="object.restore",
        )
        restored = DEFAULT_REGISTRY.validate(
            request(
                "validator.web.authorization-differential",
                (owner, other),
                restoration_required=True,
                restoration_evidence=(restoration,),
                expected_restoration_hashes=(restoration.evidence_sha256,),
                options={"restored_object_id": "object.restore"},
            )
        )
        self.assertEqual(restored.state, "verified")
        self.assertEqual(
            restored.restoration_evidence_hashes,
            (restoration.evidence_sha256,),
        )

    def test_exact_versions_and_registry_drift_fail_closed(self) -> None:
        record = evidence("version-test", b"none", source_id="source.a")
        with self.assertRaisesRegex(FindingValidationError, "exact validator"):
            DEFAULT_REGISTRY.validate(
                request(
                    "validator.web.canary-observation",
                    (record,),
                    validator_version="1.0.1",
                    canary_ids=("canary-safe",),
                )
            )
        result = DEFAULT_REGISTRY.validate(
            request(
                "validator.web.canary-observation",
                (record,),
                canary_ids=("canary-safe",),
            )
        )
        changed = result.to_dict()
        changed["registry_sha256"] = "sha256:" + "0" * 64
        body = {
            key: value
            for key, value in changed.items()
            if key not in {"result_id", "result_sha256"}
        }
        import hashlib

        canonical = json.dumps(
            {"domain": "sunderkey.finding-validation-result.v1", "result": body},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
        changed["result_sha256"] = "sha256:" + hashlib.sha256(canonical).hexdigest()
        changed["result_id"] = "FVR-" + changed["result_sha256"][7:39].upper()
        with self.assertRaisesRegex(FindingValidationError, "registry drift"):
            DEFAULT_REGISTRY.verify_result(changed)

        class Drifted(AuthorizationDifferentialValidator):
            descriptor = ValidatorDescriptor(
                "validator.web.authorization-differential",
                AuthorizationDifferentialValidator.descriptor.version,
                "authorization_differential",
                ("unauthorized_success", "authorized_control", "replacement_signal"),
                3,
            )

        with self.assertRaisesRegex(FindingValidationError, "descriptor drift"):
            type(DEFAULT_REGISTRY)((Drifted(),))
        self.assertEqual(build_default_registry().registry_sha256, DEFAULT_REGISTRY.registry_sha256)

    def test_no_effectful_imports_and_source_hygiene(self) -> None:
        tree = ast.parse(FILES[0].read_text(encoding="utf-8"))
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module and not node.level
        )
        forbidden_imports = {"http", "requests", "socket", "subprocess", "urllib"}
        self.assertTrue(forbidden_imports.isdisjoint(imported))
        forbidden_marker = re.compile(
            "(?i)(" + "chat" + "gpt|gene" + "rated by " + "ai|clau" + "de)"
        )
        for path in FILES:
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                self.assertNotIn("\u2013", text)
                self.assertNotIn("\u2014", text)
                self.assertIsNone(forbidden_marker.search(text))


if __name__ == "__main__":
    unittest.main()
