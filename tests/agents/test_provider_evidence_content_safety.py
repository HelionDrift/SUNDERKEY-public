"""Synthetic D013 content observations with no content processor or adapter."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from sunderkey import provider_evidence_content_safety as safety
from sunderkey.collaboration_executor_provider_evidence import VERIFICATION_DOMAIN
from sunderkey.collaboration_executor_provider_evidence_service import (
    CollaborationExecutorProviderEvidenceVerificationReceipt,
)
from sunderkey.provider_evidence_lifecycle import POLICY_DOMAIN, ProviderEvidenceLifecyclePolicy
from sunderkey.provider_evidence_repository import (
    INGEST_REQUEST_DOMAIN,
    ProviderEvidenceRepositoryIngestRequest,
    build_provider_evidence_repository_ingest_request,
)
from sunderkey.qualification import _canonical_json, _canonical_sha256
from tests.agents import test_provider_evidence_lifecycle_phase148 as phase148
from tests.agents import test_provider_evidence_repository_phase147 as phase147

EVIDENCE = phase147.phase144.EVIDENCE
DERIVATIVE = b"synthetic derivative candidate, not a redaction result"
ROOT = Path(__file__).resolve().parents[2]


class ForgedString(str):
    def __eq__(self, other):
        return True

    def __hash__(self):
        return str.__hash__(self)


class ProviderEvidenceContentSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Genuine existing signed synthetic source, created once for this class.
        fixture = phase147.ProviderEvidenceRepositoryPhase147Tests(methodName="runTest")
        cls.addClassCleanup(fixture.doCleanups)
        fixture.setUp()
        cls.fixture = fixture
        mission = fixture.fixture.fixture.fixture.fixture.dispatch.to_dict()["mission"]
        policy_fixture = phase148.ProviderEvidenceLifecyclePhase148Tests(methodName="runTest")
        policy_fixture.decision = fixture.decision
        cls.policy = policy_fixture._policy(
            mission_id=mission["mission_id"],
            mission_sha256=mission["mission_sha256"],
            scope_reference_sha256="sha256:"
            + hashlib.sha256(mission["scope_reference"].encode("utf-8")).hexdigest(),
            created_at="2026-07-30T10:08:39Z",
        )
        cls.request = cls.request_from_verification(fixture.verification)
        cls.request_json, cls.policy_json = cls.request.document_json, cls.policy.document_json

    @classmethod
    def request_from_verification(cls, verification):
        policy = cls.policy.to_dict()
        return build_provider_evidence_repository_ingest_request(
            cls.fixture.decision,
            verification,
            retention_policy_id=cls.policy.policy_id,
            retention_policy_sha256=cls.policy.policy_sha256,
            residency_policy_id=policy["residency"]["policy_id"],
            residency_policy_sha256=policy["residency"]["policy_sha256"],
            encryption_profile_id=policy["encryption"]["profile_id"],
            encryption_profile_sha256=policy["encryption"]["profile_sha256"],
            access_policy_id=policy["access"]["policy_id"],
            access_policy_sha256=policy["access"]["policy_sha256"],
            requested_at="2026-07-30T10:08:40Z",
            expires_at="2026-07-30T10:12:00Z",
        )

    def setUp(self) -> None:
        self.request = ProviderEvidenceRepositoryIngestRequest.from_dict(
            json.loads(self.request_json)
        )
        self.policy = ProviderEvidenceLifecyclePolicy.from_dict(json.loads(self.policy_json))

    def observe(self, evidence=EVIDENCE, **changes):
        return safety.observe_provider_evidence_content_prefix(
            **{
                "request": self.request,
                "lifecycle_policy": self.policy,
                "evidence": evidence,
                "environment_class": safety.ENVIRONMENT_CLASS,
                **changes,
            }
        )

    def declaration(self, derivative=DERIVATIVE):
        source = self.observe().to_dict()["source"]
        return {
            "source": {
                "ingest_request_id": source["ingest_request"]["request_id"],
                "ingest_request_sha256": source["ingest_request"]["request_sha256"],
                "lifecycle_policy_id": source["lifecycle_policy"]["policy_id"],
                "lifecycle_policy_sha256": source["lifecycle_policy"]["policy_sha256"],
                "mission": dict(source["mission"]),
                "content_address": source["evidence"]["content_address"],
                "evidence_size_bytes": len(EVIDENCE),
            },
            "derivative": {
                "content_address": "sha256:" + hashlib.sha256(derivative).hexdigest(),
                "evidence_size_bytes": len(derivative),
            },
            "transformation": {
                "transformation_ref": "transformationref:synthetic.placeholder.v1",
                "definition_sha256": "sha256:" + "58" * 32,
                "derivative_claim": "redacted_candidate",
            },
        }

    def derivative(self, **changes):
        if "provenance" not in changes:
            changes["provenance"] = self.declaration()
        return safety.verify_provider_evidence_derivative_provenance(
            **{
                "request": self.request,
                "lifecycle_policy": self.policy,
                "source_evidence": EVIDENCE,
                "derivative_evidence": DERIVATIVE,
                "environment_class": safety.ENVIRONMENT_CLASS,
                **changes,
            }
        )

    @staticmethod
    def addressed_request(raw):
        body = {
            key: value for key, value in raw.items() if key not in {"request_id", "request_sha256"}
        }
        digest = _canonical_sha256({"domain": INGEST_REQUEST_DOMAIN, "ingest_request": body})
        return ProviderEvidenceRepositoryIngestRequest.from_dict(
            {**body, "request_id": "EIR-" + digest[7:39].upper(), "request_sha256": digest}
        )

    def prefix_request(self, evidence):
        # These extra prefixes use unsigned serialized EPV projections. They do
        # not authenticate a changed source report or create a verification proof.
        raw = self.fixture.verification.to_dict()["evidence_verification"]
        body = {
            key: value
            for key, value in raw.items()
            if key not in {"verification_id", "verification_sha256"}
        }
        body.update(
            provider_evidence_sha256="sha256:" + hashlib.sha256(evidence).hexdigest(),
            evidence_size_bytes=len(evidence),
        )
        digest = _canonical_sha256(
            {"domain": VERIFICATION_DOMAIN, "provider_evidence_verification": body}
        )
        verification = CollaborationExecutorProviderEvidenceVerificationReceipt(
            verification_json=_canonical_json(
                {
                    **body,
                    "verification_id": "EPV-" + digest[7:39].upper(),
                    "verification_sha256": digest,
                }
            )
        )
        return self.request_from_verification(verification)

    def test_genuine_sources_round_trip_and_replay_without_authority(self) -> None:
        report = self.observe()
        raw = report.to_dict()
        self.assertEqual(raw["source"]["mission"], self.policy.to_dict()["mission"])
        self.assertEqual(
            raw["source"]["ingest_request"]["requested_at"], self.request.to_dict()["requested_at"]
        )
        self.assertEqual(
            raw["source"]["evidence"]["content_address"],
            "sha256:" + hashlib.sha256(EVIDENCE).hexdigest(),
        )
        self.assertEqual(raw["observation"]["status"], "unknown_prefix_observation")
        self.assertEqual(
            safety.ProviderEvidenceContentSafetyReport.from_json(report.document_json), report
        )
        for document in (raw, report):
            self.assertEqual(
                safety.verify_provider_evidence_content_observation_document(
                    document,
                    request=self.request,
                    lifecycle_policy=self.policy,
                    evidence=EVIDENCE,
                    environment_class=safety.ENVIRONMENT_CLASS,
                ),
                report,
            )
        self.assertTrue(all(value == "none" for value in raw["effects"].values()))
        self.assertEqual(raw["authentication_status"], "unsigned_reference_metadata")

    def test_prefix_observations_are_finite_and_never_type_or_safety_verdicts(self) -> None:
        cases = (
            (b"\x89PNG\r\n\x1a\nsynthetic", "known_prefix_observation", ["prefix:png-marker"]),
            (
                b"<?xml synthetic",
                "ambiguous_prefix_observation",
                ["prefix:angle-open", "prefix:xml-declaration-open"],
            ),
            (b"<", "ambiguous_prefix_observation", ["prefix:angle-open"]),
            (b"\xff\xd8", "truncated_prefix_observation", []),
            (b"PK", "truncated_prefix_observation", []),
            (b"fixed synthetic unknown", "unknown_prefix_observation", []),
        )
        for evidence, status, refs in cases:
            with self.subTest(evidence=evidence):
                report = self.observe(evidence, request=self.prefix_request(evidence)).to_dict()
                observed = report["observation"]
                self.assertEqual(observed["status"], status)
                self.assertEqual(observed["complete_prefix_refs"], refs)
                self.assertEqual(observed["type_verdict"], "not_determined")
                self.assertEqual(observed["malware_safety_verdict"], "not_assessed")
                self.assertLessEqual(observed["inspected_size_bytes"], safety.MAXIMUM_PREFIX_BYTES)
        for reference, marker in safety.PREFIX_FEATURES.items():
            evidence = marker + b"synthetic suffix only"
            with self.subTest(reference=reference):
                observed = self.observe(evidence, request=self.prefix_request(evidence)).to_dict()[
                    "observation"
                ]
                self.assertIn(reference, observed["complete_prefix_refs"])
                self.assertEqual(observed["type_verdict"], "not_determined")
                self.assertEqual(observed["malware_safety_verdict"], "not_assessed")
        with self.assertRaises(TypeError):
            safety.PREFIX_FEATURES["prefix:new"] = b"new"

    def test_source_digest_and_size_are_recomputed_from_exact_untouched_bytes(self) -> None:
        original = bytes(EVIDENCE)
        for evidence in (b"short", b"X" + EVIDENCE[1:]):
            with self.subTest(evidence=evidence):
                with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
                    self.observe(evidence)
        self.observe()
        self.assertEqual(EVIDENCE, original)
        self.assertEqual(self.request.document_json, self.request_json)
        self.assertEqual(self.policy.document_json, self.policy_json)

    def test_all_lifecycle_and_decision_refs_must_match_exact_policy(self) -> None:
        for field in self.request.to_dict()["lifecycle_bindings"]:
            raw = self.request.to_dict()
            raw["lifecycle_bindings"][field] = (
                "sha256:" + "00" * 32 if field.endswith("sha256") else "synthetic.unrelated"
            )
            with self.subTest(field=field):
                with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
                    self.observe(request=self.addressed_request(raw))
        raw = self.request.to_dict()
        raw["custody_decision"]["record_sha256"] = "sha256:" + "00" * 32
        with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
            self.observe(request=self.addressed_request(raw))

    def test_policy_mission_and_original_chronology_cannot_be_substituted(self) -> None:
        fixture = phase148.ProviderEvidenceLifecyclePhase148Tests(methodName="runTest")
        fixture.decision = self.fixture.decision
        for changes in (
            {"mission_id": "mission.synthetic-other"},
            {"created_at": "2026-07-30T10:08:41Z"},
        ):
            policy = fixture._policy(**changes)
            with self.subTest(changes=changes):
                with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
                    self.observe(lifecycle_policy=policy)
        # Coherent new IDs eliminate an earlier reference-mismatch rejection;
        # only the known policy-created/request chronology is contradictory.
        raw = self.policy.to_dict()
        raw["created_at"] = "2026-07-30T10:08:41Z"
        body = {
            key: value for key, value in raw.items() if key not in {"policy_id", "policy_sha256"}
        }
        digest = _canonical_sha256({"domain": POLICY_DOMAIN, "policy": body})
        policy = ProviderEvidenceLifecyclePolicy.from_dict(
            {**body, "policy_id": "ELP-" + digest[7:39].upper(), "policy_sha256": digest}
        )
        raw = self.request.to_dict()
        raw["lifecycle_bindings"].update(
            retention_policy_id=policy.policy_id, retention_policy_sha256=policy.policy_sha256
        )
        request = self.addressed_request(raw)
        with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
            self.observe(request=request, lifecycle_policy=policy)

    def test_derivative_bytes_and_declared_provenance_replay_without_transformation(self) -> None:
        declaration = self.declaration()
        declaration_before = copy.deepcopy(declaration)
        report = self.derivative(provenance=declaration)
        raw = report.to_dict()
        self.assertEqual(raw["provenance"], declaration_before)
        self.assertEqual(raw["transformation_status"], "not_executed_or_verified")
        self.assertEqual(raw["redaction_status"], "not_performed_or_verified")
        self.assertNotEqual(
            raw["provenance"]["derivative"]["content_address"],
            raw["source"]["evidence"]["content_address"],
        )
        for document in (raw, report):
            self.assertEqual(
                safety.verify_provider_evidence_derivative_provenance_document(
                    document,
                    request=self.request,
                    lifecycle_policy=self.policy,
                    source_evidence=EVIDENCE,
                    derivative_evidence=DERIVATIVE,
                    provenance=declaration,
                    environment_class=safety.ENVIRONMENT_CLASS,
                ),
                report,
            )
        declaration["transformation"]["derivative_claim"] = "derived_candidate"
        self.assertEqual(report.to_dict()["provenance"], declaration_before)
        self.assertEqual(EVIDENCE, phase147.phase144.EVIDENCE)

    def test_derivative_requires_distinct_address_and_exact_digest_size(self) -> None:
        for changes in (
            {"derivative_evidence": EVIDENCE, "provenance": self.declaration(EVIDENCE)},
            {"derivative_evidence": b"X" + DERIVATIVE[1:]},
            {"derivative_evidence": b"short"},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
                    self.derivative(**changes)

    def test_provenance_source_policy_mission_and_transform_fields_are_closed(self) -> None:
        for section, field, value in (
            ("source", "content_address", "sha256:" + "00" * 32),
            ("source", "evidence_size_bytes", len(EVIDENCE) + 1),
            ("source", "ingest_request_id", "EIR-" + "00" * 16),
            ("source", "lifecycle_policy_sha256", "sha256:" + "00" * 32),
            ("derivative", "evidence_size_bytes", True),
            ("derivative", "content_address", "not-a-digest"),
            ("transformation", "transformation_ref", "https://not-permitted.invalid"),
            ("transformation", "definition_sha256", "not-a-digest"),
            ("transformation", "derivative_claim", "redaction_completed"),
            ("transformation", "derivative_claim", []),
        ):
            declaration = self.declaration()
            declaration[section][field] = value
            with self.subTest(section=section, field=field, value=value):
                with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
                    self.derivative(provenance=declaration)
        declaration = self.declaration()
        declaration["source"]["mission"]["mission_id"] = "mission.synthetic-other"
        with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
            self.derivative(provenance=declaration)
        for section in (None, "source", "derivative", "transformation"):
            declaration = self.declaration()
            (declaration if section is None else declaration[section])["extra"] = "unsupported"
            with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
                self.derivative(provenance=declaration)

    def test_native_bytes_and_environment_are_required_before_hashing(self) -> None:
        class ByteSubclass(bytes):
            pass

        for evidence in (
            ByteSubclass(EVIDENCE),
            bytearray(EVIDENCE),
            memoryview(EVIDENCE),
            b"",
            b"x" * (safety.MAXIMUM_EVIDENCE_BYTES + 1),
        ):
            with self.subTest(kind=type(evidence).__name__):
                with mock.patch.object(safety.hashlib, "sha256") as hashed:
                    with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
                        self.observe(evidence)
                    hashed.assert_not_called()
        for environment in ("production", ForgedString("production"), None):
            with mock.patch.object(safety.hashlib, "sha256") as hashed:
                with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
                    self.observe(environment_class=environment)
                hashed.assert_not_called()

    def test_source_wrappers_are_exact_native_revalidated_and_detached(self) -> None:
        class RequestSubclass(ProviderEvidenceRepositoryIngestRequest):
            pass

        mutations = (
            replace(self.request, request_id="EIR-" + "00" * 16),
            replace(self.request, request_sha256="sha256:" + "00" * 32),
            replace(self.request, request_id=ForgedString(self.request.request_id)),
            replace(self.request, document_json=ForgedString(self.request.document_json)),
            RequestSubclass(
                self.request.request_id, self.request.request_sha256, self.request.document_json
            ),
        )
        for request in mutations:
            with self.subTest(request=request):
                with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
                    self.observe(request=request)
        report = self.observe()
        object.__setattr__(self.request, "request_sha256", "sha256:" + "00" * 32)
        with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
            self.observe()
        self.assertEqual(
            report.to_dict()["source"]["ingest_request"]["request_sha256"],
            json.loads(self.request_json)["request_sha256"],
        )
        raw = report.to_dict()
        raw["source"]["mission"]["mission_id"] = "mission.synthetic-other"
        self.assertNotEqual(raw, report.to_dict())

    def test_source_integer_aliases_are_denied_before_existing_normalizers(self) -> None:
        for family, wrapper, field in (
            (ProviderEvidenceRepositoryIngestRequest, self.request, "schema_version"),
            (ProviderEvidenceLifecyclePolicy, self.policy, "schema_version"),
            (ProviderEvidenceLifecyclePolicy, self.policy, "policy_version"),
        ):
            for value in (True, 1.0):
                raw = wrapper.to_dict()
                raw[field] = value
                changed = replace(wrapper, document_json=_canonical_json(raw))
                with self.subTest(family=family.__name__, field=field, value=value):
                    with mock.patch.object(family, "from_dict") as normalized:
                        with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
                            self.observe(
                                **(
                                    {"request": changed}
                                    if family is ProviderEvidenceRepositoryIngestRequest
                                    else {"lifecycle_policy": changed}
                                )
                            )
                        normalized.assert_not_called()

    def test_incomplete_source_wrappers_fail_before_reconstruction_or_hashing(self) -> None:
        declaration = self.declaration()
        for family, wrapper, fields, parameter in (
            (
                ProviderEvidenceRepositoryIngestRequest,
                self.request,
                ("request_id", "request_sha256", "document_json"),
                "request",
            ),
            (
                ProviderEvidenceLifecyclePolicy,
                self.policy,
                ("policy_id", "policy_sha256", "document_json"),
                "lifecycle_policy",
            ),
        ):
            for missing in (None, *fields):
                incomplete = object.__new__(family)
                for field in fields:
                    if missing is not None and field != missing:
                        object.__setattr__(incomplete, field, getattr(wrapper, field))
                for operation in ("observe", "derivative"):
                    with self.subTest(family=family.__name__, missing=missing, operation=operation):
                        with (
                            mock.patch.object(
                                ProviderEvidenceRepositoryIngestRequest, "from_dict"
                            ) as request_rebuilt,
                            mock.patch.object(
                                ProviderEvidenceLifecyclePolicy, "from_dict"
                            ) as policy_rebuilt,
                            mock.patch.object(safety.hashlib, "sha256") as hashed,
                        ):
                            with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
                                if operation == "observe":
                                    self.observe(**{parameter: incomplete})
                                else:
                                    self.derivative(
                                        provenance=declaration, **{parameter: incomplete}
                                    )
                            request_rebuilt.assert_not_called()
                            policy_rebuilt.assert_not_called()
                            hashed.assert_not_called()

    def test_incomplete_report_wrappers_fail_before_document_validation_or_hashing(self) -> None:
        report = self.observe()
        family = safety.ProviderEvidenceContentSafetyReport
        fields = ("report_id", "report_sha256", "document_json")
        for missing in (None, *fields):
            incomplete = object.__new__(family)
            for field in fields:
                if missing is not None and field != missing:
                    object.__setattr__(incomplete, field, getattr(report, field))
            for operation in ("construction", "to_dict", "replay"):
                with self.subTest(missing=missing, operation=operation):
                    with (
                        mock.patch.object(
                            safety, "_document", side_effect=AssertionError("Unexpected parsing")
                        ) as parsed,
                        mock.patch.object(safety.hashlib, "sha256") as hashed,
                    ):
                        with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
                            if operation == "construction":
                                incomplete.__post_init__()
                            elif operation == "to_dict":
                                incomplete.to_dict()
                            else:
                                safety.verify_provider_evidence_content_observation_document(
                                    incomplete,
                                    request=self.request,
                                    lifecycle_policy=self.policy,
                                    evidence=EVIDENCE,
                                    environment_class=safety.ENVIRONMENT_CLASS,
                                )
                        parsed.assert_not_called()
                        hashed.assert_not_called()
        for invalid_field in fields:
            arguments = {field: getattr(report, field) for field in fields}
            arguments[invalid_field] = None
            with self.subTest(invalid_field=invalid_field):
                with (
                    mock.patch.object(
                        safety, "_document", side_effect=AssertionError("Unexpected parsing")
                    ) as parsed,
                    mock.patch.object(safety.hashlib, "sha256") as hashed,
                ):
                    with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
                        family(**arguments)
                    parsed.assert_not_called()
                    hashed.assert_not_called()

    def test_aggregate_shared_and_escaped_metadata_bounds_precede_serialization(self) -> None:
        for large in (
            ["x" * 8192] * 9,
            ["\\" * 8192] * 5,
            {"deep": [[[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]]]},
        ):
            with self.subTest(kind=type(large).__name__):
                with mock.patch(
                    "sunderkey.provider_evidence_repository_conformance.json.dumps"
                ) as serialized:
                    with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
                        self.derivative(provenance=large)
                    serialized.assert_not_called()
        too_long = replace(self.request, document_json=" " * (safety.MAXIMUM_DOCUMENT_BYTES + 1))
        with mock.patch("sunderkey.provider_evidence_repository_conformance.json.loads") as parsed:
            with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
                self.observe(request=too_long)
            parsed.assert_not_called()

    def test_report_parsing_and_replay_reject_changed_metadata_and_false_verdicts(self) -> None:
        report = self.observe()
        for field, value in (
            ("schema_version", True),
            ("schema_version", 1.0),
            ("authentication_status", "authenticated"),
            ("content_safety_status", "safe"),
        ):
            raw = report.to_dict()
            raw[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
                    safety.ProviderEvidenceContentSafetyReport.from_dict(raw)
        raw = report.to_dict()
        raw["observation"]["malware_safety_verdict"] = "safe"
        with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
            safety.ProviderEvidenceContentSafetyReport.from_dict(
                safety._address(
                    {
                        key: value
                        for key, value in raw.items()
                        if key not in {"report_id", "report_sha256"}
                    }
                )
            )
        raw = report.to_dict()
        raw["observation"].update(
            status="known_prefix_observation", complete_prefix_refs=["prefix:pdf-marker"]
        )
        readdressed = safety.ProviderEvidenceContentSafetyReport.from_dict(
            safety._address(
                {
                    key: value
                    for key, value in raw.items()
                    if key not in {"report_id", "report_sha256"}
                }
            )
        )
        with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
            safety.verify_provider_evidence_content_observation_document(
                readdressed,
                request=self.request,
                lifecycle_policy=self.policy,
                evidence=EVIDENCE,
                environment_class=safety.ENVIRONMENT_CLASS,
            )

    def test_report_duplicate_extra_native_alias_and_wrapper_mutations_fail(self) -> None:
        report = self.derivative()
        raw = report.to_dict()
        raw["extra"] = "discarded"
        with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
            safety.ProviderEvidenceContentSafetyReport.from_dict(raw)
        duplicate = report.document_json.replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1'
        )
        with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
            safety.ProviderEvidenceContentSafetyReport.from_json(duplicate)
        raw = report.to_dict()
        raw = {ForgedString(key) if key == "kind" else key: value for key, value in raw.items()}
        with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
            safety.ProviderEvidenceContentSafetyReport.from_dict(raw)
        object.__setattr__(report, "report_id", "EDP-" + "00" * 16)
        with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
            report.to_dict()

    def test_readdressed_impossible_prefix_metadata_is_rejected_without_bytes(self) -> None:
        short = b"PK"
        short_report = self.observe(short, request=self.prefix_request(short))
        for report, changes in (
            (
                short_report,
                {
                    "complete_prefix_refs": ["prefix:png-marker"],
                    "truncated_prefix_refs": [],
                    "status": "known_prefix_observation",
                },
            ),
            (
                self.observe(),
                {
                    "complete_prefix_refs": ["prefix:jpeg-marker", "prefix:png-marker"],
                    "truncated_prefix_refs": [],
                    "status": "ambiguous_prefix_observation",
                },
            ),
            (
                self.observe(),
                {
                    "complete_prefix_refs": [],
                    "truncated_prefix_refs": ["prefix:png-marker"],
                    "status": "truncated_prefix_observation",
                },
            ),
        ):
            raw = report.to_dict()
            raw["observation"].update(changes)
            addressed = safety._address(
                {
                    key: value
                    for key, value in raw.items()
                    if key not in {"report_id", "report_sha256"}
                }
            )
            with self.subTest(changes=changes):
                with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
                    safety.ProviderEvidenceContentSafetyReport.from_dict(addressed)

    def test_readdressed_source_and_transformation_changes_fail_exact_replay(self) -> None:
        report = self.observe()
        for section, changes in (
            (
                "ingest_request",
                {"request_id": "EIR-" + "00" * 16, "request_sha256": "sha256:" + "00" * 32},
            ),
            (
                "lifecycle_policy",
                {"policy_id": "ELP-" + "00" * 16, "policy_sha256": "sha256:" + "00" * 32},
            ),
            ("mission", {"mission_id": "mission.synthetic-other"}),
            (
                "evidence",
                {
                    "verification_id": "EPV-" + "00" * 16,
                    "verification_sha256": "sha256:" + "00" * 32,
                },
            ),
            ("ingest_request", {"requested_at": "2026-07-30T10:08:41Z"}),
        ):
            raw = report.to_dict()
            raw["source"][section].update(changes)
            changed = safety.ProviderEvidenceContentSafetyReport.from_dict(
                safety._address(
                    {
                        key: value
                        for key, value in raw.items()
                        if key not in {"report_id", "report_sha256"}
                    }
                )
            )
            with self.subTest(section=section, changes=changes):
                with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
                    safety.verify_provider_evidence_content_observation_document(
                        changed,
                        request=self.request,
                        lifecycle_policy=self.policy,
                        evidence=EVIDENCE,
                        environment_class=safety.ENVIRONMENT_CLASS,
                    )
        declaration = self.declaration()
        original = self.derivative(provenance=declaration)
        raw = original.to_dict()
        raw["provenance"]["transformation"]["definition_sha256"] = "sha256:" + "00" * 32
        changed = safety.ProviderEvidenceContentSafetyReport.from_dict(
            safety._address(
                {
                    key: value
                    for key, value in raw.items()
                    if key not in {"report_id", "report_sha256"}
                }
            )
        )
        with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
            safety.verify_provider_evidence_derivative_provenance_document(
                changed,
                request=self.request,
                lifecycle_policy=self.policy,
                source_evidence=EVIDENCE,
                derivative_evidence=DERIVATIVE,
                provenance=declaration,
                environment_class=safety.ENVIRONMENT_CLASS,
            )

    def test_malformed_replay_metadata_fails_before_source_reconstruction(self) -> None:
        report = self.observe()
        for raw in (None, [], True, {**report.to_dict(), "schema_version": True}):
            with self.subTest(kind=type(raw).__name__):
                with mock.patch.object(
                    ProviderEvidenceRepositoryIngestRequest, "from_dict"
                ) as normalized:
                    with self.assertRaises(safety.ProviderEvidenceContentSafetyError):
                        safety.verify_provider_evidence_content_observation_document(
                            raw,
                            request=self.request,
                            lifecycle_policy=self.policy,
                            evidence=EVIDENCE,
                            environment_class=safety.ENVIRONMENT_CLASS,
                        )
                    normalized.assert_not_called()

    def test_reports_store_neither_input_content_nor_processed_content(self) -> None:
        for report in (self.observe(), self.derivative()):
            self.assertNotIn(EVIDENCE.decode("ascii"), report.document_json)
            self.assertNotIn(DERIVATIVE.decode("ascii"), report.document_json)
            raw = report.to_dict()
            self.assertEqual(raw["content_safety_status"], "not_assessed")
            self.assertTrue(all(effect == "none" for effect in raw["effects"].values()))
        tree = ast.parse(
            (ROOT / "src/sunderkey/provider_evidence_content_safety.py").read_text(encoding="utf-8")
        )
        imports = {
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.level == 0
        }
        imports |= {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        self.assertFalse(
            imports & {"subprocess", "socket", "sqlite3", "requests", "httpx", "google", "boto3"}
        )


if __name__ == "__main__":
    unittest.main()
