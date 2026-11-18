"""Synthetic, unsigned D013 core-ingest conformance coverage."""

from __future__ import annotations

import ast
import hashlib
import json
import sys
import types
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import sunderkey.provider_evidence_repository_conformance as conformance
from sunderkey.collaboration_executor_provider_evidence import VERIFICATION_DOMAIN
from sunderkey.collaboration_executor_provider_evidence_service import (
    CollaborationExecutorProviderEvidenceVerificationReceipt,
)
from sunderkey.provider_evidence_custody_decision import (
    RECORD_DOMAIN,
    ProviderEvidenceCustodyDecisionRecord,
    load_provider_evidence_custody_decision_record,
)
from sunderkey.provider_evidence_repository import (
    INGEST_RECEIPT_DOMAIN,
    INGEST_REQUEST_DOMAIN,
    ProviderEvidenceRepositoryIngestReceipt,
    ProviderEvidenceRepositoryIngestRequest,
    build_provider_evidence_repository_ingest_receipt,
    build_provider_evidence_repository_ingest_request,
    validate_provider_evidence_repository_ingest_bytes,
)
from sunderkey.provider_evidence_repository_conformance import (
    CASE_BEHAVIORS,
    ENVIRONMENT_CLASS,
    REPORT_DOMAIN,
    ProviderEvidenceRepositoryConformanceCase,
    ProviderEvidenceRepositoryConformanceError,
    ProviderEvidenceRepositoryConformanceReport,
    run_provider_evidence_repository_conformance,
)

from . import test_collaboration_executor_provider_evidence_service_phase144 as phase144

ROOT = Path(__file__).resolve().parents[2]
AT = "2026-09-28T10:08:45Z"
EVIDENCE = phase144.EVIDENCE


def _json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _sha(value):
    return "sha256:" + hashlib.sha256(_json(value).encode("ascii")).hexdigest()


def _address_request(document):
    body = {
        key: value for key, value in document.items() if key not in {"request_id", "request_sha256"}
    }
    digest = _sha({"domain": INGEST_REQUEST_DOMAIN, "ingest_request": body})
    document.update(request_sha256=digest, request_id="EIR-" + digest[7:39].upper())
    return ProviderEvidenceRepositoryIngestRequest.from_dict(document)


def _address_report(document):
    body = {
        key: value for key, value in document.items() if key not in {"report_id", "report_sha256"}
    }
    digest = _sha({"domain": REPORT_DOMAIN, "report": body})
    document.update(report_sha256=digest, report_id="EIC-" + digest[7:39].upper())
    return document


def _address_receipt(document):
    body = {
        key: value for key, value in document.items() if key not in {"receipt_id", "receipt_sha256"}
    }
    digest = _sha({"domain": INGEST_RECEIPT_DOMAIN, "ingest_receipt": body})
    document.update(receipt_sha256=digest, receipt_id="ERR-" + digest[7:39].upper())
    return ProviderEvidenceRepositoryIngestReceipt.from_dict(document)


class _InertAdapter:
    """An in-memory sample, not storage custody or a production backend."""

    def __init__(self, mode="accepted", *, other_request=None, mutation=None):
        self.mode = mode
        self.other_request = other_request
        self.mutation = mutation
        self.calls = 0
        self.sampled_digest = None

    def put_quarantined(self, request, evidence):
        self.calls += 1
        validate_provider_evidence_repository_ingest_bytes(request, evidence)
        self.sampled_digest = "sha256:" + hashlib.sha256(evidence).hexdigest()
        if self.mode == "lost":
            raise RuntimeError("Synthetic acknowledgement lost after the sample")
        outcome = self.mode if self.mode in {"failed", "rejected"} else "accepted"
        if self.mode == "replay" and self.calls == 2:
            outcome = "already_exists_same_digest"
        receipt = build_provider_evidence_repository_ingest_receipt(
            self.other_request or request,
            adapter_id="repository.reference-fixture",
            adapter_version="1.0.0",
            adapter_build_sha256="sha256:" + "85" * 32,
            repository_id="repository.synthetic-001",
            object_version_id="version.synthetic-002"
            if self.mode == "replay-conflict" and self.calls == 2
            else "version.synthetic-001",
            outcome="already_exists_same_digest"
            if self.mode == "replay-conflict" and self.calls == 2
            else outcome,
            responded_at="2026-09-28T10:08:46Z",
        )
        if self.mode == "malformed":
            return receipt.to_dict()
        if self.mode == "wrapper":
            object.__setattr__(receipt, "receipt_sha256", "sha256:" + "00" * 32)
        if self.mode == "late":
            object.__setattr__(request, "request_sha256", "sha256:" + "00" * 32)
        if self.mutation is not None:
            self.mutation()
        return receipt


class ProviderEvidenceRepositoryConformanceTests(unittest.TestCase):
    def setUp(self):
        self.decision = load_provider_evidence_custody_decision_record(
            ROOT / "registry/provider-evidence-custody-decision-d013.json"
        )
        self.request = self._request()

    def _request(self, *, access_sha256="sha256:" + "84" * 32):
        # This is serialized public contract material with synthetic provenance
        # references, not an authenticated report or a new verification proof.
        body = {
            "schema_version": 1,
            "report_authentication_id": "EPA-" + "01" * 16,
            "report_authentication_sha256": "sha256:" + "01" * 32,
            "report_custody_id": "EPR-" + "02" * 16,
            "report_custody_sha256": "sha256:" + "02" * 32,
            "attempt_id": "EIP-" + "03" * 16,
            "acknowledgement_id": "EXA-" + "04" * 16,
            "acknowledgement_sha256": "sha256:" + "04" * 32,
            "provider_evidence_sha256": "sha256:" + hashlib.sha256(EVIDENCE).hexdigest(),
            "evidence_size_bytes": len(EVIDENCE),
            "evidence_media_type": "application/json",
            "verified_at": "2026-09-28T10:08:36Z",
            "evidence_verification_status": "provider_evidence_digest_verified",
            "media_type_status": "caller_declared_unverified",
            "semantic_verification_status": "not_performed",
            "external_effect_status": (
                "authenticated_report_evidence_digest_verified_effect_unverified"
            ),
            "runtime_effect": "none",
        }
        digest = _sha({"domain": VERIFICATION_DOMAIN, "provider_evidence_verification": body})
        receipt = CollaborationExecutorProviderEvidenceVerificationReceipt(
            verification_json=_json(
                {
                    **body,
                    "verification_id": "EPV-" + digest[7:39].upper(),
                    "verification_sha256": digest,
                }
            )
        )
        return build_provider_evidence_repository_ingest_request(
            self.decision,
            receipt,
            retention_policy_id="retention.synthetic-short-v1",
            retention_policy_sha256="sha256:" + "81" * 32,
            residency_policy_id="residency.synthetic-local-v1",
            residency_policy_sha256="sha256:" + "82" * 32,
            encryption_profile_id="encryption.synthetic-kms-v1",
            encryption_profile_sha256="sha256:" + "83" * 32,
            access_policy_id="access.synthetic-mission-v1",
            access_policy_sha256=access_sha256,
            requested_at="2026-09-28T10:08:40Z",
            expires_at="2026-09-28T10:12:00Z",
        )

    def _case(self, behavior="accepted_ingest", *, adapter=None, **changes):
        return ProviderEvidenceRepositoryConformanceCase(
            **{
                "case_id": "case.synthetic-001",
                "expected_behavior": behavior,
                "adapter": adapter if adapter is not None else _InertAdapter(),
                "request": self.request,
                "evidence": EVIDENCE,
                "attempted_at": AT,
                **changes,
            }
        )

    def _run(self, *cases, **changes):
        return run_provider_evidence_repository_conformance(
            **{
                "environment_class": ENVIRONMENT_CLASS,
                "decision": self.decision,
                "cases": cases,
                "maximum_calls": 16,
                **changes,
            }
        )

    def test_acceptance_is_unsigned_hash_size_and_request_sample_only(self):
        adapter = _InertAdapter()
        document = self._run(self._case(adapter=adapter)).to_dict()
        self.assertEqual(adapter.calls, 1)
        self.assertEqual(
            document["summary"], {"case_count": 1, "passed_case_count": 1, "failed_case_count": 0}
        )
        case = document["case_results"][0]
        self.assertEqual(case["supplied_request"]["request_id"], self.request.request_id)
        self.assertEqual(case["supplied_evidence"]["sha256"], adapter.sampled_digest)
        self.assertEqual(
            case["receipts"][0]["ingest_request"]["evidence_size_bytes"], len(EVIDENCE)
        )
        self.assertEqual(
            set(case["receipts"][0]["provider_assertions"].values()),
            {"provider_asserted_satisfied"},
        )
        self.assertEqual(set(document["provider_controls"].values()), {"unverified"})
        self.assertEqual(document["authentication_status"], "unsigned_reference_observations")
        for field in (
            "custody_effect",
            "authority_effect",
            "runtime_effect",
            "qualification_effect",
        ):
            self.assertEqual(document[field], "none")
        self.assertFalse(document["observed_live_acceptance"])
        self.assertFalse(document["raw_evidence_in_report"])
        self.assertNotIn(EVIDENCE.decode("ascii"), _json(document))

    def test_identical_replay_is_two_explicit_calls_with_stable_bindings(self):
        adapter = _InertAdapter("replay")
        document = self._run(
            self._case("identical_replay", adapter=adapter), maximum_calls=2
        ).to_dict()
        self.assertEqual(adapter.calls, 2)
        case = document["case_results"][0]
        self.assertEqual(case["observation"], "identical_reference_replay")
        self.assertEqual(case["case_status"], "passed")
        self.assertEqual(
            [item["outcome"] for item in case["receipts"]],
            ["accepted", "already_exists_same_digest"],
        )
        self.assertEqual(
            case["receipts"][0]["repository_object"], case["receipts"][1]["repository_object"]
        )
        self.assertEqual(set(document["provider_controls"].values()), {"unverified"})

    def test_replay_conflicting_version_fails_without_third_call(self):
        adapter = _InertAdapter("replay-conflict")
        case = self._run(
            self._case("identical_replay", adapter=adapter), maximum_calls=2
        ).to_dict()["case_results"][0]
        self.assertEqual(case["observation"], "replay_binding_mismatch")
        self.assertEqual(case["case_status"], "failed")
        self.assertEqual(adapter.calls, 2)

    def test_conflicting_same_request_bytes_are_rejected_before_invocation(self):
        for evidence in (b"X" + EVIDENCE[1:], EVIDENCE + b"X"):
            with self.subTest(size=len(evidence)):
                adapter = _InertAdapter()
                case = self._run(
                    self._case("pre_invocation_rejection", adapter=adapter, evidence=evidence),
                    maximum_calls=0,
                ).to_dict()["case_results"][0]
                self.assertEqual(case["observation"], "rejected_before_invocation")
                self.assertEqual(case["case_status"], "passed")
                self.assertEqual(adapter.calls, 0)
                self.assertEqual(case["receipts"], [])
        self.assertNotIn("repository_id", self.request.to_dict())
        self.assertNotIn("object_version_id", self.request.to_dict())
        document = self._run(self._case()).to_dict()
        self.assertEqual(
            document["same_object_conflict_status"], "not_expressible_by_ingest_request"
        )

    def test_expired_future_and_tampered_policy_requests_do_not_invoke(self):
        policy = self.request.to_dict()
        policy["repository_policy"]["content_safety"] = "unsafe"
        bad_policy = replace(self.request, document_json=_json(policy))
        cases = (
            self._case(
                "pre_invocation_rejection",
                case_id="expired.fixture",
                attempted_at="2026-09-28T10:12:00Z",
            ),
            self._case(
                "pre_invocation_rejection",
                case_id="future.fixture",
                attempted_at="2026-09-28T10:08:39Z",
            ),
            self._case("pre_invocation_rejection", case_id="policy.fixture", request=bad_policy),
        )
        report = self._run(*cases, maximum_calls=0).to_dict()
        self.assertEqual(report["summary"]["passed_case_count"], 3)
        self.assertTrue(all(item.adapter.calls == 0 for item in cases))

    def test_ordinary_invalid_input_in_later_case_fails_whole_preflight(self):
        first, second = _InertAdapter(), _InertAdapter()
        with self.assertRaises(ProviderEvidenceRepositoryConformanceError):
            self._run(
                self._case(adapter=first),
                self._case(adapter=second, case_id="later.invalid", evidence=b"wrong"),
            )
        self.assertEqual((first.calls, second.calls), (0, 0))

    def test_valid_input_declared_negative_is_not_silently_accepted(self):
        adapter = _InertAdapter()
        document = self._run(
            self._case("pre_invocation_rejection", adapter=adapter), maximum_calls=0
        ).to_dict()
        self.assertEqual(document["case_results"][0]["observation"], "unexpected_valid_input")
        self.assertEqual(document["conformance_status"], "reference_simulation_cases_failed")
        self.assertEqual(adapter.calls, 0)

    def test_malformed_substituted_and_reassigned_receipts_are_rejected(self):
        for adapter in (
            _InertAdapter("malformed"),
            _InertAdapter("wrapper"),
            _InertAdapter(other_request=self._request(access_sha256="sha256:" + "86" * 32)),
        ):
            with self.subTest(mode=adapter.mode):
                result = self._run(
                    self._case("malformed_result_rejection", adapter=adapter)
                ).to_dict()["case_results"][0]
                self.assertEqual(result["observation"], "invalid_result_rejected")
                self.assertEqual(result["case_status"], "passed")
                self.assertEqual(result["receipts"], [])
                self.assertEqual(adapter.calls, 1)

    def test_late_mutation_of_owned_request_and_original_wrapper_is_rejected(self):
        for target in ("owned", "source", "decision"):
            with self.subTest(target=target):
                request = self._request()
                decision = self.decision
                mutation = None
                if target == "source":

                    def mutation():
                        object.__setattr__(request, "request_id", "EIR-" + "00" * 16)

                elif target == "decision":

                    def mutation():
                        object.__setattr__(decision, "record_sha256", "sha256:" + "00" * 32)

                adapter = _InertAdapter(
                    "late" if target == "owned" else "accepted", mutation=mutation
                )
                report = self._run(
                    self._case("late_mutation_rejection", adapter=adapter, request=request)
                ).to_dict()
                result = report["case_results"][0]
                self.assertEqual(result["observation"], "late_input_mutation_rejected")
                self.assertEqual(result["case_status"], "passed")
                self.assertEqual(adapter.calls, 1)
                self.assertEqual(result["receipts"], [])
                self.decision = load_provider_evidence_custody_decision_record(
                    ROOT / "registry/provider-evidence-custody-decision-d013.json"
                )

    def test_response_time_and_native_receipt_schema_are_revalidated(self):
        for change in ("early", "expired", "boolean-schema", "subclass"):
            with self.subTest(change=change):

                def altered_receipt(request, evidence):
                    receipt = _InertAdapter().put_quarantined(request, evidence)
                    if change in {"early", "expired"}:
                        return build_provider_evidence_repository_ingest_receipt(
                            request,
                            **receipt.to_dict()["provider"],
                            repository_id="repository.synthetic-001",
                            object_version_id="version.synthetic-001",
                            outcome="accepted",
                            responded_at="2026-09-28T10:08:44Z"
                            if change == "early"
                            else "2026-09-28T10:12:00Z",
                        )
                    if change == "subclass":

                        class ReceiptSubclass(type(receipt)):
                            pass

                        return ReceiptSubclass(
                            receipt.receipt_id, receipt.receipt_sha256, receipt.document_json
                        )
                    from sunderkey.provider_evidence_repository import (
                        INGEST_RECEIPT_DOMAIN,
                        ProviderEvidenceRepositoryIngestReceipt,
                    )

                    document = receipt.to_dict()
                    document["schema_version"] = True
                    body = {
                        key: value
                        for key, value in document.items()
                        if key not in {"receipt_id", "receipt_sha256"}
                    }
                    digest = _sha({"domain": INGEST_RECEIPT_DOMAIN, "ingest_receipt": body})
                    document.update(receipt_sha256=digest, receipt_id="ERR-" + digest[7:39].upper())
                    return ProviderEvidenceRepositoryIngestReceipt.from_dict(document)

                adapter = types.SimpleNamespace(put_quarantined=altered_receipt)
                result = self._run(
                    self._case("malformed_result_rejection", adapter=adapter)
                ).to_dict()["case_results"][0]
                self.assertEqual(result["observation"], "invalid_result_rejected")
                self.assertEqual(result["adapter_call_count"], 1)

    def test_request_decision_binding_must_match_supplied_approved_record(self):
        document = self.decision.to_dict()
        document["approval"]["rationale"] += " Synthetic alternate decision fixture."
        body = {
            key: value
            for key, value in document.items()
            if key not in {"record_id", "record_sha256"}
        }
        digest = _sha({"domain": RECORD_DOMAIN, "record": body})
        document.update(record_sha256=digest, record_id="ECR-" + digest[7:39].upper())
        other = ProviderEvidenceCustodyDecisionRecord.from_dict(document)
        adapter = _InertAdapter()
        result = self._run(
            self._case("pre_invocation_rejection", adapter=adapter), decision=other, maximum_calls=0
        ).to_dict()["case_results"][0]
        self.assertEqual(result["observation"], "rejected_before_invocation")
        self.assertEqual(adapter.calls, 0)

    def test_later_fixture_mutation_is_not_invoked_with_uncaptured_bytes(self):
        later_adapter = _InertAdapter()
        later = self._case(
            "late_mutation_rejection", adapter=later_adapter, case_id="later.fixture"
        )
        first_adapter = _InertAdapter(
            mutation=lambda: object.__setattr__(later, "evidence", b"changed")
        )
        document = self._run(self._case(adapter=first_adapter), later).to_dict()
        self.assertEqual(document["case_results"][1]["observation"], "late_input_mutation_rejected")
        self.assertEqual(document["case_results"][1]["adapter_call_count"], 0)
        self.assertEqual(later_adapter.calls, 0)
        self.assertEqual(
            document["case_results"][1]["supplied_evidence"]["size_bytes"], len(EVIDENCE)
        )

    def test_failed_rejected_and_lost_acknowledgements_never_retry(self):
        for behavior, mode, observed in (
            ("failed_acknowledgement", "failed", "failed_provider_report"),
            ("rejected_acknowledgement", "rejected", "rejected_provider_report"),
            ("lost_acknowledgement", "lost", "ambiguous_no_acknowledgement"),
        ):
            with self.subTest(mode=mode):
                adapter = _InertAdapter(mode)
                document = self._run(
                    self._case(behavior, adapter=adapter), maximum_calls=1
                ).to_dict()
                self.assertEqual(adapter.calls, 1)
                self.assertIsNotNone(adapter.sampled_digest)
                self.assertEqual(document["case_results"][0]["observation"], observed)
                self.assertEqual(document["case_results"][0]["case_status"], "passed")
                self.assertEqual(set(document["provider_controls"].values()), {"unverified"})
                if mode != "lost":
                    self.assertEqual(
                        set(
                            document["case_results"][0]["receipts"][0][
                                "provider_assertions"
                            ].values()
                        ),
                        {"not_claimed"},
                    )

    def test_replay_stops_after_lost_first_acknowledgement(self):
        adapter = _InertAdapter("lost")
        document = self._run(
            self._case("identical_replay", adapter=adapter), maximum_calls=2
        ).to_dict()
        self.assertEqual(adapter.calls, 1)
        self.assertEqual(document["case_results"][0]["observation"], "ambiguous_no_acknowledgement")
        self.assertEqual(document["case_results"][0]["case_status"], "failed")

    def test_explicit_environment_case_limit_and_call_ceiling_are_fail_closed(self):
        for changes in (
            {"environment_class": "production"},
            {"maximum_calls": True},
            {"maximum_calls": 17},
            {"maximum_calls": 0},
            {"cases": [self._case()]},
            {"cases": tuple(self._case(case_id=f"case.{index:03}") for index in range(13))},
            {"cases": (self._case(), self._case())},
        ):
            with self.subTest(changes=list(changes)):
                adapter = _InertAdapter()
                with self.assertRaises(ProviderEvidenceRepositoryConformanceError):
                    self._run(self._case(adapter=adapter), **changes)
                self.assertEqual(adapter.calls, 0)
        adapter = _InertAdapter("replay")
        with self.assertRaisesRegex(ProviderEvidenceRepositoryConformanceError, "ceiling"):
            self._run(self._case("identical_replay", adapter=adapter), maximum_calls=1)
        self.assertEqual(adapter.calls, 0)

    def test_native_wrapper_metadata_and_json_aliases_rejected_before_hooks(self):
        class Alias(str):
            def __eq__(self, other):
                return True

            def __ne__(self, other):
                return False

            __hash__ = str.__hash__

        wrong_decision = replace(self.decision, record_sha256="sha256:" + "00" * 32)
        schema_alias = self.request.to_dict()
        schema_alias["schema_version"] = True
        schema_alias = _address_request(schema_alias)
        for request in (
            replace(self.request, request_id=Alias(self.request.request_id)),
            replace(self.request, request_sha256="sha256:" + "00" * 32),
            schema_alias,
            replace(
                self.request,
                document_json=self.request.document_json.replace(
                    '"schema_version":1', '"schema_version":1.0'
                ),
            ),
            replace(self.request, document_json='{"schema_version":1,"schema_version":1}'),
        ):
            with self.subTest(request=request.request_id):
                adapter = _InertAdapter()
                with self.assertRaises(ProviderEvidenceRepositoryConformanceError):
                    self._run(self._case(adapter=adapter, request=request))
                self.assertEqual(adapter.calls, 0)
        with self.assertRaises(ProviderEvidenceRepositoryConformanceError):
            self._run(self._case(), decision=wrong_decision)

    def test_report_is_deterministic_detached_and_revalidates_wrapper(self):
        report = self._run(self._case())
        same = self._run(self._case())
        self.assertEqual(report, same)
        self.assertEqual(
            ProviderEvidenceRepositoryConformanceReport.from_dict(report.to_dict()), report
        )
        returned = report.to_dict()
        returned["provider_controls"]["quarantine"] = "verified"
        returned["case_results"][0]["receipts"][0]["provider"]["adapter_id"] = "mutated"
        self.assertEqual(report.to_dict(), same.to_dict())
        with self.assertRaises(ProviderEvidenceRepositoryConformanceError):
            replace(report, report_sha256="sha256:" + "00" * 32).to_dict()
        with self.assertRaises(TypeError):
            CASE_BEHAVIORS["accepted_ingest"] = "qualified"

    def test_report_tamper_and_readdressed_type_or_authority_changes_fail(self):
        report = self._run(self._case()).to_dict()
        changed = json.loads(_json(report))
        changed["summary"]["passed_case_count"] = 0
        with self.assertRaises(ProviderEvidenceRepositoryConformanceError):
            ProviderEvidenceRepositoryConformanceReport.from_dict(changed)
        for mutate in (
            lambda item: item.update(schema_version=True),
            lambda item: item.update(adapter_call_count=True),
            lambda item: item["summary"].update(passed_case_count=True),
            lambda item: item["provider_controls"].update(conditional_create="verified"),
            lambda item: item.update(custody_effect="accepted"),
            lambda item: item.update(observed_live_acceptance=True),
            lambda item: item.update(maximum_calls=0),
            lambda item: item["case_results"][0].update(adapter_call_count=0, receipts=[]),
        ):
            with self.subTest(mutation=mutate):
                changed = json.loads(_json(report))
                mutate(changed)
                with self.assertRaises(ProviderEvidenceRepositoryConformanceError):
                    ProviderEvidenceRepositoryConformanceReport.from_dict(_address_report(changed))

    def test_aggregate_byte_bound_rejects_shared_graph_before_serialization(self):
        shared = ["x" * 8192] * 10
        material = {"shared": [shared] * 10}
        with patch("sunderkey.provider_evidence_repository_conformance.json.dumps") as serializer:
            with self.assertRaisesRegex(ProviderEvidenceRepositoryConformanceError, "byte bound"):
                ProviderEvidenceRepositoryConformanceReport.from_dict(material)
            serializer.assert_not_called()

    def test_rehashed_report_receipt_cannot_precede_known_invocation_time(self):
        document = self._run(self._case()).to_dict()
        receipt = document["case_results"][0]["receipts"][0]
        receipt["responded_at"] = "2026-09-28T10:08:44Z"
        document["case_results"][0]["receipts"][0] = _address_receipt(receipt).to_dict()
        with self.assertRaisesRegex(ProviderEvidenceRepositoryConformanceError, "precedes"):
            ProviderEvidenceRepositoryConformanceReport.from_dict(_address_report(document))

    def test_late_mutation_before_second_replay_preserves_valid_prefix_without_retry(self):
        adapter = _InertAdapter("replay")
        fixture = self._case("identical_replay", adapter=adapter)
        original = conformance._receipt

        def validated_prefix_then_mutate(request, returned, at):
            document = original(request, returned, at)
            object.__setattr__(fixture.request, "request_sha256", "sha256:" + "00" * 32)
            return document

        with patch.object(conformance, "_receipt", side_effect=validated_prefix_then_mutate):
            report = self._run(fixture, maximum_calls=2)
        document = report.to_dict()
        result = document["case_results"][0]
        self.assertEqual(adapter.calls, 1)
        self.assertEqual(result["adapter_call_count"], 1)
        self.assertEqual(result["observation"], "late_input_mutation_rejected")
        self.assertEqual(result["case_status"], "failed")
        self.assertEqual(len(result["receipts"]), 1)
        self.assertEqual(result["receipts"][0]["outcome"], "accepted")
        self.assertEqual(document["conformance_status"], "reference_simulation_cases_failed")
        self.assertEqual(set(document["provider_controls"].values()), {"unverified"})
        self.assertEqual(ProviderEvidenceRepositoryConformanceReport.from_dict(document), report)

    def test_late_replay_prefix_cannot_rehash_a_terminal_first_outcome(self):
        fixture = self._case("identical_replay", adapter=_InertAdapter("replay"))
        original = conformance._receipt

        def valid_prefix_then_mutate(request, returned, at):
            document = original(request, returned, at)
            object.__setattr__(fixture.request, "request_sha256", "sha256:" + "00" * 32)
            return document

        with patch.object(conformance, "_receipt", side_effect=valid_prefix_then_mutate):
            source = self._run(fixture, maximum_calls=2).to_dict()
        for outcome in ("failed", "rejected", "already_exists_same_digest"):
            with self.subTest(outcome=outcome):
                changed = json.loads(_json(source))
                receipt = changed["case_results"][0]["receipts"][0]
                receipt["outcome"] = outcome
                if outcome in {"failed", "rejected"}:
                    receipt["provider_assertions"] = dict.fromkeys(
                        receipt["provider_assertions"], "not_claimed"
                    )
                changed["case_results"][0]["receipts"][0] = _address_receipt(receipt).to_dict()
                with self.assertRaisesRegex(
                    ProviderEvidenceRepositoryConformanceError, "sampled shape"
                ):
                    ProviderEvidenceRepositoryConformanceReport.from_dict(_address_report(changed))

    def test_all_eight_explicit_behaviors_have_consistent_sampled_shapes(self):
        values = (
            ("accepted_ingest", "accepted", EVIDENCE),
            ("identical_replay", "replay", EVIDENCE),
            ("pre_invocation_rejection", "accepted", EVIDENCE + b"X"),
            ("malformed_result_rejection", "malformed", EVIDENCE),
            ("late_mutation_rejection", "late", EVIDENCE),
            ("failed_acknowledgement", "failed", EVIDENCE),
            ("rejected_acknowledgement", "rejected", EVIDENCE),
            ("lost_acknowledgement", "lost", EVIDENCE),
        )
        cases = tuple(
            self._case(
                behavior,
                adapter=_InertAdapter(mode),
                case_id=f"matrix.{index:03}",
                evidence=evidence,
            )
            for index, (behavior, mode, evidence) in enumerate(values)
        )
        report = self._run(*cases, maximum_calls=8)
        document = report.to_dict()
        self.assertEqual(
            document["summary"],
            {"case_count": 8, "passed_case_count": 8, "failed_case_count": 0},
        )
        self.assertEqual(document["adapter_call_count"], 8)
        self.assertEqual(sum(case.adapter.calls for case in cases), 8)
        self.assertEqual(ProviderEvidenceRepositoryConformanceReport.from_dict(document), report)

    def test_readdressed_replay_observation_must_reproduce_receipt_shapes(self):
        report = self._run(
            self._case("identical_replay", adapter=_InertAdapter("replay")), maximum_calls=2
        ).to_dict()
        for mutation in ("no-first-acceptance", "changed-version", "missing-receipt"):
            with self.subTest(mutation=mutation):
                changed = json.loads(_json(report))
                receipts = changed["case_results"][0]["receipts"]
                if mutation == "no-first-acceptance":
                    receipts[0]["outcome"] = "already_exists_same_digest"
                    receipts[0] = _address_receipt(receipts[0]).to_dict()
                elif mutation == "changed-version":
                    receipts[1]["repository_object"]["object_version_id"] = (
                        "version.synthetic-changed"
                    )
                    receipts[1] = _address_receipt(receipts[1]).to_dict()
                else:
                    receipts.pop()
                with self.assertRaisesRegex(
                    ProviderEvidenceRepositoryConformanceError, "sampled shape"
                ):
                    ProviderEvidenceRepositoryConformanceReport.from_dict(_address_report(changed))

    def test_leaf_import_has_no_io_or_default_backend(self):
        path = ROOT / "src/sunderkey/provider_evidence_repository_conformance.py"
        source = path.read_text(encoding="ascii")
        tree = ast.parse(source)
        imports = {
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        }
        imports |= {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        self.assertFalse(
            imports
            & {
                "pathlib",
                "socket",
                "urllib",
                "requests",
                "httpx",
                "sqlite3",
                "subprocess",
                "boto3",
                "google",
            }
        )
        module = types.ModuleType("sunderkey._repository_conformance_import_test")
        module.__package__ = "sunderkey"
        with (
            patch.dict(sys.modules, {module.__name__: module}),
            patch("builtins.open", side_effect=AssertionError("Unexpected import IO")),
            patch.object(Path, "read_bytes", side_effect=AssertionError("Unexpected import IO")),
            patch.object(Path, "read_text", side_effect=AssertionError("Unexpected import IO")),
        ):
            exec(compile(source, str(path), "exec"), module.__dict__)
        self.assertEqual(module.ENVIRONMENT_CLASS, ENVIRONMENT_CLASS)


if __name__ == "__main__":
    unittest.main()
