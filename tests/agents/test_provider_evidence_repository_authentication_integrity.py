"""Bounded unsigned ERI replay and live source-correlation regressions."""

from __future__ import annotations

import copy
import unittest
from datetime import timedelta
from unittest.mock import Mock, patch

from sunderkey import provider_evidence_repository_authentication as authentication
from sunderkey.collaboration_executor import (
    ACKNOWLEDGEMENT_DOMAIN,
    CollaborationExecutorAcknowledgement,
)
from sunderkey.collaboration_executor_authentication import (
    AUTHENTICATION_DOMAIN as ACK_AUTHENTICATION_DOMAIN,
)
from sunderkey.collaboration_executor_authentication import (
    collaboration_executor_acknowledgement_selection_sha256,
)
from sunderkey.collaboration_executor_provider_evidence import VERIFICATION_DOMAIN
from sunderkey.collaboration_executor_provider_report import PROVIDER_REPORT_DOMAIN
from sunderkey.collaboration_executor_provider_report_authentication import (
    AUTHENTICATION_DOMAIN as REPORT_AUTHENTICATION_DOMAIN,
)
from sunderkey.collaboration_executor_provider_report_authentication import (
    validate_authenticated_collaboration_executor_provider_report_document,
)
from sunderkey.errors import PrincipalAuthenticationError
from sunderkey.identity import PrincipalOperation, compute_operation_intent_hash
from sunderkey.provider_evidence_repository import (
    INGEST_RECEIPT_DOMAIN,
    INGEST_REQUEST_DOMAIN,
    ProviderEvidenceRepositoryIngestReceipt,
    ProviderEvidenceRepositoryIngestRequest,
)
from sunderkey.provider_evidence_repository_authentication import (
    validate_authenticated_provider_evidence_repository_ingest_receipt_document as validate_eri,
)
from sunderkey.qualification import _canonical_json, _canonical_sha256
from sunderkey.store import parse_timestamp

from . import test_provider_evidence_repository_authentication_phase149 as phase149


def _address(document, domain, body_name, id_name, hash_name, prefix):
    body = {key: value for key, value in document.items() if key not in {id_name, hash_name}}
    digest = _canonical_sha256({"domain": domain, body_name: body})
    document[id_name] = prefix + digest.removeprefix("sha256:")[:32].upper()
    document[hash_name] = digest


def _address_eri(document):
    _address(
        document,
        authentication.AUTHENTICATION_DOMAIN,
        "authentication",
        "authentication_id",
        "authentication_sha256",
        "ERI-",
    )


def _rebind_request_and_receipt(document):
    request = document["ingest_request"]
    verification = request["evidence_verification"]
    _address(
        verification,
        VERIFICATION_DOMAIN,
        "provider_evidence_verification",
        "verification_id",
        "verification_sha256",
        "EPV-",
    )
    request["content_address"] = verification["provider_evidence_sha256"]
    _address(
        request,
        INGEST_REQUEST_DOMAIN,
        "ingest_request",
        "request_id",
        "request_sha256",
        "EIR-",
    )
    receipt = document["ingest_receipt"]
    receipt["ingest_request"] = {
        "request_id": request["request_id"],
        "request_sha256": request["request_sha256"],
        "content_address": request["content_address"],
        "evidence_size_bytes": verification["evidence_size_bytes"],
    }
    receipt["repository_object"]["content_address"] = request["content_address"]
    _address(
        receipt,
        INGEST_RECEIPT_DOMAIN,
        "ingest_receipt",
        "receipt_id",
        "receipt_sha256",
        "ERR-",
    )
    attestor = document["repository_attestor"]
    attestor["operation_intent_sha256"] = compute_operation_intent_hash(
        PrincipalOperation.EVIDENCE_REPOSITORY_ACKNOWLEDGE,
        {
            "ingest_receipt_selection_sha256": (
                authentication.provider_evidence_repository_ingest_receipt_selection_sha256(
                    ProviderEvidenceRepositoryIngestReceipt.from_dict(receipt)
                )
            ),
            "ingest_request_sha256": request["request_sha256"],
            "lifecycle_policy_sha256": document["lifecycle_policy"]["policy_sha256"],
            "mission_id": document["lifecycle_policy"]["mission"]["mission_id"],
            "principal_profile_id": attestor["profile_id"],
        },
    )
    _address_eri(document)


def _rebind_source(document, *, worker_intent=True):
    source = document["source_report_authentication"]
    report = source["provider_report"]
    acknowledgement = report["provider_acknowledgement"]
    _address(
        acknowledgement,
        ACKNOWLEDGEMENT_DOMAIN,
        "acknowledgement",
        "acknowledgement_id",
        "acknowledgement_sha256",
        "EXA-",
    )
    _address(
        report,
        PROVIDER_REPORT_DOMAIN,
        "provider_report",
        "report_custody_id",
        "report_custody_sha256",
        "EPR-",
    )
    ack_authentication = source["acknowledgement_authentication"]
    ack_authentication["acknowledgement"] = copy.deepcopy(acknowledgement)
    worker = ack_authentication["worker_attestor"]
    if worker_intent:
        worker["operation_intent_sha256"] = compute_operation_intent_hash(
            PrincipalOperation(worker["operation"]),
            {
                "acknowledgement_selection_sha256": (
                    collaboration_executor_acknowledgement_selection_sha256(
                        CollaborationExecutorAcknowledgement.from_dict(acknowledgement)
                    )
                ),
                "dispatch_sha256": document["source_dispatch"]["dispatch_sha256"],
                "mission_id": document["source_dispatch"]["mission"]["mission_id"],
                "principal_profile_id": document["source_dispatch"]["worker"][
                    "worker_principal_id"
                ],
            },
        )
    _address(
        ack_authentication,
        ACK_AUTHENTICATION_DOMAIN,
        "authentication",
        "authentication_id",
        "authentication_sha256",
        "EAX-",
    )
    _address(
        source,
        REPORT_AUTHENTICATION_DOMAIN,
        "provider_report_authentication",
        "report_authentication_id",
        "report_authentication_sha256",
        "EPA-",
    )
    verification = document["ingest_request"]["evidence_verification"]
    verification.update(
        {
            "report_authentication_id": source["report_authentication_id"],
            "report_authentication_sha256": source["report_authentication_sha256"],
            "report_custody_id": report["report_custody_id"],
            "report_custody_sha256": report["report_custody_sha256"],
            "attempt_id": report["invocation_preparation"]["attempt_id"],
            "acknowledgement_id": acknowledgement["acknowledgement_id"],
            "acknowledgement_sha256": acknowledgement["acknowledgement_sha256"],
            "provider_evidence_sha256": acknowledgement["provider_evidence_sha256"],
        }
    )
    _rebind_request_and_receipt(document)


def _at(value, seconds):
    return (
        (parse_timestamp(value, "test time") + timedelta(seconds=seconds))
        .isoformat()
        .replace("+00:00", "Z")
    )


class ForgedString(str):
    __hash__ = str.__hash__

    def __eq__(self, other):
        return True

    def __ne__(self, other):
        return False


class IntegerAlias(int):
    pass


class ObjectAlias(dict):
    pass


class ListAlias(list):
    pass


class RepositoryAuthenticationIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = phase149.ProviderEvidenceRepositoryAuthenticationPhase149Tests(
            methodName="runTest"
        )
        cls.fixture.setUp()
        cls.addClassCleanup(cls.fixture.doCleanups)
        cls.authenticated = cls.fixture._authenticate()
        cls.original = cls.authenticated.to_dict()

    def _document(self):
        return copy.deepcopy(self.original)

    def _validate(self, document):
        return validate_eri(document)

    def _live_sources(self, document):
        request = ProviderEvidenceRepositoryIngestRequest.from_dict(document["ingest_request"])
        receipt = ProviderEvidenceRepositoryIngestReceipt.from_dict(document["ingest_receipt"])
        clock = Mock(side_effect=AssertionError("invalid source reached clock"))
        with patch.object(authentication, "verify_principal_assertion") as verifier:
            with self.assertRaises(PrincipalAuthenticationError):
                self.fixture._authenticate(
                    request=request,
                    receipt=receipt,
                    source_report_authentication=document["source_report_authentication"],
                    clock=clock,
                )
            verifier.assert_not_called()
        clock.assert_not_called()

    def test_genuine_serialized_and_opaque_outputs_keep_original_body_bytes(self):
        document = self._document()
        body = {
            key: value
            for key, value in document.items()
            if key not in {"authentication_id", "authentication_sha256"}
        }
        digest = _canonical_sha256(
            {"domain": authentication.AUTHENTICATION_DOMAIN, "authentication": body}
        )
        self.assertEqual(document["authentication_sha256"], digest)
        self.assertEqual(document["authentication_id"], "ERI-" + digest[7:39].upper())
        self.assertEqual(_canonical_json(self._validate(document)), _canonical_json(document))
        self.assertTrue(self.authenticated._proof_is_valid())
        self.assertEqual(
            authentication.provider_evidence_repository_ingest_authentication_effect_payload(
                document
            ),
            authentication.provider_evidence_repository_ingest_authentication_effect_payload(
                self.authenticated
            ),
        )

    def test_unsigned_document_validation_calls_no_clock_signature_or_constructor(self):
        document = self._document()
        document["repository_attestor"]["subject"] = "service:unsigned.synthetic"
        _address_eri(document)
        with (
            patch.object(authentication, "_clock_value") as clock,
            patch.object(authentication, "verify_principal_assertion") as verifier,
            patch.object(
                authentication.AuthenticatedProviderEvidenceRepositoryIngestReceipt,
                "__post_init__",
                side_effect=AssertionError("must not resurrect an opaque wrapper"),
            ),
        ):
            self.assertEqual(self._validate(document), document)
            effect = (
                authentication.provider_evidence_repository_ingest_authentication_effect_payload(
                    document
                )
            )
            clock.assert_not_called()
            verifier.assert_not_called()
        self.assertEqual(effect["validation_status"], "unsigned_content_integrity_only")
        self.assertEqual(effect["current_authority_status"], "not_verified")
        self.assertEqual(effect["authority_effect"], "none")
        self.assertEqual(effect["qualification_effect"], "none")
        self.assertEqual(
            effect["repository_control_status"], "provider_assertions_not_independently_verified"
        )

    def test_valid_failed_receipt_still_authenticates_only_repository_identity(self):
        receipt = self.fixture._receipt(self.fixture.request, outcome="failed")
        policy, scope, assertion = self.fixture._identity(
            self.fixture.request, receipt, self.fixture.lifecycle
        )
        result = self.fixture._authenticate(
            receipt=receipt,
            verified_policy=policy,
            repository_scope=scope,
            repository_assertion=assertion,
        )
        document = self._validate(result.to_dict())
        self.assertEqual(document["ingest_receipt"]["outcome"], "failed")
        self.assertEqual(document["evidence_custody_status"], "provider_report_only")

    def test_all_eight_rehashed_epv_projection_substitutions_are_rejected(self):
        replacements = {
            "report_authentication_id": "EPA-" + "00" * 16,
            "report_authentication_sha256": "sha256:" + "01" * 32,
            "report_custody_id": "EPR-" + "02" * 16,
            "report_custody_sha256": "sha256:" + "03" * 32,
            "attempt_id": "EIP-" + "04" * 16,
            "acknowledgement_id": "EXA-" + "05" * 16,
            "acknowledgement_sha256": "sha256:" + "06" * 32,
            "provider_evidence_sha256": "sha256:" + "07" * 32,
        }
        for name, value in replacements.items():
            with self.subTest(field=name):
                document = self._document()
                document["ingest_request"]["evidence_verification"][name] = value
                _rebind_request_and_receipt(document)
                with self.assertRaisesRegex(
                    PrincipalAuthenticationError, "complete source projection"
                ):
                    self._validate(document)
                self._live_sources(document)

    def test_rehashed_epv_verification_before_source_authentication_is_rejected(self):
        document = self._document()
        source_time = document["source_report_authentication"]["acknowledgement_authentication"][
            "authenticated_at"
        ]
        document["ingest_request"]["evidence_verification"]["verified_at"] = _at(source_time, -1)
        _rebind_request_and_receipt(document)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "chronology"):
            self._validate(document)
        self._live_sources(document)

    def test_known_request_receipt_and_repository_times_are_replayed(self):
        for location, value in (
            (
                ("ingest_request", "evidence_verification", "verified_at"),
                _at(self.original["ingest_request"]["requested_at"], 1),
            ),
            (
                ("ingest_receipt", "responded_at"),
                _at(self.original["ingest_request"]["requested_at"], -1),
            ),
            (("authenticated_at",), _at(self.original["ingest_receipt"]["responded_at"], -1)),
            (("authenticated_at",), _at(self.original["ingest_request"]["expires_at"], 1)),
        ):
            with self.subTest(location=location, value=value):
                document = self._document()
                item = document
                for name in location[:-1]:
                    item = item[name]
                item[location[-1]] = value
                if location == ("authenticated_at",):
                    document["repository_attestor"]["authenticated_at"] = value
                    document["repository_attestor"]["expires_at"] = _at(value, 60)
                    _address_eri(document)
                elif location[0] == "ingest_receipt":
                    _rebind_request_and_receipt(document)
                else:
                    # Request parsing itself rejects a verification from the future.
                    verification = document["ingest_request"]["evidence_verification"]
                    _address(
                        verification,
                        VERIFICATION_DOMAIN,
                        "provider_evidence_verification",
                        "verification_id",
                        "verification_sha256",
                        "EPV-",
                    )
                    _address(
                        document["ingest_request"],
                        INGEST_REQUEST_DOMAIN,
                        "ingest_request",
                        "request_id",
                        "request_sha256",
                        "EIR-",
                    )
                    _address_eri(document)
                with self.assertRaises(PrincipalAuthenticationError):
                    self._validate(document)

    def test_rehashed_acknowledgement_dispatch_session_credential_and_fence_fail(self):
        changes = (
            ("dispatch", "operation_sequence", 1, "operation_sequence"),
            ("session", "session_sha256", "sha256:" + "08" * 32, "session_sha256"),
            ("credential", "credential_sha256", "sha256:" + "09" * 32, None),
            ("worker", "fence_generation", 1, "fence_generation"),
        )
        for group, field, replacement, preparation_field in changes:
            with self.subTest(group=group):
                document = self._document()
                report = document["source_report_authentication"]["provider_report"]
                acknowledgement = report["provider_acknowledgement"]
                if type(replacement) is int:
                    replacement += acknowledgement[group][field]
                acknowledgement[group][field] = replacement
                if preparation_field:
                    report["invocation_preparation"][preparation_field] = replacement
                _rebind_source(document)
                # Each source remains structurally valid before the dispatch join.
                validate_authenticated_collaboration_executor_provider_report_document(
                    document["source_report_authentication"]
                )
                with self.assertRaisesRegex(PrincipalAuthenticationError, "source dispatch"):
                    self._validate(document)
                self._live_sources(document)

    def test_rehashed_source_preparation_before_dispatch_is_rejected(self):
        document = self._document()
        report = document["source_report_authentication"]["provider_report"]
        report["invocation_preparation"]["prepared_at"] = _at(
            document["source_dispatch"]["issued_at"], -1
        )
        _rebind_source(document)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "chronology"):
            self._validate(document)
        self._live_sources(document)

    def test_rehashed_source_principal_intent_expiry_and_context_fail(self):
        source_authentication = self.original["source_report_authentication"][
            "acknowledgement_authentication"
        ]
        changes = (
            ("operation_intent_sha256", "sha256:" + "10" * 32),
            ("expires_at", source_authentication["authenticated_at"]),
            ("expires_at", _at(source_authentication["authenticated_at"], -1)),
            ("audience", "audience.synthetic-other"),
            ("store_id", "STR-" + "11" * 16),
        )
        for field, value in changes:
            with self.subTest(field=field, value=value):
                document = self._document()
                document["source_report_authentication"]["acknowledgement_authentication"][
                    "worker_attestor"
                ][field] = value
                _rebind_source(document, worker_intent=False)
                with self.assertRaises(PrincipalAuthenticationError):
                    self._validate(document)
                self._live_sources(document)

    def test_rehashed_repository_principal_intent_operation_and_window_fail(self):
        principal = self.original["repository_attestor"]
        changes = (
            ("operation_intent_sha256", "sha256:" + "12" * 32),
            ("operation", PrincipalOperation.EXECUTOR_ACKNOWLEDGE.value),
            ("authenticated_at", _at(principal["authenticated_at"], -1)),
            ("expires_at", principal["authenticated_at"]),
            ("expires_at", _at(principal["authenticated_at"], -1)),
            ("assertion_id", "PAS-invalid"),
            ("scope_grant_id", "SGR-invalid"),
            ("profile_id", "profile.synthetic-unknown"),
            ("policy_version", 0),
            ("policy_version", 2**31),
            ("authenticated_at", "2026-07-30T10:08:50+00:00"),
        )
        for field, value in changes:
            with self.subTest(field=field, value=value):
                document = self._document()
                document["repository_attestor"][field] = value
                _address_eri(document)
                with self.assertRaises(PrincipalAuthenticationError):
                    self._validate(document)

    def test_rehashed_repository_and_source_principal_contexts_must_agree(self):
        for field, value in (
            ("audience", "audience.synthetic-other"),
            ("store_id", "STR-" + "13" * 16),
            ("mission_id", "MISSION-SYNTHETIC-OTHER"),
        ):
            with self.subTest(field=field):
                document = self._document()
                document["repository_attestor"][field] = value
                _address_eri(document)
                with self.assertRaises(PrincipalAuthenticationError):
                    self._validate(document)

    def test_missing_or_extra_serialized_fields_are_rejected_even_if_rehashed(self):
        for parent, field in (
            ((), "runtime_effect"),
            (("repository_attestor",), "key_id"),
            (
                (
                    "source_report_authentication",
                    "acknowledgement_authentication",
                    "worker_attestor",
                ),
                "expires_at",
            ),
        ):
            for extra in (False, True):
                with self.subTest(parent=parent, field=field, extra=extra):
                    document = self._document()
                    item = document
                    for name in parent:
                        item = item[name]
                    if extra:
                        item["unexpected"] = "synthetic"
                    else:
                        del item[field]
                    _address_eri(document)
                    with self.assertRaises(PrincipalAuthenticationError):
                        self._validate(document)

    def test_boolean_float_and_integer_aliases_fail_before_source_replay(self):
        paths = (
            ("schema_version",),
            ("ingest_request", "schema_version"),
            ("ingest_request", "evidence_verification", "schema_version"),
            ("ingest_request", "evidence_verification", "evidence_size_bytes"),
            ("ingest_receipt", "schema_version"),
            ("ingest_receipt", "ingest_request", "evidence_size_bytes"),
            ("lifecycle_policy", "policy_version"),
            ("source_dispatch", "operation_sequence"),
            ("source_dispatch", "worker", "fence_generation"),
            ("source_report_authentication", "schema_version"),
            ("source_report_authentication", "acknowledgement_authentication", "schema_version"),
            (
                "source_report_authentication",
                "acknowledgement_authentication",
                "worker_attestor",
                "policy_version",
            ),
            ("repository_attestor", "policy_version"),
        )
        for path in paths:
            for replacement in (True, 1.0, IntegerAlias(1)):
                with self.subTest(path=path, replacement=type(replacement)):
                    document = self._document()
                    item = document
                    for field in path[:-1]:
                        item = item[field]
                    item[path[-1]] = replacement
                    with (
                        patch.object(authentication, "_parsed_sources") as replay,
                        patch.object(authentication, "_canonical_sha256") as hasher,
                        self.assertRaises(PrincipalAuthenticationError),
                    ):
                        self._validate(document)
                    replay.assert_not_called()
                    hasher.assert_not_called()

    def test_native_string_keys_and_container_families_are_required(self):
        for field in (
            "authentication_id",
            "authentication_sha256",
            "runtime_effect",
            "authenticated_at",
        ):
            with self.subTest(field=field):
                document = self._document()
                document[field] = ForgedString("underlying-unrelated")
                with patch.object(authentication, "_parsed_sources") as replay:
                    with self.assertRaises(PrincipalAuthenticationError):
                        self._validate(document)
                    replay.assert_not_called()
        document = self._document()
        document[ForgedString("authentication_id")] = document.pop("authentication_id")
        for candidate in (
            document,
            ObjectAlias(self.original),
            {
                **self.original,
                "repository_attestor": ObjectAlias(self.original["repository_attestor"]),
            },
            {**self.original, "unexpected": ListAlias(["synthetic"])},
        ):
            with self.subTest(candidate=type(candidate)):
                with self.assertRaises(PrincipalAuthenticationError):
                    self._validate(candidate)

    def test_aggregate_shared_and_escaped_graphs_fail_before_json_serialization(self):
        repeated = ["x" * 8192] * 256
        escaped = ['"' * 8192] * 128
        for value in ([repeated, repeated], [escaped, escaped]):
            with self.subTest(escaped=value is escaped):
                with (
                    patch.object(authentication.json, "dumps") as dumps,
                    patch.object(authentication, "_parsed_sources") as replay,
                    self.assertRaisesRegex(PrincipalAuthenticationError, "byte bound"),
                ):
                    self._validate({"supplied": value})
                dumps.assert_not_called()
                replay.assert_not_called()

    def test_depth_nodes_strings_cycles_and_integer_cost_are_bounded(self):
        nested = None
        for _ in range(34):
            nested = [nested]
        cycle = []
        cycle.append(cycle)
        values = (nested, cycle, [None] * 32769, "x" * 8193, 2**10000, float("nan"), None)
        for value in values:
            with self.subTest(kind=type(value)):
                with (
                    patch.object(authentication.json, "dumps") as dumps,
                    self.assertRaises(PrincipalAuthenticationError),
                ):
                    self._validate(value)
                dumps.assert_not_called()

    def test_producer_checks_exact_wrapper_metadata_and_raw_json_before_hooks(self):
        request = self.fixture.request
        json_cases = (
            request.document_json.replace(
                '"schema_version":1', '"schema_version":1,"schema_version":1', 1
            ),
            request.document_json.replace('"schema_version":1', '"schema_version":1.0', 1),
            " " + request.document_json,
            request.document_json + " ",
        )
        for raw in json_cases:
            with self.subTest(raw=raw[:20]):
                changed = ProviderEvidenceRepositoryIngestRequest(
                    request.request_id, request.request_sha256, raw
                )
                clock = Mock(side_effect=AssertionError("invalid wrapper reached clock"))
                with patch.object(authentication, "verify_principal_assertion") as verifier:
                    with self.assertRaises(PrincipalAuthenticationError):
                        self.fixture._authenticate(request=changed, clock=clock)
                    verifier.assert_not_called()
                clock.assert_not_called()
        for field in ("request_id", "request_sha256", "document_json"):
            changed = copy.copy(request)
            object.__setattr__(changed, field, ForgedString(getattr(changed, field)))
            with self.subTest(field=field):
                with self.assertRaises(PrincipalAuthenticationError):
                    self.fixture._authenticate(request=changed)

    def test_producer_checks_assertion_and_caller_native_metadata_before_hooks(self):
        for field in (
            "assertion_id",
            "operation_intent_sha256",
            "subject",
            "issued_at",
            "policy_version",
        ):
            assertion = copy.copy(self.fixture.assertion)
            replacement = (
                IntegerAlias(assertion.policy_version)
                if field == "policy_version"
                else ForgedString(getattr(assertion, field))
            )
            object.__setattr__(assertion, field, replacement)
            clock = Mock(side_effect=AssertionError("invalid assertion reached clock"))
            with (
                self.subTest(field=field),
                patch.object(authentication, "verify_principal_assertion") as verifier,
            ):
                with self.assertRaises(PrincipalAuthenticationError):
                    self.fixture._authenticate(repository_assertion=assertion, clock=clock)
                verifier.assert_not_called()
            clock.assert_not_called()
        for field, value in (
            ("repository_principal_subject", phase149.SUBJECT),
            ("repository_principal_profile_id", phase149.PROFILE_ID),
            ("expected_audience", phase149.AUDIENCE),
            ("expected_store_id", self.fixture.root.store_id),
        ):
            with self.subTest(field=field):
                with self.assertRaises(PrincipalAuthenticationError):
                    self.fixture._authenticate(**{field: ForgedString(value)})

    def test_producer_rejects_unsupported_source_family_without_calling_it(self):
        class UnsupportedSource:
            def to_dict(self):
                raise AssertionError("untrusted family hook must not run")

        with self.assertRaises(PrincipalAuthenticationError):
            self.fixture._authenticate(source_report_authentication=UnsupportedSource())

    def test_effect_payload_revalidates_reassigned_wrapper_and_principal_proofs(self):
        for field, replacement in (
            ("authentication_sha256", ForgedString(self.authenticated.authentication_sha256)),
            ("_proof", b"\x00" * 32),
        ):
            changed = copy.copy(self.authenticated)
            object.__setattr__(changed, field, replacement)
            with self.subTest(field=field):
                with self.assertRaises(PrincipalAuthenticationError):
                    authentication.provider_evidence_repository_ingest_authentication_effect_payload(
                        changed
                    )
        changed = copy.copy(self.authenticated)
        principal = copy.copy(changed.repository_attestor)
        object.__setattr__(principal, "_proof", b"\x00" * 32)
        object.__setattr__(changed, "repository_attestor", principal)
        with self.assertRaises(PrincipalAuthenticationError):
            authentication.provider_evidence_repository_ingest_authentication_effect_payload(
                changed
            )

    def test_outputs_are_detached_and_source_mutation_is_detected(self):
        document = self._document()
        validated = self._validate(document)
        validated["ingest_receipt"]["repository_object"]["repository_id"] = "repository.changed"
        self.assertEqual(document, self.original)
        effect = authentication.provider_evidence_repository_ingest_authentication_effect_payload(
            document
        )
        effect["repository_object"]["repository_id"] = "repository.changed"
        self.assertEqual(document, self.original)
        document["source_report_authentication"]["provider_report"]["received_at"] = (
            "2026-07-30T10:08:00Z"
        )
        with self.assertRaises(PrincipalAuthenticationError):
            self._validate(document)
        self.assertEqual(self.authenticated.to_dict(), self.original)


if __name__ == "__main__":
    unittest.main()
