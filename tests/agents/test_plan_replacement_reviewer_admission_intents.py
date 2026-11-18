"""Pure unsigned reviewer admission packets and bounded operator file inputs."""

from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

import sunderkey
from sunderkey.errors import PrincipalAuthenticationError
from sunderkey.identity import PrincipalOperation, compute_operation_intent_hash
from sunderkey.plan_replacement_reviewer_admission import (
    ADMISSION_DOMAIN,
    PlanReplacementReviewerAdmissionRequest,
    load_plan_replacement_reviewer_admission_request,
)
from sunderkey.plan_replacement_reviewer_admission_intents import (
    APPROVAL_INTENTS_DOMAIN,
    MAX_APPROVAL_INTENTS_BYTES,
    PlanReplacementReviewerAdmissionApprovalIntentPacket,
    build_plan_replacement_reviewer_admission_approval_intents,
    load_plan_replacement_reviewer_admission_approval_intents,
)
from sunderkey.store import canonical_json, sha256_text

from .test_identity_phase4 import CredentialFactory

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = (
    ROOT / "registry/schemas/plan-replacement-reviewer-admission-approval-intents-v1.schema.json"
)
REQUEST_SCHEMA_PATH = ROOT / "registry/schemas/plan-replacement-reviewer-admission-v1.schema.json"


def request_document(grant):
    body = {
        "schema_version": 1,
        "admission_id": "RVA-" + "A" * 32,
        "store_id": grant.store_id,
        "audience": grant.audience,
        "mission_id": grant.mission_id,
        "mission_context_sha256": grant.mission_context_hash,
        "active_plan_id": "CLP-" + "B" * 24,
        "active_plan_content_sha256": "sha256:" + "b" * 64,
        "active_plan_version": 1,
        "mission_policy_id": "MRP-" + "C" * 32,
        "mission_policy_sha256": "sha256:" + "c" * 64,
        "admission_sequence": 1,
        "previous_admission_sha256": None,
        "principal_ledger": {
            "assertion_count": 3,
            "effect_count": 3,
            "head_sha256": "sha256:" + "d" * 64,
        },
        "reviewer": {
            "issuer": "identity-provider",
            "subject": grant.subject,
            "profile_id": grant.profile_id,
            "role": "independent_control",
            "scope_grant": grant.to_dict(),
            "scope_grant_sha256": grant.content_sha256,
        },
        "issued_at": "2026-07-30T10:09:00Z",
        "not_before": "2026-07-30T10:09:00Z",
        "expires_at": "2026-07-30T10:25:00Z",
        "review_only": True,
        "target_authority": "none",
    }
    digest = sha256_text(canonical_json({"domain": ADMISSION_DOMAIN, "admission": body}))
    return {**body, "admission_sha256": digest}


def readdress_packet(document):
    body = {
        key: value
        for key, value in document.items()
        if key
        not in {
            "packet_id",
            "packet_sha256",
        }
    }
    digest = sha256_text(canonical_json({"domain": APPROVAL_INTENTS_DOMAIN, "packet": body}))
    return {**body, "packet_id": "RAI-" + digest[7:39].upper(), "packet_sha256": digest}


class ReviewerAdmissionApprovalIntentContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Synthetic test credentials only; no store, provider or target fixture.
        grant = CredentialFactory().grant(
            profile_id="AOE-HQ-13",
            subject="principal:reviewer",
            operations=[PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_CONTROL_APPROVE.value],
        )
        cls.raw_request = request_document(grant)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.request = PlanReplacementReviewerAdmissionRequest.from_dict(
            copy.deepcopy(self.raw_request)
        )
        self.packet = build_plan_replacement_reviewer_admission_approval_intents(
            self.request,
            mission_owner_profile_id="AOE-HQ-08",
            independent_control_profile_id="AOE-HQ-12",
        )

    def test_deterministic_packet_exact_request_and_hashes(self):
        for exported in (
            PlanReplacementReviewerAdmissionApprovalIntentPacket,
            load_plan_replacement_reviewer_admission_request,
            build_plan_replacement_reviewer_admission_approval_intents,
            load_plan_replacement_reviewer_admission_approval_intents,
        ):
            self.assertIs(getattr(sunderkey, exported.__name__), exported)
            self.assertIn(exported.__name__, sunderkey.__all__)
        packet = self.packet.to_dict()
        self.assertEqual(packet["admission"], self.request.to_dict())
        self.assertEqual(readdress_packet(packet), packet)
        self.assertEqual(self.packet.packet_id, packet["packet_id"])
        self.assertEqual(self.packet.content_sha256, packet["packet_sha256"])
        self.assertEqual(
            PlanReplacementReviewerAdmissionApprovalIntentPacket.from_dict(packet), self.packet
        )
        for role, item in packet["approval_intents"].items():
            operation = PrincipalOperation(item["operation"])
            self.assertEqual(item["operation_intent"]["role"], role)
            self.assertEqual(
                item["principal_profile_id"], item["operation_intent"]["principal_profile_id"]
            )
            self.assertEqual(
                item["operation_intent_sha256"],
                compute_operation_intent_hash(operation, item["operation_intent"]),
            )

    def test_native_constructor_rejects_unencodable_text_with_contract_error(self):
        for document in (chr(0xD800), '{"invalid":"' + chr(0xD800) + '"}'):
            with self.subTest(document_kind=len(document)), self.assertRaisesRegex(
                PrincipalAuthenticationError, "invalid UTF-8"
            ):
                PlanReplacementReviewerAdmissionApprovalIntentPacket(document)

    def test_unsigned_non_authorizing_and_assignment_not_claimed(self):
        document = build_plan_replacement_reviewer_admission_approval_intents(
            self.request,
            mission_owner_profile_id="AOE-HQ-99",
            independent_control_profile_id="AOE-HQ-98",
        ).to_dict()
        self.assertEqual(document["approval_status"], "unsigned")
        self.assertEqual(document["approver_assignment"], "not_verified")
        for field in (
            "authority_effect",
            "runtime_effect",
            "target_authority",
            "qualification_effect",
        ):
            self.assertEqual(document[field], "none")
        self.assertNotIn("signature", document)
        self.assertNotIn("private_key", canonical_json(document))

    def test_explicit_profile_inputs_no_defaults_and_obvious_separation(self):
        with self.assertRaises(TypeError):
            build_plan_replacement_reviewer_admission_approval_intents(self.request)
        for owner, control in (
            ("AOE-HQ-08", "AOE-HQ-08"),
            ("AOE-HQ-13", "AOE-HQ-12"),
            ("AOE-HQ-08", "AOE-HQ-13"),
            ("", "AOE-HQ-12"),
            (True, "AOE-HQ-12"),
            ("AOE-HQ-08", "bad-profile"),
        ):
            with (
                self.subTest(owner=owner, control=control),
                self.assertRaises(PrincipalAuthenticationError),
            ):
                build_plan_replacement_reviewer_admission_approval_intents(
                    self.request,
                    mission_owner_profile_id=owner,
                    independent_control_profile_id=control,
                )

    def test_readdressed_intent_operation_hash_role_and_request_substitution_rejected(self):
        alterations = (
            ("operation", PrincipalOperation.MISSION_STOP.value),
            ("operation_intent_sha256", "sha256:" + "a" * 64),
            ("principal_profile_id", "AOE-HQ-14"),
        )
        for field, changed in alterations:
            document = self.packet.to_dict()
            document["approval_intents"]["mission_owner"][field] = changed
            with self.subTest(field=field), self.assertRaises(PrincipalAuthenticationError):
                PlanReplacementReviewerAdmissionApprovalIntentPacket.from_dict(
                    readdress_packet(document)
                )
        for field, value in (("role", "independent_control"), ("admission_id", "RVA-" + "B" * 32)):
            document = self.packet.to_dict()
            item = document["approval_intents"]["mission_owner"]
            item["operation_intent"][field] = value
            with self.subTest(field=field), self.assertRaises(PrincipalAuthenticationError):
                PlanReplacementReviewerAdmissionApprovalIntentPacket.from_dict(
                    readdress_packet(document)
                )
        document = self.packet.to_dict()
        changed = self.request.to_dict()
        changed["admission_id"] = "RVA-" + "B" * 32
        body = {key: value for key, value in changed.items() if key != "admission_sha256"}
        changed["admission_sha256"] = sha256_text(
            canonical_json({"domain": ADMISSION_DOMAIN, "admission": body})
        )
        document["admission"] = changed
        with self.assertRaises(PrincipalAuthenticationError):
            PlanReplacementReviewerAdmissionApprovalIntentPacket.from_dict(
                readdress_packet(document)
            )

    def test_claims_and_unknown_fields_rejected_even_with_new_hash(self):
        for field, value in (
            ("approval_status", "signed"),
            ("approver_assignment", "verified"),
            ("authority_effect", "admitted"),
            ("runtime_effect", "enabled"),
            ("target_authority", "granted"),
            ("qualification_effect", "qualified"),
            ("signature", "external"),
            ("private_key", "not-a-key"),
        ):
            document = self.packet.to_dict()
            document[field] = value
            with self.subTest(field=field), self.assertRaises(PrincipalAuthenticationError):
                PlanReplacementReviewerAdmissionApprovalIntentPacket.from_dict(
                    readdress_packet(document)
                )

    def test_closed_native_types_and_frozen_document(self):
        class DictionaryAlias(dict):
            pass

        class IntegerAlias(int):
            pass

        for alias in (True, 1.0, IntegerAlias(1)):
            document = self.packet.to_dict()
            document["schema_version"] = alias
            with (
                self.subTest(alias=type(alias).__name__),
                self.assertRaises(PrincipalAuthenticationError),
            ):
                PlanReplacementReviewerAdmissionApprovalIntentPacket.from_dict(document)
        with self.assertRaises(PrincipalAuthenticationError):
            PlanReplacementReviewerAdmissionApprovalIntentPacket.from_dict(
                DictionaryAlias(self.packet.to_dict())
            )
        original = self.packet.to_dict()
        original["approval_status"] = "modified"
        self.assertEqual(self.packet.to_dict()["approval_status"], "unsigned")
        with self.assertRaises(PrincipalAuthenticationError):
            replace(self.packet, document_json=canonical_json(original))

    def test_loaders_round_trip_regular_strict_json_files(self):
        request_path, packet_path = self.directory / "request.json", self.directory / "packet.json"
        request_path.write_text(json.dumps(self.request.to_dict(), indent=2), encoding="utf-8")
        packet_path.write_text(json.dumps(self.packet.to_dict(), indent=2), encoding="utf-8")
        self.assertEqual(
            load_plan_replacement_reviewer_admission_request(request_path), self.request
        )
        self.assertEqual(
            load_plan_replacement_reviewer_admission_approval_intents(packet_path), self.packet
        )

    def test_direct_document_duplicate_invalid_json_and_size_guards(self):
        for document in (
            '{"schema_version":1,' + self.packet.document_json[1:],
            "not-json",
            False,
        ):
            with (
                self.subTest(document_type=type(document).__name__),
                self.assertRaises(PrincipalAuthenticationError),
            ):
                PlanReplacementReviewerAdmissionApprovalIntentPacket(document)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "bounded"):
            PlanReplacementReviewerAdmissionApprovalIntentPacket(
                " " * (MAX_APPROVAL_INTENTS_BYTES + 1)
            )
        changed = self.request.to_dict()
        changed["mission_policy_id"] = "MRP-" + "A" * MAX_APPROVAL_INTENTS_BYTES
        body = {key: value for key, value in changed.items() if key != "admission_sha256"}
        changed["admission_sha256"] = sha256_text(
            canonical_json({"domain": ADMISSION_DOMAIN, "admission": body})
        )
        request = PlanReplacementReviewerAdmissionRequest.from_dict(changed)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "bounded"):
            build_plan_replacement_reviewer_admission_approval_intents(
                request,
                mission_owner_profile_id="AOE-HQ-08",
                independent_control_profile_id="AOE-HQ-12",
            )

    def test_direct_input_integer_bounds_match_strict_file_inputs(self):
        document = self.packet.to_dict()
        document["admission"]["principal_ledger"]["assertion_count"] = 2**63
        with self.assertRaisesRegex(PrincipalAuthenticationError, "64-bit"):
            PlanReplacementReviewerAdmissionApprovalIntentPacket.from_dict(document)

    def test_build_and_load_never_generate_keys_admit_or_call_network(self):
        request_path = self.directory / "request.json"
        packet_path = self.directory / "packet.json"
        request_path.write_text(canonical_json(self.request.to_dict()), encoding="utf-8")
        packet_path.write_text(self.packet.document_json, encoding="utf-8")
        targets = (
            "urllib.request.urlopen",
            "socket.create_connection",
            "cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate",
            "sunderkey.plan_replacement_reviewer_admission."
            "AuthenticatedPlanReplacementReviewerAdmissionService.admit",
        )
        with ExitStack() as stack:
            for target in targets:
                stack.enter_context(
                    mock.patch(target, side_effect=AssertionError("Unexpected effect"))
                )
            request = load_plan_replacement_reviewer_admission_request(request_path)
            packet = build_plan_replacement_reviewer_admission_approval_intents(
                request,
                mission_owner_profile_id="AOE-HQ-08",
                independent_control_profile_id="AOE-HQ-12",
            )
            self.assertEqual(
                packet, load_plan_replacement_reviewer_admission_approval_intents(packet_path)
            )

    def test_loaders_reject_duplicates_floats_bom_encoding_and_large_integers(self):
        for loader, document in (
            (load_plan_replacement_reviewer_admission_request, self.request.to_dict()),
            (load_plan_replacement_reviewer_admission_approval_intents, self.packet.to_dict()),
        ):
            valid = canonical_json(document).encode("utf-8")
            malformed = (
                b'{"schema_version":1,' + valid[1:],
                b"\xef\xbb\xbf" + valid,
                b"\xff",
                valid.replace(b'"schema_version":1', b'"schema_version":1.0', 1),
                valid.replace(b'"schema_version":1', b'"schema_version":NaN', 1),
                valid.replace(b'"schema_version":1', b'"schema_version":' + b"9" * 20, 1),
            )
            for index, data in enumerate(malformed):
                path = self.directory / "bad.json"
                path.write_bytes(data)
                with (
                    self.subTest(loader=loader.__name__, index=index),
                    self.assertRaises(PrincipalAuthenticationError),
                ):
                    loader(path)

    def test_loaders_reject_nonregular_missing_and_oversized_files(self):
        for loader in (
            load_plan_replacement_reviewer_admission_request,
            load_plan_replacement_reviewer_admission_approval_intents,
        ):
            for path in (self.directory, self.directory / "missing.json"):
                with (
                    self.subTest(loader=loader.__name__, path=path.name),
                    self.assertRaises(PrincipalAuthenticationError),
                ):
                    loader(path)
            path = self.directory / "huge.json"
            path.write_bytes(b" " * (MAX_APPROVAL_INTENTS_BYTES + 1))
            with self.assertRaisesRegex(PrincipalAuthenticationError, "maximum size"):
                loader(path)

    def test_stable_read_guard_rejects_file_identity_changes(self):
        for loader, document in (
            (load_plan_replacement_reviewer_admission_request, self.request.to_dict()),
            (load_plan_replacement_reviewer_admission_approval_intents, self.packet.to_dict()),
        ):
            path = self.directory / "changing.json"
            path.write_text(canonical_json(document), encoding="utf-8")
            original_fstat = os.fstat
            calls = 0

            def changed_fstat(descriptor, fstat=original_fstat):
                nonlocal calls
                calls += 1
                result = fstat(descriptor)
                if calls == 2:
                    return SimpleNamespace(
                        st_dev=result.st_dev,
                        st_ino=result.st_ino,
                        st_size=result.st_size,
                        st_mode=result.st_mode,
                        st_mtime_ns=result.st_mtime_ns + 1,
                    )
                return result

            with (
                mock.patch("sunderkey.identity.os.fstat", side_effect=changed_fstat),
                self.assertRaisesRegex(PrincipalAuthenticationError, "changed while reading"),
            ):
                loader(path)

    def test_packet_schema_checked_without_network_retrieval(self):
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        request_schema = json.loads(REQUEST_SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        registry = Registry().with_resource(
            request_schema["$id"], Resource.from_contents(request_schema)
        )
        validator = Draft202012Validator(schema, registry=registry)
        self.assertFalse(list(validator.iter_errors(self.packet.to_dict())))
        for changes in (
            {"schema_version": True},
            {"approval_status": "signed"},
            {"private_key": "none"},
        ):
            self.assertTrue(list(validator.iter_errors({**self.packet.to_dict(), **changes})))
        oversized_integer = self.packet.to_dict()
        oversized_integer["admission"]["principal_ledger"]["assertion_count"] = 2**63
        self.assertTrue(list(validator.iter_errors(oversized_integer)))
