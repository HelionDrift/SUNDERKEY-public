"""Pure source-bound credential provenance preparation and replay coverage."""

from __future__ import annotations

import copy
import inspect
import unittest
from dataclasses import fields, replace
from unittest.mock import Mock, patch

from sunderkey import credential_broker_contracts as broker_contracts
from sunderkey.credential_broker_contracts import (
    CredentialDescriptor,
    CredentialLease,
    LeaseMode,
    ProviderAdapter,
    issue_lease,
)
from sunderkey.target_authentication_adapter_contracts import (
    AUTHENTICATION_MODE_PROFILES,
    NO_CLAIMS,
    NO_EFFECTS,
    AuthenticationFactor,
    AuthenticationMode,
    AuthenticationProfileEvidence,
    ContentAddressBinding,
    CredentialLeaseMode,
    PrincipalTopology,
    TargetAuthenticationContractError,
    TargetAuthenticationProviderBinding,
    TargetCredentialProvenance,
    canonical_json,
    parse_target_credential_provenance,
    transport_credential_reference_sha256,
)
from sunderkey.target_credential_provenance import (
    TargetCredentialProvenanceSourceError,
    prepare_target_credential_provenance,
    verify_target_credential_provenance_sources,
)
from tests.agents import test_credential_broker_contracts_phase162 as phase162
from tests.agents import test_target_authentication_adapter_contracts_phase183 as phase183


class TextAlias(str):
    pass


class IntAlias(int):
    pass


class TupleAlias(tuple):
    pass


class DescriptorAlias(CredentialDescriptor):
    pass


class LeaseAlias(CredentialLease):
    pass


class ProviderAlias(TargetAuthenticationProviderBinding):
    pass


class ProvenanceAlias(TargetCredentialProvenance):
    pass


class AdapterAlias(ProviderAdapter):
    pass


class ProfileAlias(AuthenticationProfileEvidence):
    pass


class BindingAlias(ContentAddressBinding):
    pass


class ValueHook:
    def __init__(self) -> None:
        self.reads = 0

    @property
    def value(self) -> str:
        self.reads += 1
        raise AssertionError("foreign value hook must not run")


class DocumentHook:
    def __init__(self) -> None:
        self.calls = 0

    def to_dict(self) -> dict[str, object]:
        self.calls += 1
        raise AssertionError("foreign document hook must not run")


def alias_record(record: object, alias_type: type) -> object:
    values = {item.name: getattr(record, item.name) for item in fields(record) if item.init}
    return alias_type(**values)


def mutate_native(record: object, **changes: object) -> object:
    duplicate = copy.deepcopy(record)
    for name, value in changes.items():
        object.__setattr__(duplicate, name, value)
    return duplicate


class TargetCredentialProvenanceSourcesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.broker = phase162.CredentialBrokerContractsPhase162Tests(methodName="runTest")
        self.broker.setUp()
        self.descriptor = self.broker.descriptor
        self.lease = self.broker.make_lease()
        self.provider = replace(
            phase183._chain()["provider"],
            issued_at="2026-09-20T12:00:30Z",
            expires_at="2026-09-20T12:05:00Z",
        )
        self.factor = AuthenticationFactor.PASSWORD_REFERENCE
        self.transport_ref = "credref:unrelated-runtime-handle"
        self.mapping_sha256 = phase162.DIGEST_C
        self.created_at = "2026-09-20T12:01:00Z"

    def prepare(self, **changes: object) -> TargetCredentialProvenance:
        values = {
            "descriptor": self.descriptor,
            "lease": self.lease,
            "provider": self.provider,
            "factor": self.factor,
            "lease_use_number": 1,
            "transport_credential_ref": self.transport_ref,
            "mapping_attestation_sha256": self.mapping_sha256,
            "created_at": self.created_at,
        }
        values.update(changes)
        return prepare_target_credential_provenance(**values)

    def manual(self, **changes: object) -> TargetCredentialProvenance:
        descriptor = changes.pop("descriptor", self.descriptor)
        lease = changes.pop("lease", self.lease)
        provider = changes.pop("provider", self.provider)
        transport_ref = changes.pop("transport_credential_ref", self.transport_ref)
        values = {
            "provider_binding": provider.content_binding,
            "principal_ref": lease.subject_principal_ref,
            "factor": self.factor,
            "descriptor_id": descriptor.descriptor_id,
            "descriptor_sha256": descriptor.descriptor_sha256,
            "lease_id": lease.lease_id,
            "lease_sha256": lease.lease_sha256,
            "lease_mode": CredentialLeaseMode(lease.lease_mode.value),
            "lease_issued_at": lease.issued_at,
            "lease_expires_at": lease.expires_at,
            "lease_use_number": 1,
            "source_credential_ref": descriptor.credential_ref,
            "transport_credential_ref_sha256": transport_credential_reference_sha256(transport_ref),
            "mapping_attestation_sha256": self.mapping_sha256,
            "created_at": self.created_at,
        }
        values.update(changes)
        return TargetCredentialProvenance(**values)

    def verify(
        self,
        provenance: TargetCredentialProvenance | None = None,
        **changes: object,
    ) -> TargetCredentialProvenance:
        values = {
            "provenance": self.manual() if provenance is None else provenance,
            "descriptor": self.descriptor,
            "lease": self.lease,
            "provider": self.provider,
            "transport_credential_ref": self.transport_ref,
        }
        values.update(changes)
        return verify_target_credential_provenance_sources(**values)

    def assert_source_pair_denied(
        self,
        *,
        descriptor: CredentialDescriptor | None = None,
        lease: CredentialLease | None = None,
        provider: TargetAuthenticationProviderBinding | None = None,
        **declarations: object,
    ) -> None:
        source_values = {
            "descriptor": self.descriptor if descriptor is None else descriptor,
            "lease": self.lease if lease is None else lease,
            "provider": self.provider if provider is None else provider,
        }
        candidate = self.manual(**source_values, **declarations)
        with self.assertRaises(TargetCredentialProvenanceSourceError):
            self.prepare(**source_values, **declarations)
        with self.assertRaises(TargetCredentialProvenanceSourceError):
            self.verify(candidate, **source_values)

    def test_genuine_sources_match_manual_existing_tacp_and_literal_addresses(self) -> None:
        prepared = self.prepare()
        expected = self.manual()
        self.assertIs(type(prepared), TargetCredentialProvenance)
        self.assertEqual(canonical_json(prepared.to_dict()), canonical_json(expected.to_dict()))
        self.assertEqual(
            (self.descriptor.descriptor_id, self.descriptor.descriptor_sha256),
            (
                "CBD-058F0E996C31C8F540E97BE8A863B306",
                "sha256:058f0e996c31c8f540e97be8a863b306c78a044fce3c40417dd56a828fa7488a",
            ),
        )
        self.assertEqual(
            (self.lease.lease_id, self.lease.lease_sha256),
            (
                "CLZ-B2F7E084D4AB0D6B092F7F6B8039CA9C",
                "sha256:b2f7e084d4ab0d6b092f7f6b8039ca9c85d2a1926e0a61f6c9cd49852422b186",
            ),
        )
        self.assertEqual(
            (self.provider.binding_id, self.provider.binding_sha256),
            (
                "TAPB-CAAAC77CFF9DFFBBB6D9FBDF2C129741",
                "sha256:caaac77cff9dffbbb6d9fbdf2c12974198031369f5706af7b4dab8189beabd3d",
            ),
        )
        self.assertEqual(
            (prepared.provenance_id, prepared.provenance_sha256),
            (
                "TACP-12B9E91205C7FBEE6E8C244601424489",
                "sha256:12b9e91205c7fbee6e8c2446014244896f13d7a025dff3cb6028b031fb356bfd",
            ),
        )

    def test_verifier_returns_detached_existing_tacp_without_wire_changes(self) -> None:
        original = self.manual()
        parsed = parse_target_credential_provenance(canonical_json(original.to_dict()))
        verified = self.verify(parsed)
        self.assertIs(type(verified), TargetCredentialProvenance)
        self.assertIsNot(verified, parsed)
        self.assertIsNot(verified.provider_binding, parsed.provider_binding)
        self.assertEqual(canonical_json(verified.to_dict()), canonical_json(original.to_dict()))
        self.assertEqual(verified.provenance_id, original.provenance_id)

    def test_public_apis_are_explicit_keyword_only_and_errors_keep_existing_family(self) -> None:
        expected = (
            (
                prepare_target_credential_provenance,
                {
                    "descriptor",
                    "lease",
                    "provider",
                    "factor",
                    "lease_use_number",
                    "transport_credential_ref",
                    "mapping_attestation_sha256",
                    "created_at",
                },
            ),
            (
                verify_target_credential_provenance_sources,
                {"provenance", "descriptor", "lease", "provider", "transport_credential_ref"},
            ),
        )
        for function, names in expected:
            with self.subTest(function=function.__name__):
                parameters = inspect.signature(function).parameters
                self.assertEqual(set(parameters), names)
                for parameter in parameters.values():
                    self.assertIs(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
                    self.assertIs(parameter.default, inspect.Parameter.empty)
        self.assertTrue(
            issubclass(TargetCredentialProvenanceSourceError, TargetAuthenticationContractError)
        )

    def test_both_genuine_lease_modes_and_every_supported_use_number(self) -> None:
        one_request = self.broker.make_request(lease_mode=LeaseMode.ONE_TIME, requested_max_uses=1)
        one_approval = self.broker.make_approval(
            one_request, lease_mode=LeaseMode.ONE_TIME, approved_max_uses=1
        )
        one_lease = issue_lease(
            self.descriptor,
            one_request,
            one_approval,
            issuance_ref="issuanceref:provenance-one-time",
            session_ref=None,
            now=phase162.NOW,
        )
        for lease in (one_lease, self.lease):
            for number in range(1, lease.max_uses + 1):
                with self.subTest(mode=lease.lease_mode, use=number):
                    prepared = self.prepare(lease=lease, lease_use_number=number)
                    manual = self.manual(lease=lease, lease_use_number=number)
                    self.assertEqual(
                        canonical_json(prepared.to_dict()), canonical_json(manual.to_dict())
                    )
                    self.assertEqual(
                        canonical_json(self.verify(prepared, lease=lease).to_dict()),
                        canonical_json(manual.to_dict()),
                    )

    def test_every_closed_profile_factor_can_be_declared_without_factor_material(self) -> None:
        covered = set()
        for mode, topology in AUTHENTICATION_MODE_PROFILES:
            profile = AuthenticationProfileEvidence.for_mode(mode, topology)
            provider = replace(self.provider, supported_profiles=(profile,))
            for factor in profile.factors:
                covered.add(factor)
                with self.subTest(mode=mode, topology=topology, factor=factor):
                    candidate = self.prepare(provider=provider, factor=factor)
                    self.assertEqual(
                        canonical_json(candidate.to_dict()),
                        canonical_json(self.manual(provider=provider, factor=factor).to_dict()),
                    )
                    self.verify(candidate, provider=provider)
        self.assertEqual(covered, set(AuthenticationFactor))

    def test_genuine_maximum_use_lease_is_bounded_metadata_not_consumption(self) -> None:
        descriptor = replace(self.descriptor, max_uses_per_lease=100)
        request = replace(
            self.broker.request,
            descriptor_sha256=descriptor.descriptor_sha256,
            requested_max_uses=100,
        )
        approval = self.broker.make_approval(request)
        lease = issue_lease(
            descriptor,
            request,
            approval,
            issuance_ref="issuanceref:provenance-maximum-uses",
            session_ref=self.lease.session_ref,
            now=phase162.NOW,
        )
        before = canonical_json(lease.to_dict())
        candidate = self.prepare(descriptor=descriptor, lease=lease, lease_use_number=100)
        first = self.verify(candidate, descriptor=descriptor, lease=lease)
        second = self.verify(candidate, descriptor=descriptor, lease=lease)
        self.assertEqual(first.provenance_id, second.provenance_id)
        self.assertEqual(first.lease_use_number, 100)
        self.assertEqual(canonical_json(lease.to_dict()), before)
        with self.assertRaises(TargetCredentialProvenanceSourceError):
            self.prepare(descriptor=descriptor, lease=lease, lease_use_number=101)

    def test_factor_in_any_supplied_provider_profile_is_supported(self) -> None:
        totp = AuthenticationProfileEvidence.for_mode(
            AuthenticationMode.FORM_LOGIN_TOTP, PrincipalTopology.SINGLE_PRINCIPAL
        )
        provider = replace(
            self.provider,
            supported_profiles=(*self.provider.supported_profiles, totp),
        )
        prepared = self.prepare(provider=provider, factor=AuthenticationFactor.TOTP_REFERENCE)
        self.assertEqual(prepared.factor, AuthenticationFactor.TOTP_REFERENCE)
        self.verify(prepared, provider=provider)

    def test_well_formed_unsupported_factor_fails_prepare_and_verification(self) -> None:
        self.assert_source_pair_denied(factor=AuthenticationFactor.BEARER_REFERENCE)

    def test_created_at_is_inside_both_half_open_windows_not_whole_lease_containment(self) -> None:
        for value in (self.provider.issued_at, "2026-09-20T12:04:59Z"):
            with self.subTest(valid=value):
                candidate = self.prepare(created_at=value)
                self.verify(candidate)
        for value in (
            "2026-09-20T12:00:29Z",
            self.provider.expires_at,
            "2026-09-20T12:09:59Z",
        ):
            with self.subTest(invalid=value):
                self.assert_source_pair_denied(created_at=value)
        self.assertLess(self.lease.issued_at, self.provider.issued_at)
        self.assertGreater(self.lease.expires_at, self.provider.expires_at)
        self.assertEqual(self.prepare().lease_expires_at, self.lease.expires_at)

    def test_exact_lease_window_lower_bound_is_allowed_and_upper_bound_is_denied(self) -> None:
        provider = replace(
            self.provider,
            issued_at=self.lease.issued_at,
            expires_at="2026-09-20T12:20:00Z",
        )
        at_issue = self.prepare(provider=provider, created_at=self.lease.issued_at)
        self.verify(at_issue, provider=provider)
        for value in ("2026-09-20T11:59:59Z", self.lease.expires_at):
            with self.subTest(value=value):
                with self.assertRaises(TargetCredentialProvenanceSourceError):
                    self.prepare(provider=provider, created_at=value)

    def test_readdressed_lease_descriptor_tenant_assessment_and_principal_joins(self) -> None:
        cases = (
            {"descriptor_sha256": phase162.DIGEST_A},
            {"tenant_ref": "tenantref:another"},
            {"assessment_ref": "assessmentref:another"},
            {"subject_principal_ref": "principalref:another"},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                lease = replace(self.lease, **changes)
                self.assertNotEqual(lease.lease_sha256, self.lease.lease_sha256)
                self.assert_source_pair_denied(lease=lease)

    def test_readdressed_lease_capabilities_must_remain_inside_descriptor(self) -> None:
        cases = (
            {"target_ref": "targetref:another"},
            {"technique_ref": "techniqueref:another"},
            {"purpose_ref": "purposeref:another"},
            {"scope_refs": (*self.lease.scope_refs, "scoperef:administrator")},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                self.assert_source_pair_denied(lease=replace(self.lease, **changes))
        descriptor = replace(self.descriptor, allowed_modes=(LeaseMode.ONE_TIME,))
        lease = replace(self.lease, descriptor_sha256=descriptor.descriptor_sha256)
        self.assert_source_pair_denied(descriptor=descriptor, lease=lease)

    def test_readdressed_exact_ttl_and_use_ceilings_are_enforced(self) -> None:
        for changes in (
            {"max_lease_ttl_seconds": 599},
            {"max_uses_per_lease": 2},
        ):
            with self.subTest(changes=changes):
                descriptor = replace(self.descriptor, **changes)
                lease = replace(self.lease, descriptor_sha256=descriptor.descriptor_sha256)
                self.assert_source_pair_denied(descriptor=descriptor, lease=lease)
        descriptor = replace(self.descriptor, max_lease_ttl_seconds=600, max_uses_per_lease=3)
        lease = replace(self.lease, descriptor_sha256=descriptor.descriptor_sha256)
        candidate = self.prepare(descriptor=descriptor, lease=lease, lease_use_number=3)
        self.verify(candidate, descriptor=descriptor, lease=lease)

    def test_readdressed_descriptor_lifetime_contains_original_lease_window(self) -> None:
        for changes in (
            {"created_at": "2026-09-20T12:00:01Z"},
            {"expires_at": "2026-09-20T12:05:00Z"},
        ):
            with self.subTest(changes=changes):
                descriptor = replace(self.descriptor, **changes)
                lease = replace(self.lease, descriptor_sha256=descriptor.descriptor_sha256)
                self.assert_source_pair_denied(descriptor=descriptor, lease=lease)
        descriptor = replace(
            self.descriptor,
            created_at=self.lease.issued_at,
            expires_at=self.lease.expires_at,
        )
        lease = replace(self.lease, descriptor_sha256=descriptor.descriptor_sha256)
        candidate = self.prepare(descriptor=descriptor, lease=lease)
        self.verify(candidate, descriptor=descriptor, lease=lease)

    def test_coherently_readdressed_tacp_source_projections_cannot_be_substituted(self) -> None:
        original = self.manual()
        other_provider = replace(self.provider, instance_ref="instanceref:test/another")
        cases = (
            {"provider_binding": other_provider.content_binding},
            {"principal_ref": "principalref:another"},
            {"descriptor_id": "CBD-" + "A" * 32},
            {"descriptor_sha256": phase162.DIGEST_A},
            {"lease_id": "CLZ-" + "A" * 32},
            {"lease_sha256": phase162.DIGEST_A},
            {"lease_mode": CredentialLeaseMode.ONE_TIME},
            {"lease_issued_at": "2026-09-20T12:00:01Z"},
            {"lease_expires_at": "2026-09-20T12:09:59Z"},
            {"lease_use_number": self.lease.max_uses + 1},
            {"source_credential_ref": "credentialref:another"},
            {
                "transport_credential_ref_sha256": transport_credential_reference_sha256(
                    "credref:another-runtime-handle"
                )
            },
            {"factor": AuthenticationFactor.BEARER_REFERENCE},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                candidate = replace(original, **changes)
                candidate = parse_target_credential_provenance(canonical_json(candidate.to_dict()))
                self.assertNotEqual(candidate.provenance_id, original.provenance_id)
                with self.assertRaises(TargetCredentialProvenanceSourceError):
                    self.verify(candidate)

    def test_explicit_mapping_use_and_created_declarations_are_not_external_proofs(self) -> None:
        original = self.manual()
        for changes in (
            {"mapping_attestation_sha256": phase162.DIGEST_A},
            {"lease_use_number": 2},
            {"created_at": "2026-09-20T12:02:00Z"},
        ):
            with self.subTest(changes=changes):
                candidate = replace(original, **changes)
                verified = self.verify(candidate)
                self.assertEqual(
                    canonical_json(verified.to_dict()), canonical_json(candidate.to_dict())
                )
                self.assertEqual(verified.to_dict()["claims"], dict(NO_CLAIMS))
                self.assertEqual(verified.to_dict()["effects"], dict(NO_EFFECTS))

    def test_broker_and_target_providers_are_distinct_and_opaque_suffixes_need_not_match(
        self,
    ) -> None:
        self.assertNotEqual(self.descriptor.adapter.provider_ref, self.provider.provider_ref)
        self.assertNotEqual(
            self.descriptor.credential_ref.split(":", 1)[1], self.transport_ref.split(":", 1)[1]
        )
        prepared = self.prepare()
        self.verify(prepared)
        self.assertEqual(prepared.source_credential_ref, self.descriptor.credential_ref)
        self.assertEqual(
            prepared.transport_credential_ref_sha256,
            transport_credential_reference_sha256(self.transport_ref),
        )

    def test_runtime_reference_is_exact_not_suffix_or_normalized_equality(self) -> None:
        prepared = self.prepare()
        for ref in (
            "credref:another-runtime-handle",
            "credref:Unrelated-runtime-handle",
            "credref:unrelated-runtime-handle/",
        ):
            with self.subTest(ref=ref), self.assertRaises(TargetCredentialProvenanceSourceError):
                self.verify(prepared, transport_credential_ref=ref)

    def test_historical_expired_windows_replay_without_currentness_or_usage_consumption(
        self,
    ) -> None:
        descriptor_before = canonical_json(self.descriptor.to_dict())
        lease_before = canonical_json(self.lease.to_dict())
        candidate = self.prepare()
        first = self.verify(candidate)
        second = self.verify(candidate)
        self.assertEqual(first.provenance_id, second.provenance_id)
        self.assertEqual(canonical_json(first.to_dict()), canonical_json(candidate.to_dict()))
        self.assertEqual(canonical_json(self.descriptor.to_dict()), descriptor_before)
        self.assertEqual(canonical_json(self.lease.to_dict()), lease_before)
        self.assertEqual(first.to_dict()["effects"], dict(NO_EFFECTS))
        self.assertEqual(first.to_dict()["claims"], dict(NO_CLAIMS))
        self.assertEqual(first.to_dict()["schema_version"], 2)
        self.assertEqual(first.to_dict()["record_kind"], "target_credential_provenance")
        self.assertNotIn("remaining_uses", first.to_dict())

    def test_unprovided_request_approval_and_revocation_bodies_are_not_invented(self) -> None:
        lease = replace(
            self.lease,
            request_sha256=phase162.DIGEST_A,
            approval_sha256=phase162.DIGEST_B,
            renewal_of_lease_sha256=phase162.DIGEST_C,
        )
        candidate = self.prepare(lease=lease)
        self.verify(candidate, lease=lease)
        self.assertEqual(candidate.to_dict()["claims"], dict(NO_CLAIMS))
        for absent in ("approval_verified", "revocation_verified", "issuance_verified"):
            self.assertNotIn(absent, candidate.to_dict())

    def test_declared_factor_and_use_number_require_exact_native_types(self) -> None:
        hook = ValueHook()
        for factor in (
            self.factor.value,
            TextAlias(self.factor.value),
            CredentialLeaseMode.ONE_TIME,
            hook,
            False,
            None,
        ):
            with self.subTest(factor_type=type(factor).__name__):
                with self.assertRaises(TargetCredentialProvenanceSourceError):
                    self.prepare(factor=factor)
        self.assertEqual(hook.reads, 0)
        for number in (True, 1.0, IntAlias(1), 0, -1, 4, 101, 1 << 80):
            with self.subTest(number_type=type(number).__name__):
                with self.assertRaises(TargetCredentialProvenanceSourceError):
                    self.prepare(lease_use_number=number)

    def test_declared_reference_mapping_digest_and_timestamp_require_native_primitives(
        self,
    ) -> None:
        cases = (
            ("transport_credential_ref", TextAlias(self.transport_ref)),
            ("transport_credential_ref", self.transport_ref.encode("ascii")),
            ("transport_credential_ref", "credentialref:wrong-namespace"),
            ("transport_credential_ref", self.transport_ref + " "),
            ("transport_credential_ref", "credref:bad\nvalue"),
            ("mapping_attestation_sha256", TextAlias(self.mapping_sha256)),
            ("mapping_attestation_sha256", True),
            ("mapping_attestation_sha256", "sha256:" + "A" * 64),
            ("created_at", TextAlias(self.created_at)),
            ("created_at", "2026-09-20T12:01:00+00:00"),
            ("created_at", "2026-09-20T12:01:00.000000Z"),
            ("created_at", "2026-02-30T12:01:00Z"),
            ("created_at", True),
        )
        for name, value in cases:
            with self.subTest(name=name, value_type=type(value).__name__):
                with self.assertRaises(TargetCredentialProvenanceSourceError):
                    self.prepare(**{name: value})
        for value in (TextAlias(self.transport_ref), self.transport_ref.encode("ascii"), None):
            with self.subTest(verify_reference_type=type(value).__name__):
                with self.assertRaises(TargetCredentialProvenanceSourceError):
                    self.verify(transport_credential_ref=value)

    def test_top_level_native_families_reject_foreign_hooks_and_subclasses(self) -> None:
        originals = {
            "descriptor": self.descriptor,
            "lease": self.lease,
            "provider": self.provider,
        }
        alias_types = {
            "descriptor": DescriptorAlias,
            "lease": LeaseAlias,
            "provider": ProviderAlias,
        }
        for name, record in originals.items():
            hook = DocumentHook()
            for invalid in (record.to_dict(), hook, alias_record(record, alias_types[name])):
                with self.subTest(name=name, value_type=type(invalid).__name__):
                    with self.assertRaises(TargetCredentialProvenanceSourceError):
                        self.prepare(**{name: invalid})
                    with self.assertRaises(TargetCredentialProvenanceSourceError):
                        self.verify(**{name: invalid})
            self.assertEqual(hook.calls, 0)
        original = self.manual()
        hook = DocumentHook()
        for invalid in (original.to_dict(), hook, alias_record(original, ProvenanceAlias)):
            with self.subTest(provenance_type=type(invalid).__name__):
                with self.assertRaises(TargetCredentialProvenanceSourceError):
                    self.verify(invalid)
        self.assertEqual(hook.calls, 0)

    def test_missing_slots_fail_in_new_error_family_before_serialization(self) -> None:
        families = (
            ("descriptor", CredentialDescriptor),
            ("lease", CredentialLease),
            ("provider", TargetAuthenticationProviderBinding),
        )
        for name, family in families:
            incomplete = object.__new__(family)
            with self.subTest(name=name), patch.object(family, "to_dict") as serialize:
                with self.assertRaises(TargetCredentialProvenanceSourceError):
                    self.prepare(**{name: incomplete})
                with self.assertRaises(TargetCredentialProvenanceSourceError):
                    self.verify(**{name: incomplete})
                serialize.assert_not_called()
        incomplete = object.__new__(TargetCredentialProvenance)
        with patch.object(TargetCredentialProvenance, "to_dict") as serialize:
            with self.assertRaises(TargetCredentialProvenanceSourceError):
                self.verify(incomplete)
            serialize.assert_not_called()

    def test_nested_native_families_reject_byte_preserving_subclasses(self) -> None:
        adapter = alias_record(self.descriptor.adapter, AdapterAlias)
        descriptor = replace(self.descriptor, adapter=adapter)
        self.assertEqual(
            canonical_json(descriptor.to_dict()), canonical_json(self.descriptor.to_dict())
        )
        profile = alias_record(self.provider.supported_profiles[0], ProfileAlias)
        provider = replace(self.provider, supported_profiles=(profile,))
        self.assertEqual(
            canonical_json(provider.to_dict()), canonical_json(self.provider.to_dict())
        )
        original = self.manual()
        binding = alias_record(original.provider_binding, BindingAlias)
        provenance = replace(original, provider_binding=binding)
        self.assertEqual(canonical_json(provenance.to_dict()), canonical_json(original.to_dict()))
        for name, value in (("descriptor", descriptor), ("provider", provider)):
            with self.subTest(name=name):
                with self.assertRaises(TargetCredentialProvenanceSourceError):
                    self.prepare(**{name: value})
                with self.assertRaises(TargetCredentialProvenanceSourceError):
                    self.verify(**{name: value})
        with self.assertRaises(TargetCredentialProvenanceSourceError):
            self.verify(provenance)

    def test_byte_preserving_string_and_integer_aliases_are_not_normalized(self) -> None:
        descriptor_aliases = (
            replace(self.descriptor, tenant_ref=TextAlias(self.descriptor.tenant_ref)),
            replace(
                self.descriptor, max_uses_per_lease=IntAlias(self.descriptor.max_uses_per_lease)
            ),
            replace(
                self.descriptor,
                adapter=replace(
                    self.descriptor.adapter,
                    adapter_version=TextAlias(self.descriptor.adapter.adapter_version),
                ),
            ),
        )
        for descriptor in descriptor_aliases:
            with self.subTest(descriptor=descriptor.descriptor_id):
                self.assertEqual(
                    broker_contracts.canonical_json(descriptor.to_dict()),
                    broker_contracts.canonical_json(self.descriptor.to_dict()),
                )
                with self.assertRaises(TargetCredentialProvenanceSourceError):
                    self.prepare(descriptor=descriptor)
                with self.assertRaises(TargetCredentialProvenanceSourceError):
                    self.verify(descriptor=descriptor)
        lease = replace(self.lease, max_uses=IntAlias(self.lease.max_uses))
        self.assertEqual(
            broker_contracts.canonical_json(lease.to_dict()),
            broker_contracts.canonical_json(self.lease.to_dict()),
        )
        with self.assertRaises(TargetCredentialProvenanceSourceError):
            self.prepare(lease=lease)
        with self.assertRaises(TargetCredentialProvenanceSourceError):
            self.verify(lease=lease)

    def test_byte_preserving_collection_and_foreign_enum_aliases_are_not_replayed(self) -> None:
        original = self.manual()
        cases = (
            (
                "descriptor",
                mutate_native(
                    self.descriptor, allowed_scope_refs=list(self.descriptor.allowed_scope_refs)
                ),
            ),
            (
                "descriptor",
                mutate_native(
                    self.descriptor,
                    allowed_target_refs=TupleAlias(self.descriptor.allowed_target_refs),
                ),
            ),
            (
                "descriptor",
                mutate_native(
                    self.descriptor,
                    allowed_modes=tuple(
                        CredentialLeaseMode(mode.value) for mode in self.descriptor.allowed_modes
                    ),
                ),
            ),
            ("lease", mutate_native(self.lease, scope_refs=list(self.lease.scope_refs))),
            (
                "lease",
                mutate_native(
                    self.lease, lease_mode=CredentialLeaseMode(self.lease.lease_mode.value)
                ),
            ),
            (
                "provider",
                mutate_native(
                    self.provider, supported_profiles=list(self.provider.supported_profiles)
                ),
            ),
            (
                "provider",
                mutate_native(
                    self.provider, supported_operations=list(self.provider.supported_operations)
                ),
            ),
        )
        originals = {"descriptor": self.descriptor, "lease": self.lease, "provider": self.provider}
        for name, record in cases:
            with self.subTest(name=name, record_type=type(record).__name__):
                self.assertEqual(
                    canonical_json(record.to_dict()), canonical_json(originals[name].to_dict())
                )
                with self.assertRaises(TargetCredentialProvenanceSourceError):
                    self.prepare(**{name: record})
                with self.assertRaises(TargetCredentialProvenanceSourceError):
                    self.verify(**{name: record})
        provenance = mutate_native(original, lease_mode=LeaseMode(original.lease_mode.value))
        self.assertEqual(canonical_json(provenance.to_dict()), canonical_json(original.to_dict()))
        with self.assertRaises(TargetCredentialProvenanceSourceError):
            self.verify(provenance)

    def test_wrong_nested_enum_hook_is_rejected_before_value_or_document_hook(self) -> None:
        for family, field, record in (
            (CredentialDescriptor, "allowed_modes", self.descriptor),
            (CredentialLease, "lease_mode", self.lease),
            (TargetAuthenticationProviderBinding, "execution_environment", self.provider),
        ):
            hook = ValueHook()
            bad_value = (hook,) if field == "allowed_modes" else hook
            invalid = mutate_native(record, **{field: bad_value})
            name = {
                CredentialDescriptor: "descriptor",
                CredentialLease: "lease",
                TargetAuthenticationProviderBinding: "provider",
            }[family]
            with self.subTest(name=name), patch.object(family, "to_dict") as serialize:
                with self.assertRaises(TargetCredentialProvenanceSourceError):
                    self.prepare(**{name: invalid})
                with self.assertRaises(TargetCredentialProvenanceSourceError):
                    self.verify(**{name: invalid})
                serialize.assert_not_called()
            self.assertEqual(hook.reads, 0)
        hook = ValueHook()
        profile = mutate_native(self.provider.supported_profiles[0], factors=(hook,))
        provider = mutate_native(self.provider, supported_profiles=(profile,))
        with patch.object(TargetAuthenticationProviderBinding, "to_dict") as serialize:
            with self.assertRaises(TargetCredentialProvenanceSourceError):
                self.prepare(provider=provider)
            serialize.assert_not_called()
        self.assertEqual(hook.reads, 0)

    def test_preentry_native_mutation_cannot_retain_an_original_source_address(self) -> None:
        cases = (
            ("descriptor", self.descriptor, "credential_ref", "credentialref:another"),
            ("descriptor", self.descriptor, "descriptor_id", "CBD-" + "A" * 32),
            ("descriptor", self.descriptor, "descriptor_sha256", phase162.DIGEST_A),
            ("lease", self.lease, "task_ref", "taskref:another"),
            ("lease", self.lease, "lease_id", "CLZ-" + "A" * 32),
            ("lease", self.lease, "lease_sha256", phase162.DIGEST_A),
            ("provider", self.provider, "instance_ref", "instanceref:test/another"),
            ("provider", self.provider, "binding_id", "TAPB-" + "A" * 32),
            ("provider", self.provider, "binding_sha256", phase162.DIGEST_A),
        )
        for name, record, field, value in cases:
            with self.subTest(name=name, field=field):
                invalid = mutate_native(record, **{field: value})
                with self.assertRaises(TargetCredentialProvenanceSourceError):
                    self.prepare(**{name: invalid})
                with self.assertRaises(TargetCredentialProvenanceSourceError):
                    self.verify(**{name: invalid})
        original = self.manual()
        for field, value in (
            ("source_credential_ref", "credentialref:another"),
            ("provenance_id", "TACP-" + "A" * 32),
            ("provenance_sha256", phase162.DIGEST_A),
        ):
            with self.subTest(field=field):
                with self.assertRaises(TargetCredentialProvenanceSourceError):
                    self.verify(mutate_native(original, **{field: value}))

    def test_original_constructor_normalization_remains_valid_at_new_boundary(self) -> None:
        descriptor = replace(
            self.descriptor,
            allowed_target_refs=list(self.descriptor.allowed_target_refs),
            allowed_scope_refs=list(self.descriptor.allowed_scope_refs),
            allowed_modes=tuple(mode.value for mode in self.descriptor.allowed_modes),
        )
        lease = replace(
            self.lease,
            scope_refs=list(self.lease.scope_refs),
            lease_mode=self.lease.lease_mode.value,
        )
        profile = AuthenticationProfileEvidence.from_dict(
            self.provider.supported_profiles[0].to_dict()
        )
        provider = replace(
            self.provider,
            supported_profiles=[profile],
            supported_operations=[
                operation.value for operation in self.provider.supported_operations
            ],
            execution_environment=self.provider.execution_environment.value,
        )
        prepared = self.prepare(descriptor=descriptor, lease=lease, provider=provider)
        self.assertEqual(
            canonical_json(prepared.to_dict()), canonical_json(self.manual().to_dict())
        )
        self.verify(prepared, descriptor=descriptor, lease=lease, provider=provider)

    def test_large_native_scalars_and_array_counts_reject_before_serialization_or_hashing(
        self,
    ) -> None:
        too_large_integer = 1 << 20_000
        oversized_text = "x" * (1_048_576 + 1)
        cases = (
            ("descriptor", self.descriptor, "max_uses_per_lease", too_large_integer),
            ("descriptor", self.descriptor, "credential_ref", oversized_text),
            (
                "descriptor",
                self.descriptor,
                "allowed_scope_refs",
                self.descriptor.allowed_scope_refs * 51,
            ),
            ("lease", self.lease, "max_uses", too_large_integer),
            ("lease", self.lease, "scope_refs", self.lease.scope_refs * 101),
            (
                "provider",
                self.provider,
                "supported_profiles",
                self.provider.supported_profiles * 17,
            ),
            ("provider", self.provider, "implementation_name", oversized_text),
        )
        for name, record, field, value in cases:
            invalid = mutate_native(record, **{field: value})
            with (
                self.subTest(name=name, field=field),
                patch.object(type(record), "to_dict") as serialize,
                patch.object(broker_contracts, "canonical_sha256") as broker_hash,
            ):
                with self.assertRaises(TargetCredentialProvenanceSourceError):
                    self.prepare(**{name: invalid})
                serialize.assert_not_called()
                broker_hash.assert_not_called()
        with patch("json.dumps") as dumps:
            with self.assertRaises(TargetCredentialProvenanceSourceError):
                self.prepare(lease_use_number=too_large_integer)
            dumps.assert_not_called()

    def test_results_and_nested_exports_are_detached_from_all_supplied_sources(self) -> None:
        descriptor = copy.deepcopy(self.descriptor)
        lease = copy.deepcopy(self.lease)
        provider = copy.deepcopy(self.provider)
        prepared = self.prepare(descriptor=descriptor, lease=lease, provider=provider)
        manual = self.manual()
        verified = self.verify(manual, descriptor=descriptor, lease=lease, provider=provider)
        original = canonical_json(prepared.to_dict())
        object.__setattr__(descriptor, "credential_ref", "credentialref:late-change")
        object.__setattr__(lease, "subject_principal_ref", "principalref:late-change")
        object.__setattr__(provider, "binding_id", "TAPB-" + "A" * 32)
        object.__setattr__(manual.provider_binding, "record_id", "TAPB-" + "B" * 32)
        self.assertEqual(canonical_json(prepared.to_dict()), original)
        self.assertEqual(canonical_json(verified.to_dict()), original)
        exported = prepared.to_dict()
        exported["provider_binding"]["record_id"] = "TAPB-" + "C" * 32
        exported["claims"]["authorization"] = "not-an-authority"
        self.assertEqual(canonical_json(prepared.to_dict()), original)
        self.assertEqual(canonical_json(verified.to_dict()), original)

    def test_no_provider_resolver_or_authentication_callbacks_are_used(self) -> None:
        deny = Mock(side_effect=AssertionError("external interaction is forbidden"))
        with patch("socket.socket", deny), patch("subprocess.Popen", deny):
            candidate = self.prepare()
            self.verify(candidate)
        deny.assert_not_called()
        self.assertEqual(candidate.to_dict()["effects"], dict(NO_EFFECTS))
        self.assertEqual(candidate.to_dict()["claims"], dict(NO_CLAIMS))


if __name__ == "__main__":
    unittest.main()
