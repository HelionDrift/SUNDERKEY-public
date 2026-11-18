"""Genuine reference transport callbacks cannot redefine their delivery inputs."""

from __future__ import annotations

import copy
import unittest
from dataclasses import replace
from datetime import timedelta

from sunderkey.candidate_enrollment_production_custody_contract import (
    CatalogObjectPutRequest,
    LedgerHeadCompareAndSwapRequest,
    LedgerHeadReadRequest,
    LedgerObjectReadRequest,
    ProviderPolicyRejection,
    RetentionStateReadRequest,
)
from sunderkey.gcp_gcs_catalog import GCSCatalogError, GCSImmutableCatalogObjectProvider
from sunderkey.gcp_gcs_custody import (
    GCSConditionalLedgerHeadProvider,
    GCSCustodyError,
    GCSPreconditionFailed,
    GCSReadRequest,
    GCSWriteRequest,
)
from sunderkey.qualification import _canonical_sha256
from tests.agents import test_gcp_gcs_catalog as catalog_reference
from tests.agents import test_gcp_gcs_custody as custody_reference


def custody_fixture():
    fixture = custody_reference.GCPCustodyMappingTests()
    fixture.setUp()
    return fixture


def catalog_fixture():
    fixture = catalog_reference.GCSCatalogMappingTests()
    fixture.setUp()
    return fixture


def initial_sha(fixture):
    return _canonical_sha256(custody_reference.head_document(fixture.initial))


class GCSCallbackRequestIntegrityTests(unittest.TestCase):
    def assert_unconfirmed_mutation(self, operation, family=GCSCustodyError):
        with self.assertRaisesRegex(family, "request changed.*unconfirmed") as raised:
            operation()
        self.assertNotIsInstance(raised.exception, ProviderPolicyRejection)
        return raised.exception

    def test_stale_head_fence_mutation_rejects_without_claiming_external_undo(self):
        fixture = custody_fixture()
        fixture.create_head()
        competing = GCSConditionalLedgerHeadProvider(
            fixture.transport, fixture.profiles, clock=lambda: custody_reference.NOW
        )
        winner = replace(fixture.successor, entry_id="entry.competing")
        observed = []

        def change_fence(delivered):
            receipt = competing.compare_and_swap_head(
                LedgerHeadCompareAndSwapRequest("request.competing", initial_sha(fixture), winner)
            )
            observed.append(receipt.compare_and_swap_status)
            metadata = fixture.transport.objects[(delivered.bucket, delivered.object_name)].metadata
            object.__setattr__(delivered, "if_generation_match", metadata.generation)
            object.__setattr__(delivered, "if_metageneration_match", metadata.metageneration)

        fixture.transport.before_write = change_fence
        self.assert_unconfirmed_mutation(
            lambda: fixture.heads.compare_and_swap_head(
                LedgerHeadCompareAndSwapRequest(
                    "request.outer", initial_sha(fixture), fixture.successor
                )
            )
        )
        self.assertEqual(observed, ["advanced"])
        self.assertEqual(len(fixture.transport.write_attempts), 3)
        self.assertEqual(fixture.transport.applied_writes, 3)
        # The callback already applied the outer write. Rejection is not rollback.
        actual = fixture.heads.read_head(
            LedgerHeadReadRequest("request.inspect", fixture.initial.deployment_id)
        )
        self.assertEqual(actual.head, fixture.successor)
        self.assertNotEqual(actual.head, winner)

    def test_unchanged_head_race_preserves_real_conflict_without_retry(self):
        fixture = custody_fixture()
        fixture.create_head()
        competing = GCSConditionalLedgerHeadProvider(
            fixture.transport, fixture.profiles, clock=lambda: custody_reference.NOW
        )
        winner = replace(fixture.successor, entry_id="entry.competing")

        def race(_):
            competing.compare_and_swap_head(
                LedgerHeadCompareAndSwapRequest("request.competing", initial_sha(fixture), winner)
            )

        fixture.transport.before_write = race
        with self.assertRaises(ProviderPolicyRejection) as raised:
            fixture.heads.compare_and_swap_head(
                LedgerHeadCompareAndSwapRequest(
                    "request.outer", initial_sha(fixture), fixture.successor
                )
            )
        self.assertEqual(raised.exception.rejection_code, "ledger_head_conflict")
        self.assertEqual(fixture.transport.applied_writes, 2)
        self.assertEqual(len(fixture.transport.write_attempts), 3)

    def test_same_head_race_replays_only_when_delivery_is_unchanged(self):
        for mutate in (False, True):
            with self.subTest(mutate=mutate):
                fixture = custody_fixture()
                fixture.create_head()
                competing = GCSConditionalLedgerHeadProvider(
                    fixture.transport, fixture.profiles, clock=lambda: custody_reference.NOW
                )
                calls_at_failure = []

                def race(
                    delivered,
                    *,
                    competing=competing,
                    fixture=fixture,
                    mutate=mutate,
                    calls_at_failure=calls_at_failure,
                ):
                    competing.compare_and_swap_head(
                        LedgerHeadCompareAndSwapRequest(
                            "request.competing", initial_sha(fixture), fixture.successor
                        )
                    )
                    if mutate:
                        object.__setattr__(delivered, "request_id", "request.substituted")
                    calls_at_failure.append(len(fixture.transport.calls))

                fixture.transport.before_write = race

                def operation(fixture=fixture):
                    return fixture.heads.compare_and_swap_head(
                        LedgerHeadCompareAndSwapRequest(
                            "request.outer", initial_sha(fixture), fixture.successor
                        )
                    )

                if mutate:
                    self.assert_unconfirmed_mutation(operation)
                    self.assertEqual(len(fixture.transport.calls), calls_at_failure[0])
                else:
                    receipt = operation()
                    self.assertEqual(receipt.compare_and_swap_status, "already_current_same_digest")
                self.assertEqual(fixture.transport.applied_writes, 2)
                self.assertEqual(len(fixture.transport.write_attempts), 3)

    def test_ledger_request_id_mutation_rejects_genuine_success_before_readback(self):
        fixture = custody_fixture()
        fixture.transport.before_write = lambda delivered: object.__setattr__(
            delivered, "request_id", "request.substituted"
        )
        self.assert_unconfirmed_mutation(fixture.create_ledger)
        self.assertEqual(fixture.put.request_id, "request.create")
        self.assertEqual(fixture.transport.applied_writes, 1)
        self.assertFalse(any(call[0] == "read" for call in fixture.transport.calls))

    def test_each_valid_head_write_precondition_mutation_rejects_after_application(self):
        for field, value in (("if_generation_match", "999"), ("if_metageneration_match", "2")):
            with self.subTest(field=field):
                fixture = custody_fixture()
                fixture.create_head()
                original = fixture.transport.write_object
                reads_before = sum(call[0] == "read" for call in fixture.transport.calls)

                def write_then_mutate(delivered, *, original=original, field=field, value=value):
                    result = original(delivered)
                    object.__setattr__(delivered, field, value)
                    return result

                fixture.transport.write_object = write_then_mutate
                self.assert_unconfirmed_mutation(
                    lambda fixture=fixture: fixture.heads.compare_and_swap_head(
                        LedgerHeadCompareAndSwapRequest(
                            "request.outer", initial_sha(fixture), fixture.successor
                        )
                    )
                )
                self.assertEqual(fixture.transport.applied_writes, 2)
                # Only the pre-write current-head read occurred, not acknowledgement readback.
                self.assertEqual(
                    sum(call[0] == "read" for call in fixture.transport.calls), reads_before + 1
                )

    def test_ledger_descriptor_and_payload_mutations_are_deep_and_source_isolated(self):
        for field in ("descriptor", "payload"):
            with self.subTest(field=field):
                fixture = custody_fixture()
                original_descriptor = copy.deepcopy(fixture.descriptor)

                def mutate(delivered, *, field=field, fixture=fixture):
                    self.assertIsNot(delivered.ledger_object, fixture.put.object)
                    if field == "descriptor":
                        object.__setattr__(
                            delivered.ledger_object, "namespace_id", "namespace.substituted"
                        )
                    else:
                        object.__setattr__(delivered, "payload", b"x" * len(fixture.payload))

                fixture.transport.before_write = mutate
                self.assert_unconfirmed_mutation(fixture.create_ledger)
                self.assertEqual(fixture.put.object, original_descriptor)
                self.assertEqual(fixture.put.payload, fixture.payload)
                self.assertEqual(fixture.transport.applied_writes, 1)
                self.assertFalse(any(call[0] == "read" for call in fixture.transport.calls))

    def test_custody_delivery_is_a_distinct_owned_request_and_descriptor(self):
        fixture = custody_fixture()
        source = GCSWriteRequest(
            fixture.put.request_id,
            fixture.profiles.ledger.bucket,
            "ledger/" + fixture.descriptor.object_id,
            fixture.payload,
            "0",
            None,
            fixture.descriptor,
        )
        received = []

        def inspect(delivered):
            self.assertIsNot(delivered, source)
            self.assertIsNot(delivered.ledger_object, source.ledger_object)
            self.assertEqual(delivered, source)
            received.append(delivered)

        fixture.transport.before_write = inspect
        metadata = fixture.ledger._write(source)
        self.assertEqual(metadata.ledger_object, fixture.descriptor)
        self.assertEqual(len(received), 1)
        self.assertEqual(fixture.transport.applied_writes, 1)

    def test_custody_native_aliases_reject_before_comparison_hooks(self):
        hooks = []

        class Alias(str):
            def __eq__(self, other):
                hooks.append("eq")
                return True

            def __ne__(self, other):
                hooks.append("ne")
                return False

        for field in ("request_id", "generation", "size_bytes"):
            with self.subTest(field=field):
                fixture = custody_fixture()
                original = fixture.transport.write_object

                def mutate(delivered, *, original=original, field=field):
                    result = original(delivered)
                    if field == "size_bytes":
                        object.__setattr__(delivered.ledger_object, "size_bytes", True)
                    elif field == "generation":
                        object.__setattr__(delivered, "if_generation_match", Alias("0"))
                    else:
                        object.__setattr__(delivered, "request_id", Alias("request.substituted"))
                    return result

                fixture.transport.write_object = mutate
                self.assert_unconfirmed_mutation(fixture.create_ledger)
        self.assertEqual(hooks, [])

    def test_custody_reads_reject_post_return_generation_mutation(self):
        for kind in ("ledger", "retention", "head"):
            with self.subTest(kind=kind):
                fixture = custody_fixture()
                if kind == "head":
                    fixture.create_head()

                    def operation(fixture=fixture):
                        return fixture.heads.read_head(
                            LedgerHeadReadRequest("request.read", fixture.initial.deployment_id)
                        )

                elif kind == "retention":
                    fixture.create_ledger()

                    def operation(fixture=fixture):
                        return fixture.ledger.read_retention_state(
                            RetentionStateReadRequest(
                                "request.read",
                                fixture.descriptor.object_id,
                                custody_reference.RETENTION_UNTIL,
                            )
                        )

                else:
                    fixture.create_ledger()

                    def operation(fixture=fixture):
                        return fixture.ledger.read_verified(
                            LedgerObjectReadRequest(
                                "request.read",
                                fixture.descriptor.object_id,
                                fixture.descriptor.sha256,
                            )
                        )

                original = fixture.transport.read_object

                def read_then_mutate(delivered, *, original=original):
                    result = original(delivered)
                    object.__setattr__(delivered, "generation", "999")
                    return result

                fixture.transport.read_object = read_then_mutate
                writes = fixture.transport.applied_writes
                self.assert_unconfirmed_mutation(operation)
                self.assertEqual(fixture.transport.applied_writes, writes)

    def test_custody_read_missing_field_and_family_substitution_fail_closed(self):
        class Substitute(GCSReadRequest):
            pass

        for substitute in (False, True):
            with self.subTest(substitute=substitute):
                fixture = custody_fixture()
                fixture.create_ledger()
                original = fixture.transport.read_object

                def mutate(delivered, *, original=original, substitute=substitute):
                    result = original(delivered)
                    if substitute:
                        object.__setattr__(delivered, "__class__", Substitute)
                    else:
                        object.__delattr__(delivered, "generation")
                    return result

                fixture.transport.read_object = mutate
                self.assert_unconfirmed_mutation(
                    lambda fixture=fixture: fixture.ledger.read_verified(
                        LedgerObjectReadRequest(
                            "request.read", fixture.descriptor.object_id, fixture.descriptor.sha256
                        )
                    )
                )

    def test_custody_read_mutation_precedes_genuine_precondition_translation(self):
        fixture = custody_fixture()
        fixture.create_ledger()
        original = fixture.transport.read_object

        def mutate(delivered):
            object.__setattr__(delivered, "generation", "999")
            return original(delivered)

        fixture.transport.read_object = mutate
        error = self.assert_unconfirmed_mutation(
            lambda: fixture.ledger.read_verified(
                LedgerObjectReadRequest(
                    "request.read", fixture.descriptor.object_id, fixture.descriptor.sha256
                )
            )
        )
        self.assertIsInstance(error.__context__, GCSPreconditionFailed)

    def test_custody_write_mutation_precedes_ambiguous_and_generic_errors(self):
        for kind in ("ambiguous", "generic", "policy"):
            with self.subTest(kind=kind):
                fixture = custody_fixture()

                def mutate(delivered, *, kind=kind, fixture=fixture):
                    object.__setattr__(delivered, "request_id", "request.substituted")
                    if kind == "generic":
                        raise RuntimeError("synthetic transport failure")
                    if kind == "policy":
                        raise ProviderPolicyRejection(
                            "immutable_ledger_overwrite",
                            delivered.request_id,
                            fixture.descriptor.sha256,
                        )

                fixture.transport.before_write = mutate
                if kind == "ambiguous":
                    fixture.transport.ambiguous = "after"
                self.assert_unconfirmed_mutation(fixture.create_ledger)
                self.assertEqual(len(fixture.transport.write_attempts), 1)
                self.assertEqual(fixture.transport.applied_writes, int(kind == "ambiguous"))

    def test_unchanged_errors_retain_existing_semantics_without_retry(self):
        fixture = custody_fixture()
        fixture.transport.ambiguous = "after"
        with self.assertRaisesRegex(GCSCustodyError, "Write outcome is unconfirmed"):
            fixture.create_ledger()
        self.assertEqual(fixture.transport.applied_writes, 1)
        self.assertEqual(len(fixture.transport.write_attempts), 1)
        fixture = custody_fixture()
        failure = RuntimeError("synthetic transport failure")

        def fail(_):
            raise failure

        fixture.transport.before_write = fail
        with self.assertRaises(RuntimeError) as raised:
            fixture.create_ledger()
        self.assertIs(raised.exception, failure)
        self.assertEqual(fixture.transport.applied_writes, 0)
        self.assertEqual(len(fixture.transport.write_attempts), 1)

    def test_catalog_write_request_id_mutation_rejects_genuine_create(self):
        fixture = catalog_fixture()
        fixture.transport.before_write = lambda delivered: object.__setattr__(
            delivered, "request_id", "request.substituted"
        )
        self.assert_unconfirmed_mutation(fixture._put, GCSCatalogError)
        self.assertEqual(fixture.transport.applied_writes, 1)
        self.assertEqual(fixture.provider._confirmed, {})
        self.assertFalse(any(call[0] == "read" for call in fixture.transport.calls))

    def test_catalog_descriptor_payload_and_precondition_mutation_is_unconfirmed(self):
        for field in ("descriptor", "payload", "precondition", "metageneration"):
            with self.subTest(field=field):
                fixture = catalog_fixture()
                original = fixture.transport.write_object

                def write_then_mutate(
                    delivered, *, original=original, fixture=fixture, field=field
                ):
                    result = original(delivered)
                    self.assertIsNot(delivered.descriptor, fixture.descriptor)
                    if field == "descriptor":
                        object.__setattr__(
                            delivered.descriptor, "namespace_id", "namespace.substituted"
                        )
                    elif field == "payload":
                        object.__setattr__(
                            delivered, "payload", b"x" * len(catalog_reference.PAYLOAD)
                        )
                    elif field == "metageneration":
                        object.__setattr__(delivered, "if_metageneration_match", "7")
                    else:
                        object.__setattr__(delivered, "if_generation_match", "1001")
                    return result

                fixture.transport.write_object = write_then_mutate
                self.assert_unconfirmed_mutation(fixture._put, GCSCatalogError)
                self.assertEqual(fixture.descriptor.namespace_id, "namespace.catalog")
                self.assertEqual(fixture.transport.applied_writes, 1)
                self.assertEqual(fixture.provider._confirmed, {})
                self.assertEqual(fixture._stored().payload, catalog_reference.PAYLOAD)

    def test_catalog_create_race_replays_only_when_delivery_is_unchanged(self):
        for mutate in (False, True):
            with self.subTest(mutate=mutate):
                fixture = catalog_fixture()
                competing = GCSImmutableCatalogObjectProvider(
                    fixture.transport, fixture.profile, clock=lambda: catalog_reference.NOW
                )
                calls_at_failure = []

                def race(
                    delivered,
                    *,
                    competing=competing,
                    fixture=fixture,
                    mutate=mutate,
                    calls_at_failure=calls_at_failure,
                ):
                    competing.put_sha256_object(
                        CatalogObjectPutRequest(
                            "request.competing", fixture.descriptor, catalog_reference.PAYLOAD
                        )
                    )
                    if mutate:
                        object.__setattr__(delivered, "request_id", "request.substituted")
                    calls_at_failure.append(len(fixture.transport.calls))

                fixture.transport.before_write = race
                if mutate:
                    self.assert_unconfirmed_mutation(fixture._put, GCSCatalogError)
                    self.assertEqual(len(fixture.transport.calls), calls_at_failure[0])
                    self.assertEqual(fixture.provider._confirmed, {})
                else:
                    self.assertEqual(fixture._put().write_status, "already_present_same_digest")
                self.assertEqual(fixture.transport.applied_writes, 1)
                self.assertEqual(len(fixture.transport.write_attempts), 2)

    def test_catalog_read_rejects_post_return_scalar_and_nested_mutation(self):
        for field in ("generation", "descriptor", "observed_at"):
            with self.subTest(field=field):
                fixture = catalog_fixture()
                fixture._put()
                confirmed = copy.deepcopy(fixture.provider._confirmed)
                original = fixture.transport.read_object

                def read_then_mutate(delivered, *, original=original, field=field):
                    result = original(delivered)
                    if field == "descriptor":
                        object.__setattr__(
                            delivered.descriptor, "namespace_id", "namespace.substituted"
                        )
                    elif field == "observed_at":
                        object.__setattr__(
                            delivered, "observed_at", delivered.observed_at + timedelta(seconds=1)
                        )
                    else:
                        object.__setattr__(delivered, "generation", "999")
                    return result

                fixture.transport.read_object = read_then_mutate
                self.assert_unconfirmed_mutation(fixture._read, GCSCatalogError)
                self.assertEqual(fixture.provider._confirmed, confirmed)
                self.assertEqual(fixture.transport.applied_writes, 1)
                self.assertEqual(fixture.descriptor.namespace_id, "namespace.catalog")

    def test_catalog_read_mutation_precedes_genuine_precondition_translation(self):
        fixture = catalog_fixture()
        fixture._put()
        original = fixture.transport.read_object

        def mutate(delivered):
            object.__setattr__(delivered, "generation", "999")
            return original(delivered)

        fixture.transport.read_object = mutate
        error = self.assert_unconfirmed_mutation(fixture._read, GCSCatalogError)
        self.assertIsInstance(error.__context__, GCSPreconditionFailed)

    def test_catalog_native_aliases_do_not_execute_comparison_hooks(self):
        hooks = []

        class Alias(str):
            def __eq__(self, other):
                hooks.append("eq")
                return True

            def __ne__(self, other):
                hooks.append("ne")
                return False

        for read in (False, True):
            with self.subTest(read=read):
                fixture = catalog_fixture()
                if read:
                    fixture._put()
                    original = fixture.transport.read_object

                    def mutate(delivered, *, original=original):
                        result = original(delivered)
                        object.__setattr__(delivered, "generation", Alias(delivered.generation))
                        return result

                    fixture.transport.read_object = mutate
                    operation = fixture._read
                else:
                    original = fixture.transport.write_object

                    def mutate(delivered, *, original=original):
                        result = original(delivered)
                        object.__setattr__(delivered, "request_id", Alias(delivered.request_id))
                        return result

                    fixture.transport.write_object = mutate
                    operation = fixture._put
                self.assert_unconfirmed_mutation(operation, GCSCatalogError)
        self.assertEqual(hooks, [])

    def test_catalog_write_mutation_precedes_ambiguous_and_generic_errors(self):
        for ambiguous in (False, True):
            with self.subTest(ambiguous=ambiguous):
                fixture = catalog_fixture()

                def mutate(delivered, *, ambiguous=ambiguous):
                    object.__setattr__(delivered, "request_id", "request.substituted")
                    if not ambiguous:
                        raise RuntimeError("synthetic catalog failure")

                fixture.transport.before_write = mutate
                if ambiguous:
                    fixture.transport.ambiguous = "after"
                self.assert_unconfirmed_mutation(fixture._put, GCSCatalogError)
                self.assertEqual(fixture.transport.applied_writes, int(ambiguous))
                self.assertEqual(len(fixture.transport.write_attempts), 1)
                self.assertEqual(fixture.provider._confirmed, {})

    def test_read_mutation_precedes_generic_errors_for_both_port_families(self):
        for catalog in (False, True):
            with self.subTest(catalog=catalog):
                fixture = catalog_fixture() if catalog else custody_fixture()
                if catalog:
                    fixture._put()
                    operation = fixture._read
                    family = GCSCatalogError
                else:
                    fixture.create_ledger()

                    def operation(fixture=fixture):
                        return fixture.ledger.read_verified(
                            LedgerObjectReadRequest(
                                "request.read",
                                fixture.descriptor.object_id,
                                fixture.descriptor.sha256,
                            )
                        )

                    family = GCSCustodyError

                def fail(delivered):
                    object.__setattr__(delivered, "generation", "999")
                    raise RuntimeError("synthetic read failure")

                fixture.transport.read_object = fail
                self.assert_unconfirmed_mutation(operation, family)
                self.assertEqual(fixture.transport.applied_writes, 1)

    def test_unchanged_catalog_errors_and_normal_create_replay_read_are_preserved(self):
        fixture = catalog_fixture()
        created = fixture._put()
        self.assertEqual(created.write_status, "created")
        self.assertEqual(fixture._put().write_status, "already_present_same_digest")
        self.assertEqual(fixture._read().payload, catalog_reference.PAYLOAD)
        self.assertEqual(fixture.transport.applied_writes, 1)
        fixture = catalog_fixture()
        fixture.transport.ambiguous = "after"
        with self.assertRaisesRegex(GCSCatalogError, "Catalog write outcome is unconfirmed"):
            fixture._put()
        self.assertEqual(fixture.transport.applied_writes, 1)
        fixture = catalog_fixture()
        failure = RuntimeError("synthetic catalog failure")

        def fail(_):
            raise failure

        fixture.transport.before_write = fail
        with self.assertRaises(RuntimeError) as raised:
            fixture._put()
        self.assertIs(raised.exception, failure)
        self.assertEqual(fixture.transport.applied_writes, 0)
        self.assertEqual(len(fixture.transport.write_attempts), 1)


if __name__ == "__main__":
    unittest.main()
