"""Exact native replay checks for the nonexecuting containment profiles."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from dataclasses import replace
from unittest.mock import patch

from scripts.build_candidate_adapter_catalog import load_blueprints
from sunderkey import local_microvm_containment as microvm
from sunderkey import local_oci_containment as oci
from sunderkey.candidate_adapter_runner import prepare_containment_execution_plan
from sunderkey.candidate_adapter_sdk import SOURCE_PATH, build_candidate_adapter_catalog
from sunderkey.candidate_implementation_strategy import load_candidate_implementation_strategy
from sunderkey.errors import QualificationError
from sunderkey.qualification import _canonical_json, _canonical_sha256
from sunderkey.reference_adapters import build_reference_adapters
from tests.agents import test_local_microvm_containment_phase169 as microvm_tests
from tests.agents import test_local_oci_containment_phase169 as oci_tests

HISTORICAL_REFERENCE_SOURCE_SHA256 = (
    "sha256:65b7ba1bbbd4b0131707e378bb6194bab0c07cb3455bff9b7db2f3798d931e62"
)


def readdress(raw, *, domain, body_key, id_field, sha_field, prefix):
    body = {key: value for key, value in raw.items() if key not in {id_field, sha_field}}
    digest = _canonical_sha256({"domain": domain, body_key: body})
    raw[sha_field] = digest
    raw[id_field] = prefix + digest.removeprefix("sha256:")[:32].upper()
    return json.loads(_canonical_json(raw))


def address_spec(raw, module):
    return readdress(
        raw,
        domain=module.SPEC_DOMAIN,
        body_key="specification",
        id_field="spec_id",
        sha_field="spec_sha256",
        prefix="OCS-" if module is oci else "MVS-",
    )


def address_observation(raw, module):
    return readdress(
        raw,
        domain=module.OBSERVATION_DOMAIN,
        body_key="observation",
        id_field="observation_id",
        sha_field="observation_sha256",
        prefix="OCO-" if module is oci else "MVO-",
    )


def address_fixture(raw, module):
    return readdress(
        raw,
        domain=oci.FIXTURE_DOMAIN if module is oci else microvm.RECEIPT_DOMAIN,
        body_key="fixture" if module is oci else "receipt",
        id_field="fixture_id" if module is oci else "receipt_id",
        sha_field="fixture_sha256" if module is oci else "receipt_sha256",
        prefix="OCF-" if module is oci else "MVR-",
    )


def numeric_paths(raw, prefix=()):
    if type(raw) in {bool, int}:
        yield prefix, raw
    elif type(raw) is dict:
        for key, value in raw.items():
            yield from numeric_paths(value, (*prefix, key))
    elif type(raw) is list:
        for index, value in enumerate(raw):
            yield from numeric_paths(value, (*prefix, index))


def replace_path(raw, path, value):
    parent = raw
    for part in path[:-1]:
        parent = parent[part]
    parent[path[-1]] = value


class UnexpectedInt(int):
    def __eq__(self, _other):
        raise AssertionError("integer alias hook must not execute")


class UnexpectedStr(str):
    def __eq__(self, _other):
        raise AssertionError("string alias hook must not execute")

    __hash__ = str.__hash__


class UnexpectedList(list):
    def __iter__(self):
        raise AssertionError("list alias hook must not execute")


class UnexpectedDict(dict):
    def __iter__(self):
        raise AssertionError("dictionary alias hook must not execute")


class LocalContainmentNativeReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class CheckedOciFixture(oci_tests.LocalOciContainmentPhase169Tests):
            pass

        class CheckedMicrovmFixture(microvm_tests.LocalMicrovmContainmentPhase169Tests):
            pass

        CheckedOciFixture.setUpClass()
        CheckedMicrovmFixture.setUpClass()
        cls.oci_case = CheckedOciFixture("runTest")
        cls.microvm_case = CheckedMicrovmFixture("runTest")
        cls.oci_fixture = cls.oci_case.fixture()
        cls.microvm_fixture = microvm.build_local_microvm_containment_fixture(
            cls.microvm_case.spec()
        )

    def fixtures(self):
        return (
            (
                oci,
                self.oci_fixture,
                oci.LocalOciExecutionSpec,
                oci.LocalOciContainmentObservation,
                oci.LocalOciContainmentFixture,
            ),
            (
                microvm,
                self.microvm_fixture,
                microvm.LocalMicrovmExecutionSpec,
                microvm.LocalMicrovmContainmentObservation,
                microvm.LocalMicrovmContainmentFixtureReceipt,
            ),
        )

    def test_original_golden_specification_and_fixture_addresses_are_unchanged(self):
        # Historical metadata only: this fixed source digest does not attest
        # current source bytes and no reference adapter is executed.
        strategy = load_candidate_implementation_strategy(
            oci_tests.REGISTRY / "candidate-implementation-strategy-v1.json"
        )
        historical_catalog = build_candidate_adapter_catalog(
            strategy, load_blueprints(), HISTORICAL_REFERENCE_SOURCE_SHA256
        )
        historical_adapters = build_reference_adapters(historical_catalog)
        historical_oci = oci_tests.LocalOciContainmentPhase169Tests("runTest")
        historical_oci.adapter = historical_adapters["AOE-GB-D06-S09"]
        historical_oci.conformance_catalog = self.oci_case.conformance_catalog
        historical_microvm = microvm_tests.LocalMicrovmContainmentPhase169Tests("runTest")
        historical_microvm.binding = self.microvm_case.binding
        historical_manifest = historical_adapters["AOE-GC-D14-S01"].manifest
        historical_microvm.plan = prepare_containment_execution_plan(
            historical_manifest,
            replace(
                self.microvm_case.invocation,
                profile_id=historical_manifest.profile_id,
                vector_id=historical_manifest.vector_id,
            ),
            self.microvm_case.attestation,
            self.microvm_case.limits,
            issued_at="2026-09-20T12:00:00Z",
            expires_at="2026-09-20T12:00:45Z",
        )
        goldens = (
            (
                historical_oci.fixture(),
                "OCS-4B1A2AD77304D3E40DA8BF753450A421",
                "sha256:4b1a2ad77304d3e40da8bf753450a4217ab9c4c87753d47f7faeeda5819f2f88",
                "OCF-C8C5BDC0240578BD4290E766BEF1ADC6",
                "sha256:c8c5bdc0240578bd4290e766bef1adc65e3daa05dbbf0f33448d2d646d01ec42",
            ),
            (
                microvm.build_local_microvm_containment_fixture(historical_microvm.spec()),
                "MVS-20E33A9C2DD625AE2EF2D9C0836D3DC7",
                "sha256:20e33a9c2dd625ae2ef2d9c0836d3dc74c0b0d5abcc9778b41a96f704c2ac78c",
                "MVR-954835048F3A1E8169ED68DA041FFF41",
                "sha256:954835048f3a1e8169ed68da041fff412bc5190368c9e98acae22b1f7f6c76f2",
            ),
        )
        for fixture, spec_id, spec_sha, root_id, root_sha in goldens:
            with self.subTest(spec=spec_id):
                raw = fixture.to_dict()
                self.assertEqual(raw["specification"]["spec_id"], spec_id)
                self.assertEqual(raw["specification"]["spec_sha256"], spec_sha)
                self.assertEqual(raw.get("fixture_id", raw.get("receipt_id")), root_id)
                self.assertEqual(raw.get("fixture_sha256", raw.get("receipt_sha256")), root_sha)

    def test_current_fixtures_keep_exact_checked_source_and_plan_bindings(self):
        actual_source_sha256 = (
            "sha256:" + hashlib.sha256((oci_tests.ROOT / SOURCE_PATH).read_bytes()).hexdigest()
        )
        for case, fixture, plan in (
            (self.oci_case, self.oci_fixture, self.oci_case.contracts()[2]),
            (self.microvm_case, self.microvm_fixture, self.microvm_case.plan),
        ):
            with self.subTest(profile=case.adapter.manifest.profile_id):
                self.assertEqual(case.adapter.manifest.source_sha256, actual_source_sha256)
                self.assertEqual(plan.manifest_sha256, case.adapter.manifest.manifest_sha256)
                specification = fixture.specification.to_dict()
                self.assertEqual(specification["plan_id"], plan.plan_id)
                self.assertEqual(specification["plan_sha256"], plan.plan_sha256)

    def test_native_json_round_trips_preserve_all_valid_canonical_bytes(self):
        for module, fixture, spec_type, observation_type, fixture_type in self.fixtures():
            with self.subTest(module=module.__name__):
                raw = json.loads(_canonical_json(fixture.to_dict()))
                self.assertEqual(fixture_type.from_dict(raw).document_json, fixture.document_json)
                self.assertEqual(
                    spec_type.from_dict(raw["specification"]).document_json,
                    fixture.specification.document_json,
                )
                for value, original in zip(raw["observations"], fixture.observations, strict=True):
                    self.assertEqual(
                        observation_type.from_dict(value).document_json, original.document_json
                    )

    def test_oci_normative_boolean_and_integer_aliases_reject_coherent_rehash(self):
        raw = self.oci_fixture.specification.to_dict()
        sections = (
            "security_policy",
            "workspace_policy",
            "cancellation_policy",
            "cleanup_policy",
            "observation_policy",
        )
        for section in sections:
            for path, original in numeric_paths(raw[section], (section,)):
                alias = int(original) if type(original) is bool else float(original)
                with self.subTest(path=path, alias=alias):
                    changed = copy.deepcopy(raw)
                    replace_path(changed, path, alias)
                    changed = address_spec(changed, oci)
                    self.assertNotEqual(changed["spec_sha256"], raw["spec_sha256"])
                    with self.assertRaises(QualificationError):
                        oci.LocalOciExecutionSpec.from_dict(changed)

    def test_microvm_normative_boolean_and_integer_aliases_reject_coherent_rehash(self):
        raw = self.microvm_fixture.specification.to_dict()
        sections = (
            "host_preflight_contract",
            "host_requirements",
            "artifact_policy",
            "jailer_policy",
            "machine_configuration",
            "resource_limits",
            "credential_policy",
            "logging_policy",
            "lifecycle_policy",
        )
        for section in sections:
            for path, original in numeric_paths(raw[section], (section,)):
                alias = int(original) if type(original) is bool else float(original)
                with self.subTest(path=path, alias=alias):
                    changed = copy.deepcopy(raw)
                    replace_path(changed, path, alias)
                    changed = address_spec(changed, microvm)
                    self.assertNotEqual(changed["spec_sha256"], raw["spec_sha256"])
                    with self.assertRaises(QualificationError):
                        microvm.LocalMicrovmExecutionSpec.from_dict(changed)

    def test_schema_version_aliases_reject_rehashed_specs_observations_and_fixtures(self):
        for module, fixture, spec_type, observation_type, fixture_type in self.fixtures():
            forms = (
                (fixture.specification.to_dict(), spec_type, address_spec),
                (fixture.observations[0].to_dict(), observation_type, address_observation),
                (fixture.to_dict(), fixture_type, address_fixture),
            )
            for original, model, address in forms:
                for alias in (True, 1.0):
                    with self.subTest(module=module.__name__, model=model.__name__, alias=alias):
                        raw = copy.deepcopy(original)
                        raw["schema_version"] = alias
                        with self.assertRaises(QualificationError):
                            model.from_dict(address(raw, module))

    def test_microvm_native_zero_counters_reject_rehashed_bool_and_float_aliases(self):
        for field in ("output_bytes", "log_bytes"):
            for alias in (False, 0.0, -0.0):
                with self.subTest(field=field, alias=alias):
                    raw = self.microvm_fixture.to_dict()
                    raw[field] = alias
                    with self.assertRaises(QualificationError):
                        microvm.LocalMicrovmContainmentFixtureReceipt.from_dict(
                            address_fixture(raw, microvm)
                        )

    def test_rehashed_zero_counter_receipt_cannot_hide_inside_valid_outer_source(self):
        raw = self.microvm_fixture.to_dict()
        raw["output_bytes"] = False
        raw["log_bytes"] = 0.0
        with self.assertRaises(QualificationError):
            microvm.LocalMicrovmContainmentFixtureReceipt.from_dict(address_fixture(raw, microvm))

    def test_microvm_public_fixture_builder_rejects_aliased_specification_document(self):
        original = self.microvm_fixture.specification
        for path, alias in (
            (("host_preflight_contract", "external_preflight_required_before_dispatch"), 1),
            (("machine_configuration", "smt"), 0),
            (("machine_configuration", "memory_mib"), 512.0),
            (("jailer_policy", "seccomp_level"), 2.0),
        ):
            with self.subTest(path=path):
                raw = original.to_dict()
                replace_path(raw, path, alias)
                raw = address_spec(raw, microvm)
                changed = replace(
                    original,
                    spec_id=raw["spec_id"],
                    spec_sha256=raw["spec_sha256"],
                    document_json=_canonical_json(raw),
                )
                with self.assertRaises(QualificationError):
                    microvm.build_local_microvm_containment_fixture(changed)

    def test_native_subclasses_are_rejected_before_normalization_or_hashing(self):
        for module, fixture, spec_type, _, _ in self.fixtures():
            original = fixture.specification.to_dict()
            variants = [UnexpectedDict(original)]
            for field, value in (
                ("schema_version", UnexpectedInt(1)),
                ("spec_id", UnexpectedStr(original["spec_id"])),
            ):
                raw = copy.deepcopy(original)
                raw[field] = value
                variants.append(raw)
            list_field = "command_argv" if module is oci else "jailer_argv"
            raw = copy.deepcopy(original)
            raw[list_field] = UnexpectedList(raw[list_field])
            variants.append(raw)
            raw = copy.deepcopy(original)
            map_field = "security_policy" if module is oci else "machine_configuration"
            raw[map_field] = UnexpectedDict(raw[map_field])
            variants.append(raw)
            raw = {
                UnexpectedStr("schema_version") if key == "schema_version" else key: value
                for key, value in original.items()
            }
            variants.append(raw)
            for index, raw in enumerate(variants):
                with (
                    self.subTest(module=module.__name__, variant=index),
                    patch.object(
                        module, "_canonical_json", side_effect=AssertionError("normalize")
                    ),
                    patch.object(module, "_canonical_sha256", side_effect=AssertionError("hash")),
                    self.assertRaises(QualificationError),
                ):
                    spec_type.from_dict(raw)

    def test_numeric_aliases_are_rejected_before_normalization_or_hashing(self):
        for module, fixture, spec_type, _, fixture_type in self.fixtures():
            variants = []
            raw = fixture.specification.to_dict()
            raw["schema_version"] = True
            variants.append((spec_type, raw))
            raw = fixture.specification.to_dict()
            field = "security_policy" if module is oci else "machine_configuration"
            raw[field]["rootless" if module is oci else "smt"] = 1 if module is oci else 0
            variants.append((spec_type, raw))
            raw = fixture.to_dict()
            raw["schema_version"] = 1.0
            variants.append((fixture_type, raw))
            for model, raw in variants:
                with (
                    self.subTest(module=module.__name__, model=model.__name__),
                    patch.object(
                        module, "_canonical_json", side_effect=AssertionError("normalize")
                    ),
                    patch.object(module, "_canonical_sha256", side_effect=AssertionError("hash")),
                    self.assertRaises(QualificationError),
                ):
                    model.from_dict(raw)

    def test_malformed_native_assertion_entries_raise_contract_error_before_hashing(self):
        for module, fixture, _, observation_type, _ in self.fixtures():
            for entry in ({}, [], 1, True, None, UnexpectedStr("invented_assertion")):
                raw = fixture.observations[0].to_dict()
                raw["assertions"] = [entry]
                with (
                    self.subTest(module=module.__name__, entry=type(entry).__name__),
                    patch.object(module, "_canonical_sha256", side_effect=AssertionError("hash")),
                    self.assertRaises(QualificationError),
                ):
                    observation_type.from_dict(raw)

    def test_observation_specification_reference_is_native_before_hashing(self):
        for module, fixture, _, observation_type, _ in self.fixtures():
            for value in (False, 0, [], {}, None):
                raw = fixture.observations[0].to_dict()
                raw["spec_id"] = value
                raw = address_observation(raw, module)
                with (
                    self.subTest(module=module.__name__, value=type(value).__name__),
                    patch.object(module, "_canonical_sha256", side_effect=AssertionError("hash")),
                    self.assertRaises(QualificationError),
                ):
                    observation_type.from_dict(raw)

    def test_collection_subclasses_and_tuples_reject_in_observations_and_fixtures(self):
        for module, fixture, _, observation_type, fixture_type in self.fixtures():
            for original, model, field in (
                (fixture.observations[0].to_dict(), observation_type, "assertions"),
                (fixture.to_dict(), fixture_type, "observations"),
            ):
                for value in (UnexpectedList(original[field]), tuple(original[field])):
                    raw = copy.deepcopy(original)
                    raw[field] = value
                    with (
                        self.subTest(
                            module=module.__name__, field=field, value=type(value).__name__
                        ),
                        patch.object(
                            module, "_canonical_json", side_effect=AssertionError("normalize")
                        ),
                        patch.object(
                            module, "_canonical_sha256", side_effect=AssertionError("hash")
                        ),
                        self.assertRaises(QualificationError),
                    ):
                        model.from_dict(raw)

    def test_coherently_readdressed_nested_control_aliases_reject_at_fixture_boundary(self):
        for module, fixture, _, _, fixture_type in self.fixtures():
            raw = fixture.to_dict()
            path = (
                ("security_policy", "rootless")
                if module is oci
                else ("machine_configuration", "smt")
            )
            replace_path(raw["specification"], path, 1 if module is oci else 0)
            specification = address_spec(raw["specification"], module)
            raw["specification"] = specification
            for index, original in enumerate(raw["observations"]):
                original["spec_id"] = specification["spec_id"]
                original["spec_sha256"] = specification["spec_sha256"]
                raw["observations"][index] = address_observation(original, module)
            with self.subTest(module=module.__name__), self.assertRaises(QualificationError):
                fixture_type.from_dict(address_fixture(raw, module))

    def test_cyclic_deep_and_shared_native_graphs_cannot_reach_normalization(self):
        for module, fixture, spec_type, _, _ in self.fixtures():
            cycle = []
            cycle.append(cycle)
            deep = []
            for _ in range(1500):
                deep = [deep]
            shared = []
            for _ in range(24):
                shared = [shared, shared]
            for name, value in (("cycle", cycle), ("deep", deep), ("shared", shared)):
                raw = fixture.specification.to_dict()
                section, field = (
                    ("security_policy", "rootless")
                    if module is oci
                    else ("machine_configuration", "smt")
                )
                raw[section][field] = value
                with (
                    self.subTest(module=module.__name__, graph=name),
                    patch.object(
                        module, "_canonical_json", side_effect=AssertionError("normalize")
                    ),
                    patch.object(module, "_canonical_sha256", side_effect=AssertionError("hash")),
                    self.assertRaises(QualificationError),
                ):
                    spec_type.from_dict(raw)

    def test_huge_native_schema_integer_rejects_without_string_conversion(self):
        for module, fixture, spec_type, observation_type, fixture_type in self.fixtures():
            for raw, model in (
                (fixture.specification.to_dict(), spec_type),
                (fixture.observations[0].to_dict(), observation_type),
                (fixture.to_dict(), fixture_type),
            ):
                raw["schema_version"] = 10**5000
                with (
                    self.subTest(module=module.__name__, model=model.__name__),
                    patch.object(
                        module, "_canonical_json", side_effect=AssertionError("normalize")
                    ),
                    patch.object(module, "_canonical_sha256", side_effect=AssertionError("hash")),
                    self.assertRaises(QualificationError),
                ):
                    model.from_dict(raw)

    def test_owned_round_trips_do_not_mutate_or_alias_native_source_collections(self):
        for module, fixture, _, _, fixture_type in self.fixtures():
            raw = fixture.to_dict()
            before = _canonical_json(raw)
            restored = fixture_type.from_dict(raw)
            self.assertEqual(_canonical_json(raw), before)
            raw["observations"][0]["assertions"].clear()
            copied = restored.to_dict()
            copied["observations"].clear()
            with self.subTest(module=module.__name__):
                self.assertEqual(restored.document_json, fixture.document_json)
                self.assertTrue(restored.to_dict()["observations"][0]["assertions"])

    def test_nonexecuting_flags_remain_exact_and_cannot_be_promoted(self):
        for module, fixture, _, observation_type, fixture_type in self.fixtures():
            for original, model, address in (
                (fixture.observations[0].to_dict(), observation_type, address_observation),
                (fixture.to_dict(), fixture_type, address_fixture),
            ):
                for field in ("runtime_execution_performed", "external_containment_proven"):
                    for value in (0, 0.0, True):
                        with self.subTest(module=module.__name__, field=field, value=value):
                            raw = copy.deepcopy(original)
                            raw[field] = value
                            with self.assertRaises(QualificationError):
                                model.from_dict(address(raw, module))

    def test_valid_fixtures_keep_exact_nonqualifying_effect_declarations(self):
        for module, fixture, _, _, fixture_type in self.fixtures():
            raw = fixture_type.from_dict(fixture.to_dict()).to_dict()
            with self.subTest(module=module.__name__):
                self.assertIs(raw["runtime_execution_performed"], False)
                self.assertIs(raw["external_containment_proven"], False)
                for record in (raw, raw["specification"], *raw["observations"]):
                    self.assertIs(type(record["schema_version"]), int)
                    for field in module.BOUNDARY_EFFECTS:
                        self.assertEqual(record[field], "none")
                if module is microvm:
                    self.assertIs(type(raw["output_bytes"]), int)
                    self.assertIs(type(raw["log_bytes"]), int)
                    self.assertEqual((raw["output_bytes"], raw["log_bytes"]), (0, 0))


if __name__ == "__main__":
    unittest.main()
