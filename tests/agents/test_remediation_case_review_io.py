"""Offline archives and CLI results stay bounded, exact, and nonauthoritative."""

from __future__ import annotations

import argparse
import contextlib
import copy
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

try:
    from jsonschema import Draft202012Validator, ValidationError
    from referencing import Registry, Resource
except ImportError:
    Draft202012Validator = None

from sunderkey.cli import _validate_write_path_collisions, build_parser, main
from sunderkey.errors import SunderkeyError
from sunderkey.remediation_case_review_io import (
    MAX_JSON_DEPTH,
    MAX_JSON_NODES,
    MAX_REVIEW_BYTES,
    MAX_SOURCE_BYTES,
    RemediationCaseInputError,
    _file_stamp,
    build_remediation_case_review_from_request,
    load_remediation_case_request,
    load_remediation_case_review,
    serialize_remediation_case_review,
    verify_remediation_case_review_from_request,
)
from sunderkey.remediation_validation_contracts import RemediationValidationError, canonical_json
from tests.agents.test_remediation_validation_contracts_phase168 import (
    _context,
    _decide,
    _exception,
    _observation,
    _plan,
    _retest,
)
from tests.agents.test_remediation_workflow_visibility import observation, target


def request():
    context = _context()
    plan = _plan(context)
    retest = _retest(plan)
    observed = _observation(plan, retest)
    closure = _decide(plan, retest, observed)
    return {
        "schema_version": 1,
        "context": context.to_dict(),
        "plan": plan.to_dict(),
        "as_of": "2026-09-20T12:40:00Z",
        "targets": [target(item).to_dict() for item in plan.items],
        "delivery_observations": [observation(item).to_dict() for item in plan.items],
        "retest": retest.to_dict(),
        "retest_observation": observed.to_dict(),
        "closure": closure.to_dict(),
        "exception": None,
        "max_delivery_observation_age_seconds": 86_400,
    }


class RemediationCaseReviewIoTests(unittest.TestCase):
    @unittest.skipIf(Draft202012Validator is None, "jsonschema is unavailable")
    def test_closed_archive_schema_uses_only_registered_local_contract_sources(self) -> None:
        root = Path(__file__).resolve().parents[2] / "registry" / "schemas"
        schema = json.loads((root / "remediation-case-request-v1.schema.json").read_text("utf-8"))
        contracts = json.loads(
            (root / "remediation-validation-contract-v1.schema.json").read_text("utf-8")
        )
        Draft202012Validator.check_schema(schema)
        registry = Registry().with_resource(contracts["$id"], Resource.from_contents(contracts))
        validator = Draft202012Validator(schema, registry=registry)
        raw = request()
        validator.validate(raw)
        planning = copy.deepcopy(raw)
        for name in ("retest", "retest_observation", "closure"):
            planning[name] = None
        validator.validate(planning)
        for changes in ({"schema_version": True}, {"execute": True}, {"context": raw["plan"]}):
            with self.assertRaises(ValidationError):
                validator.validate({**raw, **changes})
        changed = copy.deepcopy(raw)
        changed["targets"][0]["target_sha256"] = ""
        with self.assertRaises(ValidationError):
            validator.validate(changed)
        del changed["targets"][0]["target_sha256"]
        with self.assertRaises(ValidationError):
            validator.validate(changed)

    def test_exact_archives_round_trip_without_mutating_inputs(self) -> None:
        raw = request()
        before = copy.deepcopy(raw)
        review = build_remediation_case_review_from_request(raw)
        verify_remediation_case_review_from_request(raw, review)
        self.assertEqual(raw, before)
        self.assertEqual(review["historical_closure_disposition"], "closed_nonqualified")
        self.assertTrue(all(value is False for value in review["claims"].values()))
        self.assertTrue(all(value == "none" for value in review["effects"].values()))

    def test_explicit_null_stages_and_exception_metadata_are_supported(self) -> None:
        raw = request()
        for name in ("retest", "retest_observation", "closure"):
            raw[name] = None
        raw["exception"] = _exception(_plan()).to_dict()
        review = build_remediation_case_review_from_request(raw)
        self.assertEqual(review["review_stage"], "planning_only")
        self.assertIs(review["exception_summary"]["used_by_historical_closure"], False)

    def test_unknown_missing_and_wrongly_typed_request_fields_fail_closed(self) -> None:
        for changes in (
            {"schema_version": True},
            {"schema_version": 1.0},
            {"schema_version": 2},
            {"execute": True},
            {"targets": {}},
            {"delivery_observations": "[]"},
        ):
            raw = request()
            raw.update(changes)
            with self.subTest(changes=changes):
                with self.assertRaises(RemediationCaseInputError):
                    build_remediation_case_review_from_request(raw)
        raw = request()
        del raw["exception"]
        with self.assertRaises(RemediationCaseInputError):
            build_remediation_case_review_from_request(raw)

    def test_contract_digest_omission_and_type_inflation_fail_closed(self) -> None:
        for section, field, value in (
            ("context", "context_sha256", ""),
            ("plan", "plan_sha256", ""),
            ("retest", "schema_version", True),
            ("closure", "schema_version", 1.0),
        ):
            raw = request()
            raw[section][field] = value
            with self.subTest(section=section):
                with self.assertRaises(RemediationCaseInputError):
                    build_remediation_case_review_from_request(raw)
        for section, field in (
            ("targets", "target_sha256"),
            ("delivery_observations", "observation_sha256"),
        ):
            raw = request()
            raw[section][0][field] = ""
            with self.assertRaises(RemediationCaseInputError):
                build_remediation_case_review_from_request(raw)

    def test_nested_unknown_fields_are_not_silently_dropped(self) -> None:
        for section in ("context", "plan", "retest", "retest_observation", "closure"):
            raw = request()
            raw[section]["execute"] = True
            with self.assertRaises(RemediationCaseInputError):
                build_remediation_case_review_from_request(raw)
        for section in ("targets", "delivery_observations"):
            raw = request()
            raw[section][0]["url"] = "https://tickets.example/item"
            with self.assertRaises(RemediationCaseInputError):
                build_remediation_case_review_from_request(raw)

    def test_source_substitution_is_rejected_after_successful_shape_parse(self) -> None:
        raw = request()
        raw["context"] = _context(tenant_ref="tenantref:other").to_dict()
        with self.assertRaises(RemediationValidationError):
            build_remediation_case_review_from_request(raw)

    def test_collection_byte_depth_and_node_limits_are_enforced(self) -> None:
        raw = request()
        raw["targets"] = raw["targets"] * 1_025
        with self.assertRaisesRegex(RemediationCaseInputError, "bounded list"):
            build_remediation_case_review_from_request(raw)
        raw = request()
        raw["delivery_observations"] = raw["delivery_observations"] * 2_049
        with self.assertRaises(RemediationCaseInputError):
            build_remediation_case_review_from_request(raw)
        nested = None
        for _ in range(MAX_JSON_DEPTH + 1):
            nested = [nested]
        with self.assertRaisesRegex(RemediationCaseInputError, "structural"):
            build_remediation_case_review_from_request(nested)
        raw = request()
        with patch("sunderkey.remediation_case_review_io.MAX_JSON_NODES", 10):
            with self.assertRaisesRegex(RemediationCaseInputError, "structural"):
                build_remediation_case_review_from_request(raw)
        with patch("sunderkey.remediation_case_review_io.MAX_SOURCE_BYTES", 100):
            with self.assertRaisesRegex(RemediationCaseInputError, "byte"):
                build_remediation_case_review_from_request(raw)
        with patch("sunderkey.remediation_case_review_io.MAX_REVIEW_BYTES", 100):
            with self.assertRaisesRegex(RemediationCaseInputError, "byte"):
                build_remediation_case_review_from_request(raw)
        self.assertEqual(MAX_JSON_NODES, 200_000)

    def test_nonfinite_values_and_non_json_collections_are_rejected(self) -> None:
        for value in (float("nan"), float("inf"), 1.0, {1: "invalid"}, ("tuple",)):
            raw = request()
            raw["as_of"] = value
            with self.assertRaises(RemediationCaseInputError):
                build_remediation_case_review_from_request(raw)

    def test_saved_view_requires_complete_source_replay_not_just_a_digest(self) -> None:
        raw = request()
        review = build_remediation_case_review_from_request(raw)
        changed = copy.deepcopy(review)
        changed["claims"]["remediation_verified"] = 0
        with self.assertRaises(RemediationValidationError):
            verify_remediation_case_review_from_request(raw, changed)
        raw["closure"] = None
        with self.assertRaises(RemediationValidationError):
            verify_remediation_case_review_from_request(raw, review)

    def test_regular_local_json_files_are_read_without_being_modified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source.json"
            raw = request()
            source.write_text(json.dumps(raw), encoding="utf-8")
            before = source.read_bytes()
            loaded = load_remediation_case_request(source)
            self.assertEqual(loaded, raw)
            self.assertEqual(source.read_bytes(), before)
            saved = Path(temporary) / "review.json"
            review = build_remediation_case_review_from_request(loaded)
            saved.write_text(json.dumps(review), encoding="utf-8")
            self.assertEqual(load_remediation_case_review(saved), review)

    def test_duplicate_keys_utf8_errors_and_malformed_json_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source.json"
            for content in (
                b'{"schema_version":1,"schema_version":1}',
                b'{"nested":{"duplicate":1,"duplicate":1}}',
                b"\xff",
                b"{",
                b'{"value":NaN}',
                b"[" * 1_100,
            ):
                source.write_bytes(content)
                with self.subTest(content=content[:20]):
                    with self.assertRaises(RemediationCaseInputError):
                        load_remediation_case_request(source)

    def test_oversized_file_is_rejected_before_opening_a_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source.json"
            source.write_bytes(b" " * 101)
            with patch("sunderkey.remediation_case_review_io.MAX_SOURCE_BYTES", 100):
                with patch("sunderkey.remediation_case_review_io.os.open") as opened:
                    with self.assertRaisesRegex(RemediationCaseInputError, "byte"):
                        load_remediation_case_request(source)
                    opened.assert_not_called()
        self.assertEqual(MAX_SOURCE_BYTES, 8_000_000)
        self.assertEqual(MAX_REVIEW_BYTES, 4_000_000)

    def test_missing_directory_and_linked_inputs_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for source in (root, root / "missing.json"):
                with self.assertRaises(RemediationCaseInputError):
                    load_remediation_case_request(source)
            source = root / "source.json"
            source.write_text("{}", encoding="utf-8")
            link = root / "linked.json"
            try:
                link.symlink_to(source)
            except OSError:
                with patch("sunderkey.remediation_case_review_io._linked", return_value=True):
                    with self.assertRaisesRegex(RemediationCaseInputError, "links"):
                        load_remediation_case_request(source)
            else:
                with self.assertRaisesRegex(RemediationCaseInputError, "non-linked"):
                    load_remediation_case_request(link)

    def test_open_descriptor_identity_and_read_time_changes_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source.json"
            source.write_text("{}", encoding="utf-8")
            real_fstat = os.fstat
            for mismatch_call in (1, 2):
                calls = 0

                def substituted(descriptor):
                    nonlocal calls
                    calls += 1
                    metadata = real_fstat(descriptor)
                    return SimpleNamespace(
                        st_mode=metadata.st_mode,
                        st_dev=metadata.st_dev,
                        st_ino=metadata.st_ino,
                        st_size=metadata.st_size,
                        st_mtime_ns=metadata.st_mtime_ns + (1 if calls == mismatch_call else 0),
                        st_ctime_ns=metadata.st_ctime_ns,
                        st_birthtime_ns=getattr(metadata, "st_birthtime_ns", metadata.st_ctime_ns),
                    )

                with patch(
                    "sunderkey.remediation_case_review_io.os.fstat", side_effect=substituted
                ):
                    with self.assertRaisesRegex(RemediationCaseInputError, "changed"):
                        load_remediation_case_request(source)

    def test_platform_timestamp_choice_preserves_stable_windows_identity(self) -> None:
        values = {
            "st_dev": 1,
            "st_ino": 2,
            "st_size": 3,
            "st_mtime_ns": 4,
            "st_ctime_ns": 5,
            "st_birthtime_ns": 6,
        }
        first = SimpleNamespace(**values)
        changed_ctime = SimpleNamespace(**{**values, "st_ctime_ns": 7})
        with patch("sunderkey.remediation_case_review_io.os.name", "nt"):
            self.assertEqual(_file_stamp(first), _file_stamp(changed_ctime))
            changed_birthtime = SimpleNamespace(**{**values, "st_birthtime_ns": 8})
            self.assertNotEqual(_file_stamp(first), _file_stamp(changed_birthtime))
        with patch("sunderkey.remediation_case_review_io.os.name", "posix"):
            self.assertNotEqual(_file_stamp(first), _file_stamp(changed_ctime))

    def test_network_style_paths_are_rejected_without_filesystem_access(self) -> None:
        for filename in (r"\\example.invalid\share\source.json", "//example.invalid/source.json"):
            with patch("sunderkey.remediation_case_review_io.os.open") as opened:
                with patch.object(Path, "lstat") as metadata:
                    with self.assertRaisesRegex(RemediationCaseInputError, "local"):
                        load_remediation_case_request(filename)
                    metadata.assert_not_called()
                    opened.assert_not_called()

    def test_linked_ancestor_is_rejected_before_descendant_metadata_access(self) -> None:
        linked_parent = Path.cwd() / "asserted-linked-parent"
        source = linked_parent / "nested" / "source.json"
        original = Path.lstat

        def guarded(path):
            if path == linked_parent:
                return SimpleNamespace(st_mode=stat.S_IFLNK)
            if linked_parent in path.parents:
                raise AssertionError("descendant metadata was inspected before its ancestor")
            return original(path)

        with patch.object(Path, "lstat", guarded):
            with self.assertRaisesRegex(RemediationCaseInputError, "parents"):
                load_remediation_case_request(source)

    def test_public_cli_entry_point_translates_validation_without_partial_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source.json"
            source.write_text(json.dumps(request()), encoding="utf-8")
            arguments = ["sunderkey", "remediation-case-review", "--input", str(source)]
            stdout = io.StringIO()
            with patch.object(sys, "argv", arguments), contextlib.redirect_stdout(stdout):
                main()
            self.assertEqual(json.loads(stdout.getvalue())["case_status"], "review_required")
            source.write_text("{}", encoding="utf-8")
            stdout = io.StringIO()
            with patch.object(sys, "argv", arguments), contextlib.redirect_stdout(stdout):
                with self.assertRaisesRegex(SystemExit, "Validation error"):
                    main()
            self.assertEqual(stdout.getvalue(), "")

    def test_cli_build_and_verify_print_advisory_output_only(self) -> None:
        parser = build_parser()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.json"
            raw = request()
            source.write_text(json.dumps(raw), encoding="utf-8")
            before = source.read_bytes()
            args = parser.parse_args(["remediation-case-review", "--input", str(source)])
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                args.handler(args)
            review = json.loads(stdout.getvalue())
            self.assertEqual(source.read_bytes(), before)
            self.assertEqual(set(root.iterdir()), {source})
            saved = root / "review.json"
            saved.write_text(json.dumps(review), encoding="utf-8")
            args = parser.parse_args(
                ["remediation-case-review-verify", "--input", str(source), "--review", str(saved)]
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                args.handler(args)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["status"], "valid")
            self.assertEqual(result["case_status"], "review_required")
            self.assertEqual(result["verification_kind"], "offline_source_replay")
            self.assertTrue(all(value == "none" for value in result["effects"].values()))

    def test_cli_failure_prints_no_partial_review(self) -> None:
        parser = build_parser()
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "invalid.json"
            source.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            args = parser.parse_args(["remediation-case-review", "--input", str(source)])
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                with self.assertRaises(SunderkeyError):
                    args.handler(args)
            self.assertEqual(stdout.getvalue(), "")

    def test_printed_archive_including_newline_fits_its_reader_cap(self) -> None:
        raw = request()
        review = build_remediation_case_review_from_request(raw)
        limit = len(canonical_json(review).encode("ascii")) + 1
        args = build_parser().parse_args(["remediation-case-review", "--input", "source.json"])
        stdout = io.StringIO()
        with patch("sunderkey.cli.load_remediation_case_request", return_value=raw):
            with patch("sunderkey.remediation_case_review_io.MAX_REVIEW_BYTES", limit):
                with contextlib.redirect_stdout(stdout):
                    args.handler(args)
                self.assertEqual(len(stdout.getvalue().encode("ascii")), limit)
                with tempfile.TemporaryDirectory() as temporary:
                    source = Path(temporary) / "review.json"
                    source.write_bytes(stdout.getvalue().encode("ascii"))
                    self.assertEqual(load_remediation_case_review(source), review)
        verify_remediation_case_review_from_request(raw, json.loads(stdout.getvalue()))

    def test_newline_budget_failure_does_not_print_partial_output(self) -> None:
        raw = request()
        review = build_remediation_case_review_from_request(raw)
        limit = len(canonical_json(review).encode("ascii"))
        args = build_parser().parse_args(["remediation-case-review", "--input", "source.json"])
        stdout = io.StringIO()
        with patch("sunderkey.cli.load_remediation_case_request", return_value=raw):
            with patch("sunderkey.remediation_case_review_io.MAX_REVIEW_BYTES", limit):
                with contextlib.redirect_stdout(stdout):
                    with self.assertRaisesRegex(SunderkeyError, "byte"):
                        args.handler(args)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(serialize_remediation_case_review(review), canonical_json(review) + "\n")

    def test_public_verification_preserves_guarded_path_loading(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.json"
            saved = root / "review.json"
            raw = request()
            source.write_text(json.dumps(raw), encoding="utf-8")
            saved.write_text(
                serialize_remediation_case_review(build_remediation_case_review_from_request(raw)),
                encoding="utf-8",
            )
            arguments = [
                "sunderkey",
                "remediation-case-review-verify",
                "--input",
                str(source),
                "--review",
                str(saved),
            ]
            stdout = io.StringIO()
            with patch.object(Path, "resolve", side_effect=AssertionError("premature resolution")):
                with patch.object(sys, "argv", arguments), contextlib.redirect_stdout(stdout):
                    main()
            self.assertEqual(json.loads(stdout.getvalue())["status"], "valid")

    def test_collision_guard_skips_only_absent_outputs_and_preserves_write_checks(self) -> None:
        with patch.object(Path, "resolve", side_effect=AssertionError("premature resolution")):
            _validate_write_path_collisions(argparse.Namespace(review="readonly.json"))
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "review.json"
            source.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(SunderkeyError, "must not replace"):
                _validate_write_path_collisions(
                    argparse.Namespace(output=str(source), review=str(source))
                )


if __name__ == "__main__":
    unittest.main()
