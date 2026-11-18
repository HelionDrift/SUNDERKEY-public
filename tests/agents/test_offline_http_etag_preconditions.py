"""Finite independent predicate and replay checks for supplied HTTP ETags."""

from __future__ import annotations

import base64
import copy
import hashlib
import itertools
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_http_etag_preconditions as etag

ERROR = etag.HttpEtagPreconditionsError


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def tag(value=b"v1", *, weak=False):
    return {"weak": weak, "opaque_tag_base64": base64.b64encode(value).decode("ascii")}


def clause(*tags, any_representation=False):
    return {"mode": "any" if any_representation else "tags", "tags": list(tags)}


def model(**changes):
    return {**etag.component_fixture(), **changes}


def analyze(**changes):
    return etag.analyze_supplied_http_etag_preconditions(model(**changes)).to_dict()


def readdress(document):
    body = copy.deepcopy(document)
    body.pop("analysis_id")
    body.pop("analysis_sha256")
    digest = hashlib.sha256((etag.DOMAIN + "\n" + canonical(body)).encode("ascii")).hexdigest()
    return {
        **body,
        "analysis_id": "HEP-" + digest[:32].upper(),
        "analysis_sha256": "sha256:" + digest,
    }


class HttpEtagPreconditionsTests(unittest.TestCase):
    def before_hash(self, call):
        with patch.object(etag.hashlib, "sha256") as sha:
            with self.assertRaises(ERROR):
                call()
            sha.assert_not_called()

    def test_literal_public_fixture_and_conditional_observation(self):
        document = etag.analyze_supplied_http_etag_preconditions(model()).to_dict()
        self.assertEqual(document["analysis_id"], "HEP-7AB77A0513B521180797040AAB02728E")
        self.assertEqual(
            document["analysis_sha256"],
            "sha256:7ab77a0513b521180797040aab02728ea26dd0cb8e69db4030af83defde1db98",
        )
        self.assertEqual(
            document["source_model_sha256"],
            "sha256:ba2663beb9b4dd04eafd7a18ad5be9668a6f7a82ccbb5a344548d16f4776d975",
        )
        self.assertEqual(document["analysis_status"], "conditional_304_predicate")
        self.assertEqual(
            document["precondition_observations"],
            [{"field": "if_none_match", "comparison": "weak", "predicate_true": False}],
        )
        self.assertEqual(document["effects"], {name: "none" for name in document["effects"]})
        self.assertFalse(document["flags"]["positive_use_approved"])

    def test_full_eight_public_operations_retain_exact_original(self):
        source = model()
        original = copy.deepcopy(source)
        report = etag.analyze_supplied_http_etag_preconditions(source)
        text = report.to_json()
        document = report.to_dict()
        operations = (
            lambda: etag.HttpEtagPreconditionsAnalysis(text),
            lambda: etag.HttpEtagPreconditionsAnalysis.from_dict(document),
            lambda: etag.HttpEtagPreconditionsAnalysis.from_json(text),
            lambda: etag.analyze_supplied_http_etag_preconditions_bytes(
                model_bytes=canonical(source).encode("ascii")
            ),
            lambda: etag.verify_supplied_http_etag_preconditions_analysis(report, model=source),
        )
        for operation in operations:
            self.assertEqual(operation().to_json(), text)
        self.assertEqual(report.analysis_id, document["analysis_id"])
        self.assertEqual(report.analysis_sha256, document["analysis_sha256"])
        source["selected_entity_tag"]["opaque_tag_base64"] = "djI="
        document["precondition_observations"].clear()
        self.assertEqual(report.to_json(), text)
        self.assertEqual(original, report.to_dict()["source_model"])

    def test_strong_if_match_and_weak_if_none_match_differ(self):
        current = tag(b"v1", weak=True)
        candidate = tag(b"v1", weak=False)
        match = analyze(selected_entity_tag=current, if_match=clause(candidate), if_none_match=None)
        none = analyze(selected_entity_tag=current, if_match=None, if_none_match=clause(candidate))
        self.assertEqual(match["analysis_status"], "conditional_412_predicate")
        self.assertEqual(none["analysis_status"], "conditional_304_predicate")
        self.assertEqual(match["precondition_observations"][0]["comparison"], "strong")
        self.assertEqual(none["precondition_observations"][0]["comparison"], "weak")

    def test_tag_lists_use_any_comparison_and_byte_exactness(self):
        for weak_current, weak_candidate, expected in (
            (False, False, True),
            (False, True, False),
            (True, False, False),
            (True, True, False),
        ):
            row = analyze(
                selected_entity_tag=tag(b"v1", weak=weak_current),
                if_match=clause(tag(b"other"), tag(b"v1", weak=weak_candidate)),
                if_none_match=None,
            )
            self.assertIs(row["precondition_observations"][0]["predicate_true"], expected)
        other = analyze(if_none_match=clause(tag(b"V1")))
        self.assertEqual(other["analysis_status"], "preconditions_pass")

    def test_wildcard_uses_any_target_representation_not_selected_one(self):
        for selected_exists, target_any, match_expected, none_expected in (
            (False, False, False, True),
            (False, True, True, False),
            (True, True, True, False),
        ):
            selected = None
            match = analyze(
                selected_representation_exists=selected_exists,
                target_has_current_representation=target_any,
                selected_entity_tag=selected,
                if_match=clause(any_representation=True),
                if_none_match=None,
            )
            none = analyze(
                selected_representation_exists=selected_exists,
                target_has_current_representation=target_any,
                selected_entity_tag=selected,
                if_match=None,
                if_none_match=clause(any_representation=True),
            )
            self.assertIs(match["precondition_observations"][0]["predicate_true"], match_expected)
            self.assertIs(none["precondition_observations"][0]["predicate_true"], none_expected)

    def test_tag_list_still_compares_selected_when_another_representation_exists(self):
        row = analyze(
            target_has_current_representation=True,
            selected_representation_exists=False,
            selected_entity_tag=None,
            if_match=clause(tag(b"v1")),
            if_none_match=None,
        )
        self.assertEqual(row["analysis_status"], "conditional_412_predicate")
        self.assertEqual(row["precondition_observations"][0]["comparison"], "strong")

    def test_if_match_precedes_if_none_match_and_can_stop_evaluation(self):
        row = analyze(if_match=clause(tag(b"wrong")), if_none_match=clause(tag(b"v1")))
        self.assertEqual(row["analysis_status"], "conditional_412_predicate")
        self.assertEqual(len(row["precondition_observations"]), 1)
        self.assertEqual(row["precondition_observations"][0]["field"], "if_match")
        row = analyze(if_match=clause(tag(b"v1")), if_none_match=clause(tag(b"v1")))
        self.assertEqual(
            [r["field"] for r in row["precondition_observations"]], ["if_match", "if_none_match"]
        )
        self.assertEqual(row["analysis_status"], "conditional_304_predicate")

    def test_baseline_ineligible_suppresses_both_without_response_claim(self):
        row = analyze(
            baseline_preconditions_eligible=False,
            if_match=clause(tag(b"wrong")),
            if_none_match=clause(tag(b"v1")),
        )
        self.assertEqual(row["analysis_status"], "preconditions_not_evaluated")
        self.assertEqual(row["precondition_observations"], [])
        self.assertFalse(row["flags"]["actual_http_response_observed"])

    def test_method_specific_false_predicates_and_put_exception(self):
        for method in ("GET", "HEAD", "PUT"):
            match = analyze(method=method, if_match=clause(tag(b"wrong")), if_none_match=None)
            none = analyze(method=method, if_match=None, if_none_match=clause(tag(b"v1")))
            self.assertEqual(
                match["analysis_status"],
                "put_if_match_false_new_mutation_blocked_status_unassessed"
                if method == "PUT"
                else "conditional_412_predicate",
            )
            self.assertEqual(
                none["analysis_status"],
                "conditional_412_predicate" if method == "PUT" else "conditional_304_predicate",
            )
            self.assertFalse(match["flags"]["method_executed"])

    def test_independent_small_boolean_and_byte_oracle(self):
        count = 0
        for method, exists, selected_weak, candidate_weak, same, which in itertools.product(
            ("GET", "HEAD", "PUT"),
            (False, True),
            (False, True),
            (False, True),
            (False, True),
            ("match", "none"),
        ):
            current = tag(b"A", weak=selected_weak) if exists else None
            candidate = tag(b"A" if same else b"B", weak=candidate_weak)
            fields = {
                "method": method,
                "selected_representation_exists": exists,
                "selected_entity_tag": current,
                "if_match": clause(candidate) if which == "match" else None,
                "if_none_match": clause(candidate) if which == "none" else None,
            }
            row = analyze(**fields)
            if which == "match":
                expected = exists and same and not selected_weak and not candidate_weak
            else:
                expected = not (exists and same)
            self.assertIs(row["precondition_observations"][0]["predicate_true"], expected)
            count += 1
        self.assertEqual(count, 96)

    def test_empty_and_high_bit_opaque_bytes_are_permitted(self):
        for opaque in (b"", b"!", b"#", b"\x80\xff"):
            row = analyze(
                selected_entity_tag=tag(opaque), if_match=clause(tag(opaque)), if_none_match=None
            )
            self.assertEqual(row["analysis_status"], "preconditions_pass")

    def test_tag_grammar_and_canonical_base64_refuse_bad_bytes(self):
        for opaque in (b'"', b" ", b"\t", b"\x7f", b"\x00"):
            self.before_hash(lambda opaque=opaque: analyze(selected_entity_tag=tag(opaque)))
        for encoded in ("djE", "djE==", "!", "\u00e9"):
            source = model(selected_entity_tag={"weak": False, "opaque_tag_base64": encoded})
            self.before_hash(
                lambda source=source: etag.analyze_supplied_http_etag_preconditions(source)
            )

    def test_selected_absence_and_clause_forms_are_closed(self):
        bad = (
            model(selected_representation_exists=False),
            model(target_has_current_representation=False),
            model(if_match={"mode": "any", "tags": [tag()]}),
            model(if_match={"mode": "tags", "tags": []}),
            model(if_match={"mode": "tags", "tags": [tag()] * 17}),
            model(if_match={"mode": "many", "tags": [tag()]}),
            model(if_none_match={"mode": "any", "tags": [], "extra": 1}),
        )
        for source in bad:
            self.before_hash(
                lambda source=source: etag.analyze_supplied_http_etag_preconditions(source)
            )

    def test_exact_native_scalar_aliases_and_unknown_fields_fail_pre_hash(self):
        for field, replacement in (
            ("schema_version", True),
            ("schema_version", 1.0),
            ("source_id", b"source"),
            ("recipient_role", 1),
            ("baseline_preconditions_eligible", 1),
            ("method", "DELETE"),
            ("target_has_current_representation", 1),
            ("selected_representation_exists", 1),
            ("selected_entity_tag", {"weak": 0, "opaque_tag_base64": "djE="}),
        ):
            self.before_hash(
                lambda field=field, replacement=replacement: (
                    etag.analyze_supplied_http_etag_preconditions(model(**{field: replacement}))
                )
            )
        self.before_hash(
            lambda: etag.analyze_supplied_http_etag_preconditions({**model(), "extra": 1})
        )

    def test_cycles_subclasses_and_noncanonical_native_shape_fail(self):
        cyclic = model()
        cyclic["extra"] = cyclic

        class Number(int):
            pass

        class Bytes(bytes):
            pass

        self.before_hash(lambda: etag.analyze_supplied_http_etag_preconditions(cyclic))
        self.before_hash(
            lambda: etag.analyze_supplied_http_etag_preconditions(model(schema_version=Number(1)))
        )
        self.before_hash(
            lambda: etag.analyze_supplied_http_etag_preconditions_bytes(
                model_bytes=Bytes(canonical(model()).encode("ascii"))
            )
        )

    def test_raw_duplicate_keys_float_alias_and_malformed_numeric_are_predecoder(self):
        raw = canonical(model())
        for text in (
            raw.replace('"schema_version":1', '"schema_version":1,"schema_version":1', 1),
            raw.replace('"schema_version":1', '"schema_version":1.0', 1),
            raw.replace('"schema_version":1', '"schema_version":--1', 1),
            raw.replace('"schema_version":1', '"schema_version":9223372036854775808', 1),
        ):
            self.before_hash(
                lambda text=text: etag.analyze_supplied_http_etag_preconditions_bytes(
                    model_bytes=text.encode("ascii")
                )
            )

    def test_raw_predecoder_limits_before_parser(self):
        with patch.object(etag.json, "loads") as decoder:
            self.before_hash(
                lambda: etag.analyze_supplied_http_etag_preconditions_bytes(
                    model_bytes=b"[" * 13 + b"]" * 13
                )
            )
            self.before_hash(
                lambda: etag.analyze_supplied_http_etag_preconditions_bytes(
                    model_bytes=b'"' + b"a" * 1025 + b'"'
                )
            )
            decoder.assert_not_called()

    def test_full_report_replay_denies_semantic_cohash_and_promotion(self):
        original = etag.analyze_supplied_http_etag_preconditions(model()).to_dict()
        for field, replacement in (
            ("analysis_status", "preconditions_pass"),
            ("precondition_observations", []),
            ("effects", {**original["effects"], "execution": "allow"}),
            ("flags", {**original["flags"], "positive_use_approved": True}),
            ("component_id", "other"),
        ):
            altered = copy.deepcopy(original)
            altered[field] = replacement
            altered = readdress(altered)
            self.before_hash(
                lambda altered=altered: etag.HttpEtagPreconditionsAnalysis.from_dict(altered)
            )

    def test_separate_original_rejects_coherent_source_substitution(self):
        source = model()
        report = etag.analyze_supplied_http_etag_preconditions(source)
        changed = model(if_none_match=clause(tag(b"v2")))
        other = etag.analyze_supplied_http_etag_preconditions(changed)
        self.assertNotEqual(report.analysis_id, other.analysis_id)
        self.assertEqual(
            etag.HttpEtagPreconditionsAnalysis.from_json(other.to_json()).to_json(), other.to_json()
        )
        with self.assertRaises(ERROR):
            etag.verify_supplied_http_etag_preconditions_analysis(other, model=source)

    def test_invalid_retained_text_and_late_wrapper_mutation_are_denied(self):
        report = etag.analyze_supplied_http_etag_preconditions(model())
        forged = object.__new__(etag.HttpEtagPreconditionsAnalysis)
        object.__setattr__(
            forged,
            "document_json",
            report.to_json().replace("conditional_304_predicate", "preconditions_pass"),
        )
        self.before_hash(forged.to_dict)
        self.before_hash(
            lambda: etag.verify_supplied_http_etag_preconditions_analysis(forged, model=model())
        )

    def test_all_eight_public_operation_work_thresholds_precede_digest(self):
        source = model()
        report = etag.analyze_supplied_http_etag_preconditions(source)
        text = report.to_json()
        document = report.to_dict()
        cases = (
            lambda: etag.analyze_supplied_http_etag_preconditions(source),
            lambda: etag.analyze_supplied_http_etag_preconditions_bytes(
                model_bytes=canonical(source).encode("ascii")
            ),
            lambda: etag.HttpEtagPreconditionsAnalysis(text),
            lambda: etag.HttpEtagPreconditionsAnalysis.from_dict(document),
            lambda: etag.HttpEtagPreconditionsAnalysis.from_json(text),
            report.to_dict,
            report.to_json,
            lambda: etag.verify_supplied_http_etag_preconditions_analysis(report, model=source),
        )
        for operation in cases:
            totals = []
            original_charge = etag._Budget.charge

            def observe(budget, amount):
                original_charge(budget, amount)
                totals.append(budget.used)

            with patch.object(etag._Budget, "charge", observe):
                operation()
            exact = max(totals)
            with patch.object(etag, "MAX_WORK", exact - 1):
                self.before_hash(operation)
            with patch.object(etag, "MAX_WORK", exact):
                self.assertIsNotNone(operation())

    def test_actual_tag_and_document_ceiling_before_hash(self):
        self.before_hash(lambda: analyze(selected_entity_tag=tag(b"a" * 513)))
        oversized = model(source_id="a" * 100)
        oversized["if_match"] = clause(*[tag(b"x" * 512) for _ in range(16)])
        with patch.object(etag, "MAX_REPORT_BYTES", 800):
            self.before_hash(lambda: etag.analyze_supplied_http_etag_preconditions(oversized))

    def test_immutable_metadata_and_declared_scope(self):
        report = etag.analyze_supplied_http_etag_preconditions(model()).to_dict()
        self.assertEqual(report["profile_id"], "AOE-GB-D05-S01")
        self.assertEqual(report["work_package_id"], "IWP2-AOE-GB-D05-S01")
        self.assertEqual(report["wave_id"], "IW2-001")
        self.assertEqual(report["group_owner_id"], "AOE-HQ-04")
        self.assertEqual(report["independent_validator_id"], "AOE-HQ-34")
        self.assertEqual(report["roadmap_package_ids"], ["A7.4"])
        self.assertFalse(report["flags"]["origin_state_authenticated"])


if __name__ == "__main__":
    unittest.main()
