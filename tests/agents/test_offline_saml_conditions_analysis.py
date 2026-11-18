"""Synthetic source-bound SAML condition arithmetic controls."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_saml_conditions_analysis as saml

NS = "urn:oasis:names:tc:SAML:2.0:assertion"
AUDIENCE = "https://service.invalid/sp"
OTHER = "https://other.invalid/sp"


def xml(
    *,
    before: str | None = "2026-09-29T00:00:00Z",
    after: str | None = "2026-09-30T00:00:00Z",
    restrictions: tuple[tuple[str, ...], ...] = ((AUDIENCE,),),
    extra: str = "",
    conditions: bool = True,
) -> bytes:
    attributes = ""
    if before is not None:
        attributes += f' NotBefore="{before}"'
    if after is not None:
        attributes += f' NotOnOrAfter="{after}"'
    rows = "".join(
        "<s:AudienceRestriction>"
        + "".join(f"<s:Audience>{item}</s:Audience>" for item in group)
        + "</s:AudienceRestriction>"
        for group in restrictions
    )
    condition = f"<s:Conditions{attributes}>{rows}{extra}</s:Conditions>" if conditions else ""
    return (
        f'<s:Assertion xmlns:s="{NS}" Version="2.0" ID="_synthetic" '
        f'IssueInstant="2026-09-29T00:00:00Z">{condition}</s:Assertion>'
    ).encode("ascii")


def model(
    raw: bytes | None = None, *, now: str = "2026-09-29T12:00:00Z", audience: str = AUDIENCE
) -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-saml-conditions",
        "assertion_xml_base64": base64.b64encode(xml() if raw is None else raw).decode("ascii"),
        "evaluation_context": {"evaluated_at_utc": now, "audience": audience},
    }


def encoded(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


class SamlConditionsAnalysisTests(unittest.TestCase):
    def test_synthetic_fixture_and_literal_source_golden(self) -> None:
        source = saml.component_fixture()
        self.assertEqual(source, model())
        report = saml.analyze_supplied_saml_conditions(source)
        body = report.to_dict()
        self.assertEqual(body["analysis_status"], "supported_conditions_satisfied")
        self.assertEqual(body["time_result"], "within_window")
        self.assertEqual(
            body["audience_restrictions"], [{"audiences": [AUDIENCE], "result": "matched"}]
        )
        self.assertEqual(
            body["assertion_xml_sha256"], "sha256:" + hashlib.sha256(xml()).hexdigest()
        )
        self.assertEqual(
            body["assertion_xml_sha256"],
            "sha256:026aa766ed1e6ecdf6a39bc3044c3b1abccdd4a8ada57a64aafd761d61b03c43",
        )
        self.assertEqual(
            body["source_model_sha256"],
            "sha256:72bd48206c5e8f0595c0e2bad89dbd2e4066be96719935c298f92f65b39a089f",
        )
        self.assertEqual(body["analysis_id"], "SCA-DF6D58C0D7EAE4D0E83F2DD92252CA36")
        self.assertEqual(
            body["analysis_sha256"],
            "sha256:df6d58c0d7eae4d0e83f2dd92252ca36322bde49e690a7e3fdbcfcb49375cf8d",
        )
        self.assertEqual(body["analysis_id"], report.analysis_id)
        self.assertEqual(body["analysis_sha256"], report.analysis_sha256)
        self.assertEqual(body["flags"]["login_authorized"], False)
        self.assertEqual(body["effects"]["target"], "none")

    def test_all_eight_public_forms_and_detached_exports(self) -> None:
        source = model()
        report = saml.analyze_supplied_saml_conditions(source)
        original = report.to_json()
        self.assertEqual(
            saml.analyze_supplied_saml_conditions_bytes(model_bytes=encoded(source)).to_json(),
            original,
        )
        self.assertEqual(saml.SamlConditionsAnalysis(original).to_json(), original)
        self.assertEqual(
            saml.SamlConditionsAnalysis.from_dict(report.to_dict()).to_json(), original
        )
        self.assertEqual(saml.SamlConditionsAnalysis.from_json(original).to_json(), original)
        self.assertEqual(
            saml.verify_supplied_saml_conditions_analysis(report, model=source).to_json(), original
        )
        source["evaluation_context"]["audience"] = OTHER
        detached = report.to_dict()
        detached["flags"]["login_authorized"] = True
        self.assertFalse(report.to_dict()["flags"]["login_authorized"])
        self.assertEqual(report.to_json(), original)

    def test_independent_time_boundary_table(self) -> None:
        cases = [
            ("2026-09-28T23:59:59Z", "outside_window"),
            ("2026-09-29T00:00:00Z", "within_window"),
            ("2026-09-29T12:00:00Z", "within_window"),
            ("2026-09-30T00:00:00Z", "outside_window"),
            ("2026-09-30T00:00:01Z", "outside_window"),
        ]
        for now, expected in cases:
            with self.subTest(now=now):
                result = saml.analyze_supplied_saml_conditions(model(now=now)).to_dict()
                self.assertEqual(result["time_result"], expected)
                self.assertEqual(
                    result["analysis_status"],
                    "known_condition_false"
                    if expected == "outside_window"
                    else "supported_conditions_satisfied",
                )

    def test_fractional_and_missing_time_bounds(self) -> None:
        raw = xml(before="2026-09-29T00:00:00.125Z", after="2026-09-29T00:00:00.126Z")
        for now, expected in (
            ("2026-09-29T00:00:00.124Z", "outside_window"),
            ("2026-09-29T00:00:00.125Z", "within_window"),
            ("2026-09-29T00:00:00.126Z", "outside_window"),
        ):
            with self.subTest(now=now):
                self.assertEqual(
                    saml.analyze_supplied_saml_conditions(model(raw, now=now)).to_dict()[
                        "time_result"
                    ],
                    expected,
                )
        for before, after in (
            (None, None),
            (None, "2026-09-30T00:00:00Z"),
            ("2026-09-29T00:00:00Z", None),
        ):
            with self.subTest(before=before, after=after):
                self.assertEqual(
                    saml.analyze_supplied_saml_conditions(
                        model(xml(before=before, after=after))
                    ).to_dict()["time_result"],
                    "within_window",
                )

    def test_invalid_interval_and_unsupported_clock_source(self) -> None:
        for after in ("2026-09-29T00:00:00Z", "2026-09-28T00:00:00Z"):
            result = saml.analyze_supplied_saml_conditions(model(xml(after=after))).to_dict()
            self.assertEqual(result["time_result"], "invalid_interval")
            self.assertEqual(result["analysis_status"], "known_condition_false")
        result = saml.analyze_supplied_saml_conditions(
            model(xml(before="2026-09-29T00:00:00+00:00"))
        ).to_dict()
        self.assertEqual(result["time_result"], "indeterminate")
        self.assertEqual(result["analysis_status"], "indeterminate")
        expired_and_unknown = saml.analyze_supplied_saml_conditions(
            model(xml(before="2026-09-29T00:00:00+00:00", after="2026-09-29T01:00:00Z"))
        ).to_dict()
        self.assertEqual(expired_and_unknown["time_result"], "outside_window")
        self.assertEqual(expired_and_unknown["analysis_status"], "known_condition_false")
        with self.assertRaises(saml.SamlConditionsAnalysisError):
            saml.analyze_supplied_saml_conditions(model(now="2026-09-29T12:00:00+00:00"))

    def test_independent_audience_or_and_table(self) -> None:
        cases = [
            (((AUDIENCE, OTHER),), "matched", "supported_conditions_satisfied"),
            (((OTHER,),), "unmatched", "known_condition_false"),
            (((AUDIENCE,), (AUDIENCE, OTHER)), "matched", "supported_conditions_satisfied"),
            (((AUDIENCE,), (OTHER,)), "unmatched", "known_condition_false"),
            ((), None, "supported_conditions_satisfied"),
        ]
        for groups, last, expected in cases:
            with self.subTest(groups=groups):
                result = saml.analyze_supplied_saml_conditions(
                    model(xml(restrictions=groups))
                ).to_dict()
                self.assertEqual(result["analysis_status"], expected)
                if last is not None:
                    self.assertEqual(result["audience_restrictions"][-1]["result"], last)

    def test_cross_product_time_and_audience_oracle(self) -> None:
        instants = (
            "2026-09-29T00:00:00Z",
            "2026-09-29T12:00:00Z",
            "2026-09-30T00:00:00Z",
            "2026-09-30T12:00:00Z",
        )
        groups = (
            (),
            ((AUDIENCE,),),
            ((OTHER,),),
            ((AUDIENCE, OTHER), (AUDIENCE,)),
            ((AUDIENCE,), (OTHER,)),
        )
        cases = 0
        for before_index in (None, 0, 1):
            for after_index in (None, 2, 3):
                for now_index in range(4):
                    for restrictions in groups:
                        raw = xml(
                            before=None if before_index is None else instants[before_index],
                            after=None if after_index is None else instants[after_index],
                            restrictions=restrictions,
                        )
                        expected_time = (before_index is None or now_index >= before_index) and (
                            after_index is None or now_index < after_index
                        )
                        expected_audience = all(
                            AUDIENCE in alternatives for alternatives in restrictions
                        )
                        expected = (
                            "supported_conditions_satisfied"
                            if expected_time and expected_audience
                            else "known_condition_false"
                        )
                        with self.subTest(
                            before=before_index,
                            after=after_index,
                            now=now_index,
                            groups=restrictions,
                        ):
                            result = saml.analyze_supplied_saml_conditions(
                                model(raw, now=instants[now_index])
                            ).to_dict()
                            self.assertEqual(result["analysis_status"], expected)
                        cases += 1
        self.assertEqual(cases, 180)

    def test_unknown_condition_indeterminate_unless_known_false(self) -> None:
        extra = "<s:OneTimeUse/>"
        accepted = saml.analyze_supplied_saml_conditions(model(xml(extra=extra))).to_dict()
        self.assertEqual(accepted["analysis_status"], "indeterminate")
        self.assertEqual(accepted["unsupported_conditions"], 1)
        false = saml.analyze_supplied_saml_conditions(
            model(xml(extra=extra, restrictions=((OTHER,),)))
        ).to_dict()
        self.assertEqual(false["analysis_status"], "known_condition_false")
        self.assertEqual(false["unsupported_conditions"], 1)
        malformed_alternative = xml().replace(
            b"</s:AudienceRestriction>",
            b'<x:Unknown xmlns:x="urn:unknown"/></s:AudienceRestriction>',
        )
        inside = saml.analyze_supplied_saml_conditions(model(malformed_alternative)).to_dict()
        self.assertEqual(inside["audience_restrictions"][0]["result"], "indeterminate")
        self.assertEqual(inside["analysis_status"], "indeterminate")

    def test_unrecognized_namespace_does_not_masquerade_as_saml(self) -> None:
        foreign = xml().replace(NS.encode("ascii"), b"urn:foreign:assertion")
        with self.assertRaises(saml.SamlConditionsAnalysisError):
            saml.analyze_supplied_saml_conditions(model(foreign))
        unknown = xml(extra='<x:Condition xmlns:x="urn:foreign:extension"/>')
        self.assertEqual(
            saml.analyze_supplied_saml_conditions(model(unknown)).to_dict()["analysis_status"],
            "indeterminate",
        )

    def test_absent_and_duplicate_direct_conditions(self) -> None:
        result = saml.analyze_supplied_saml_conditions(model(xml(conditions=False))).to_dict()
        self.assertEqual(result["analysis_status"], "conditions_absent_unassessed")
        raw = xml().replace(b"</s:Assertion>", b"<s:Conditions/></s:Assertion>")
        with self.assertRaises(saml.SamlConditionsAnalysisError):
            saml.analyze_supplied_saml_conditions(model(raw))

    def test_dtd_entity_comment_and_malformed_xml_refused(self) -> None:
        samples = (
            b'<!DOCTYPE s:Assertion [<!ENTITY x "a">]>' + xml(),
            (
                '<?xml version="1.0" encoding="UTF-16LE"?>'
                '<!DOCTYPE s:Assertion [<!ENTITY x "a">]>' + xml().decode("ascii")
            ).encode("utf-16le"),
            b'<?xml version="1.0" encoding="ISO-8859-1"?>' + xml(),
            xml().replace(b"<s:Conditions", b"<!-- comment --><s:Conditions"),
            xml().replace(b"https://service.invalid/sp", b"&foreign;"),
            xml()[:-1],
        )
        for raw in samples:
            with self.subTest(raw=raw[:32]), self.assertRaises(saml.SamlConditionsAnalysisError):
                saml.analyze_supplied_saml_conditions(model(raw))

    def test_plain_utf8_declaration_is_source_bound(self) -> None:
        raw = b'<?xml version="1.0" encoding="UTF-8"?>' + xml()
        report = saml.analyze_supplied_saml_conditions(model(raw))
        self.assertEqual(report.to_dict()["analysis_status"], "supported_conditions_satisfied")
        self.assertEqual(
            report.to_dict()["assertion_xml_sha256"], "sha256:" + hashlib.sha256(raw).hexdigest()
        )

    def test_source_byte_and_context_substitutions_change_addresses(self) -> None:
        original = model()
        first = saml.analyze_supplied_saml_conditions(original)
        changed = copy.deepcopy(original)
        changed["assertion_xml_base64"] = base64.b64encode(
            xml().replace(b"<s:Conditions", b"\n<s:Conditions")
        ).decode("ascii")
        second = saml.analyze_supplied_saml_conditions(changed)
        self.assertNotEqual(first.analysis_id, second.analysis_id)
        self.assertNotEqual(
            first.to_dict()["assertion_xml_sha256"], second.to_dict()["assertion_xml_sha256"]
        )
        with self.assertRaises(saml.SamlConditionsAnalysisError):
            saml.verify_supplied_saml_conditions_analysis(first, model=changed)
        changed = copy.deepcopy(original)
        changed["evaluation_context"]["audience"] = OTHER
        with self.assertRaises(saml.SamlConditionsAnalysisError):
            saml.verify_supplied_saml_conditions_analysis(first, model=changed)

    def test_coherently_rehashed_false_report_is_not_replayed(self) -> None:
        report = saml.analyze_supplied_saml_conditions(model()).to_dict()
        report["analysis_status"] = "known_condition_false"
        body = {
            key: value
            for key, value in report.items()
            if key not in {"analysis_id", "analysis_sha256"}
        }
        digest = (
            "sha256:"
            + hashlib.sha256(
                (
                    saml.DOMAIN + "\n" + json.dumps(body, sort_keys=True, separators=(",", ":"))
                ).encode("ascii")
            ).hexdigest()
        )
        report["analysis_sha256"] = digest
        report["analysis_id"] = "SCA-" + digest[7:39].upper()
        with self.assertRaises(saml.SamlConditionsAnalysisError):
            saml.SamlConditionsAnalysis.from_dict(report)

    def test_exact_native_aliases_and_incomplete_wrappers_refused(self) -> None:
        class IntAlias(int):
            pass

        source = model()
        source["schema_version"] = True
        with self.assertRaises(saml.SamlConditionsAnalysisError):
            saml.analyze_supplied_saml_conditions(source)
        source["schema_version"] = IntAlias(1)
        with self.assertRaises(saml.SamlConditionsAnalysisError):
            saml.analyze_supplied_saml_conditions(source)
        source = model()
        source["evaluation_context"] = dict(source["evaluation_context"])
        source["evaluation_context"]["audience"] = [AUDIENCE]
        with self.assertRaises(saml.SamlConditionsAnalysisError):
            saml.analyze_supplied_saml_conditions(source)
        incomplete = object.__new__(saml.SamlConditionsAnalysis)
        with self.assertRaises(saml.SamlConditionsAnalysisError):
            incomplete.to_json()

    def test_raw_duplicate_key_float_and_integer_guard(self) -> None:
        source = model()
        raw = encoded(source)
        for bad in (
            raw.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1'),
            raw.replace(b'"schema_version":1', b'"schema_version":1.0'),
            raw.replace(b'"schema_version":1', b'"schema_version":--1'),
            raw.replace(b'"schema_version":1', b'"schema_version":9223372036854775808'),
        ):
            with self.subTest(bad=bad[:64]), self.assertRaises(saml.SamlConditionsAnalysisError):
                saml.analyze_supplied_saml_conditions_bytes(model_bytes=bad)

    def test_xml_and_audience_ceiling(self) -> None:
        source = model(b"X" * (saml.MAX_XML_BYTES + 1))
        with self.assertRaises(saml.SamlConditionsAnalysisError):
            saml.analyze_supplied_saml_conditions(source)
        many = xml(restrictions=tuple((AUDIENCE,) for _ in range(saml.MAX_AUDIENCES + 1)))
        with self.assertRaises(saml.SamlConditionsAnalysisError):
            saml.analyze_supplied_saml_conditions(model(many))

    def test_complete_public_cost_refusal_precedes_first_digest(self) -> None:
        source = model()
        report = saml.analyze_supplied_saml_conditions(source)
        forms = (
            lambda: saml.analyze_supplied_saml_conditions(source),
            lambda: saml.analyze_supplied_saml_conditions_bytes(model_bytes=encoded(source)),
            lambda: saml.SamlConditionsAnalysis(report.to_json()),
            lambda: saml.SamlConditionsAnalysis.from_dict(report.to_dict()),
            lambda: saml.SamlConditionsAnalysis.from_json(report.to_json()),
            report.to_dict,
            report.to_json,
            lambda: saml.verify_supplied_saml_conditions_analysis(report, model=source),
        )
        with (
            patch.object(saml, "MAX_WORK", 1),
            patch.object(saml.hashlib, "sha256", side_effect=AssertionError("digest reached")),
        ):
            for operation in forms:
                with (
                    self.subTest(operation=operation),
                    self.assertRaises(saml.SamlConditionsAnalysisError),
                ):
                    operation()

    def test_all_eight_actual_work_thresholds_precede_digest(self) -> None:
        source = model()
        report = saml.analyze_supplied_saml_conditions(source)
        text = report.to_json()
        document = report.to_dict()
        forms = (
            lambda: saml.analyze_supplied_saml_conditions(source),
            lambda: saml.analyze_supplied_saml_conditions_bytes(model_bytes=encoded(source)),
            lambda: saml.SamlConditionsAnalysis(text),
            lambda: saml.SamlConditionsAnalysis.from_dict(copy.deepcopy(document)),
            lambda: saml.SamlConditionsAnalysis.from_json(text),
            report.to_dict,
            report.to_json,
            lambda: saml.verify_supplied_saml_conditions_analysis(report, model=source),
        )
        original_charge = saml._Budget.charge
        for operation in forms:
            measured = [0]

            def observe(budget: saml._Budget, amount: int) -> None:
                original_charge(budget, amount)
                measured[0] = max(measured[0], budget.used)

            with self.subTest(operation=operation):
                with patch.object(saml._Budget, "charge", observe):
                    operation()
                self.assertGreater(measured[0], 1)
                with patch.object(saml, "MAX_WORK", measured[0]):
                    operation()
                with (
                    patch.object(saml, "MAX_WORK", measured[0] - 1),
                    patch.object(
                        saml.hashlib, "sha256", side_effect=AssertionError("digest reached")
                    ),
                    self.assertRaises(saml.SamlConditionsAnalysisError),
                ):
                    operation()


if __name__ == "__main__":
    unittest.main()
