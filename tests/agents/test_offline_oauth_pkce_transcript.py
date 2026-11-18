"""Finite public controls for digest-only OAuth code/PKCE transcript arithmetic."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from dataclasses import FrozenInstanceError
from unittest import mock

from sunderkey import offline_oauth_pkce_transcript as oauth

EXPECTED_ID = "OAT-CBC7D63DEF61A9F46A1CFFE3AA326EB5"
EXPECTED_SHA256 = "sha256:cbc7d63def61a9f46a1cffe3aa326eb5f06f57adc75755382fb6515a24a61e96"
EXPECTED_SOURCE_SHA256 = "sha256:4fa60356bd42d030e8373fb2b5a7c566a3d494d4f3d2c6e4d83fdf39bdba47d9"


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(domain: str, value: dict) -> str:
    return (
        "sha256:" + hashlib.sha256((domain + "\n" + canonical(value)).encode("ascii")).hexdigest()
    )


def fixture() -> dict:
    return oauth.component_fixture()


def status_map(report: oauth.OAuthPkceTranscriptAnalysis) -> dict[str, str]:
    return {row["check_id"]: row["status"] for row in report.to_dict()["checks"]}


class OAuthPkceTranscriptTests(unittest.TestCase):
    def test_literal_golden_and_six_exact_matched_bindings(self) -> None:
        model = fixture()
        report = oauth.analyze_supplied_oauth_pkce_transcript(model)
        document = report.to_dict()
        self.assertEqual(report.analysis_id, EXPECTED_ID)
        self.assertEqual(report.analysis_sha256, EXPECTED_SHA256)
        self.assertEqual(document["source_model_sha256"], EXPECTED_SOURCE_SHA256)
        self.assertEqual(document["analysis_status"], "consistent_with_supplied_bindings")
        self.assertEqual(set(status_map(report).values()), {"matched"})
        self.assertEqual(len(document["checks"]), 6)
        self.assertEqual(document["source_model"], model)
        self.assertEqual(document["effects"]["provider_requests"], "none")
        self.assertFalse(document["flags"]["token_validated"])
        self.assertFalse(document["flags"]["login_authorized"])

    def test_bytes_and_native_input_have_one_content_address(self) -> None:
        model = fixture()
        first = oauth.analyze_supplied_oauth_pkce_transcript(model)
        second = oauth.analyze_supplied_oauth_pkce_transcript_bytes(
            model_bytes=json.dumps(model, indent=2).encode("ascii")
        )
        self.assertEqual(first.to_json(), second.to_json())
        self.assertEqual(
            oauth.verify_supplied_oauth_pkce_transcript(first, model=model).to_json(),
            first.to_json(),
        )

    def test_stage_sources_are_exact_and_distinct(self) -> None:
        model = fixture()
        report = oauth.analyze_supplied_oauth_pkce_transcript(model).to_dict()
        self.assertEqual(
            [row["source_ids"] for row in report["checks"]],
            [
                ["synthetic-authorization-request", "synthetic-token-request"],
                ["synthetic-authorization-response", "synthetic-token-request"],
                ["synthetic-authorization-request", "synthetic-authorization-response"],
                ["synthetic-authorization-request", "synthetic-authorization-response"],
                ["synthetic-authorization-request", "synthetic-token-request"],
                ["synthetic-authorization-request", "synthetic-token-request"],
            ],
        )
        model["token_request"]["source_id"] = model["authorization_request"]["source_id"]
        with self.assertRaises(oauth.OAuthPkceTranscriptError):
            oauth.analyze_supplied_oauth_pkce_transcript(model)

    def test_each_known_digest_or_client_mismatch_is_a_contradiction(self) -> None:
        cases = (
            ("token_request", "client_id", "different-client", "client_id_binding"),
            ("token_request", "code_sha256", "sha256:" + "4" * 64, "authorization_code_binding"),
            ("authorization_response", "state_sha256", "sha256:" + "4" * 64, "state_binding"),
            (
                "authorization_response",
                "callback_redirect_uri_sha256",
                "sha256:" + "4" * 64,
                "callback_redirect_binding",
            ),
            (
                "token_request",
                "redirect_uri_sha256",
                "sha256:" + "4" * 64,
                "token_redirect_binding",
            ),
            (
                "token_request",
                "code_verifier_sha256",
                "sha256:" + "4" * 64,
                "pkce_s256_digest_binding",
            ),
        )
        for stage, name, value, check_id in cases:
            with self.subTest(check_id=check_id):
                model = fixture()
                model[stage][name] = value
                report = oauth.analyze_supplied_oauth_pkce_transcript(model)
                self.assertEqual(report.to_dict()["analysis_status"], "contradicted")
                self.assertEqual(status_map(report)[check_id], "contradicted")

    def test_s256_challenge_uses_declared_digest_bytes_not_hex_text(self) -> None:
        model = fixture()
        verifier_digest = bytes.fromhex("17" * 32)
        model["token_request"]["code_verifier_sha256"] = "sha256:" + verifier_digest.hex()
        model["authorization_request"]["code_challenge"] = (
            base64.urlsafe_b64encode(verifier_digest).rstrip(b"=").decode("ascii")
        )
        self.assertEqual(
            status_map(oauth.analyze_supplied_oauth_pkce_transcript(model))[
                "pkce_s256_digest_binding"
            ],
            "matched",
        )
        model["authorization_request"]["code_challenge"] = "A" * 43
        self.assertEqual(
            status_map(oauth.analyze_supplied_oauth_pkce_transcript(model))[
                "pkce_s256_digest_binding"
            ],
            "contradicted",
        )

    def test_incomplete_missing_evidence_is_unknown(self) -> None:
        for stage, name, check_id in (
            ("token_request", "client_id", "client_id_binding"),
            ("token_request", "code_sha256", "authorization_code_binding"),
            ("authorization_response", "state_sha256", "state_binding"),
            (
                "authorization_response",
                "callback_redirect_uri_sha256",
                "callback_redirect_binding",
            ),
            ("token_request", "redirect_uri_sha256", "token_redirect_binding"),
            ("token_request", "code_verifier_sha256", "pkce_s256_digest_binding"),
        ):
            with self.subTest(check_id=check_id):
                model = fixture()
                model[stage]["complete"] = False
                model[stage][name] = None
                report = oauth.analyze_supplied_oauth_pkce_transcript(model)
                self.assertEqual(report.to_dict()["analysis_status"], "unknown")
                self.assertEqual(status_map(report)[check_id], "unknown")

    def test_declared_complete_missing_required_binding_contradicts_only_supplied_flow(
        self,
    ) -> None:
        for stage, name, check_id in (
            ("token_request", "client_id", "client_id_binding"),
            ("authorization_response", "code_sha256", "authorization_code_binding"),
            ("token_request", "code_verifier_sha256", "pkce_s256_digest_binding"),
            ("authorization_response", "state_sha256", "state_binding"),
        ):
            with self.subTest(check_id=check_id):
                model = fixture()
                model[stage][name] = None
                report = oauth.analyze_supplied_oauth_pkce_transcript(model)
                self.assertEqual(status_map(report)[check_id], "contradicted")

    def test_unrequested_state_and_redirect_are_not_invented(self) -> None:
        model = fixture()
        model["authorization_request"]["state_sha256"] = None
        model["authorization_request"]["redirect_uri_sha256"] = None
        report = oauth.analyze_supplied_oauth_pkce_transcript(model)
        statuses = status_map(report)
        self.assertEqual(statuses["state_binding"], "unknown")
        self.assertEqual(statuses["callback_redirect_binding"], "unknown")
        self.assertEqual(statuses["token_redirect_binding"], "unknown")
        self.assertEqual(report.to_dict()["analysis_status"], "unknown")

    def test_full_callback_url_is_not_a_normalized_redirect_target(self) -> None:
        model = fixture()
        model["authorization_response"]["callback_redirect_target_declared"] = False
        # Even a matching digest cannot establish the required normalization premise.
        report = oauth.analyze_supplied_oauth_pkce_transcript(model)
        self.assertEqual(status_map(report)["callback_redirect_binding"], "unknown")
        self.assertEqual(report.to_dict()["analysis_status"], "unknown")
        model["authorization_response"]["callback_redirect_uri_sha256"] = "sha256:" + "4" * 64
        self.assertEqual(
            status_map(oauth.analyze_supplied_oauth_pkce_transcript(model))[
                "callback_redirect_binding"
            ],
            "unknown",
        )
        model["authorization_response"]["callback_redirect_target_declared"] = True
        self.assertEqual(
            status_map(oauth.analyze_supplied_oauth_pkce_transcript(model))[
                "callback_redirect_binding"
            ],
            "contradicted",
        )

    def test_unsupported_flow_and_noncanonical_challenge_fail_closed(self) -> None:
        for stage, field, value in (
            ("authorization_request", "response_type", "token"),
            ("token_request", "grant_type", "client_credentials"),
            ("authorization_request", "code_challenge_method", "plain"),
            ("authorization_request", "code_challenge", "A" * 43 + "="),
            ("authorization_request", "code_challenge", "A" * 42 + "B"),
            ("authorization_request", "code_challenge", "A" * 42),
        ):
            with self.subTest(field=field, value=value):
                model = fixture()
                model[stage][field] = value
                with self.assertRaises(oauth.OAuthPkceTranscriptError):
                    oauth.analyze_supplied_oauth_pkce_transcript(model)

    def test_closed_native_shapes_reject_aliases_and_cycles(self) -> None:
        class IntAlias(int):
            pass

        class TextAlias(str):
            pass

        changes = (
            ("schema_version", True),
            ("schema_version", IntAlias(1)),
            ("authorization_request.complete", 1),
            ("authorization_request.client_id", TextAlias("client.invalid")),
            ("authorization_request.code_challenge", TextAlias("A" * 43)),
            ("authorization_response.code_sha256", False),
        )
        for path, value in changes:
            with self.subTest(path=path):
                model = fixture()
                keys = path.split(".")
                target = model
                for key in keys[:-1]:
                    target = target[key]
                target[keys[-1]] = value
                with self.assertRaises(oauth.OAuthPkceTranscriptError):
                    oauth.analyze_supplied_oauth_pkce_transcript(model)
        model = fixture()
        model["cycle"] = model
        with self.assertRaises(oauth.OAuthPkceTranscriptError):
            oauth.analyze_supplied_oauth_pkce_transcript(model)

    def test_raw_code_or_verifier_fields_and_long_metadata_never_reach_digest(self) -> None:
        cases = (
            ("token_request", "code_verifier", "synthetic-verifier-not-accepted"),
            ("authorization_response", "code", "synthetic-code-not-accepted"),
            ("authorization_request", "client_id", "c" * 129),
            ("authorization_request", "client_id", "nonascii-\u00e9"),
            ("authorization_request", "state_sha256", "sha256:" + "A" * 64),
        )
        for stage, name, value in cases:
            with self.subTest(stage=stage, name=name):
                model = fixture()
                model[stage][name] = value
                with mock.patch.object(
                    oauth.hashlib, "sha256", side_effect=AssertionError("hashed")
                ):
                    with self.assertRaises(oauth.OAuthPkceTranscriptError):
                        oauth.analyze_supplied_oauth_pkce_transcript(model)
        model = fixture()
        model["unexpected"] = "metadata"
        with self.assertRaises(oauth.OAuthPkceTranscriptError):
            oauth.analyze_supplied_oauth_pkce_transcript(model)

    def test_raw_duplicate_keys_and_integer_lexicals_fail_closed(self) -> None:
        raw = canonical(fixture())
        duplicate = raw.replace('"schema_version":1', '"schema_version":1,"schema_version":1', 1)
        with self.assertRaises(oauth.OAuthPkceTranscriptError):
            oauth.analyze_supplied_oauth_pkce_transcript_bytes(
                model_bytes=duplicate.encode("ascii")
            )
        for token in ("true", "1.0", "--1", "01", "9223372036854775808", "9" * 400):
            with self.subTest(token=token):
                changed = raw.replace('"schema_version":1', f'"schema_version":{token}', 1)
                with self.assertRaises(oauth.OAuthPkceTranscriptError):
                    oauth.analyze_supplied_oauth_pkce_transcript_bytes(
                        model_bytes=changed.encode("ascii")
                    )

    def test_raw_predecoder_rejects_depth_and_large_number_before_json_loads(self) -> None:
        raw = canonical(fixture())
        candidates = (
            ("[" * 17 + "0" + "]" * 17).encode("ascii"),
            raw.replace('"schema_version":1', '"schema_version":' + "9" * 500, 1).encode("ascii"),
        )
        for content in candidates:
            with self.subTest(content=content[:32]):
                with mock.patch.object(oauth.json, "loads", side_effect=AssertionError("decoded")):
                    with self.assertRaises(oauth.OAuthPkceTranscriptError):
                        oauth.analyze_supplied_oauth_pkce_transcript_bytes(model_bytes=content)

    def test_report_constructor_parser_and_export_replay(self) -> None:
        report = oauth.analyze_supplied_oauth_pkce_transcript(fixture())
        document = report.to_dict()
        self.assertEqual(
            oauth.OAuthPkceTranscriptAnalysis(report.to_json()).to_json(), report.to_json()
        )
        self.assertEqual(
            oauth.OAuthPkceTranscriptAnalysis.from_dict(document).to_json(), report.to_json()
        )
        self.assertEqual(
            oauth.OAuthPkceTranscriptAnalysis.from_json(report.to_json()).to_json(),
            report.to_json(),
        )
        document["checks"][0]["status"] = "contradicted"
        self.assertEqual(report.to_dict()["checks"][0]["status"], "matched")
        with self.assertRaises(FrozenInstanceError):
            report.document_json = "changed"

    def test_noncanonical_report_json_and_incomplete_wrapper_refused(self) -> None:
        report = oauth.analyze_supplied_oauth_pkce_transcript(fixture())
        with self.assertRaises(oauth.OAuthPkceTranscriptError):
            oauth.OAuthPkceTranscriptAnalysis.from_json(" " + report.to_json())
        incomplete = object.__new__(oauth.OAuthPkceTranscriptAnalysis)
        with self.assertRaises(oauth.OAuthPkceTranscriptError):
            incomplete.to_dict()

    def test_coherently_readdressed_false_check_and_flag_do_not_replay(self) -> None:
        report = oauth.analyze_supplied_oauth_pkce_transcript(fixture())
        for field in ("checks", "flags"):
            with self.subTest(field=field):
                forged = report.to_dict()
                if field == "checks":
                    forged["checks"][0]["status"] = "contradicted"
                else:
                    forged["flags"]["login_authorized"] = True
                body = {
                    key: value
                    for key, value in forged.items()
                    if key not in {"analysis_id", "analysis_sha256"}
                }
                forged["analysis_sha256"] = digest(oauth.DOMAIN, body)
                forged["analysis_id"] = "OAT-" + forged["analysis_sha256"][7:39].upper()
                with self.assertRaises(oauth.OAuthPkceTranscriptError):
                    oauth.OAuthPkceTranscriptAnalysis.from_dict(forged)

    def test_separately_original_model_and_source_ids_are_bound(self) -> None:
        model = fixture()
        report = oauth.analyze_supplied_oauth_pkce_transcript(model)
        changed = copy.deepcopy(model)
        changed["authorization_response"]["source_id"] += "-foreign"
        with self.assertRaises(oauth.OAuthPkceTranscriptError):
            oauth.verify_supplied_oauth_pkce_transcript(report, model=changed)
        other_report = oauth.analyze_supplied_oauth_pkce_transcript(changed)
        self.assertNotEqual(other_report.analysis_sha256, report.analysis_sha256)

    def test_report_and_model_byte_limits_precede_first_digest(self) -> None:
        model = fixture()
        report = oauth.analyze_supplied_oauth_pkce_transcript(model)
        report_size = len(report.to_json())
        source_size = len(canonical(model))
        with mock.patch.object(oauth, "MAX_MODEL_BYTES", source_size - 1):
            with mock.patch.object(oauth.hashlib, "sha256", side_effect=AssertionError("hashed")):
                with self.assertRaises(oauth.OAuthPkceTranscriptError):
                    oauth.analyze_supplied_oauth_pkce_transcript(model)
        with mock.patch.object(oauth, "MAX_REPORT_BYTES", report_size - 1):
            with mock.patch.object(oauth.hashlib, "sha256", side_effect=AssertionError("hashed")):
                with self.assertRaises(oauth.OAuthPkceTranscriptError):
                    oauth.analyze_supplied_oauth_pkce_transcript(model)

    def test_all_eight_public_forms_fund_one_complete_operation_before_sha(self) -> None:
        model = fixture()
        report = oauth.analyze_supplied_oauth_pkce_transcript(model)
        document = report.to_dict()
        text = report.to_json()
        forms = (
            ("native", lambda: oauth.analyze_supplied_oauth_pkce_transcript(model)),
            (
                "bytes",
                lambda: oauth.analyze_supplied_oauth_pkce_transcript_bytes(
                    model_bytes=canonical(model).encode("ascii")
                ),
            ),
            ("constructor", lambda: oauth.OAuthPkceTranscriptAnalysis(text)),
            ("from_dict", lambda: oauth.OAuthPkceTranscriptAnalysis.from_dict(document)),
            ("from_json", lambda: oauth.OAuthPkceTranscriptAnalysis.from_json(text)),
            ("to_dict", report.to_dict),
            ("to_json", report.to_json),
            ("verify", lambda: oauth.verify_supplied_oauth_pkce_transcript(report, model=model)),
        )

        class FirstDigest(Exception):
            pass

        original_charge = oauth._Budget.charge
        for name, operation in forms:
            with self.subTest(name=name):
                observed = {}

                def charge(budget: oauth._Budget, amount: int) -> None:
                    original_charge(budget, amount)
                    observed["used"] = budget.used

                with mock.patch.object(oauth._Budget, "charge", charge):
                    with mock.patch.object(oauth.hashlib, "sha256", side_effect=FirstDigest):
                        with self.assertRaises(FirstDigest):
                            operation()
                threshold = observed["used"]
                self.assertGreater(threshold, 0)
                with mock.patch.object(oauth, "MAX_WORK", threshold - 1):
                    with mock.patch.object(
                        oauth.hashlib, "sha256", side_effect=AssertionError("hashed")
                    ):
                        with self.assertRaises(oauth.OAuthPkceTranscriptError):
                            operation()
                with mock.patch.object(oauth, "MAX_WORK", threshold):
                    self.assertIsNotNone(operation())


if __name__ == "__main__":
    unittest.main()
