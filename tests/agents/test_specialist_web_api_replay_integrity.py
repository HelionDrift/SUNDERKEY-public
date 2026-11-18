"""Exact native JSON replay for addressed specialist requests and receipts."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from unittest.mock import patch

from sunderkey import specialist_web_api_adapters as specialist
from tests.agents import test_specialist_web_api_adapters_phase166 as fixture

EVALUATED_AT = datetime(2026, 9, 20, 10, 10, tzinfo=UTC)
GOLDEN_DIGESTS = {
    "api_file_serialization": (
        "sha256:7d45b4dcfa9441810456ee76e218e5d0ff552de7ae86528966d76b99db8a605b",
        "sha256:4e4d7c4cee09fd8d27bb2017499f912d889cd52cead5535da5c055e2bf70bc6d",
    ),
    "api_rest_graphql_async": (
        "sha256:1982b45c8a41a7c4de34f26ac1c0d5e5d7c73425f9c91a247bc987695a4e7732",
        "sha256:104e951595e816c015b0eedf20bc2122b5f2aa3fa93fe48472f0225f17da48ff",
    ),
    "auth_login_session": (
        "sha256:6c94c566aef310877a798e064722938f43584609af1ca72c30f5f041323752d1",
        "sha256:7f6bdc956df2540b1076c4b4aa4a9dc04323de0255c00a5d90932d3db3fd2a63",
    ),
    "auth_refresh_logout_mfa_recovery": (
        "sha256:1160bc501c1162dd0667297945c38e4ca4c329c1516f8d3e730240aa89d5d192",
        "sha256:1526be4d257b60f38006d9ff5fe968190a087a5e2e2b5f8019c2b8ca9afaca66",
    ),
    "authz_object_function_field": (
        "sha256:25b93fc6a7354069857a61a41c7908fe1cef43f6ba9b9e79c5ff89d44a3733f5",
        "sha256:0053c7c6aef08ba4c01de8bfdb74c2629c552bcc330988772103d64136641c18",
    ),
    "authz_tenant_role": (
        "sha256:75a631eb756374511b3254e23afd4b3c291ec7c358021238a1da1fc0043caaff",
        "sha256:c707d2d5ae33f28dd56de90a41c2fd943e6dcd4a29820b640d3ca1d8cbd498e0",
    ),
    "business_concurrency_workflow": (
        "sha256:35e3bea3c533c915da198f120a557a75167bc33cb8c0c5c7c6e1971f7843d32c",
        "sha256:c9471bfe474f1fbb60fd73c0aac2edc18c737ac888755b3d8c57e9b9375c89fc",
    ),
    "business_state_order_limit": (
        "sha256:8ebaec159173e7383ec69f9b6007a7180b231d42b24842052a2fafffd7a09f3c",
        "sha256:d7d451ae807f5dc0169cd667e6ff05021c7577f10bf37dbe33fdc71739f34fda",
    ),
    "http_proxy_cache_parser": (
        "sha256:3ccc806f3ef73321c0e9f8c79cedbe26eab064c9374bc412990b3aeef3221f7f",
        "sha256:568332496e97ee56cb17fdf0acc15510bdedf2bfb299a2fb6b7345c8c6eed9cf",
    ),
    "http_request_construction": (
        "sha256:24ed2c1e186ef5e7e6c55cd2c76e67457aaf648cdd1d9211912d8b45e0f344eb",
        "sha256:d1fe414d53171d0f22b858390b55f885d84e5a9eaaebbb0c80a326eabec9aea1",
    ),
    "input_injection_ssrf_deserialization": (
        "sha256:809d926ab16f56149dd09e817333a5ecab0b39bc03987e8d960672a96f065b12",
        "sha256:197c8d50a085aaf4c12402b9e5b6b0e8dde9ba0292fa6753b527f2b0e5389329",
    ),
    "input_parser_template": (
        "sha256:1743284164dbdbeffc4fe364d5690c1226dd22028fae23d76446ae762ba5bd70",
        "sha256:df4493e599fd1a1f1738d833de37ccb7c4999fe8f3cc9bbc21f98ac7f463a385",
    ),
    "oauth_exchange_federation": (
        "sha256:b59c4b4f007c7256d33ae13ef7ecccd5ba1cec17f573c4a33fe435b6a375ff38",
        "sha256:3057a500e9f6c3775bd87cac1fabe9b08700eedd10cc6a53ffcf053d1e73030a",
    ),
    "oauth_redirect_claim_audience_scope": (
        "sha256:ad49a621758f8a80744f179a9c8b81cc40e0137eb030669771582fb464e7f1a6",
        "sha256:032f88d8edaa12667c9e9a9b29f1d133544b24f8df1b89c1e2cde434718cf1f8",
    ),
}


def wire_json(document: dict) -> str:
    """Keep native JSON type distinctions, including malformed float aliases."""

    return json.dumps(
        document, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )


class SpecialistWebApiReplayIntegrityTests(unittest.TestCase):
    def receipt(self, request):
        adapter = fixture.FakeAdapter(operation=request.operation)
        result = specialist.execute_specialist_action(
            request,
            expected_context=request.context,
            adapter=adapter,
            replay_guard=specialist.SpecialistReplayGuard(),
            evaluated_at=EVALUATED_AT,
        )
        self.assertEqual(adapter.calls, [request])
        return result

    def assert_request_rejected_before_execution(self, original, altered) -> None:
        baseline = original.to_dict()
        self.assertNotEqual(wire_json(altered), wire_json(baseline))
        self.assertEqual(altered["request_id"], baseline["request_id"])
        self.assertEqual(altered["request_sha256"], baseline["request_sha256"])
        for parser in (
            specialist.SpecialistActionRequest.from_dict,
            specialist.parse_specialist_contract,
        ):
            with self.subTest(parser=parser.__qualname__):
                adapter = fixture.FakeAdapter(operation=original.operation)
                # Decode actual native JSON. There are no subclass fixtures,
                # credentials, real adapters, or live target actions here.
                supplied = json.loads(wire_json(altered))
                with self.assertRaises(specialist.SpecialistAdapterError):
                    parsed = parser(supplied)
                    specialist.execute_specialist_action(
                        parsed,
                        expected_context=original.context,
                        adapter=adapter,
                        replay_guard=specialist.SpecialistReplayGuard(),
                        evaluated_at=EVALUATED_AT,
                    )
                self.assertEqual(adapter.calls, [])
        self.assertEqual(original.to_dict(), baseline)

    def assert_receipt_rejected(self, original, altered) -> None:
        baseline = original.to_dict()
        self.assertNotEqual(wire_json(altered), wire_json(baseline))
        self.assertEqual(altered["receipt_id"], baseline["receipt_id"])
        self.assertEqual(altered["receipt_sha256"], baseline["receipt_sha256"])
        for parser in (
            specialist.SpecialistActionReceipt.from_dict,
            specialist.parse_specialist_contract,
        ):
            with self.subTest(parser=parser.__qualname__):
                with self.assertRaises(specialist.SpecialistAdapterError):
                    parser(json.loads(wire_json(altered)))
        self.assertEqual(original.to_dict(), baseline)

    def test_all_fourteen_operation_golden_requests_and_receipts_roundtrip(self) -> None:
        self.assertEqual(set(GOLDEN_DIGESTS), {op.value for op in specialist.SpecialistOperation})
        for operation in specialist.SpecialistOperation:
            with self.subTest(operation=operation):
                request = fixture.request(operation)
                receipt = self.receipt(request)
                expected_request, expected_receipt = GOLDEN_DIGESTS[operation.value]
                self.assertEqual(request.request_sha256, expected_request)
                self.assertEqual(receipt.receipt_sha256, expected_receipt)
                self.assertEqual(request.request_id, "SAR-" + expected_request[7:39].upper())
                self.assertEqual(receipt.receipt_id, "SRR-" + expected_receipt[7:39].upper())
                for record, parser in (
                    (request, specialist.SpecialistActionRequest.from_dict),
                    (receipt, specialist.SpecialistActionReceipt.from_dict),
                ):
                    document = record.to_dict()
                    for parse in (parser, specialist.parse_specialist_contract):
                        parsed = parse(json.loads(wire_json(document)))
                        self.assertEqual(parsed, record)
                        self.assertEqual(wire_json(parsed.to_dict()), wire_json(document))
                    self.assertEqual(document["effects"], dict(specialist.REPOSITORY_ONLY_EFFECTS))

    def test_request_schema_boolean_and_float_reject_before_execution(self) -> None:
        request = fixture.request()
        for value in (True, 1.0):
            with self.subTest(value=value, type=type(value).__name__):
                altered = copy.deepcopy(request.to_dict())
                altered["schema_version"] = value
                self.assert_request_rejected_before_execution(request, altered)

    def test_all_operation_policy_native_aliases_reject_before_execution(self) -> None:
        for operation in specialist.SpecialistOperation:
            request = fixture.request(operation)
            policy = request.to_dict()["policy"]
            cases = [
                ("authenticated_session_required", int(policy["authenticated_session_required"])),
                ("authenticated_session_required", float(policy["authenticated_session_required"])),
                ("minimum_principals", float(policy["minimum_principals"])),
            ]
            if policy["minimum_principals"] in (0, 1):
                cases.append(("minimum_principals", bool(policy["minimum_principals"])))
            for field, value in cases:
                with self.subTest(operation=operation, field=field, type=type(value).__name__):
                    altered = copy.deepcopy(request.to_dict())
                    altered["policy"][field] = value
                    self.assert_request_rejected_before_execution(request, altered)

    def test_request_list_order_is_not_normalized_under_original_identity(self) -> None:
        request = fixture.request()
        for field in ("evidence_refs", "sessions"):
            with self.subTest(field=field):
                altered = copy.deepcopy(request.to_dict())
                altered[field].reverse()
                self.assert_request_rejected_before_execution(request, altered)

    def test_receipt_schema_boolean_and_float_reject_both_public_parsers(self) -> None:
        receipt = self.receipt(fixture.request())
        for value in (True, 1.0):
            with self.subTest(value=value, type=type(value).__name__):
                altered = copy.deepcopy(receipt.to_dict())
                altered["schema_version"] = value
                self.assert_receipt_rejected(receipt, altered)

    def test_receipt_list_order_is_not_normalized_under_original_identity(self) -> None:
        receipt = self.receipt(fixture.request())
        altered = copy.deepcopy(receipt.to_dict())
        altered["evidence_refs"].reverse()
        self.assert_receipt_rejected(receipt, altered)
        adapter = specialist.AdapterIdentity(
            "adapter:fixture",
            "1.0.0",
            (
                specialist.SpecialistOperation.AUTHZ_TENANT_ROLE,
                specialist.SpecialistOperation.HTTP_REQUEST_CONSTRUCTION,
            ),
        )
        receipt = replace(receipt, adapter=adapter, receipt_id="", receipt_sha256="")
        altered = copy.deepcopy(receipt.to_dict())
        altered["adapter"]["supported_operations"].reverse()
        self.assert_receipt_rejected(receipt, altered)

    def test_historical_receipts_do_not_require_fresh_activation(self) -> None:
        request = fixture.request()
        receipt = self.receipt(request)
        self.assertEqual(receipt.observed_at, "2026-09-20T10:10:00Z")
        with patch.object(
            specialist,
            "_at",
            side_effect=AssertionError("historical parsing must not evaluate time"),
        ):
            for parser in (
                specialist.SpecialistActionReceipt.from_dict,
                specialist.parse_specialist_contract,
            ):
                parsed = parser(json.loads(wire_json(receipt.to_dict())))
                self.assertEqual(parsed, receipt)
                self.assertEqual(parsed.receipt_sha256, GOLDEN_DIGESTS[request.operation.value][1])

    def test_effect_statuses_remain_fixed_detached_and_nonqualifying(self) -> None:
        request = fixture.request()
        receipt = self.receipt(request)
        expected = dict(specialist.REPOSITORY_ONLY_EFFECTS)
        for record in (request, receipt):
            document = record.to_dict()
            document["effects"]["qualification"] = "performed"
            self.assertEqual(record.to_dict()["effects"], expected)
            for field in ("authority_grant", "qualification", "remote_execution"):
                altered = copy.deepcopy(record.to_dict())
                altered["effects"][field] = "performed"
                if isinstance(record, specialist.SpecialistActionRequest):
                    self.assert_request_rejected_before_execution(record, altered)
                else:
                    self.assert_receipt_rejected(record, altered)
        self.assertEqual(dict(specialist.REPOSITORY_ONLY_EFFECTS), expected)
        self.assertEqual(expected["authority_grant"], "none")
        self.assertEqual(expected["qualification"], "none")


if __name__ == "__main__":
    unittest.main()
