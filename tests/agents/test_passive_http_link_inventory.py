"""Offline passive link inventory tests over a real authorized exchange receipt."""

from __future__ import annotations

import unittest
from dataclasses import replace

from sunderkey.assessment_transport_contracts import HeaderField, MimeLimit
from sunderkey.authorized_http_runtime import ExchangeStatus, HttpBackendResponse
from sunderkey.passive_http_link_inventory import (
    PassiveLinkInventoryError,
    extract_passive_link_inventory,
)
from tests.agents import test_authorized_http_runtime_phase173 as runtime_fixture


def completed_html_exchange(body: bytes):
    fixture = runtime_fixture.AuthorizedHttpRuntimePhase173Tests(
        methodName="test_completed_exchange_is_single_send_and_content_addressed"
    )
    fixture.setUp()
    html_limit = (MimeLimit("text/html", 4096),)
    binding = replace(
        fixture.assessment_binding,
        budget=replace(fixture.transport_budget, mime_limits=html_limit),
    )
    intent = replace(
        fixture.intent,
        binding=binding,
        headers=(HeaderField("accept", "text/html"),),
    )
    request = fixture.make_execution_request(intent=intent)
    admission = replace(
        fixture.admission,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        receipt_id="",
        receipt_sha256="",
    )
    backend = runtime_fixture.FakeBackend(
        HttpBackendResponse(
            200,
            (("content-length", str(len(body))), ("content-type", "text/html")),
            body,
            True,
            False,
            False,
            1,
        )
    )
    receipt = fixture.invoke(
        intent=intent,
        execution_request=request,
        admission=admission,
        policy=replace(
            fixture.policy,
            mime_limits=html_limit,
            policy_id="",
            policy_sha256="",
        ),
        backend=backend,
    )
    assert receipt.status is ExchangeStatus.COMPLETED, receipt.reason
    return intent, receipt


class PassiveHttpLinkInventoryTests(unittest.TestCase):
    def test_same_origin_links_are_proposals_with_query_values_removed(self) -> None:
        body = (
            b'<a href="/assess/items?view=list&amp;sort=asc">items</a>'
            b'<a href="/assess/items?sort=desc&amp;view=grid">duplicate</a>'
            b'<form action="next?mode=edit"><button>go</button></form>'
            b'<script src="https://app.example.test/assess/app.js"></script>'
            b'<a href="https://outside.example/never">outside</a>'
            b'<a href="javascript:alert(1)">script</a>'
        )
        intent, receipt = completed_html_exchange(body)
        inventory = extract_passive_link_inventory(
            intent=intent, receipt=receipt, response_body=body
        )
        self.assertEqual(len(inventory.candidate_links), 3)
        self.assertEqual(inventory.rejected_link_count, 2)
        paths = {item.url_without_query for item in inventory.candidate_links}
        self.assertEqual(
            paths,
            {
                "https://app.example.test/assess/items",
                "https://app.example.test/assess/next",
                "https://app.example.test/assess/app.js",
            },
        )
        self.assertEqual(
            next(
                item.query_parameter_names
                for item in inventory.candidate_links
                if item.tag == "a"
            ),
            ("sort", "view"),
        )
        self.assertNotIn("view=list", str(inventory.to_dict()))
        self.assertFalse(inventory.to_dict()["network_call_performed"])
        self.assertEqual(inventory.to_dict()["authority_effect"], "none")

    def test_tampered_body_and_mismatched_intent_are_rejected(self) -> None:
        body = b'<a href="/assess/next">next</a>'
        intent, receipt = completed_html_exchange(body)
        with self.assertRaisesRegex(PassiveLinkInventoryError, "does not match"):
            extract_passive_link_inventory(
                intent=intent, receipt=receipt, response_body=body + b"x"
            )
        changed_intent = replace(intent, url="https://app.example.test/assess/other")
        with self.assertRaisesRegex(PassiveLinkInventoryError, "intent does not match"):
            extract_passive_link_inventory(
                intent=changed_intent, receipt=receipt, response_body=body
            )

    def test_candidate_count_fails_closed(self) -> None:
        body = b'<a href="/assess/one">one</a><a href="/assess/two">two</a>'
        intent, receipt = completed_html_exchange(body)
        with self.assertRaisesRegex(PassiveLinkInventoryError, "accepted link count"):
            extract_passive_link_inventory(
                intent=intent, receipt=receipt, response_body=body, maximum_links=1
            )

    def test_invalid_utf8_is_rejected(self) -> None:
        body = b"<html>\xff</html>"
        intent, receipt = completed_html_exchange(body)
        with self.assertRaisesRegex(PassiveLinkInventoryError, "must be UTF-8"):
            extract_passive_link_inventory(intent=intent, receipt=receipt, response_body=body)

    def test_result_digest_is_independent_of_link_order(self) -> None:
        first = b'<a href="/assess/a">a</a><a href="/assess/b">b</a>'
        second = b'<a href="/assess/b">b</a><a href="/assess/a">a</a>'
        first_intent, first_receipt = completed_html_exchange(first)
        second_intent, second_receipt = completed_html_exchange(second)
        first_result = extract_passive_link_inventory(
            intent=first_intent, receipt=first_receipt, response_body=first
        )
        second_result = extract_passive_link_inventory(
            intent=second_intent, receipt=second_receipt, response_body=second
        )
        self.assertEqual(first_result.candidate_links, second_result.candidate_links)
        self.assertNotEqual(first_result.inventory_sha256, second_result.inventory_sha256)


if __name__ == "__main__":
    unittest.main()
