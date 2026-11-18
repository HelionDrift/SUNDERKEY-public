#!/usr/bin/env python3
"""Run one nonqualifying synthetic Phase 193/201 OpenAI expert-runtime smoke."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from sunderkey.openai_expert_provider_adapter import (
    OPENAI_ENDPOINT_HOST,
    OPENAI_ENDPOINT_PATH,
    HttpsOpenAIExpertTransport,
    OpenAIExpertProviderAdapter,
)
from sunderkey.provider_credential_resolver import EnvironmentProviderCredentialResolver
from sunderkey.validation import loads_json_without_duplicate_keys
from tests.agents.test_openai_expert_provider_adapter_phase201 import (
    OpenAIExpertProviderAdapterPhase201Tests,
)

ROOT = Path(__file__).resolve().parents[1]
MAXIMUM_REQUESTS = 1
TOKEN_CEILING = 18_000
OUTPUT_TOKEN_CEILING = 8_000
CREDENTIAL_REFERENCE = "ref:vault/provider/expert-runtime"
SAFE_REQUEST_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")


class SingleCallTransport:
    """Count attempted transport calls without retaining authorization material."""

    def __init__(self, delegate) -> None:
        self.delegate = delegate
        self.call_count = 0
        self.client_request_id = str(uuid4())
        self.http_response_received = False
        self.http_status: int | None = None
        self.http_request_id_unverified: str | None = None
        self.response_status_unverified: str | None = None
        self.incomplete_reason_unverified: str | None = None

    def post_json(self, **kwargs):
        self.call_count += 1
        if self.call_count != 1:
            raise ValueError("operator smoke transport cannot retry")
        headers = kwargs.get("headers")
        if not isinstance(headers, Mapping) or any(
            isinstance(key, str) and key.lower() == "x-client-request-id"
            for key in headers
        ):
            raise ValueError("operator smoke client request ID cannot be substituted")
        response = self.delegate.post_json(
            **{
                **kwargs,
                "headers": {**headers, "X-Client-Request-Id": self.client_request_id},
            }
        )
        if type(response) is tuple and len(response) == 3:
            status, headers, response_body = response
            self.http_response_received = True
            if type(status) is int and 100 <= status <= 599:
                self.http_status = status
            if isinstance(headers, Mapping):
                values = [
                    value for key, value in headers.items()
                    if isinstance(key, str) and key.lower() == "x-request-id"
                ]
                if (
                    len(values) == 1
                    and isinstance(values[0], str)
                    and SAFE_REQUEST_ID_RE.fullmatch(values[0]) is not None
                ):
                    self.http_request_id_unverified = values[0]
            if status == 200 and type(response_body) is bytes:
                try:
                    parsed = loads_json_without_duplicate_keys(
                        response_body.decode("utf-8")
                    )
                except (UnicodeError, ValueError, RecursionError):
                    parsed = None
                if isinstance(parsed, dict):
                    raw_status = parsed.get("status")
                    if type(raw_status) is str and raw_status in {
                        "completed", "incomplete", "failed"
                    }:
                        self.response_status_unverified = raw_status
                    details = parsed.get("incomplete_details")
                    if raw_status == "incomplete" and isinstance(details, dict):
                        reason = details.get("reason")
                        if type(reason) is str and reason in {
                            "max_output_tokens", "content_filter"
                        }:
                            self.incomplete_reason_unverified = reason
        return response

    def diagnostic(self) -> dict[str, object]:
        """Expose only bounded transport metadata, never credentials or response body."""

        return {
            "client_request_id": self.client_request_id,
            "http_response_received": self.http_response_received,
            "http_status": self.http_status,
            "http_request_id_unverified": self.http_request_id_unverified,
            "response_status_unverified": self.response_status_unverified,
            "incomplete_reason_unverified": self.incomplete_reason_unverified,
        }

    def network_outcome(self) -> bool | str:
        """A missing HTTP response cannot prove whether the API received the call."""

        if self.http_response_received:
            return True
        if self.call_count:
            return "indeterminate_after_attempt"
        return False


class OperatorSyntheticFixture(OpenAIExpertProviderAdapterPhase201Tests):
    """Use the signed synthetic custody fixture with accurate standard data controls."""

    def runTest(self) -> None:
        pass

    def capability(self):
        return replace(
            super().capability(),
            region="openai_standard_global",
            retention_days=30,
        )

    def budget(self):
        return replace(super().budget(), request_output_token_limit=OUTPUT_TOKEN_CEILING)

    def request(self, **changes: object):
        return super().request(output_token_ceiling=OUTPUT_TOKEN_CEILING, **changes)


def _prepare(transport_factory=None):
    OperatorSyntheticFixture.setUpClass()
    fixture = OperatorSyntheticFixture(methodName="runTest")
    fixture.setUp()
    try:
        admission, values = fixture.admit()
        plan = admission.invocation_plan
        if (
            plan.request_count != MAXIMUM_REQUESTS
            or plan.input_token_ceiling + plan.output_token_ceiling != TOKEN_CEILING
        ):
            raise ValueError("synthetic invocation does not match the smoke ceiling")
        transport = SingleCallTransport(
            transport_factory(fixture, values[1])
            if transport_factory is not None else HttpsOpenAIExpertTransport()
        )
        adapter = OpenAIExpertProviderAdapter.for_operator_confirmed_network_smoke(
            confirm_invocation_plan_sha256=plan.plan_sha256,
            adapter_principal_id="adapter.fixture",
            runtime_catalog=fixture.catalog,
            runtime_pack=fixture.pack,
            envelope=values[1],
            credential_resolver=EnvironmentProviderCredentialResolver(
                approved_reference=CREDENTIAL_REFERENCE
            ),
            transport=transport,
            clock=lambda: fixture.now,
        )
        request = adapter.request_document(plan)
        if (
            request.get("store") is not False
            or request.get("tools") != []
            or request.get("max_output_tokens") != OUTPUT_TOKEN_CEILING
        ):
            raise ValueError("OpenAI request escaped the fixed smoke policy")
        return fixture, admission, values, adapter, transport
    except Exception:
        fixture.doCleanups()
        raise


def _write_new(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as output:
        json.dump(value, output, ensure_ascii=True, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


def _replace(path: Path, value: dict) -> None:
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as output:
            temporary_path = Path(output.name)
            json.dump(value, output, ensure_ascii=True, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main(argv=None, transport_factory=None, confirmation_input=input) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--preflight", action="store_true", help="Inspect policy without a key or call"
    )
    parser.add_argument("--run", action="store_true", help="Attempt one confirmed paid request")
    parser.add_argument("--output", type=Path, help="New receipt path outside the repository")
    parser.add_argument("--confirm-maximum-requests", type=int)
    parser.add_argument("--confirm-token-ceiling", type=int)
    args = parser.parse_args(argv)
    if args.preflight == args.run:
        parser.error("choose exactly one of --preflight and --run")
    if args.run:
        if args.confirm_maximum_requests != MAXIMUM_REQUESTS:
            parser.error("confirm one request")
        if args.confirm_token_ceiling != TOKEN_CEILING:
            parser.error("confirm the 18000-token ceiling")
        if args.output is None or not args.output.is_absolute():
            parser.error("--output must be an absolute path")
        if args.output.resolve().is_relative_to(ROOT):
            parser.error("receipt must be stored outside the repository")
        if args.output.exists():
            parser.error("receipt path already exists")
    fixture, admission, values, adapter, transport = _prepare(transport_factory)
    try:
        plan = admission.invocation_plan
        summary = {
            "schema_version": 2,
            "status": "preflight_ready",
            "synthetic_fixture": True,
            "qualification_effect": "none",
            "target_interaction": False,
            "model": plan.model_version,
            "endpoint": f"https://{OPENAI_ENDPOINT_HOST}{OPENAI_ENDPOINT_PATH}",
            "plan_sha256": plan.plan_sha256,
            "maximum_requests": MAXIMUM_REQUESTS,
            "input_token_ceiling": plan.input_token_ceiling,
            "output_token_ceiling": plan.output_token_ceiling,
            "token_ceiling": TOKEN_CEILING,
            "pricing_basis": "synthetic_fixture_not_provider_billable_cost",
            "standard_abuse_monitoring_retention_days_maximum": 30,
            "store": False,
            "tools_allowed": False,
            "network_call_performed": False,
        }
        print(json.dumps(summary, ensure_ascii=True, indent=2))
        if args.preflight:
            return 0
        if not os.environ.get("OPENAI_API_KEY"):
            parser.error("OPENAI_API_KEY is not set in this process")
        print("Type the plan_sha256 shown above to confirm this one paid call:", flush=True)
        if confirmation_input().strip() != plan.plan_sha256:
            parser.error("plan confirmation did not match; no network call was made")
        output = args.output.resolve()
        reserved = {
            **summary,
            "status": "reserved_no_terminal_result",
            "network_call_performed": "unknown_until_terminal_result",
            "operator_started_at": datetime.now(UTC).isoformat(),
            **transport.diagnostic(),
        }
        _write_new(output, reserved)
        try:
            result = fixture.custody.execute(
                admission, fixture.catalog, fixture.pack, values[1],
                values[2], values[3], adapter,
            )
            terminal = {
                **reserved,
                "status": result.receipt.execution_state,
                "network_call_performed": transport.network_outcome(),
                **transport.diagnostic(),
                "receipt_id": result.receipt.receipt_id,
                "receipt_sha256": result.receipt.receipt_sha256,
                "provider_request_id": (
                    result.observation.provider_request_id if result.observation else None
                ),
                "returned_model": result.observation.model_version if result.observation else None,
                "input_tokens": result.observation.input_tokens if result.observation else None,
                "output_tokens": result.observation.output_tokens if result.observation else None,
                "settlement_usage_basis": result.settlement.usage_basis,
                "settlement_outcome_reason": result.settlement.outcome_reason,
                "output_status": result.receipt.output_status,
                "work_product": result.work_product.to_dict() if result.work_product else None,
                "store_integrity": fixture.store.verify_store(fixture.registry).status,
                "operator_completed_at": datetime.now(UTC).isoformat(),
            }
            _replace(output, terminal)
            displayed = {key: value for key, value in terminal.items() if key != "work_product"}
            print(json.dumps(displayed, indent=2))
            return 0 if result.receipt.execution_state == "completed_settled" else 1
        except Exception as exc:
            _replace(
                output,
                {
                    **reserved,
                    "status": "indeterminate_do_not_rerun",
                    "network_call_performed": transport.network_outcome(),
                    **transport.diagnostic(),
                    "error_type": type(exc).__name__,
                },
            )
            print(
                "Smoke outcome is indeterminate. Preserve the receipt and do not rerun.",
                file=sys.stderr,
            )
            return 1
    finally:
        fixture.doCleanups()


if __name__ == "__main__":
    raise SystemExit(main())
