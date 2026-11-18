# OpenAI Expert-Runtime Smoke

This operator-only smoke exercises one authenticated execution and
the OpenAI Responses adapter with a synthetic mission, synthetic
authority, and no target. It is nonqualifying. It does not activate a route or
show that live missions, target actions, or production retention controls work.
The test fixture is intentionally temporary; only the selected local receipt
is preserved.

## Fixed Limits and Data Controls

- Exactly one request at most, with no automatic retry and no tools.
- A 10,000-token input reservation and 8,000-token provider output ceiling,
  with an 18,000-token combined plan reservation. The fixed synthetic input
  is small, but the input reservation is not a provider-enforced token cap.
  The fixture's pricing declaration is synthetic. None of these limits is a
  guaranteed dollar limit.
- Exact `gpt-5.6-sol` model identity and `api.openai.com:443/v1/responses` endpoint.
- `store: false`, no streaming, no background mode, and no redirects.
- Standard OpenAI abuse-monitoring retention may be up to 30 days, subject to
  provider policy exceptions. This is not Zero Data Retention.
- The fixture models a standard global OpenAI region. It does not claim a
  specific processing location.

Use a separate test project, a short-lived project-scoped key, and a low
project spend limit. OpenAI project limits are not necessarily instantaneous,
so the one-request and token ceilings remain the primary local bound. Do not
paste the key into chat, write it to a repository file, or include it in a
shell command history entry.

## Operator Procedure

From a checkout containing this command, first inspect the offline preflight:

```bash
export PYTHONPATH=src
python -m scripts.openai_expert_runtime_smoke --preflight
```

The preflight makes no network call and does not require a key. The plan digest
will change in the run because synthetic signing keys are freshly generated.
Review the printed model, endpoint policy, and token limits. For the paid run,
choose a new receipt path outside the repository and set the key only in the
current shell:

```bash
receipt_dir="${XDG_STATE_HOME:-$HOME/.local/state}/sunderkey"
mkdir -p "$receipt_dir"
receipt_path="$receipt_dir/expert-runtime-smoke-$(date -u +%Y%m%dT%H%M%SZ).json"
read -rsp "OpenAI API key: " OPENAI_API_KEY
echo
export OPENAI_API_KEY

python -m scripts.openai_expert_runtime_smoke --run \
  --confirm-maximum-requests 1 \
  --confirm-token-ceiling 18000 \
  --output "$receipt_path"

run_exit=$?
unset OPENAI_API_KEY
printf 'Runner exit: %s\nReceipt: %s\n' "$run_exit" "$receipt_path"
```

The run prints a fresh plan digest and waits for you to type that exact digest.
The receipt path is reserved before dispatch. If the process is interrupted or
the result is indeterminate, preserve the file and do not rerun automatically.
The local receipt includes the work product for review but no API key. Treat
model output as untrusted. A successful smoke records conservative full-budget
settlement, not actual billable cost or independent qualification.

Version 2 sends a unique client request ID and records it before dispatch, so
the identifier survives an interrupted run. [OpenAI's API reference](https://developers.openai.com/api/reference/overview#supplying-your-own-request-id-with-x-client-request-id)
describes how it can help support locate a request when the server request ID
was not received. Version 2 receipts also record whether an HTTP
response was received, its status code, a sanitized and explicitly unverified
`x-request-id` header when present, closed response-status and incomplete-reason
labels when recognized, the local settlement reason, and the output status.
They never store the HTTP response body or authorization
header. These fields help separate a rejected HTTP response from a transport
failure or an unaccepted HTTP 200 response. They cannot reveal the exact
provider error or recover diagnostics from an earlier receipt. Keep any
indeterminate receipt and do not automatically repeat the paid call.
If no HTTP response arrived after dispatch, version 2 records
`network_call_performed` as `indeterminate_after_attempt`, not `true`.

## Evidence Boundary

The synthetic fixture validates the integration path and can reveal output
schema failures, model substitution, incomplete responses, provider errors,
latency, token usage, and local custody settlement. It cannot validate live
target authorization, deployed credentials, GCP containment, database
failover, production recovery, or reviewer independence. A later test plan
must cover those separately.

OpenAI data-control and spend-limit details should be checked against the
current [API data controls](https://developers.openai.com/api/docs/guides/your-data)
and [project spend-limit guidance](https://developers.openai.com/api/docs/guides/spend-limits)
before execution.
