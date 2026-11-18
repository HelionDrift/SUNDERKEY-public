# OpenAI Expert Provider Adapter

The OpenAI Responses adapter is an optional provider worker for authenticated expert execution. It accepts an admitted invocation plan and a runtime pack, constructs a bounded request, and parses the returned work product. It does not approve an action, admit execution, reserve a budget, grant tool use, or create mission authority.

The transport is limited to `api.openai.com:443/v1/responses`. Requests disable provider-side application storage and tools. An uncertain outcome after dispatch is quarantined by the execution custody layer rather than treated as a success or retried automatically.

The [synthetic runtime smoke](openai-expert-runtime-smoke.md) documents an optional one-request operator check. That check is nonqualifying and does not contact a target. Provider credentials, signing material, and production configuration are not included in this repository.
