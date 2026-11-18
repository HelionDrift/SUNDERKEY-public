# Offline API attested planning handoff

`sunderkey.offline_api_attested_planning` joins four local artifacts for one
initial API assessment batch: the exact case sources, a reproduced Army
planning bundle, a receipt-sourced source ledger, and an Ed25519 attestation
over that ledger. Its verifier rebuilds the planning bundle and the ledger
from the same inputs. It then checks the caller-provided producer key, the
signed mission and scope, and a bounded local signature window.

The handoff rejects a different key, source receipt, ledger, scope digest,
planning bundle, or review instant before the source observation. A prior
signature remains historically verifiable after expiry, but this handoff
requires the review instant to lie inside its local signed window.

This is not a production trust decision. The caller supplies both the source
receipts and producer key, and the code cannot establish their external
custody or current authorization. The result records source replay but sets
`live_currentness_verified` and `positive_use_approved` to false. It does not
publish a finding, admit an action, contact a target, or route an expert.

Run the focused regression check from the repository root:

```powershell
$env:PYTHONPATH = "src"
python -m unittest tests.agents.test_offline_api_attested_planning -v
```
