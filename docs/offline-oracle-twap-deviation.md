# Offline Oracle TWAP Deviation

This R0 component supports a narrow part of `AOE-GB-D10-S03`. It calculates a duration-weighted reference from bounded, caller-supplied price samples and compares it with a supplied spot price using exact integer arithmetic. It emits a review candidate only when the deviation strictly exceeds the supplied basis-point threshold and the caller declares a complete sequence, matching market and independent reference. Missing premises produce an unknown result.

The [Uniswap v2 whitepaper](https://docs.uniswap.org/whitepaper.pdf) describes time-weighted average pricing, but this component does not reproduce a live Uniswap oracle or establish that supplied samples are authentic. It does not inspect a pool, query a chain, model liquidity or simulate a flash loan. A deviation candidate does not prove manipulation, profit, feasibility or a vulnerability.

The unsigned report requires separately retained original-model replay and grants no finding, qualification or positive-use authority.

Example: [`examples/offline-oracle-twap-deviation-component.json`](../examples/offline-oracle-twap-deviation-component.json).
