# Supplied price and rounding arithmetic

The `AOE-GB-D09-S02` partial specialist evaluates integer minor-unit price,
quantity, discount, tax, and total arithmetic over a bounded caller-supplied
checkout model. It calculates both per-line and order-level tax rounding, then
uses the declared `tax_basis` to select one for comparison. A difference
between those two calculations is preserved as an explicit rounding gap.
Subtotal, discount, tax, and total comparisons are reported separately.

The model has exact fields `schema_version: 1`,
`semantics_profile: supplied-minor-unit-price-rounding-v1`,
`currency_label`, `minor_unit_scale`, `lines`, `tax_rate_basis_points`,
`tax_basis`, `rounding_mode`, and four declared minor-unit amounts. It accepts
one to 128 lines, positive bounded quantities, nonnegative bounded integer
unit prices, and per-line discounts no greater than the line gross. The
rounding mode is `floor` or `half_up`, and the tax basis is `line` or `order`.
The typed report replays the source model and verifies against current input.

The currency label and scale, tax rate and basis, rounding policy, line data,
and declared totals are supplied assertions. This component does not check a
currency registry, FX rates, real tax law, deployed checkout behavior,
economic loss, or authorization. A mismatch is a review observation, not a
validated exploit. No target request, checkout, payment, financial transaction,
qualification, or publication occurs. The
[synthetic example](../examples/offline-price-rounding-component.json)
uses a fictitious `TST` currency label.
