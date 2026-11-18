# Offline Power Recovery Cadence Review

This partial GD-D19-S09 algorithm projects supplied synthetic recovery-test dates against the 15-calendar-month cadence in [NERC CIP-009-6, Requirement Parts R2.1 and R2.2](https://www.nerc.com/globalassets/standards/reliability-standards/cip/cip-009-6.pdf). The [NERC standards index](https://www.nerc.com/standards/reliability-standards/cip) listed CIP-009-6 as mandatory and CIP-009-7.1 as subject to future enforcement when this source was reviewed. The algorithm pins its reference to CIP-009-6 and does not dynamically decide which version or requirement applies to a real entity.

The report records only whether two declared dates fall inside the modeled window and whether the supplied model declares its recovery-information sample usable and compatible. Missing cadence or a negative declaration produces a review cue, not a compliance finding. Applicability, actual test execution, sample quality, and recoverability remain unverified.

The fixture is synthetic, R0, dry-run, and requires no credential or resource grants. Original-model replay is mandatory for report verification. No backup is read or restored, no power asset is contacted, and no operational authority or qualification is granted.
