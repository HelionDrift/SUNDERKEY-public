# Offline OT Remote-Access Policy Projection

This R0 component compares caller-supplied remote-access paths for operators,
vendors, and IIoT gateways with a caller-supplied policy. The bounded policy
declares allowed actor kinds, required controls, and a maximum session duration.
The component reports missing controls and unexpected decisions for each path.
Its policy must include approved identity; MFA, brokering, and session logging
are explicit local policy choices, not asserted universal requirements.

The control vocabulary is informed by [NIST SP 800-82 Rev. 3](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
and [NIST SP 1800-45](https://www.nist.gov/publications/cybersecurity-water-and-wastewater-sector).
Those publications discuss remote access security and reference designs. This
component does not certify conformance to either publication. A mismatch is
only an unsigned, nonqualifying supplied-data candidate.

No OT device, network, identity provider, broker, log store, or live session is
contacted. Authentication, enforcement, reachability, and session recording
are not verified. Incomplete inventory returns unknown, and report verification
requires replay against the original model.
