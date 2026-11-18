# Offline OT Zone and Conduit Projection

This R0 component compares caller-supplied OT flows with a supplied zone and
directed conduit model. It finds a declared path only when the source zone,
destination zone and service match a conduit. Same-zone flows are assumed
allowed within this deliberately narrow model. A mismatch is an unsigned,
nonqualifying candidate, not proof of actual network reachability or a
security finding.

The model supports offline review of segmentation plans aligned with the
zone-and-conduit approach discussed in
[NIST SP 800-82 Rev. 3](https://csrc.nist.gov/pubs/sp/800/82/r3/final).
It does not inspect firewall rules, routing, protocol semantics, physical
links, device state or authorization. Incomplete topology returns unknown.
No OT target or network is contacted, and original-model replay is required.
