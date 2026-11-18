# Supplied Happens-Before Conflicts

The GE-D21-S11 component checks a bounded, caller-supplied event-order graph
for pairs of accesses to the same named resource by different actors. A pair
is reported only when at least one access is a write and neither event is
ordered before the other, including by a transitive path. Cyclic or unresolved
ordering declarations are rejected.

The component does not collect a trace, run code, resolve memory aliasing, or
verify synchronization. Event identities, resource aliases, and ordering are
supplied assertions. An unordered conflicting pair is not proof that events
can occur concurrently or that a data race exists. The report creates no
finding, candidate, qualification, or action authority.

The checked synthetic example is
[`examples/offline-happens-before-component.json`](../examples/offline-happens-before-component.json).
Verification requires replay against the original supplied model.
