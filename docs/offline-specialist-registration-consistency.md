# Offline Specialist Registration Consistency

The registration preflight compares every component tuple with its published
descriptor, planned work package, fixed profile default, and closed dispatcher
branch. It parses every `examples/*-component.json` request and checks that
each registered component has exactly one example with an inert R0 envelope.
Two representative examples also run through the real dispatcher and result
replay. This keeps the routine check bounded while testing both an older
protocol component and a newer vehicle component.

At this check's introduction, all 207 catalog components had one parsed example,
but 63 older examples were not source-bound. Every `examples/*-component.json`
fixture is now declared in `INTEGRATION_PATHS` and included in the published
catalog's source digests. The preflight checks exact set equality among files
on disk, declared integration paths, and catalog source paths. It also rejects
duplicate declarations and source rows. Mutating either an older agent or
workspace example invalidates the prior catalog, including at dispatch.

The static checks detect missing, duplicate, or orphan component dispatch
branches and examples. They do not prove that every analyzer is semantically
correct or replay every example. Analyzer-specific tests and the full CI suite
retain that responsibility. Adding or changing an example requires a matching
integration-path update and catalog rebuild.
