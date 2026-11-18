# Supplied archive member paths

The `AOE-GE-D23-S05` partial specialist compares caller-supplied archive
member names with one declared finite lexical profile:
`posix-lexical-v1` or `windows-lexical-v1`. It separates absolute or
drive-prefixed names, parent traversal beyond a declared extraction root,
potential destination collisions, and unresolved transformations such as
symlink targets, percent sequences, Unicode names, and Windows reserved
or trailing-dot names. A `lexically_contained` label means only that this
bounded string model did not find an escape.

The exact native JSON model declares `schema_version: 1`,
`semantics_profile: supplied-archive-member-paths-v1`, an opaque root
reference, and up to 256 named file, directory, or symlink entries. Names
are bounded and control characters are refused. Windows collision candidates
use case-folded lexical segments; actual filesystem case mode is not known.
The typed report replays against the original model and rejects changed
input. No archive bytes, extraction library, link target, actual destination,
or filesystem state is inspected.

Every entry and the platform profile are caller-supplied. None of these
labels proves that an extractor accepts the name, writes outside a root,
overwrites a file, or has a vulnerability. The projection opens no archive,
touches no file, credential, network, or target, and grants no action
authority or qualification. The
[synthetic example](../examples/offline-archive-member-paths-component.json)
uses only fictitious references and names.
