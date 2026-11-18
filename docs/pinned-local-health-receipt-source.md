# Pinned local health-receipt source

`PinnedLocalHealthReceiptSource` is a concrete, read-only implementation of
the [target-health capture](target-health-capture.md) source port. A caller
provides an absolute local directory and an ordered tuple of one to 128
`LocalHealthReceiptPin` values. Each pin names a relative file and the SHA-256
digest of its raw bytes. The adapter does not enumerate the directory, poll,
watch, retry, delete, rename, acknowledge, or write files.

`parse_local_health_receipt_manifest` accepts at most 64 KiB of strict UTF-8
JSON with only `schema_version: 1` and an ordered `pins` list. Duplicate JSON
fields, duplicate case-folded filenames, extra fields, floats and non-native
pin values are refused. The parser returns pins but never reads files or
chooses a root. The manifest is not signed or authenticated by this module.

Each call checks the caller-supplied byte ceiling, resolves the next file under
the directory, rejects symlink components and nonregular files, reads at most
the ceiling plus one byte, checks basic before/after file metadata, and
compares the raw-byte digest. It returns the bytes once, then advances. After
any file read failure it is terminal, so later pins cannot be consumed by an
implicit retry. Exhaustion returns `None`. The capture workflow independently
replays canonical receipt bytes, verifies current policy and binding, and
uses its existing injected signer and custody port. A local source failure
halts capture before signing or appending that receipt.

UNC roots and Windows remote-drive types are refused. The adapter also rejects
reserved Windows names and checks file type before opening it. Filesystem
mounts, junctions, concurrent path replacement and host-specific redirection
cannot be fully attested by this adapter. The caller must choose and protect a
genuinely local directory.

Pins and files are caller-supplied. A matching digest proves byte equality to
the supplied pin, not who produced the pin, whether the file came from a
target, or whether telemetry is current or complete. Path and metadata checks
are best-effort against ordinary replacement; they do not make a concurrently
mutated filesystem trustworthy. The adapter cannot supply a live target probe,
authenticated collector, provider credential, production custody, target
authority, or qualification evidence. The module makes no application-level
network or target call; it cannot certify that every host filesystem access is
local or side-effect free.
