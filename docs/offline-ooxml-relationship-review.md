# Supplied OOXML Relationship Review

The GA-D02-S08 partial component parses one bounded synthetic Office Open XML
relationship declaration. Microsoft's [Open Packaging Conventions reference](https://learn.microsoft.com/en-us/dotnet/api/system.io.packaging.package.createrelationship)
distinguishes `Internal` and `External` target modes and permits absolute or
relative external target URIs. The checked example is
[`examples/offline-ooxml-relationship-component.json`](../examples/offline-ooxml-relationship-component.json).

The parser rejects DTDs, nested elements, duplicate relationship IDs,
unsupported modes, and non-HTTP(S) absolute external targets. It hashes
external IDs and targets rather than retaining them in the report. An
`External` declaration is not evidence that the target is reachable, fetched,
or used when a document opens. No package, macro, linked content, or browser
behavior is examined. No document or lure is created or delivered, and no
finding or qualification is produced.
