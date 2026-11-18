# Supplied Interpreter Input Boundary

The `AOE-GE-D23-S02` partial specialist compares declared untrusted dataflow
with a data-only requirement at a command, code, or template interpreter
boundary. It uses opaque input references and a closed choice between
data-only and interpreter-source incorporation. A complete asserted invocation
with untrusted input declared as interpreter source produces a candidate
declared boundary conflict.

The model does not accept or generate command, code, template, or injection
payload text. It does not invoke an interpreter, verify a source-to-sink path,
or establish a vulnerability. Unknown input trust or incorporation withholds
a candidate disposition. A construction conflict without declared invocation
is kept separate from a candidate invoked path.

The source is limited to 64 sinks, 16 inputs per sink, and 32 KiB. The 64 KiB
report embeds the source for separate-source replay. No file, network,
process, credential, target, execution, publication, or qualification effect
occurs. The [synthetic example](../examples/offline-interpreter-input-boundary-component.json)
uses labels and assertions only.
