# Supplied Observable Field Discrepancy

The `AOE-GE-D23-S16` partial specialist compares caller-declared fields
permitted for a restricted observer with fields claimed to be observed. It
marks the extra field references that are also declared sensitive. Only a
complete model with such an overlap yields a candidate declared sensitive
field exposure. Extra fields without a sensitivity marker remain a generic
declared discrepancy.

No response content or target identity is accepted. Field and resource
references are opaque labels, not data values or network selectors. The model
does not observe a response, verify permission policy, or establish an
information disclosure. Incomplete policy or capture withholds a candidate
disposition.

The source is limited to 64 comparisons, 64 references per field set, and
32 KiB. The 64 KiB report embeds the source for separate-source replay. No
file, network, process, credential, target, execution, publication, or
qualification effect occurs. The
[synthetic example](../examples/offline-observable-discrepancy-component.json)
contains labels and assertions only.
