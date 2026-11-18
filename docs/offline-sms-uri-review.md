# Supplied SMS URI Review

The GA-D02-S03 partial component parses a supplied synthetic SMS URI without
opening an SMS client. [RFC 5724](https://www.rfc-editor.org/rfc/rfc5724.html)
defines the recipient list and optional body field. The checked example is
[`examples/offline-sms-uri-component.json`](../examples/offline-sms-uri-component.json).

The analyzer accepts only a bounded subset with recipient numbers in NANPA's
[reserved fictional 555-0100 to 555-0199 range](https://nanpa.com/numbering/555-line-numbers).
It counts recipients, compares their order with a caller-declared
expectation, and hashes numbers, URI, and optional body in the report. It does
not validate recipient reachability or message content safety. An SMS URI can
be used to initiate composition, but this component never opens, composes, or
sends a message. It produces no delivery, finding, or qualification claim.
