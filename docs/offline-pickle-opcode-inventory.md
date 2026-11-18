# Supplied Pickle Opcode Inventory

The `AOE-GE-D23-S03` partial specialist inventories opcodes in one bounded,
caller-supplied Python pickle byte string. It uses the standard library's
`pickletools.genops` syntax scanner. It does not call `pickle.load`,
`pickle.loads`, or an application deserializer. The source is not fetched from
a file, URL, service, or target.

The exact native model declares `schema_version: 1`,
`semantics_profile: python-pickletools-opcode-inventory-v1`, an opaque source
ID, and canonical base64 for at most 8 KiB of bytes. The inventory records
opcode counts and byte offsets for resolution, construction, persistent-ID,
and state-application opcodes. It requires one complete stream ending at its
final byte. An opcode in one of those categories is a review candidate only.
It is not proof that an application loads the bytes or that an exploit exists.

This parser does not validate full stack semantics, model extension registry
state, execute constructors, resolve classes, or test a target deserializer.
Its replay report embeds the supplied source and is nonqualifying. It grants
no action authority and has no file, network, process, credential, target,
publication, or execution effects. The [synthetic example](../examples/offline-pickle-opcode-component.json)
contains a benign class reference and is never unpickled.
