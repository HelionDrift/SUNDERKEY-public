# Supplied Smartcard File-Access Projection

The GD-D18-S13 partial component compares at most 64 synthetic card-file
access declarations against caller-supplied role policies. It lists declared
read or write roles absent from the corresponding policy. Separate verification
replays the original supplied model.

Roles, files, policy, access declarations, and completeness are unverified
assertions. A mismatch does not establish actual card access or a vulnerability.
The component does not connect to a card or reader, use a radio, send an APDU,
read file contents, access a credential, or interact with a target. It cannot
grant authority, publish a finding, or qualify the specialist. RFID and NFC
radio behavior are outside this first partial model.

The checked synthetic example is
[`examples/offline-smartcard-file-component.json`](../examples/offline-smartcard-file-component.json).
