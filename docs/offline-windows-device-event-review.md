# Supplied Windows Device Event Review

The GA-D02-S11 partial component parses one synthetic Windows Security 6416
version 1 XML event. [Microsoft's event reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-6416)
describes external-device recognition and its device and class fields. The
checked example is
[`examples/offline-windows-device-event-component.json`](../examples/offline-windows-device-event-component.json).

It checks a closed event subset and hashes the device ID in the report.
Recognition does not prove the device is removable storage, that files were
read or written, or that anyone placed it. The event source and operator are
not authenticated. No device is attached or accessed, and no finding or
qualification is produced.
