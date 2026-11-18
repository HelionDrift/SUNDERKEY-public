# Supplied Visitor Escort Record Review

The GA-D02-S09 partial component compares bounded synthetic visitor records
with caller-declared controlled entries and escort requirements.
[NIST SP 800-53 PE-3 and PE-8](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf)
address physical access control and visitor access records. The checked example
is [`examples/offline-visitor-escort-record-component.json`](../examples/offline-visitor-escort-record-component.json).

The analyzer counts declared missing escort and exit fields and checks visit
chronology. These are record gaps, not proof of an access-control failure or
tailgating. Supplied records are not authenticated, and no person, facility,
badge, sensor, or escort is observed. No visit, contact, finding, or
qualification occurs.
