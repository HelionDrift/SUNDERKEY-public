# Offline FHIR Device Association Review

This partial GD-D25-S11 algorithm compares a privacy-minimal synthetic [FHIR R5 Device](https://hl7.org/fhir/R5/device.html) record with one [DeviceAssociation](https://hl7.org/fhir/R5/deviceassociation.html) record. It checks the relative Device reference, a bounded Device status, and a single status coding from the [R5 DeviceAssociation Status Code System](https://hl7.org/fhir/R5/codesystem-deviceassociation-status.html). Only a synthetic Patient reference is accepted, and it is hashed in the report. Names, serial numbers, UDI values, clinical narratives, and other patient details reject.

An inactive Device paired with a declared implanted association or a mismatched reference is a review cue, not a device fault, patient-safety conclusion, FHIR conformance result, or cybersecurity finding. FHIR R5 DeviceAssociation is a draft resource; this component implements only its stated subset. It does not access a clinical record, device, or FHIR server.

The fixture is synthetic, R0, dry-run, and has no credential or resource grants. Original-model replay is required. No operational authority, positive use, or qualification is granted.
