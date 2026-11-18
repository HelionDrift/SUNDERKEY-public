# Supplied RINEX 4.02 Observation Header Projection

The GD-D25-S09 partial component inspects a bounded, synthetic subset of a
RINEX 4.02 observation-file header. The [IGS/RTCM RINEX 4.02 format](https://files.igs.org/pub/data/format/rinex_4.02.pdf)
defines the fixed header labels in columns 61 through 80 and the version,
file type, marker, and per-system observation-type declarations. The checked
example is [`examples/offline-rinex-observation-header-component.json`](../examples/offline-rinex-observation-header-component.json).

Only five labels, one-line observation lists of at most 13 codes per system,
and ASCII LF records of exactly 80 columns are supported. Continuations,
optional records, observation measurements, and navigation records are
excluded. This is not a full RINEX conformance check. A declared marker or
observation code does not establish station identity, signal quality,
position, or time accuracy.

No file is acquired from a receiver or target. No finding or qualification
is produced. Independent verification replays the separate original model.
