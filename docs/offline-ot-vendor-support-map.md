# Offline OT Vendor Support Map

This partial GD-D19-S07 algorithm projects supplied synthetic vendor-to-OT-asset support relationships. It records which declared assets have more than one vendor path and which paths lack selected, caller-declared safeguards: site initiation, time bounds, operator awareness, or session monitoring. [NIST SP 800-82 Revision 3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-82r3.pdf) discusses these considerations for temporary OT and vendor remote access. The output is not a NIST compliance result or an assertion that any particular safeguard is universally mandatory.

The input is a bounded graph of opaque vendor and asset references. Cross-references and duplicates are validated before projection. References are hashed in the report. A missing declared control or shared asset is a review cue only. The component cannot establish real network reachability, vendor identity, credential control, safety separation, or completeness of the site inventory.

The fixture is synthetic, R0, dry-run, and has no credential or resource grants. Original-model replay is required. No vendor, network path, process system, or safety system is contacted, and no positive-use or qualification authority is granted.
