# Offline API retest lineage

An offline retest has two separate histories: the source identifiers used by
each assessment batch and the immutable world observations derived from those
sources. `build_initial_offline_api_retest_lineage` starts both histories from
one reproduced batch and its verified projection.

`append_offline_api_retest_lineage` verifies the prior archive, reproduces the
new batch, rejects cross-batch source replay, verifies its projection, and
appends only new facts to a child world snapshot. It returns a single
content-addressed envelope binding the latest source ledger, child snapshot,
and parent lineage digest. A contradictory negative retest remains visible
alongside the earlier hypothesis, including the resulting conflict. It does
not erase the original observation or establish a verified attack path.

`verify_offline_api_retest_lineage` checks archived structure and hashes. When
the prior envelope is supplied, it also checks exact parent linkage, context,
and retained source entries. It cannot authenticate the producer of prior
sources or prove that an observation is currently valid. Source replay and
current authority checks remain required before any positive use. The
envelope has no execution, network, qualification, or publication effects.
