# Evaluation Corpus Assembly and Contamination Checks

WQ-001 provides a deterministic repository-only boundary for assembling a
versioned evaluation corpus manifest from caller-supplied local records. The
module emits content-addressed receipts, exact and approximate duplicate
indicators, holdout separation checks, and explicit contamination findings.

This capability does not discover files or directories. It does not read a
path, contact a network service, invoke a provider or model, execute a
subprocess, access a target, run an evaluation, grant authority, or issue a
qualification decision.

## Caller-supplied records

Each input record has an exact closed shape:

- record identity and immutable version
- one required corpus partition
- source identity, immutable version, and SHA-256 digest
- provenance SHA-256 digest
- nonempty caller-supplied text content

The five required partitions are `public`, `private_holdout`,
`adversarial_safety`, `regression`, and `pilot`. At least one record must be
present in every partition. Record identifiers must be unique. Moving versions
and unknown fields are rejected.

The caller supplies content directly to the API. Content is never loaded from
a path, and the receipt does not retain it. The receipt records the UTF-8 byte
digest, byte count, token count, and a bounded set of hashed two-token shingle
components. This representation supports deterministic overlap checks without
placing raw corpus text in the manifest. Hashed components reduce disclosure
but are not a confidentiality system, so receipts still require appropriate
custody.

## Duplicate and contamination analysis

Exact duplicate indicators compare content digests. Near-duplicate indicators
compare the Jaccard overlap of bounded hashed shingle components. The threshold
is an integer number of basis points and is part of the receipt budget.
Approximate similarity is only an indicator. It does not assert semantic
equivalence.

Cross-partition pairs involving `private_holdout` or `adversarial_safety` are
holdout separation checks. The assembler reports separate findings for:

- exact content overlap
- near content overlap
- source digest overlap
- provenance digest overlap

Every finding is marked `requires_independent_review`. Findings do not change
qualification state or grant authority. Exact or approximate duplicates that
exist only between nonholdout partitions remain visible as indicators but do
not create a holdout contamination claim.

## Resource budgets

Assembly fails closed against explicit ceilings for record count, total and
per-record content bytes, tokens per record, pair comparisons, findings, and
fingerprint components. The comparison threshold is also recorded. Pair count
is checked before pairwise analysis begins, and byte and token limits are
checked before accepting a record into the manifest.

## Integrity and verification

Records, partition memberships, indicators, findings, and the overall receipt
are canonically serialized with printable ASCII JSON and bound to SHA-256
content addresses. `EvaluationCorpusAssemblyReceipt.from_dict`,
`EvaluationCorpusAssemblyReceipt.from_json`, and
`verify_evaluation_corpus_receipt` reject unknown or missing fields, duplicate
JSON keys, invalid identifiers and digests, reordered records, budget
violations, altered derived checks, and content-address mismatches.

Replay compares canonical JSON with the fully reconstructed receipt, not
Python value equality. Boolean substitutions for integer counts or basis
points are rejected even when Python would compare them as equal. The schema
version must be a native integer, and floats remain unsupported. Both a stale
address and a newly calculated address over incorrect derived values fail
verification. Valid native JSON retains its existing serialized identity.

The strict Draft 2020-12 schema is located at
`registry/schemas/evaluation-corpus-assembly-v1.schema.json`. Python
verification remains authoritative for content-address reconstruction,
cross-record uniqueness, partition coverage, pairwise similarity, and derived
finding consistency.

## Effects and limitations

Every receipt records `none` for authority, evaluation execution, model calls,
network access, provider calls, qualification, routing, and target access. A
clean receipt means only that the supplied bounded records produced no holdout
contamination indicator under this deterministic method. It does not prove
that an external corpus is uncontaminated, grant access to a corpus, or make a
candidate eligible for execution or qualification.
