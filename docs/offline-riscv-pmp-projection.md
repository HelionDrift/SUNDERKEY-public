# Offline RISC-V PMP Projection

This R0 analysis projects supplied, predecoded Physical Memory Protection (PMP)
intervals onto supplied S-mode and U-mode accesses. Entries are evaluated in
priority order. A lower-numbered entry that overlaps any access byte controls
the decision; a partial overlap denies. If no entry matches, this bounded model
denies the access. The 48-bit address ceiling is a model limit, not a statement
about all RISC-V implementations.

The output identifies mismatches against caller-supplied expectations. It is an
unsigned, nonqualifying candidate only. It does not decode CSRs, validate that
the entry set is complete, resolve virtual addresses, cover M-mode or Smepmp,
or prove a hardware decision. No SoC, network, process, credential or target
is contacted. Original-model replay is required to verify the report.

The priority and partial-match rules follow the
[RISC-V Privileged Architecture specification](https://docs.riscv.org/reference/isa/priv/machine.html).
