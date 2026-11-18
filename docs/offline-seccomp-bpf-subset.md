# Offline Seccomp BPF Subset Projection

This partial GE-D21-S08 algorithm interprets a bounded synthetic classic-BPF seccomp subset. It supports only word loads of `seccomp_data.nr` and `.arch`, equality jumps against constants, and three return actions: kill process, errno, and allow. It validates all forward branches before projecting actions for supplied test cases. The opcode structure and return constants follow the [Linux UAPI filter header](https://github.com/torvalds/linux/blob/master/include/uapi/linux/filter.h), [seccomp header](https://github.com/torvalds/linux/blob/master/include/uapi/linux/seccomp.h), and [kernel seccomp guide](https://docs.kernel.org/userspace-api/seccomp_filter.html).

The projection is intentionally smaller than the kernel implementation. It does not model arguments, filter stacking, user notification, alternate ABIs, installation constraints, kernel versions, or an actual sandbox escape. It neither loads a BPF program nor executes a syscall. A projected `allow` or `errno` action is not proof of runtime enforcement or bypass.

The fixture is synthetic, R0, dry-run, and has no credential or resource grants. Original-model replay is required. The result makes no finding and grants no positive-use or qualification authority.
