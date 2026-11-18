# Supplied Hardware Trace and Timing Common Task

The checked common task joins GD-D18-S08 synthetic trace comparison and
GE-D22-S09 scalar timing summary as two distinct specialist jobs. Their
inputs are independent caller-supplied artifacts. The common task
preserves both original requests and their separate commander ownership,
requires R0 and empty resources before dispatch, and verifies the
combined report against the separate original task.

The comparison is methodological, not corroborating evidence of a
physical side channel. Neither input is an instrument capture and
neither report verifies leakage, a secret-dependent behavior, a target,
or qualification.
