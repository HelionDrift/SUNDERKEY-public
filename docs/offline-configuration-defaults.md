# Supplied Layered Configuration Defaults

The `AOE-GE-D23-S13` partial specialist compares a caller-declared required
setting value with a default and an ordered sequence of supplied scope layers.
Each layer can declare an explicit value, inheritance, or an unknown value.
The last explicit layer determines the computed effective value. The result
compares that value with a separately declared effective value.

A complete and consistent declaration with a default that differs from the
required value yields `candidate_declared_insecure_default` only when every
layer inherits. A conflicting explicit layer yields
`candidate_declared_insecure_override`. Missing declarations, unknown values,
and mismatched effective values withhold those candidate dispositions. The
model does not know a platform's actual precedence or whether the setting
controls a real security boundary.

The source is limited to 64 settings, eight layers per setting, and 32 KiB.
The 64 KiB report embeds the original native model for separate-source replay.
Setting and scope labels are inert identifiers. This projection does not read
a configuration, contact a target, establish an insecure default, or grant
any authority, execution, publication, or qualification effect. The
[synthetic example](../examples/offline-configuration-defaults-component.json)
contains only caller assertions.
