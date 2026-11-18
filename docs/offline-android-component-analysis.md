# Supplied Android component declarations

`sunderkey.offline_android_component_analysis` computes a finite exported/enabled
declaration subset from caller-supplied merged metadata. It neither reads an APK
nor decodes XML. A resolved row is not installation success, current component
state, IPC access, permission enforcement or a vulnerability judgment.

This is partial offline evidence for `AOE-GB-D08-S03`, `army.gb.d08.s03`,
`AV-GB-D08-S03-01`, `IWP2-AOE-GB-D08-S03`, `IW2-007`, commander
`AOE-GB-D08-CMD`, group `AOE-HQ-04`, validator `AOE-HQ-19` and roadmap A7.4.
The blueprint is
`sha256:85aad60ac63ea5f31466de3fcbc888d6ce67b9ec1358e231de7ee8a34709031b`.
Component ID: `android_supplied_component_declarations`.

## Primary semantics and exact subset

Android documents the explicit-exported requirement for target SDK 31 and higher
filter-bearing activities, services and receivers. See the official
[Android 12 behavior changes](https://developer.android.com/about/versions/12/behavior-changes-12#exported).
The analyzer does not assert that a supplied projection is the actual installed
manifest, or that this isolated rule establishes installability.

The pinned rule is AOSP commit
[`c4e90ac06ad3e0fd2af9e3864742e2d1199a8cdd`](https://android.googlesource.com/platform/frameworks/base/+/c4e90ac06ad3e0fd2af9e3864742e2d1199a8cdd%5E%21/):
the missing-exported check applies above target SDK 30. Parser defaults are
checked against
[activity/receiver parsing at `ff4060f5a59b787139570d733712fae34283ed6c`](https://android.googlesource.com/platform/frameworks/base/+/ff4060f5a59b787139570d733712fae34283ed6c/core/java/android/content/pm/parsing/component/ParsedActivityUtils.java)
and
[service parsing at `380f9be2ee11a8caa2f5eb053cdcd3ea88c93545`](https://android.googlesource.com/platform/frameworks/base/+/380f9be2ee11a8caa2f5eb053cdcd3ea88c93545/core/java/android/content/pm/parsing/component/ParsedServiceUtils.java).
These checks use retained parsed filters. Some malformed activity/receiver
filters can be discarded; a raw `<intent-filter>` element alone is not the
model's retained-filter premise. No upstream implementation is copied.

Application enabled defaults to true and combines with component enabled,
which also defaults to true. See the official
[application enabled attribute](https://developer.android.com/guide/topics/manifest/application-element#enabled)
and
[enabled parsing at `android-12.0.0_r1`](https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/android-12.0.0_r1/core/java/android/content/pm/parsing/component/ParsedMainComponentUtils.java).
The subset excludes compatibility overrides, runtime toggles, aliases,
providers, permission checks and all other manifest/package validation.

## Closed model

```json
{
  "schema_version": 1,
  "source_id": "synthetic-merged-declarations",
  "projection_complete": true,
  "target_sdk": 31,
  "application_enabled": null,
  "components": [
    {
      "component_id": "activity-explicit",
      "kind": "activity",
      "enabled": null,
      "exported": false,
      "has_intent_filters": true
    }
  ]
}
```

All fields are required and closed. Names are opaque declared source/component
identifiers, not class-name validation. Component IDs are unique across the
supplied array. An explicitly empty component array is supported; it is not
evidence that a real application has no components.

`kind` is exactly `activity`, `service` or `receiver`. `enabled` and `exported`
are exact native booleans or null. Null means declared attribute absence, not
unknown extraction. `application_enabled` follows the same rule. Filter
presence and projection completeness are exact booleans. `target_sdk` is an
exact integer from 1 through 2,147,483,647 or null, where null means the target
SDK premise is unavailable, not a manifest default.

`projection_complete` is a caller assertion that these fields are complete
merged declarations. False withholds all effective declaration conclusions;
the raw supplied attributes remain visible. True is not independently verified.

## Declaration results

For a complete projection, application and component enabled declarations
combine by conjunction after applying their true defaults. Explicit false is
never replaced by a default. Exported is resolved as follows:

- Explicit true or false is retained at every supplied target SDK, including an
  unavailable target SDK.
- With no retained filters, an absent exported attribute defaults to false.
- With retained filters and target SDK below 31, absence defaults to true.
- With retained filters and target SDK 31 or higher, absence yields
  `missing_required_exported_declaration`, even when the application or
  component is disabled. No effective exported value is asserted for that row.
- With retained filters, absent exported and unavailable target SDK, the row is
  `unassessed` rather than guessing a historical or modern default.

Rows retain `requires_explicit_exported` separately from whether that
requirement is satisfied. An explicit attribute can satisfy either possible
SDK branch without proving the unavailable SDK value. The combined
`declared_enabled_and_exported` is only a declaration conjunction, never an
external reachability or access result.

## APIs and replay

`analyze_supplied_android_components(model)` and
`analyze_supplied_android_components_bytes(model_bytes=...)` return the exact
frozen `AndroidComponentAnalysis` family. Native bytes intake requires ASCII
JSON; there is no file loader or acquisition callback. `component_fixture()`
returns a fresh wholly synthetic model with an explicit false activity, a
disabled filter-bearing service missing exported, and a no-filter receiver.

`from_dict`, `from_json`, `to_dict` and `to_json` recompute the entire result
from its embedded original model. A coherently rehashed false conclusion does
not pass this content replay. Exports are detached. A coherently changed
source can still describe unsigned content;
`verify_supplied_android_component_analysis(report, model=original)` additionally
requires the separately supplied original model. Hashes do not authenticate
the source, prove merge completion or grant current device authority.

The separate address domains are
`sunderkey.offline-android-component-model.v1` and
`sunderkey.offline-android-component-analysis.v1`. IDs have prefix `ACD-`.
All promotion flags are false and every effect is `none`.

## Software-cost ceilings

Per document, native model, raw model and retained report ceilings are 1 MiB,
32,768 nodes including dictionary keys, depth 16, and 512 printable ASCII
bytes per string. Source/component IDs are at most 128 characters. Numeric
values have signed-64-bit intake limits before decimal conversion. The model
allows at most 1,024 component declarations, subject to the stricter aggregate
input and output ceilings; not every maximum-sized model fits its report.

Repeated shared subtrees are charged per occurrence. Native bounds precede
copying, serialization and hashing. The raw scanner bounds values, escaped
strings, keys, nodes, scalar/container depths and numeric lexicals before JSON
decoding, with duplicate-key rejection. Construction charges row retention
incrementally and reserves complete fixed-width identities before retaining
the final report. Cumulative work is capped at 8,388,608 byte/node reservation
units per reconstruction, including full result serialization, equality and
bounded replay/export reserves before either digest. Each export performs a
new bounded reconstruction; this is not a lifetime limit on caller calls or a
wall-clock/process-memory guarantee. Software exhaustion raises
`AndroidComponentAnalysisError`, not a negative declaration observation.

No APK/XML/file access, merging, installation, IPC, target interaction, runtime
toggle, process, network, credential, provider, retry or qualification occurs.
