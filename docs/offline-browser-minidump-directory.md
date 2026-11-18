# Supplied Browser Minidump Directory Projection

The GE-D21-S07 partial component checks the header and stream-directory
geometry of a bounded synthetic minidump. Chromium uses Crashpad for crash
reports, and [Crashpad's minidump definitions](https://chromium.googlesource.com/chromium/src/+/b212e219b061f342502635af586ff4fc0e14a4d5/third_party/crashpad/crashpad/compat/non_win/dbghelp.h)
define the signature, version, header, and directory entries. The checked
example is
[`examples/offline-browser-minidump-directory-component.json`](../examples/offline-browser-minidump-directory-component.json).

The parser bounds the supplied bytes and directory count, validates offsets,
rejects duplicate or overlapping structural ranges, and reports stream types
and lengths without retaining payload bytes. It does not parse stack memory,
identify a browser process, infer crash cause, or assess exploitability. The
fixture is synthetic, and independent verification replays the separate
original model. No browser, debugger, process, or target is contacted. No
finding or qualification is produced.
