# Supplied Cache-Set Mapping Projection

The GD-D18-S11 partial component maps synthetic addresses into declared
cache lines and sets, then counts distinct lines per set against a supplied
way count. The checked example is
[`examples/offline-cache-set-projection-component.json`](../examples/offline-cache-set-projection-component.json).

The arithmetic is a simplified parameterized model of cache lines, sets,
and associativity. Intel's [optimization reference](https://www.intel.com/content/dam/doc/manual/64-ia-32-architectures-optimization-manual.pdf)
describes set-associative caches and competition for ways. This component
does not establish actual cache topology, physical address mapping,
replacement behavior, misses, timing, leakage, or a side channel. It
does not retain addresses or line tags in the report.

No target, process, device, or provider interaction occurs. No finding or
qualification is produced. Independent verification replays the separate
original model.
