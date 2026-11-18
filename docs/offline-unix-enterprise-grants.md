# Supplied Enterprise Unix Grant Policy

The GC-D16-S03 partial component compares synthetic opaque grant triples with
a supplied policy for the AIX, Solaris, and HP-UX specialist lane. Its checked
example is [`examples/offline-unix-enterprise-grants-component.json`](../examples/offline-unix-enterprise-grants-component.json).

No host, native privilege database, credential, or network is accessed. The
model does not resolve platform-specific privilege semantics. A mismatch is
not proof of effective access or exploitation. The result is nonqualifying R0
evidence and grants no authority.
