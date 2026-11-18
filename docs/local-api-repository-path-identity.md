# Local API Repository Path Identity

`SQLiteServiceRepository` is a local development and evaluation store. Its
constructor pins the supplied database path to an absolute path, so a later
working-directory change does not redirect reads or writes to another database.

For a new store, the constructor checks existing path components and creates
the database file exclusively before applying the embedded migration. For an
existing store, it rejects foreign or empty SQLite files before changing the
main database schema or setting WAL mode. The SQL read-only check compares the
migration identifier and digest, exact SQLite schema definitions compiled from
the embedded migration, and SQLite `quick_check` result. Schema is checked
before a bounded, two-row migration query. A valid existing store
can be reopened. SQLite may create or touch WAL sidecars during a read-only
reopen, including while inspecting a foreign WAL-mode database, so the check
does not promise zero filesystem writes.

Before opening SQLite, path inspection rejects symbolic links and Windows
reparse points in the database path or its existing parent components. It also
checks existing `-wal`, `-shm`, and `-journal` sidecar paths for links, reparse
points, and nonregular files. A repository file removed after initialization
is not silently recreated by a later repository operation.

These checks do not authenticate who created a matching database, prove an
external trust root or anti-rollback state, or replace
`SQLiteServiceRepository.verify_integrity()` for semantic content, audit, event,
and result verification. Constructor validation is not an atomic snapshot of
the filesystem. A concurrent process with permission to replace path
components or sidecars between inspection and SQLite open may still redirect
the open. Defending that race requires platform-specific handle-based opening
and directory identity controls outside this local adapter. A later replacement
with another regular file at the same absolute path is not independently
detected by the path inspection alone. No live authority,
production route enforcement, target action, or qualification is established.
