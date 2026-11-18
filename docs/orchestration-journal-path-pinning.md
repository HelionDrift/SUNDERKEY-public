# Orchestration Journal Path Pinning

`SQLiteOrchestrationJournal` normalizes its supplied file path and pins it as an
absolute path when constructed. Later changes to the process working directory
cannot redirect that journal object to another valid database with the same
relative filename. The in-memory SQLite path remains disallowed. Fresh file
initialization, reopening, and concurrent initialization retain their existing
behavior.

This change does not authenticate the database or protect against a file or
directory alias, symlink, Windows reparse point, sidecar substitution, or a
regular file replaced at the same absolute path. Those require separate path
identity and filesystem-handle controls. The journal remains an
authority-neutral local custody component and grants no target action or
production qualification.
