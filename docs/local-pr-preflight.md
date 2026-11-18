# Local PR Preflight

Run `python scripts/check_pr_preflight_local.py` before pushing a branch. It
executes the same repository-only preflight checks as CI, with the
critical-test manifest and release-version assertions first for fast failure.
CI runs that manifest check last. The local runner does not install
dependencies, run the eight complete test shards, call a provider, or contact
a target. `--plan` lists the checks without executing them.

The CI preflight itself checks that its repository commands and the local
runner's commands remain the same set. Local ordering may differ for fast
failure, but adding or removing a CI repository check requires updating the
runner in the same change.

When CPython 3.11 and the reviewed dependencies are already installed,
`--environment` also checks the CI dependency lock and installed packages.
The default mode remains useful on other supported local interpreters, but
cannot substitute for the Python 3.11 environment and full required CI run.
Passing this local preflight never authorizes a merge by itself. The exact PR
head still needs CI preflight, all eight shards, and the aggregate `checks`
job to pass.
