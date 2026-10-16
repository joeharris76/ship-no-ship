# ship-no-ship

The ship-no-ship review engine: it plans, runs and reports independent AI code
reviews that gate pull requests. See the repository README for the project overview.

## Command line

Installing the package provides the `ship-no-ship` command with the
subcommands `plan`, `select`, `review`, `ensure-attempt`, `finalize`, `guard`
and `sweep`. Their flags, outputs, review markers and plan fields match the
oracle reviewer engine this package was extracted from, so reviews written by
either can be read by the other.

## Current limits

The engine still carries assumptions from the repository it came from, so no
other repository can adopt it yet:

- `plan` needs a soundness path predicate to classify changed files. It is
  not configurable yet, so `plan` exits with "no soundness path manifest is
  configured" for any open, non-draft pull request on the base branch.
- The base branch is fixed to `develop`. `plan` skips a pull request that
  targets any other branch without reviewing it, `sweep` only looks at pull
  requests into `develop`, and dispatches and trust checks require `develop`.
- Workflow names are fixed: `.github/workflows/oracle-verdict.yml` for runs
  and dispatches, and `.github/workflows/oracle-review-shadow.yml` as a
  legacy source of retry state.
- Artifact names use the `oracle-verdict-state-` prefix, and the command
  reports itself as `oracle-verdict` in usage and error messages.

Policy configuration for the base branch, the path manifest, and workflow and
artifact names is planned and will remove these limits.
