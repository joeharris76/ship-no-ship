# ship-no-ship

The ship-no-ship review engine: it plans, runs and reports independent AI code
reviews that gate pull requests. See the repository README for the project overview.

## Command line

Installing the package provides the `ship-no-ship` command with the
subcommands `plan`, `select`, `review`, `ensure-attempt`, `finalize`, `guard`
and `sweep`. Their flags, outputs, review markers and plan fields match the
oracle reviewer engine this package was extracted from, so reviews written by
either can be read by the other.

`plan` needs a soundness path predicate to classify changed files. The
predicate is not yet configurable from the command line, so `plan` exits with
"no soundness path manifest is configured" until configuration support lands.
The other subcommands work on the plan directory `plan` writes.
