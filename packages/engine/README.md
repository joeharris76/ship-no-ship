# ship-no-ship

The ship-no-ship review engine: it plans, runs and reports independent AI code
reviews that gate pull requests. See the repository README for the project overview.

## Command line

Installing the package provides the `ship-no-ship` command with the
subcommands `plan`, `select`, `review`, `ensure-attempt`, `finalize`, `guard`,
`sweep` and `validate-config`. Review markers, review bodies and plan fields
match the oracle reviewer engine this package was extracted from, so reviews
written by either can be read by the other.

`plan` and `validate-config` take `--policy <file>` and `--root <dir>`
(default: the current directory). Relative paths in the policy, such as the
path manifest, are resolved against `--root`, which should be the checkout of
the repository under review.

`validate-config` checks the policy and loads its path manifest. It prints a
summary and exits 0, or prints the first problem and exits 1.

## Policy

The policy is a YAML file. Reviewers, tiers, classifier rules, retry and
protocol limits are the same in both versions. Version 2 adds two blocks:

```yaml
version: 2
repository:
  base_branch: main                      # required
  paths_manifest: config/review-paths.txt  # required, relative to --root
  bot_login: review-bot                  # required, the GitHub App's slug
  slug: octo-org/widgets                 # optional; plan and sweep refuse other repositories
  workflows:                             # optional
    verdict: .github/workflows/oracle-verdict.yml
    record: .github/workflows/oracle-verdict-record.yml
  artifacts:                             # optional
    plan: oracle-verdict-plan
    request: oracle-verdict-request
    state_prefix: oracle-verdict-state-
  heartbeat_context: ship-no-ship/heartbeat  # optional
executor:                                # optional
  mode: hosted                           # hosted | proof | local
  proof_label: oracle-local-proof
```

The values shown for the optional keys are their defaults. In version 2,
`bot_login` belongs under `repository`; a top-level `bot_login` is an error.

A version 1 policy keeps `bot_login` at the top level, may not contain
`repository` or `executor`, and gets the defaults above plus
`base_branch: develop` and `paths_manifest: .github/soundness-paths.txt`.

`plan` reviews only open, non-draft pull requests into `base_branch`, accepts
`workflow_dispatch` runs only from that branch, and fails before planning if
the path manifest is missing or malformed. `sweep` lists open pull requests
into `base_branch` and dispatches the `verdict` workflow on that branch. Retry
state is read from artifacts named `<state_prefix><pr>` uploaded by the
`verdict` workflow.

`executor` and the `record`, `plan`, `request` and `heartbeat_context` names
are validated now and used by the local review service.

## Path manifest

The path manifest lists the files whose changes need review, one rule per
line as `kind<TAB>pattern`. Blank lines and lines starting with `#` are
ignored.

| Kind | Matches |
|---|---|
| `file` | the exact path |
| `glob` | an `fnmatch` pattern; `/**/` also matches a single `/`. The pattern also matches itself as an exact path |
| `prefix` | any path starting with the pattern, which must end with `/` |
| `regex` | a Python regular expression matched at the start of the path |

Paths are compared after trimming whitespace and turning `\` into `/`. A
manifest with no rules, an unknown kind, a missing tab, a prefix without a
trailing `/` or an invalid regular expression is an error.
