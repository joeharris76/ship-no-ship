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
path manifest, are resolved against `--root`.

The policy and the path manifest decide what gets reviewed, so they must come
from the trusted base commit, never from the pull request head. In a workflow,
check out `${{ github.sha }}` (under `pull_request_target`, the head of the
base branch) and run `plan` from that checkout. Before classifying a pull
request, `plan` compares the git blob hashes of the policy and the manifest
with the copies GitHub holds at `GITHUB_SHA`. It stops if either differs, if
`GITHUB_SHA` is not set, or if either copy cannot be read. The policy file must
therefore sit inside `--root`, and the workflow token needs `contents: read`.

`base_branch` must be the branch the workflow runs from. `issue_comment`,
`schedule` and `workflow_dispatch` runs of `plan`, and every `sweep`, exit 2
unless `GITHUB_REF` is `refs/heads/<base_branch>`; for comment and scheduled
runs that is the repository's default branch. A `pull_request_target` run
whose `GITHUB_REF` is another branch is a pull request into that branch: it
is skipped without review and reported with a `::warning::` annotation.

`validate-config` checks the policy and loads its path manifest. It prints a
summary and exits 0, or prints the problem and exits 1. With `--check-tree`
it also requires `--root` to be a git checkout in which the manifest matches
at least one tracked file, the `verdict` workflow to exist (and the `record`
workflow, unless `executor.mode` is `hosted`), and the policy's `slug`, if
set, to match `--repository` or `GITHUB_REPOSITORY`.

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
Unknown top-level keys are errors in both versions. `base_branch` is a branch
name, not a ref: `refs/...` and `HEAD` are rejected. `paths_manifest` must be
a relative path inside the repository. A `slug` is compared without regard to
case.

A version 1 policy keeps `bot_login` at the top level, may not contain
`repository` or `executor`, and gets the defaults above plus
`base_branch: develop` and `paths_manifest: .github/soundness-paths.txt`.

`plan` reviews only open, non-draft pull requests into `base_branch`, accepts
`workflow_dispatch` runs only from that branch (see above), and fails before
planning if the path manifest is missing, malformed or different from the base
commit's copy. `sweep` lists open pull requests into `base_branch` and
dispatches the `verdict` workflow on that branch. Retry state is read from
artifacts named `<state_prefix><pr>` uploaded by the `verdict` workflow, from
runs whose code is on `base_branch` (the branch is resolved through
`refs/heads/`, so a tag with the same name does not count). At most 1,000 such
artifacts are listed; more is an error.

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
