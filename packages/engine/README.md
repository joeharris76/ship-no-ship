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

`executor` selects where reviews run. `ORACLE_EXECUTOR` may force `hosted`
(it accepts nothing else) as a rollback switch. Under `local`, a review plan
outputs `handoff=true` and `post=false`, records `"executor": "local"` in
`plan.json`, and writes `request.json` and usually `queued-status.json`.
Consumer workflows must skip their reviewer and post jobs when `handoff` is
`true`, upload the plan directory as the `request` artifact, and run
`ship-no-ship post-queued-status --plan <plan dir>/plan.json` when
`queued_status` is `true`, rather than posting `queued-status.json` themselves.
That command re-reads the head's newest status and posts the waiting status
only if the status is unchanged since `plan` read it. If the status cannot be
re-read, it posts nothing. A status posted in the one API call between the
re-read and the post can still be covered; the sweep's re-offer and the
service's next status repair that. As a backstop, `select`,
`review` and `finalize` exit with an error on a local review plan inside
GitHub Actions. Hosted plans omit the `executor` key, so their `plan.json` is
unchanged. `executor.stalled_after_hours` (default 24) is how long a head may
sit queued or running at the local reviewer before the sweep offers it again.
A re-offered stalled head gets a new waiting status, so it goes to the back
of the queue. No head is re-offered within 60 minutes of its last status,
even when `stalled_after_hours` would allow it sooner.

Under `local`, the sweep also keeps one issue labelled `oracle-local-offline`
while the heartbeat is stale. It opens the issue when a pull request waits for
the local reviewer, lists the waiting pull requests (or says none is waiting),
and closes it when the heartbeat is fresh again. It touches only open issues
with that label and title that the App's bot (`<bot_login>[bot]`) opened, so
the sweep must use the App's token and needs `issues: write`.

### Reviewer availability

A quota absence blocks the reviewer's pool until the reset time the CLI
states. The reset time is read only from the line that holds the CLI's quota
message, never from the rest of the reviewer's output. A stated reset is
capped at 7 days. When no reset time is stated, or it cannot be parsed, the
pool is blocked for `retry.quota_default_block_minutes` (default 60).

Reviewers whose CLI needs a credential variable on hosted runners (agy needs
`GEMINI_API_KEY`) are marked `auth` absent without running when that variable
is missing. This check runs only when `GITHUB_ACTIONS` is `true` or
`ORACLE_EXECUTOR` is `hosted`. A local review service signs reviewers in as
their own users and must never set either variable in a reviewer's
environment.

### Retry state generations

Each retry state carries a `generation` and the `predecessor` it replaces.
`finalize` writes the successor of the state its plan read, and
`latest_state` reads trusted state artifacts newest first and keeps the
highest generation among the newest three it can read. At equal
generations a state that `record-state` accepted beats one a plan run
wrote, and otherwise the newer artifact wins. For `plan` and `sweep`, an
artifact that cannot be read is skipped with a warning; `record-state`
fails instead, because the unread state could be the current generation.

`record-state` checks a state sent back by the local review service. The
plan run it names must be a trusted run whose `request` artifact planned a
review of that pull request and head, and that head must still be the pull
request's head. The state is written to `--out` only when it is the successor
of the current generation, and it is then tagged with the record run's ID;
`latest_state` ignores record-run state without that tag. A workflow must
upload `state.json` only when `record-state` outputs `upload=true`, and must
name the artifact with the `artifact` output, never a prefix written into the
workflow.

With `--proof`, the state comes from a proof run. The plan must be a proof
plan, the state must follow the generation that plan read, and `artifact` is
`<proof_state_prefix><pr>` (default prefix `oracle-verdict-proof-state-`),
which `latest_state` never reads. Gating and proof state are never accepted
for each other, and the two prefixes must not start each other.

Writers of state must share one concurrency group per pull request, for
example `oracle-verdict-state-<pr>` without `cancel-in-progress`, and it
must cover everything from the plan's read of the state to the upload: the
whole `verdict` workflow (or its plan, reviewer and post jobs together) and
the whole `record` workflow. Generations order the writes; the shared group
keeps a hosted run and a record run from both writing the same generation,
and keeps generations in time order, which is why reading the newest three
artifacts is enough.

Rollback: an engine from before generations writes state without one. When
such a state is the newest readable artifact, `latest_state` returns it and
reads nothing older, so a rolled-back engine keeps working on its own newest
state. When a newer engine runs again, it writes generation 1 on top of it.

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
