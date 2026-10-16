# ship-no-ship

ship-no-ship gates pull requests on an independent AI code review. It decides
whether a change needs review, picks reviewers from a configured chain, runs
them read-only against the pull request, and posts a SHIP, SHIP WITH FIXES or
DO NOT SHIP verdict that a required status check can enforce.

The project has two parts:

- an engine that plans, runs and reports reviews for a repository that
  supplies a policy file and a path manifest (see
  [packages/engine/README.md](packages/engine/README.md)); and
- a macOS service that runs those reviews on a machine the repository owner
  controls, so no reviewer credentials live in CI.

The project is at an early stage and its interfaces are not yet stable.

## Repository layout

- `packages/engine`: the `ship-no-ship` distribution (import `ship_no_ship`).
  Its only runtime dependency is PyYAML.
- `packages/service`: the `ship-no-ship-service` distribution (import
  `ship_no_ship_service`).
- `tests`: tests for both packages and for the repository itself.
- `scripts/check_publish_safety.py`: the publish-safety check (below).
- `scripts/build_wheels.sh`, `scripts/verify_wheel.py`,
  `scripts/check_release_version.py` and `build-constraints.txt`: the
  release build and checks (see [Releasing](#releasing)).

## Publish safety

The repository is private now and meant to become public, so CI fails when it
finds content that should not be published. `scripts/check_publish_safety.py`
reads files from git, not the working tree, so a symbolic link is checked as
its link text. It reports:

- absolute home paths (`/Users/<name>`, `/home/<name>`, `C:\Users\<name>`);
- credential patterns (GitHub, AWS, Slack, Google and `sk-` API keys, private
  key blocks, and `user:password@` credentials in URLs), printed masked;
- email addresses, except placeholder domains such as `example.com` and
  GitHub noreply addresses, printed with the local part masked;
- IPv4 and IPv6 addresses other than loopback and `0.0.0.0`, numeric App or
  installation IDs, and private host names (`.local`, `.lan`, `.internal`,
  `.localdomain`, `.home.arpa`, `.ts.net`).

With no option it checks the files in the git index. With `--history` it also
checks every blob reachable from any ref, every commit message, every
annotated tag message, and commit author, committer and tagger email
addresses. A blob stored at several paths is checked once.

`scripts/publish-safety-allow.txt` lists the exceptions:

- `blob<TAB><sha><TAB><rule>` skips one rule for one git blob wherever it
  appears, for example an old version of a test file that held sample values;
- `commit-email-sha256<TAB><hex>` allows a commit or tag email address in
  history by its SHA-256. Allowed addresses are still printed, so the decision
  to keep them stays visible.

CI also runs gitleaks over the full history.

Limits: the check matches patterns, so it misses credentials in formats it
does not know, encoded or split values, and host names under public domains.
It skips binary files and lists each one it skipped. It does not read git
notes, stashes, reflogs, unreachable objects, branch or tag names, or
anything stored only on GitHub, such as pull request titles, descriptions and
comments, and it cannot remove anything already pushed.

## Development

The project uses [uv](https://docs.astral.sh/uv/) and supports Python 3.11
and later.

```sh
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run ty check
uv run python scripts/check_publish_safety.py
uv run python scripts/check_publish_safety.py --history
```

## Releasing

Only the repository owner cuts releases. The repository has no branch or tag
protection while it is private, so nothing on GitHub enforces this; it is a
rule for every contributor and agent. Do not push a `v*` tag unless you are
the owner.

To cut a release, the owner:

1. merges a change to `main` that sets the same version in
   `packages/engine/pyproject.toml` and `packages/service/pyproject.toml`, and
   in the service's `ship-no-ship==<version>` dependency;
2. tags that commit on `main` as `v<version>`, for example `v0.2.0`, and
   pushes the tag.

The `release` workflow (`.github/workflows/release.yml`) then:

- fails unless the tag's commit is on `main` and the tag matches both package
  versions (`scripts/check_release_version.py`);
- builds both wheels twice with `scripts/build_wheels.sh`, from fresh
  worktrees at different paths, with `SOURCE_DATE_EPOCH` set to the commit
  time and the build backend pinned by hash in `build-constraints.txt`, and
  fails unless the two builds are byte-identical;
- checks each wheel with `scripts/verify_wheel.py` and installs both into a
  clean virtual environment;
- writes `SHA256SUMS` and a source diff from the previous `v*` tag (or from
  the empty tree for the first release); and
- creates a GitHub release with the wheels, `SHA256SUMS` and the diff, after
  checking that the tag still points to the commit it built.

Only the publishing job can write to the repository. Nothing is published to
PyPI. CI runs the same reproducible build on every pull request.

Anyone can rebuild a release and compare it with the published sums:

```sh
scripts/build_wheels.sh v0.2.0 dist/
```

`scripts/verify_wheel.py` checks a wheel before a repository that vendors it
trusts it: the file's SHA-256, every `RECORD` hash and size, and that the
wheel holds only the expected package and its `.dist-info` directory, with no
`.pth` files, compiled code, `.data` directory or unexpected entry points. It
needs Python 3.11 or later and only the standard library, so it can be copied
as is:

```sh
python3 scripts/verify_wheel.py ship_no_ship-0.2.0-py3-none-any.whl \
  --sha256 <sha256 from SHA256SUMS> --version 0.2.0 --package ship_no_ship \
  --console-script 'ship-no-ship=ship_no_ship.engine.cli:main'
```

## License

MIT. See [LICENSE](LICENSE).
