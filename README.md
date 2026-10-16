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

## License

MIT. See [LICENSE](LICENSE).
