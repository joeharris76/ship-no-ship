# ship-no-ship

ship-no-ship gates pull requests on an independent AI code review. It decides
whether a change needs review, picks reviewers from a configured chain, runs
them read-only against the pull request, and posts a SHIP, SHIP WITH FIXES or
DO NOT SHIP verdict that a required status check can enforce.

The project has two parts:

- an engine that plans, runs and reports reviews, installable by any
  repository that supplies a policy file; and
- a macOS service that runs those reviews on a machine the repository owner
  controls, so no reviewer credentials live in CI.

The project is at an early stage and its interfaces are not yet stable.

## Repository layout

- `packages/engine`: the `ship-no-ship` distribution (import `ship_no_ship`).
  Its only runtime dependency is PyYAML.
- `packages/service`: the `ship-no-ship-service` distribution (import
  `ship_no_ship_service`).
- `tests`: tests for both packages and for the repository itself.
- `scripts/check_publish_safety.py`: fails if a tracked file holds an absolute
  home path, a real email address, a credential pattern, or (in `examples/`
  and `macos/`) a host name, IP address, or numeric App or installation ID.

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
```

## License

MIT. See [LICENSE](LICENSE).
