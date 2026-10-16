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

## License

MIT. See [LICENSE](LICENSE).
