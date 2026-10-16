# ship-no-ship-service

The macOS service that runs ship-no-ship reviews on a machine the repository
owner controls. See the repository README for the project overview.

## Installed layout

`ship-no-ship-service doctor` checks this table (`doctor.table`). `<data>` is
`/Library/Application Support/ship-no-ship`, owned `root:wheel 0755`. The
LaunchDaemon label is `ship-no-ship.daemon`.

| Path | Owner:group | Mode |
|---|---|---|
| `/usr/local/libexec/ship-no-ship/` and everything in it | `root:wheel` | dirs `0755`, files `0755` or `0644`; links stay inside |
| `/etc/sudoers.d/ship-no-ship` | `root:wheel` | `0440` |
| `/etc/newsyslog.d/ship-no-ship.conf` | `root:wheel` | `0644` |
| `/Library/LaunchDaemons/ship-no-ship.daemon.plist` | `root:wheel` | `0644` |
| `<data>/config/`, `config/service.toml` | `root:_ssnsd` | `0750`, `0440` |
| `<data>/keys/`, `keys/*.pem` | `_ssnsd:_ssnsd` | `0700`, `0400` |
| `<data>/state/`, `state/state.db*` | `_ssnsd:_ssnsd` | `0700`, `0600` |
| `<data>/mirror/`, `<data>/requests/` | `_ssnsd:_ssnsd` | `0755` |
| `<data>/work/` | `root:wheel` | `0755` |
| `<data>/captured/` | `_ssnsd:_ssnsd` | `0700` |
| `<data>/run/`, `run/*.json` | `_ssnsd:_ssnsd` | `0755`, `0644` |
| `<data>/attempts/` (supervisor process records) | `root:wheel` | `0700` |
| `<data>/home/<cli>/` | `_ssns<cli>` | `0700` |
| `/Library/Logs/ship-no-ship/` | `_ssnsd:admin` | `0750` |

The supervisor's process records live in `<data>/attempts/`, not under the
daemon-owned `run/`, so the daemon cannot replace them.

Every directory above a listed path must be owned by root (or, above a path a
service user owns, by that user), must not be group-writable except by wheel or
the path's own service group, must not be world-writable or carry a write ACL,
and must not be a symlink other than `/etc`, `/tmp` or `/var`. No person may be
a member of wheel or a service group.

Run `sudo ship-no-ship-service doctor` once installed. Exit codes: 0 passed,
1 failed, 3 incomplete (a check did not run). `--allow-not-run` is for use
before installation only.
