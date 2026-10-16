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
| `<data>/home/<cli>/` | `_ssns<cli>` | `0700`; see role homes below |
| `/Library/Logs/ship-no-ship/` | `_ssnsd:admin` | `0750` |

Accounts. `_ssnsd` has home `/var/empty`; each role user `_ssns<cli>` has home
`<data>/home/<cli>/`. Every service account has shell `/usr/bin/false`.

Role homes may hold only what their CLI needs, and never a file that a shell or
Python loads on its own (`.zshrc`, `.zshenv`, `.zprofile`, `.zlogin`,
`.profile`, `.bashrc`, `.bash_profile`, `.bash_login`, `.pythonrc`,
`sitecustomize.py`, `usercustomize.py`, `Library/Python`, `.local/lib`):

| Role home | Expected entries |
|---|---|
| `home/claude/` | `.claude/`, `.claude.json`, `Library/` (keychain) |
| `home/codex/` | `.codex/` (`CODEX_HOME`), `Library/` |
| `home/muse/` | `.config/`, `.muse/`, `Library/` |
| `home/agy/` | `.gemini/`, `.config/`, `Library/` (keychain) |

Toolchain files. `toolchain.lock.json` pins every file in `bin/` by SHA-256
(keys without a slash), and any other file a shim runs (keys are paths relative
to the toolchain). Each `bin/` file must be one of: a Mach-O binary; a Python
console script whose first line is exactly `#!<toolchain>/venvs/<name>/bin/python`
or that line plus ` -I`; or a `#!/bin/sh` shim whose only command is
`exec <pinned toolchain file> "$@"`. No system interpreter, flag or other
argument is allowed.

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
