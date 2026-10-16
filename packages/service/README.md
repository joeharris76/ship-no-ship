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

Confidential paths (`config/`, `keys/`, `state/`, `captured/`, the role homes,
and the listed files inside them) may carry no ACL entry that allows any access,
including read, list and search, and no directory above them may carry an
inheritable (`file_inherit` or `directory_inherit`) entry that allows any
access. Other paths may not carry one that allows any kind of write.
`captured/` must exist once installed.

App keys. `keys/` may hold only regular files with lowercase names ending in
`.pem`. Each repository's `key_path` in `service.toml` must be exactly
`<data>/keys/<name>.pem`, reached through no symlink, because doctor reads the
key as root on the daemon user's behalf.

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

Nothing in the toolchain may load code from outside it. Every Mach-O file
(every slice of a fat file) may load libraries, rpaths and a dynamic linker
only from the toolchain or from `/usr/lib` and `/System/Library` (never
`/System/Volumes`), with `@rpath` and `@loader_path` resolved against the file
itself. Every library or dynamic linker that is not a system library, weak
ones included, must exist as a regular file in the toolchain (for `@rpath`, in
at least one rpath; when a library's own rpaths find nothing, the rpaths of
the toolchain images that load it, up to a main program, are tried, as dyld
does, and every chain of loaders that reaches it must find the file; a main
program borrows none),
because dyld looks for a missing one by file name in
`/usr/local/lib`. A system library must exist as a regular file under
`/usr/lib` or `/System/Library`, or be in the dyld shared cache (asked through
`_dyld_shared_cache_contains_path`); where the cache cannot be asked (before
macOS 11), the path alone is accepted. Libraries and bundles may not use `@executable_path`, and any load
command outside a known-safe list (such as `LC_DYLD_ENVIRONMENT`) fails. Every
`.pth` file may only add directories inside the toolchain and may not contain
`import` lines; `sitecustomize` and `usercustomize` start-up hooks are not
allowed in the toolchain in any form Python imports (`.py`, `.pyc`, extension
modules, packages, and cached `__pycache__/<hook>.*.pyc` files), pinned or not;
no `.pth` file may be a symlink; no
package may be an editable install. So the reviewer CLIs (claude, codex, muse,
agy) must be installed self-contained inside the toolchain, as standalone
binaries or with a bundled runtime (for example node) and its libraries inside
`/usr/local/libexec/ship-no-ship`, never linked against `/opt/homebrew` or any
other directory the owner's account can write. The installer has to do this.

The supervisor's process records live in `<data>/attempts/`, not under the
daemon-owned `run/`, so the daemon cannot replace them.

Every directory above a listed path must be owned by root (or, above a path a
service user owns, by that user), must not be group-writable except by wheel or
the path's own service group, must not be world-writable or carry a write ACL,
and must not be a symlink other than `/etc`, `/tmp` or `/var`. Only root may be
a member of wheel, each service group may hold only its own service user, and no
service user may be a member of staff or admin. Membership counts listed
members, users whose primary group it is, and whoever macOS counts as a member
(`mbr_check_membership`, which follows nested groups); if the system cannot
answer, the check fails. Wheel and the service groups may not have
NestedGroups, and none of these groups may share its GID with another group
record. Staff and admin may nest groups, as they often do on managed Macs.

Run `sudo ship-no-ship-service doctor` once installed. Exit codes: 0 passed,
1 failed, 3 incomplete (a check did not run). `--allow-not-run` is for use
before installation only.

With sudo, doctor also checks each CLI's sign-in as its role user and whether
codex's read-only sandbox can read codex's own token (a `warn` the owner must
decide on). `--post-reboot` runs only the claude and agy keychain checks.
`--actor-probe --probe-plan-run <run>` is the one-time activation check that
only the App's bot can record state: it dispatches the record workflow as the
App for a proof plan run, then asks you to dispatch it as yourself and confirm
that run failed closed and opened an `oracle-record-rejected` issue.
