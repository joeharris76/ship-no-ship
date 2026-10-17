"""The ``ship-no-ship-service`` command."""

from __future__ import annotations

import sys

from . import doctor

COMMANDS = {"doctor": doctor.main}


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] not in COMMANDS:
        print(f"usage: ship-no-ship-service {{{','.join(COMMANDS)}}} [options]", file=sys.stderr)
        return 2
    return COMMANDS[args[0]](args[1:])


if __name__ == "__main__":
    raise SystemExit(main())
