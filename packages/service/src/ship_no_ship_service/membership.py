"""Group membership as macOS decides it: nested groups and GIDs, not only a group's member list.

``grp`` reports a group's listed members and nothing else. macOS also honours groups nested inside a
group and compares GIDs, so membership is asked of the system through ``mbr_check_membership``, and a
group's nested groups are read with ``dscl``. Elsewhere the answer is unknown, and the callers fall
back to ``grp``.
"""

from __future__ import annotations

import ctypes
import subprocess
import sys

DSCL = "/usr/bin/dscl"
_UUID = ctypes.c_ubyte * 16


def _library() -> ctypes.CDLL | None:
    if sys.platform != "darwin":
        return None
    try:
        library = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        for name in ("mbr_uid_to_uuid", "mbr_gid_to_uuid"):
            function = getattr(library, name)
            function.argtypes = [ctypes.c_uint32, _UUID]
            function.restype = ctypes.c_int
        library.mbr_check_membership.argtypes = [_UUID, _UUID, ctypes.POINTER(ctypes.c_int)]
        library.mbr_check_membership.restype = ctypes.c_int
    except (OSError, AttributeError):
        return None
    return library


def is_member(uid: int, gid: int) -> bool | None:
    """Whether the user is an effective member of the group, nesting included, or None when unknown."""
    library = _library()
    if library is None:
        return None
    user, group, answer = _UUID(), _UUID(), ctypes.c_int(0)
    if library.mbr_uid_to_uuid(uid, user) or library.mbr_gid_to_uuid(gid, group):
        return None
    if library.mbr_check_membership(user, group, ctypes.byref(answer)):
        return None
    return bool(answer.value)


def nested_groups(group: str) -> list[str] | None:
    """The NestedGroups of a local group record ([] when it has none), or None when they cannot be read."""
    if sys.platform != "darwin":
        return []
    try:
        done = subprocess.run(
            [DSCL, ".", "-read", f"/Groups/{group}", "NestedGroups"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if done.returncode != 0:
        return None
    if "No such key: NestedGroups" in done.stdout + done.stderr:
        return []
    return parse_nested(done.stdout)


def parse_nested(text: str) -> list[str] | None:
    """The values of a ``dscl -read`` NestedGroups attribute, on its own line or continued below it."""
    values: list[str] = []
    found = collecting = False
    for line in text.splitlines():
        if line.startswith("NestedGroups:"):
            found = collecting = True
            values += line.removeprefix("NestedGroups:").split()
        elif collecting and line[:1].isspace():
            values += line.split()
        else:
            collecting = False
    return values if found else None
