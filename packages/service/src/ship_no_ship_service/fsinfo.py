"""File-system facts that ``os.stat`` does not give: macOS ACLs and volumes that ignore ownership.

Both use libc through ctypes on macOS. Elsewhere there is nothing to read: the service runs only on
macOS, and the checks report the platform rather than guessing.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
from pathlib import Path

ACL_TYPE_EXTENDED = 0x100
MNT_IGNORE_OWNERSHIP = 0x00200000
# ACL permissions that let someone change a file or directory, or what it contains.
WRITE_PERMISSIONS = frozenset(
    {
        "write",
        "append",
        "delete",
        "delete_child",
        "writeattr",
        "writeextattr",
        "writesecurity",
        "chown",
        "add_file",
        "add_subdirectory",
    }
)
# ACL permissions that let someone read a file, list or search a directory, or read its attributes.
# Confidential paths must not grant any of these, nor any write permission.
READ_PERMISSIONS = frozenset({"read", "list", "search", "execute", "readattr", "readextattr", "readsecurity"})


class FsInfoError(OSError):
    pass


class _Statfs(ctypes.Structure):
    _fields_ = [  # noqa: RUF012 - ctypes layout of struct statfs (64-bit inodes)
        ("f_bsize", ctypes.c_uint32),
        ("f_iosize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64),
        ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64),
        ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64),
        ("f_fsid", ctypes.c_int32 * 2),
        ("f_owner", ctypes.c_uint32),
        ("f_type", ctypes.c_uint32),
        ("f_flags", ctypes.c_uint32),
        ("f_fssubtype", ctypes.c_uint32),
        ("f_fstypename", ctypes.c_char * 16),
        ("f_mntonname", ctypes.c_char * 1024),
        ("f_mntfromname", ctypes.c_char * 1024),
        ("f_flags_ext", ctypes.c_uint32),
        ("f_reserved", ctypes.c_uint32 * 7),
    ]


def _libc() -> ctypes.CDLL:
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    libc.acl_get_link_np.restype = ctypes.c_void_p
    libc.acl_get_link_np.argtypes = [ctypes.c_char_p, ctypes.c_int]
    libc.acl_to_text.restype = ctypes.c_void_p
    libc.acl_to_text.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ssize_t)]
    libc.acl_free.argtypes = [ctypes.c_void_p]
    return libc


def acl_text(path: Path) -> str:
    """The extended ACL of ``path`` (not following a final symlink), or "" when it has none."""
    if sys.platform != "darwin":
        return ""
    libc = _libc()
    acl = libc.acl_get_link_np(os.fsencode(path), ACL_TYPE_EXTENDED)
    if not acl:
        error = ctypes.get_errno()
        if error == 2:  # ENOENT: the file exists but carries no ACL
            return ""
        raise FsInfoError(error, f"cannot read the ACL of {path}")
    try:
        length = ctypes.c_ssize_t()
        text = libc.acl_to_text(acl, ctypes.byref(length))
        if not text:
            raise FsInfoError(ctypes.get_errno(), f"cannot render the ACL of {path}")
        try:
            return ctypes.string_at(text).decode("utf-8", "replace")
        finally:
            libc.acl_free(ctypes.c_void_p(text))
    finally:
        libc.acl_free(ctypes.c_void_p(acl))


def write_grants(text: str) -> list[str]:
    """The allow entries of an ACL text that grant any kind of write, as ``who: permissions``."""
    return grants(text, WRITE_PERMISSIONS)


def access_grants(text: str) -> list[str]:
    """The allow entries of an ACL text that grant any read, search or write access."""
    return grants(text, WRITE_PERMISSIONS | READ_PERMISSIONS)


INHERIT_FLAGS = frozenset({"file_inherit", "directory_inherit"})


def inheritable_grants(text: str) -> list[str]:
    """The allow entries that pass any read, search or write access on to new files or directories."""
    return grants(text, WRITE_PERMISSIONS | READ_PERMISSIONS, inheritable=True)


def grants(text: str, permissions: frozenset[str], inheritable: bool = False) -> list[str]:
    """The allow entries of an ACL text that grant any of ``permissions``, as ``who: permissions``.

    With ``inheritable``, only entries that new files or directories below inherit.
    """
    found = []
    for line in text.splitlines():
        fields = line.split(":")
        # The kind field may carry flags, as in "allow,inherited" or "allow,file_inherit,directory_inherit".
        if len(fields) < 6 or "allow" not in fields[4].split(","):
            continue
        if inheritable and not INHERIT_FLAGS & set(fields[4].split(",")):
            continue
        granted = set(fields[5].split(",")) & permissions
        if granted:
            found.append(f"{fields[0]}:{fields[2]} allow {','.join(sorted(granted))}")
    return found


def ignores_ownership(path: Path) -> bool:
    """Whether the volume holding ``path`` is mounted to ignore file ownership."""
    if sys.platform != "darwin":
        return False
    result = _Statfs()
    if ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True).statfs(os.fsencode(path), ctypes.byref(result)):
        raise FsInfoError(ctypes.get_errno(), f"cannot read the volume of {path}")
    return bool(result.f_flags & MNT_IGNORE_OWNERSHIP)
