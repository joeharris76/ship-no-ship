"""A small Mach-O reader: the libraries, rpaths and dynamic linker a binary asks for.

It reads thin 32- and 64-bit files in either byte order and every slice of a fat file. It needs no
developer tools, so doctor can check a machine without otool.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

FAT_MAGIC, FAT_MAGIC_64 = 0xCAFEBABE, 0xCAFEBABF
THIN = {0xFEEDFACE: ("<", 28), 0xFEEDFACF: ("<", 32), 0xCEFAEDFE: (">", 28), 0xCFFAEDFE: (">", 32)}
LC_REQ_DYLD = 0x80000000
LC_LOAD_DYLIB = 0xC
LC_LOAD_DYLINKER = 0xE
LC_LAZY_LOAD_DYLIB = 0x20
LC_LOAD_WEAK_DYLIB = 0x18 | LC_REQ_DYLD
LC_RPATH = 0x1C | LC_REQ_DYLD
LC_REEXPORT_DYLIB = 0x1F | LC_REQ_DYLD
LC_LOAD_UPWARD_DYLIB = 0x23 | LC_REQ_DYLD
LIBRARY_COMMANDS = frozenset(
    {LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LOAD_UPWARD_DYLIB, LC_LAZY_LOAD_DYLIB}
)
MAX_SLICES = 16


class MachOError(ValueError):
    pass


@dataclass
class LoadInfo:
    libraries: list[str] = field(default_factory=list)
    rpaths: list[str] = field(default_factory=list)
    dylinkers: list[str] = field(default_factory=list)


def is_macho(head: bytes) -> bool:
    if len(head) < 4:
        return False
    return struct.unpack(">I", head[:4])[0] in (FAT_MAGIC, FAT_MAGIC_64) or struct.unpack("<I", head[:4])[0] in THIN


def _string(data: bytes, start: int, end: int, offset: int) -> str:
    if not 0 < offset < end - start:
        raise MachOError("a load command names a string outside itself")
    raw = data[start + offset : end]
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace")


def _thin(data: bytes, base: int, info: LoadInfo) -> None:
    if len(data) < base + 28:
        raise MachOError("the Mach-O header is cut short")
    magic = struct.unpack_from("<I", data, base)[0]
    if magic not in THIN:
        raise MachOError("a slice is not a Mach-O image")
    order, header = THIN[magic]
    ncmds, sizeofcmds = struct.unpack_from(f"{order}II", data, base + 16)
    position, end_of_commands = base + header, base + header + sizeofcmds
    if end_of_commands > len(data):
        raise MachOError("the load commands run past the end of the file")
    for _ in range(ncmds):
        if position + 8 > end_of_commands:
            raise MachOError("a load command runs past the command area")
        cmd, size = struct.unpack_from(f"{order}II", data, position)
        if size < 8 or position + size > end_of_commands:
            raise MachOError("a load command has a bad size")
        end = position + size
        if cmd in LIBRARY_COMMANDS or cmd in (LC_RPATH, LC_LOAD_DYLINKER):
            if size < 12:
                raise MachOError("a load command is too short to name a path")
            name = _string(data, position, end, struct.unpack_from(f"{order}I", data, position + 8)[0])
            target = info.rpaths if cmd == LC_RPATH else info.dylinkers if cmd == LC_LOAD_DYLINKER else info.libraries
            target.append(name)
        position = end


def load_info(data: bytes) -> LoadInfo:
    """Every library, rpath and dynamic linker named by any slice."""
    info = LoadInfo()
    if len(data) < 8:
        raise MachOError("the file is too short to be Mach-O")
    magic = struct.unpack(">I", data[:4])[0]
    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        count = struct.unpack_from(">I", data, 4)[0]
        if not 0 < count <= MAX_SLICES:
            raise MachOError(f"a fat file with {count} slices")
        entry, layout = (20, ">IIIII") if magic == FAT_MAGIC else (32, ">IIQQII")
        for index in range(count):
            fields = struct.unpack_from(layout, data, 8 + index * entry)
            offset, size = fields[2], fields[3]
            if offset + size > len(data):
                raise MachOError("a slice runs past the end of the file")
            _thin(data[: offset + size], offset, info)
    else:
        _thin(data, 0, info)
    return info


def resolve(name: str, origin: Path, rpaths: list[str]) -> list[Path] | None:
    """The paths a library name can load from, or None when it cannot be resolved statically.

    ``@loader_path`` and ``@executable_path`` are resolved against the file's own directory; ``@rpath``
    against each of the file's rpaths, which are resolved the same way.
    """

    def expand(text: str) -> Path | None:
        for token in ("@loader_path", "@executable_path"):
            if text.startswith(token):
                return Path(str(origin) + text[len(token) :])
        return Path(text) if text.startswith("/") else None

    if name.startswith("@rpath/"):
        bases = [expand(item) for item in rpaths]
        if not bases or any(base is None for base in bases):
            return None
        return [base / name[len("@rpath/") :] for base in bases if base is not None]
    path = expand(name)
    return None if path is None else [path]
