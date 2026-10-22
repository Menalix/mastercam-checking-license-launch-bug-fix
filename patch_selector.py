"""Repair the hidden-start argument in Mastercam's file version selector.

Default: inspect only. This does not patch Mastercam's licensing code.
"""

import argparse
import hashlib
import json
import os
import struct
import sys
from pathlib import Path

import capstone
import pefile
from capstone import x86 as X

DEFAULT = Path(r"C:\Program Files\Common Files\Mastercam\McamVersionSelector.exe")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def matches_memory(op, base, disp, size):
    return (
        op.type == X.X86_OP_MEM
        and op.mem.base == base
        and op.mem.index == 0
        and op.mem.disp == disp
        and op.size == size
    )


def matches_register(op, value):
    return op.type == X.X86_OP_REG and op.reg == value


def identify(data: bytes) -> dict:
    pe = pefile.PE(data=data)
    if pe.FILE_HEADER.Machine != 0x8664 or pe.OPTIONAL_HEADER.Magic != 0x20B:
        raise ValueError("Only native AMD64 PE files are supported.")
    strings = {}
    for group in getattr(pe, "FileInfo", []):
        for item in group:
            for table in getattr(item, "StringTable", []):
                strings.update(
                    {
                        k.decode(errors="replace"): v.decode(errors="replace")
                        for k, v in table.entries.items()
                    }
                )
    if strings.get("OriginalFilename", "").lower() != "mcamversionselector.exe":
        raise ValueError(
            "The PE version resource does not identify McamVersionSelector.exe."
        )
    base = pe.OPTIONAL_HEADER.ImageBase
    targets = {
        i.address
        for verb in pe.DIRECTORY_ENTRY_IMPORT
        if verb.dll.lower() == b"shell32.dll"
        for i in verb.imports
        if i.name == b"ShellExecuteW"
    }
    if len(targets) != 1:
        raise ValueError("Expected exactly one ShellExecuteW import.")
    target = next(iter(targets))
    disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    disassembler.detail = True
    matches = []
    calls = []
    # Discover RIP-relative references to the actual import. Then decode only
    # the argument block ending at that call, avoiding assumptions about RVAs.
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        raw = section.get_data()
        for position in range(len(raw) - 5):
            if raw[position : position + 2] != b"\xff\x15":
                continue
            address = base + section.VirtualAddress + position
            if address + 6 + struct.unpack_from("<i", raw, position + 2)[0] != target:
                continue
            calls.append(address)
            for start in range(max(0, position - 64), position):
                block = list(
                    disassembler.disasm(
                        raw[start : position + 6], base + section.VirtualAddress + start
                    )
                )
                if (
                    len(block) != 7
                    or block[-1].address != address
                    or sum(i.size for i in block) != position + 6 - start
                ):
                    continue
                show_command, directory, parameters, executable, verb, owner, _ = block
                if not (
                    show_command.mnemonic == "mov"
                    and len(show_command.operands) == 2
                    and matches_memory(show_command.operands[0], X.X86_REG_RSP, 0x28, 4)
                    and show_command.operands[1].type == X.X86_OP_IMM
                    and show_command.operands[1].imm in (0, 1)
                    and show_command.size == 8
                    and show_command.bytes[:4] == b"\xc7\x44\x24\x28"
                ):
                    continue
                if not (
                    directory.mnemonic == "mov"
                    and len(directory.operands) == 2
                    and matches_memory(directory.operands[0], X.X86_REG_RSP, 0x20, 8)
                    and directory.operands[1].type == X.X86_OP_IMM
                    and directory.operands[1].imm == 0
                ):
                    continue
                if not all(
                    i.mnemonic == "mov"
                    and len(i.operands) == 2
                    and matches_register(i.operands[0], r)
                    and i.operands[1].type == X.X86_OP_MEM
                    and i.operands[1].mem.base == X.X86_REG_RSP
                    and i.operands[1].mem.index == 0
                    and i.operands[1].mem.disp >= 0x30
                    and i.operands[1].size == 8
                    for i, r in [(parameters, X.X86_REG_R9), (executable, X.X86_REG_R8)]
                ):
                    continue
                if not (
                    verb.mnemonic == "lea"
                    and len(verb.operands) == 2
                    and matches_register(verb.operands[0], X.X86_REG_RDX)
                    and verb.operands[1].type == X.X86_OP_MEM
                    and verb.operands[1].mem.base == X.X86_REG_RIP
                ):
                    continue
                verb_rva = verb.address + verb.size + verb.operands[1].mem.disp - base
                if pe.get_data(verb_rva, 10) != "open\0".encode("utf-16le"):
                    continue
                if not (
                    owner.mnemonic == "xor"
                    and len(owner.operands) == 2
                    and all(matches_register(o, X.X86_REG_ECX) for o in owner.operands)
                ):
                    continue
                patch_rva = show_command.address - base + 4
                offset = pe.get_offset_from_rva(patch_rva)
                matches.append(
                    dict(
                        offset=offset,
                        instruction_rva=show_command.address - base,
                        patch_rva=patch_rva,
                        call_rva=address - base,
                        value=show_command.operands[1].imm,
                        instructions=[
                            f"{i.address - base:08x}: {i.bytes.hex(' ')}  "
                            f"{i.mnemonic} {i.op_str}"
                            for i in block
                        ],
                    )
                )
    # Multiple launch sites or a compiler change require fresh review.
    if len(calls) != 1 or len(matches) != 1:
        raise ValueError(
            f"Unsupported build: {len(calls)} ShellExecuteW calls, "
            f"{len(matches)} verified argument blocks. No bytes changed."
        )
    result = matches[0]
    result.update(
        sha256=sha256(data),
        version=strings.get("FileVersion"),
        status="patched" if result["value"] == 1 else "needs_patch",
        certificate_present=bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size),
    )
    return result


def make_patch(data: bytes) -> tuple[bytes, dict]:
    info = identify(data)
    if info["value"] == 1:
        return data, info
    changed = bytearray(data)
    changed[info["offset"]] = 1
    changed = bytes(changed)
    verification = identify(changed)
    differences = [i for i, (old, new) in enumerate(zip(data, changed)) if old != new]
    if verification["status"] != "patched" or differences != [info["offset"]]:
        raise ValueError("Patch verification failed.")
    return changed, info


def exclusive_write(path: Path, data: bytes) -> None:
    with path.open("xb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def replace_byte(path: Path, data: bytes, replacement: bytes, offset: int) -> None:
    # Preserve file identity and permissions. Deny any concurrent process that
    # opens/changes the file; do not replace a new vendor update accidentally.
    import ctypes as C
    from ctypes import wintypes as W

    k = C.WinDLL("kernel32", use_last_error=True)
    k.CreateFileW.argtypes = [
        W.LPCWSTR,
        W.DWORD,
        W.DWORD,
        C.c_void_p,
        W.DWORD,
        W.DWORD,
        W.HANDLE,
    ]
    k.CreateFileW.restype = W.HANDLE
    k.CloseHandle.argtypes = [W.HANDLE]
    h = k.CreateFileW(str(path), 0xC0000000, 0, None, 3, 0x80, None)
    if h == C.c_void_p(-1).value:
        raise C.WinError(C.get_last_error())
    import msvcrt

    try:
        fd = msvcrt.open_osfhandle(int(h), os.O_RDWR | os.O_BINARY)
    except BaseException:
        k.CloseHandle(h)
        raise
    with os.fdopen(fd, "r+b") as f:
        if f.read() != data:
            raise ValueError("Target changed since inspection. No bytes changed.")
        f.seek(offset)
        f.write(replacement[offset : offset + 1])
        f.flush()
        os.fsync(f.fileno())
        f.seek(0)
        if f.read() != replacement:
            raise IOError("Post-write verification failed; original backup retained.")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target", nargs="?", type=Path, default=DEFAULT)
    modes = ap.add_mutually_exclusive_group()
    modes.add_argument(
        "--output", type=Path, help="Write a patched copy; leave target unchanged."
    )
    modes.add_argument(
        "--apply", action="store_true", help="Back up and patch this target in place."
    )
    modes.add_argument(
        "--restore",
        type=Path,
        metavar="BACKUP",
        help="Restore only a byte-for-byte matching original backup.",
    )
    args = ap.parse_args(argv)
    path = args.target.resolve()
    data = path.read_bytes()
    info = identify(data)
    print(json.dumps({"target": str(path), **info}, indent=2))
    if args.restore:
        backup = args.restore.resolve().read_bytes()
        original = identify(backup)
        expected, _ = make_patch(backup)
        if original["status"] != "needs_patch" or data != expected:
            raise ValueError(
                "Backup does not match this exact patched binary. Refusing restore."
            )
        replacement = backup
    elif args.output or args.apply:
        replacement, _ = make_patch(data)
    else:
        return
    if args.output:
        if args.output.resolve() == path:
            raise ValueError("Use --apply to modify the original.")
        exclusive_write(args.output.resolve(), replacement)
        print("Wrote patched copy:", args.output.resolve())
        return
    if replacement == data:
        print("Already patched; no change.")
        return
    backup_path = path.with_name(path.name + "." + sha256(data)[:16] + ".original.bak")
    if args.apply:
        if backup_path.exists():
            if backup_path.read_bytes() != data:
                raise ValueError("Existing backup has unexpected contents.")
        else:
            exclusive_write(backup_path, data)
    replace_byte(path, data, replacement, info["offset"])
    if args.apply:
        print("Patched one byte. Backup:", backup_path)
    else:
        print("Restored matching original.")
    print("SHA256:", sha256(replacement))
    print(
        "Changing the byte invalidates the vendor Authenticode signature; "
        "restoring the exact backup restores it."
    )


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, pefile.PEFormatError) as exc:
        print("REFUSED:", exc, file=sys.stderr)
        sys.exit(1)
