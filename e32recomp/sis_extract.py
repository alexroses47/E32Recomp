#!/usr/bin/env python3
"""Extract the files of a Symbian 9.x (SIS v2) package — pure Python.

Usage: sis_extract.py package.sis outdir [--list]

Writes every installable file under outdir using its target path without the
drive letter (e.g. "!:\\private\\2000C4D4\\x.hgr" -> outdir/private/2000C4D4/x.hgr)
and checks the SHA-1 stored in the package for each file.

SIS v2 layout, as used here:
  header  4 x u32 LE: UID1 0x10201A7A, UID2, UID3 (package UID), UID checksum
  then a tree of fields. Field = u32 type, u32 length (bit 31 set: 64-bit length,
  high word follows), data, zero padding to 4 bytes. Elements of an array field
  omit the type (the array gives it once).
"""
import hashlib
import os
import struct
import sys
import zlib

UID1 = 0x10201A7A

T_STRING, T_ARRAY, T_COMPRESSED = 1, 2, 3
T_CONTENTS, T_CONTROLLER, T_INFO = 12, 13, 14
T_FILEDESC, T_HASH, T_IF, T_ELSEIF, T_INSTALLBLOCK = 24, 25, 26, 27, 28
T_DATA, T_DATAUNIT, T_FILEDATA = 30, 31, 32
T_BLOB, T_CAPABILITIES, T_DATAINDEX = 37, 41, 40

# Field types whose payload is a plain sequence of fields we may descend into.
CONTAINERS = {T_CONTENTS, T_CONTROLLER, T_IF, T_ELSEIF, T_INSTALLBLOCK, T_DATA,
              T_DATAUNIT, T_FILEDATA}


class SisError(ValueError):
    pass


def read_len(buf, pos):
    (n,) = struct.unpack_from("<I", buf, pos)
    pos += 4
    if n & 0x80000000:
        (hi,) = struct.unpack_from("<I", buf, pos)
        pos += 4
        n = (n & 0x7FFFFFFF) | (hi << 31)
    return n, pos


def read_field(buf, pos, ftype=None):
    """Return (type, payload_start, payload_len, next_pos)."""
    if ftype is None:
        (ftype,) = struct.unpack_from("<I", buf, pos)
        pos += 4
    n, pos = read_len(buf, pos)
    if pos + n > len(buf):
        raise SisError(f"field {ftype} at {pos:#x} runs past the end")
    nxt = pos + n
    nxt += -nxt % 4
    return ftype, pos, n, nxt


def fields(buf, start, end):
    pos = start
    while pos < end:
        f = read_field(buf, pos)
        yield f
        pos = f[3]


def array(buf, start, length):
    """Elements of a SISArray payload: [(type, start, len)]."""
    (etype,) = struct.unpack_from("<I", buf, start)
    pos, end, out = start + 4, start + length, []
    while pos < end:
        _, s, n, pos = read_field(buf, pos, etype)
        out.append((etype, s, n))
    return out


def sis_string(buf, start, length):
    return buf[start:start + length].decode("utf-16-le")


def decompress(buf, start, length):
    """SISCompressed payload -> bytes."""
    algo, size = struct.unpack_from("<IQ", buf, start)
    data = buf[start + 12:start + length]
    if algo == 0:
        out = bytes(data)
    elif algo == 1:
        out = zlib.decompress(data)
    else:
        raise SisError(f"unknown compression {algo}")
    if len(out) != size:
        raise SisError(f"decompressed {len(out)} bytes, expected {size}")
    return out


def file_description(buf, start, length):
    pos, end = start, start + length
    t, s, n, pos = read_field(buf, pos)
    target = sis_string(buf, s, n)
    t, s, n, pos = read_field(buf, pos)  # MIME type
    t, s, n, nxt = read_field(buf, pos)
    if t == T_CAPABILITIES:
        pos = nxt
        t, s, n, nxt = read_field(buf, pos)
    if t != T_HASH:
        raise SisError(f"expected hash in file description, got field {t}")
    (halgo,) = struct.unpack_from("<I", buf, s)
    _, bs, bn, _ = read_field(buf, s + 4)
    digest = bytes(buf[bs:bs + bn])
    pos = nxt
    op, opopt, flen, ulen, index = struct.unpack_from("<IIQQI", buf, pos)
    return {"target": target, "hash_algo": halgo, "hash": digest, "operation": op,
            "length": flen, "uncompressed": ulen, "index": index}


def walk_controller(buf, start, length, out, data_index_holder):
    """Collect file descriptions from a controller (descends into SISIf/ElseIf)."""
    for t, s, n, _ in fields(buf, start, start + length):
        if t == T_INSTALLBLOCK:
            walk_install_block(buf, s, n, out, data_index_holder)
        elif t == T_DATAINDEX:
            data_index_holder.append(struct.unpack_from("<I", buf, s)[0])


def walk_install_block(buf, start, length, out, dih):
    for t, s, n, _ in fields(buf, start, start + length):
        if t != T_ARRAY:
            continue
        for et, es, en in array(buf, s, n):
            if et == T_FILEDESC:
                out.append(file_description(buf, es, en))
            elif et == T_CONTROLLER:
                pass  # embedded packages: not present in Bounce Touch
            elif et in (T_IF, T_ELSEIF):
                for t2, s2, n2, _ in fields(buf, es, es + en):
                    if t2 == T_INSTALLBLOCK:
                        walk_install_block(buf, s2, n2, out, dih)
                    elif t2 == T_ARRAY:
                        for et3, es3, en3 in array(buf, s2, n2):
                            if et3 == T_ELSEIF:
                                for t4, s4, n4, _ in fields(buf, es3, es3 + en3):
                                    if t4 == T_INSTALLBLOCK:
                                        walk_install_block(buf, s4, n4, out, dih)


def parse(buf):
    uid1, uid2, uid3, _ = struct.unpack_from("<4I", buf, 0)
    if uid1 != UID1:
        raise SisError("not a Symbian 9 SIS file (UID1)")
    t, s, n, _ = read_field(buf, 16)
    if t != T_CONTENTS:
        raise SisError("missing SISContents")
    controller, data = None, None
    for t, fs, fn, _ in fields(buf, s, s + n):
        if t == T_COMPRESSED:
            controller = decompress(buf, fs, fn)
        elif t == T_DATA:
            data = (fs, fn)
    if controller is None or data is None:
        raise SisError("missing controller or data")
    ct, cs, cn, _ = read_field(controller, 0)
    if ct != T_CONTROLLER:
        raise SisError("compressed block is not a controller")
    descs, dih = [], []
    walk_controller(controller, cs, cn, descs, dih)
    # data units -> list of file blobs (still compressed)
    units = []
    for t, s2, n2, _ in fields(buf, data[0], data[0] + data[1]):
        if t != T_ARRAY:
            continue
        for _, us, un in array(buf, s2, n2):
            files = []
            for t3, s3, n3, _ in fields(buf, us, us + un):
                if t3 == T_ARRAY:
                    for _, fs3, fn3 in array(buf, s3, n3):
                        for t4, s4, n4, _ in fields(buf, fs3, fs3 + fn3):
                            if t4 == T_COMPRESSED:
                                files.append((s4, n4))
            units.append(files)
    unit = units[dih[0] if dih else 0]
    return {"uid3": uid3, "files": descs, "unit": unit}


def target_to_relpath(target):
    p = target.replace("\\", "/")
    if len(p) > 2 and p[1] == ":":
        p = p[2:]
    parts = [q for q in p.split("/") if q not in ("", ".", "..")]
    return "/".join(parts)


def extract(sis_path, outdir, list_only=False):
    buf = memoryview(open(sis_path, "rb").read())
    pkg = parse(buf)
    written = []
    for d in pkg["files"]:
        rel = target_to_relpath(d["target"])
        if not rel:
            continue  # files without target (e.g. text shown at install)
        s, n = pkg["unit"][d["index"]]
        data = decompress(buf, s, n)
        if d["hash_algo"] == 1 and hashlib.sha1(data).digest() != d["hash"]:
            raise SisError(f"SHA-1 mismatch: {rel}")
        if list_only:
            print(f"{len(data):9d}  {rel}")
            continue
        dst = os.path.join(outdir, *rel.split("/"))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "wb") as f:
            f.write(data)
        written.append(rel)
    return pkg["uid3"], written


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    uid3, written = extract(argv[0], argv[1], "--list" in argv)
    if "--list" not in argv:
        print(f"UID3 {uid3:#010x}: {len(written)} files -> {argv[1]} (SHA-1 ok)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
