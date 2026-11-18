#!/usr/bin/env python3
"""Recover C++ class info (ARM EABI / Itanium RTTI) from an E32 code section.

Usage: rtti_scan.py code.bin imports.tsv outdir [base=0x8000]

Writes:
  outdir/rtti.tsv     one row per class: typeinfo, kind, name, bases, vtable, nslots
  outdir/vtables.tsv  one row per vtable slot: vtable, class, slot, target, owner
                      (owner = most-base class whose vtable has the same target
                       in the same slot, i.e. where the method is introduced
                       or last overridden)
  outdir/classes.txt  inheritance tree, readable

Only the layout of the RTTI structures is used; no code is decompiled.
"""
import re
import struct
import subprocess
import sys
from collections import defaultdict

TI_KINDS = {
    "_ZTVN10__cxxabiv117__class_type_infoE": "class",
    "_ZTVN10__cxxabiv120__si_class_type_infoE": "si",
    "_ZTVN10__cxxabiv121__vmi_class_type_infoE": "vmi",
}


def demangle_all(raw_names):
    """Turn typeinfo name strings (e.g. 10PlayerBall) into C++ names via c++filt."""
    syms = ["_ZTS" + n for n in raw_names]
    try:
        out = subprocess.run(["c++filt"], input="\n".join(syms), capture_output=True,
                             text=True, check=True).stdout.splitlines()
    except (OSError, subprocess.CalledProcessError):
        return {n: n for n in raw_names}
    res = {}
    for raw, dem in zip(raw_names, out):
        dem = dem.strip()
        for pre in ("typeinfo name for ", "typeinfo name for"):
            if dem.startswith(pre):
                dem = dem[len(pre):]
        res[raw] = dem if not dem.startswith("_ZTS") else raw
    return res


def main():
    code_path, imports_path, outdir = sys.argv[1:4]
    base = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0x8000
    code = open(code_path, "rb").read()
    end = base + len(code)
    nwords = len(code) // 4
    words = struct.unpack_from("<%dI" % nwords, code)

    def word_at(addr):
        return words[(addr - base) // 4]

    # data imports: address -> symbol (typeinfo vptrs are patched imports)
    data_imports = {}
    for line in open(imports_path, encoding="utf-8"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 5 and f[0] == "data":
            data_imports[int(f[1], 16)] = f[4]

    # typeinfo objects: first word is an import of a *_type_info vtable
    tinfo = {}  # addr -> dict
    for addr, sym in data_imports.items():
        kind = TI_KINDS.get(sym)
        if not kind:
            continue
        name_ptr = word_at(addr + 4)
        if not (base <= name_ptr < end):
            continue
        nul = code.index(b"\0", name_ptr - base)
        raw = code[name_ptr - base:nul].decode("latin1")
        bases = []
        if kind == "si":
            bases.append((word_at(addr + 8), 0))
        elif kind == "vmi":
            count = word_at(addr + 12)
            for i in range(min(count, 32)):
                bases.append((word_at(addr + 16 + 8 * i), word_at(addr + 20 + 8 * i)))
        tinfo[addr] = {"kind": kind, "raw": raw, "bases": bases}

    names = demangle_all(sorted({t["raw"] for t in tinfo.values()}))
    for t in tinfo.values():
        t["name"] = names[t["raw"]]

    # vtables: [offset_to_top][typeinfo*][slots...]
    ti_set = set(tinfo)
    vt_starts = []
    for i in range(1, nwords):
        if words[i] in ti_set:
            ott = words[i - 1]
            if ott == 0 or ott >= 0xFFFF0000:  # 0 or small negative (secondary)
                vt_starts.append(base + (i - 1) * 4)
    vt_start_set = set(vt_starts)
    code_lo, code_hi = base, min(ti_set)  # functions live below the RTTI area
    vtables = {}  # vt addr -> (ti, offset_to_top, [slots])
    for vt in vt_starts:
        ti = word_at(vt + 4)
        ott = word_at(vt)
        slots = []
        a = vt + 8
        while a + 4 <= end and a not in vt_start_set:
            w = word_at(a)
            if not (code_lo <= (w & ~1) < code_hi):
                break
            slots.append(w)
            a += 4
        vtables[vt] = (ti, ott if ott < 0x80000000 else ott - (1 << 32), slots)

    primary = {}
    for vt, (ti, ott, slots) in vtables.items():
        if ott == 0 and ti not in primary:
            primary[ti] = vt

    def ancestors(ti):
        """Primary-base chain, nearest first."""
        chain, seen = [], set()
        while tinfo.get(ti, {}).get("bases"):
            b = tinfo[ti]["bases"][0][0]
            if b in seen or b not in tinfo:
                break
            seen.add(b)
            chain.append(b)
            ti = b
        return chain

    # write rtti.tsv
    with open(f"{outdir}/rtti.tsv", "w", encoding="utf-8") as out:
        out.write("typeinfo\tkind\tname\tbases\tvtable\tslots\n")
        for ti in sorted(tinfo):
            t = tinfo[ti]
            bnames = ",".join(tinfo[b]["name"] if b in tinfo else hex(b) for b, _ in t["bases"])
            vt = primary.get(ti)
            ns = len(vtables[vt][2]) if vt else 0
            out.write(f"{ti:#x}\t{t['kind']}\t{t['name']}\t{bnames}\t{vt:#x}\t{ns}\n" if vt
                      else f"{ti:#x}\t{t['kind']}\t{t['name']}\t{bnames}\t-\t0\n")

    # write vtables.tsv with owner resolution
    with open(f"{outdir}/vtables.tsv", "w", encoding="utf-8") as out:
        out.write("vtable\tclass\toffset_to_top\tslot\ttarget\towner\n")
        for vt in sorted(vtables):
            ti, ott, slots = vtables[vt]
            cname = tinfo[ti]["name"]
            chain = ancestors(ti) if ott == 0 else []
            for i, tgt in enumerate(slots):
                owner = cname
                for anc in chain:
                    avt = primary.get(anc)
                    if avt and i < len(vtables[avt][2]) and vtables[avt][2][i] == tgt:
                        owner = tinfo[anc]["name"]
                    else:
                        break
                out.write(f"{vt:#x}\t{cname}\t{ott}\t{i}\t{tgt:#x}\t{owner}\n")

    # inheritance tree
    children = defaultdict(list)
    roots = []
    for ti, t in tinfo.items():
        if t["bases"] and t["bases"][0][0] in tinfo:
            for b, _ in t["bases"]:
                if b in tinfo:
                    children[b].append(ti)
        else:
            roots.append(ti)
    lines = []

    def walk(ti, depth):
        t = tinfo[ti]
        vt = primary.get(ti)
        extra = f"  [{len(vtables[vt][2])} slots @ {vt:#x}]" if vt else ""
        mi = " (MI: " + ", ".join(tinfo[b]["name"] for b, _ in t["bases"][1:] if b in tinfo) + ")" \
            if len(t["bases"]) > 1 else ""
        lines.append("  " * depth + t["name"] + mi + extra)
        for c in sorted(children[ti], key=lambda x: tinfo[x]["name"]):
            if tinfo[c]["bases"][0][0] == ti or depth < 8:
                walk(c, depth + 1)

    for r in sorted(roots, key=lambda x: tinfo[x]["name"]):
        walk(r, 0)
    open(f"{outdir}/classes.txt", "w", encoding="utf-8").write("\n".join(lines) + "\n")

    kinds = defaultdict(int)
    for t in tinfo.values():
        kinds[t["kind"]] += 1
    nslots = sum(len(v[2]) for v in vtables.values())
    uniq = len({s & ~1 for v in vtables.values() for s in v[2]})
    print(f"typeinfo: {len(tinfo)} ({dict(kinds)}), vtables: {len(vtables)} "
          f"({sum(1 for v in vtables.values() if v[1] != 0)} secondary), "
          f"slots: {nslots}, distinct targets: {uniq}")


if __name__ == "__main__":
    main()
