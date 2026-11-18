#!/usr/bin/env python3
"""Inventory of a game's own functions for the progress page / Inventario de funciones de un juego.

Every function of the game executable that has been *discovered* so far, with the furthest stage it reached:
  discovered     found through the RTTI / vtables (class and slot known)  / descubierta por RTTI/vtables
  studied        decompiled and read (Ghidra)                              / decompilada y leída
  reimplemented  a rule of the port cites it                               / la cita una regla del port
  verified       that rule is checked against the original (test or trace) / regla comprobada con el original

Only addresses, class/slot names and stages are written: no code.

Usage / Uso:
  game_functions.py vtables.tsv out.tsv [--studied DIR_OF_GHIDRA_C_EXPORTS] [--rules RULES.md]
  vtables.tsv: from rtti_scan.py. --studied: *.c files with "// ===== NAME @ ADDR" headers.
  --rules: Markdown tables "| rule | state | evidence ... |"; addresses 0x... in the evidence column;
           states starting with V-test or V-traza count as verified.
"""
import argparse
import glob
import re

CODE_MIN, CODE_MAX = 0x8000, 0x400000
ORDER = {"discovered": 0, "studied": 1, "reimplemented": 2, "verified": 3}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("vtables")
    ap.add_argument("out")
    ap.add_argument("--studied")
    ap.add_argument("--rules")
    a = ap.parse_args()
    funcs = {}

    def mark(addr, name, stage):
        if not CODE_MIN <= addr < CODE_MAX:
            return
        cur = funcs.get(addr)
        if cur is None:
            funcs[addr] = [name, stage]
            return
        if ORDER[stage] > ORDER[cur[1]]:
            cur[1] = stage
        if cur[0].startswith("FUN_") and not name.startswith("FUN_"):
            cur[0] = name

    for line in open(a.vtables, encoding="utf-8").readlines()[1:]:
        vtable, cls, off, slot, target, owner = line.rstrip("\n").split("\t")
        mark(int(target, 16), f"{owner}::v{int(slot):02d}", "discovered")
    if a.studied:
        for path in glob.glob(a.studied + "/*.c"):
            for m in re.finditer(r"^// ===== (\S+) @ ([0-9a-f]+)", open(path, encoding="utf-8", errors="replace").read(), re.M):
                mark(int(m.group(2), 16), m.group(1), "studied")
    if a.rules:
        for line in open(a.rules, encoding="utf-8"):
            if not line.startswith("| "):
                continue
            cells = [c.strip() for c in line.replace("\\|", "¦").strip("|").split("|")]
            if len(cells) < 3:
                continue
            stage = "verified" if cells[1].startswith(("V-test", "V-traza")) else "reimplemented"
            if not cells[1].startswith(("V-", "Pendiente", "Port")):
                continue
            for m in re.finditer(r"0x([0-9a-f]{4,6})\b", cells[2]):
                mark(int(m.group(1), 16), f"FUN_{int(m.group(1), 16):08x}", stage)
    with open(a.out, "w", encoding="utf-8") as o:
        o.write("# address\tname\tstage (discovered | studied | reimplemented | verified)\n")
        for addr in sorted(funcs):
            o.write(f"0x{addr:x}\t{funcs[addr][0]}\t{funcs[addr][1]}\n")
    from collections import Counter
    print(a.out, len(funcs), dict(Counter(s for _, s in funcs.values())))


if __name__ == "__main__":
    main()
