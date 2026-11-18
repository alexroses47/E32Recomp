#!/usr/bin/env python3
"""docs/CLASES.md from re/rtti.tsv + re/vtables.tsv (tools/rtti_scan.py).

Usage: classes_doc.py re/ docs/CLASES.md

For every class: base chain and, slot by slot, which function actually runs
(the address and the class that implements it). Use it before reimplementing
any method: the version that runs for an object is the one in its own table.
"""
import csv
import sys
from collections import defaultdict

ENGINE = ("lang::", "io::", "gr::", "hgr::", "img::", "math::", "framework::", "nlibs::", "std::")


def origin(name):
    if name.startswith("nlibs::") or "N3D" in name:
        return "N3D"
    if name.startswith(ENGINE):
        return "KA3D"
    if (name[0] in "CM" and len(name) > 1 and name[1].isupper()) or name.startswith("MMda"):
        return "S60"
    return "juego"


def main(redir, out):
    rtti = list(csv.DictReader(open(f"{redir}/rtti.tsv", encoding="utf-8"), delimiter="\t"))
    vt = defaultdict(list)
    for r in csv.DictReader(open(f"{redir}/vtables.tsv", encoding="utf-8"), delimiter="\t"):
        if r["offset_to_top"] == "0":
            vt[r["class"]].append(r)
    base = {r["name"]: (r["bases"].split(",")[0] if r["bases"] else "") for r in rtti}
    children = defaultdict(list)
    for r in rtti:
        children[base[r["name"]]].append(r["name"])

    def chain(c):
        out = []
        while base.get(c):
            c = base[c]
            out.append(c)
        return out

    lines = ["# Class map / Mapa de clases", "",
             "Generado con `tools/classes_doc.py` a partir de la RTTI y las vtables del binario "
             "(`tools/rtti_scan.py`). **Antes de reimplementar un método, mira aquí qué versión se "
             "ejecuta para ese objeto:** la entrada de la vtable de su propia clase.", "",
             "- *Entrada*: índice en la vtable (las 0 y 1 son los destructores en los descendientes de `lang::Object`).",
             "- *Implementa*: la clase que aporta esa versión. **Negrita** = la sobrescribe esta clase.",
             "- Los nombres `Clase::vNN` de Ghidra siguen esta misma regla.", ""]

    # árbol del juego
    lines += ["## Jerarquía (clases del juego)", "", "```"]

    def walk(c, d):
        n = len(vt.get(c, []))
        lines.append("  " * d + c + (f"  [{n} entradas]" if n else ""))
        for k in sorted(children.get(c, [])):
            if origin(k) == "juego":
                walk(k, d + 1)
    roots = sorted({c for c in base if origin(c) == "juego" and origin(base[c] or "juego") != "juego"} |
                   {c for c in base if origin(c) == "juego" and not base[c]})
    for r in roots:
        lines.append(f"{base[r] or '(sin base)'}")
        walk(r, 1)
    lines += ["```", ""]

    # tablas por clase (juego primero)
    order = sorted(base, key=lambda c: (origin(c) != "juego", c))
    lines += ["## Vtables", ""]
    for c in order:
        slots = vt.get(c)
        if not slots:
            continue
        own = sum(1 for s in slots if s["owner"] == c)
        lines += [f"### {c}", "",
                  f"Origen: {origin(c)} · base: {' → '.join(chain(c)) or '—'} · {len(slots)} entradas, {own} propias", "",
                  "| Entrada | Función | Implementa |", "|---|---|---|"]
        for s in slots:
            who = f"**{s['owner']}**" if s["owner"] == c else s["owner"]
            lines.append(f"| {s['slot']} | `{s['target']}` | {who} |")
        lines.append("")
    open(out, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    print(f"{out}: {len(order)} clases")


if __name__ == "__main__":
    main(*sys.argv[1:3])
