#!/usr/bin/env python3
"""Progress page for E32Recomp / Página de progreso de E32Recomp.

Counts, for every Symbian library used by the tracked games (games/*.tsv), how many of the imported
functions the runtime implements (STUBS in e32recomp/e32emu.py), and how many exports the library has
(third_party/symbian-defs/*.def). Writes progress.json, progress.svg and index.html.

Cuenta, por cada biblioteca de Symbian que usan los juegos de referencia, cuántas de las funciones que
importan implementa el runtime y cuántas exporta la biblioteca.

Usage / Uso: python3 tools/progress.py [out_dir]   (default: docs/)
No third-party dependencies.
"""
import glob
import html
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
REPO = "https://github.com/alexroses47/E32Recomp"


def implemented_symbols():
    src = open(os.path.join(ROOT, "e32recomp", "e32emu.py"), encoding="utf-8").read()
    block = src[src.index("STUBS = {"):]
    block = block[:block.index("\n}\n")]
    return set(re.findall(r'^\s+"([^"]+)":', block, re.M))


def exports(lib):
    path = os.path.join(ROOT, "third_party", "symbian-defs", lib + ".def")
    if not os.path.exists(path):
        return None
    return sum(1 for line in open(path, encoding="latin-1") if re.match(r"^\s*\S+\s+@\s*\d+", line))


def games():
    out = {}
    for path in sorted(glob.glob(os.path.join(ROOT, "games", "*.tsv"))):
        rows = []
        for line in open(path, encoding="utf-8"):
            if line.startswith("#") or not line.strip():
                continue
            kind, dll, ordinal, sym = line.rstrip("\n").split("\t")
            if kind == "func":
                rows.append((dll, int(ordinal), sym))
        out[os.path.splitext(os.path.basename(path))[0]] = rows
    return out


def bar_svg(pct):
    w = 400
    fill = int(w * pct / 100)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w + 70}" height="24">'
            f'<rect width="{w}" height="24" fill="#6e7681"/><rect width="{fill}" height="24" fill="#2ea043"/>'
            f'<text x="{w + 8}" y="17" font-family="sans-serif" font-size="14">{pct:.1f}%</text></svg>')


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "docs")
    os.makedirs(out, exist_ok=True)
    impl = implemented_symbols()
    gm = games()
    used = defaultdict(set)
    for rows in gm.values():
        for dll, ordinal, sym in rows:
            used[dll].add(sym)
    libs = []
    for dll in sorted(used, key=str.lower):
        u = used[dll]
        i = sorted(s for s in u if s in impl)
        libs.append({"library": dll, "implemented": len(i), "used": len(u), "exports": exports(dll),
                     "implemented_names": i})
    tot_used = sum(l["used"] for l in libs)
    tot_impl = sum(l["implemented"] for l in libs)
    pct = 100.0 * tot_impl / tot_used if tot_used else 0.0
    game_rows = []
    for name, rows in gm.items():
        syms = {s for _, _, s in rows}
        n = sum(1 for s in syms if s in impl)
        game_rows.append({"game": name, "implemented": n, "imports": len(syms)})
    data = {"generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), "percent": round(pct, 2),
            "implemented": tot_impl, "used": tot_used, "libraries": libs, "games": game_rows}
    json.dump(data, open(os.path.join(out, "progress.json"), "w"), indent=1)
    open(os.path.join(out, "progress.svg"), "w").write(bar_svg(pct))

    def row(l):
        p = 100.0 * l["implemented"] / l["used"] if l["used"] else 0
        ex = l["exports"] if l["exports"] is not None else "?"
        return (f'<tr><td>{html.escape(l["library"])}</td><td>{l["implemented"]}</td><td>{l["used"]}</td>'
                f'<td>{ex}</td><td>{p:.0f}%</td><td class="b"><div class="bar"><i style="width:{p:.0f}%"></i></div></td></tr>')

    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>E32Recomp progress</title>
<style>body{{font-family:sans-serif;max-width:1000px;margin:auto;padding:16px;background:#fff;color:#1f2328}}
img{{max-width:100%}}.bar{{background:#6e7681;width:100%;min-width:120px;height:14px}}.bar i{{display:block;height:14px;background:#2ea043}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccc;padding:2px 8px}}td+td,th+th{{text-align:right}}td.b{{width:30%}}
@media(prefers-color-scheme:dark){{body{{background:#0d1117;color:#e6edf3}}th,td{{border-color:#30363d}}a{{color:#58a6ff}}}}</style>
</head><body>
<h1>E32Recomp — Progress / Progreso</h1>
<img src="progress.svg" alt="{pct:.1f}%">
<p><b>{tot_impl}</b> of <b>{tot_used}</b> Symbian functions imported by the tracked games are implemented by the
runtime. / <b>{tot_impl}</b> de <b>{tot_used}</b> funciones de Symbian que importan los juegos de referencia están
implementadas en el runtime.</p>
<p>Generated by <a href="{REPO}/blob/main/tools/progress.py">tools/progress.py</a> on every push to <code>main</code>
({data["generated"]}). Raw numbers: <a href="progress.json">progress.json</a>.</p>
<h2>Games / Juegos</h2>
<table><tr><th>Game / Juego</th><th>Implemented</th><th>Imports</th><th>%</th></tr>
{"".join(f'<tr><td>{html.escape(g["game"])}</td><td>{g["implemented"]}</td><td>{g["imports"]}</td><td>{100.0 * g["implemented"] / g["imports"]:.0f}%</td></tr>' for g in game_rows)}
</table>
<h2>Symbian libraries / Bibliotecas de Symbian</h2>
<p><i>Used</i> = functions imported by the tracked games; <i>Exports</i> = size of the library (from its .def).
/ <i>Used</i> = funciones que importan los juegos; <i>Exports</i> = tamaño de la biblioteca.</p>
<table><tr><th>Library</th><th>Implemented</th><th>Used</th><th>Exports</th><th>%</th><th></th></tr>
{"".join(row(l) for l in libs)}
</table>
</body></html>
"""
    open(os.path.join(out, "index.html"), "w", encoding="utf-8").write(page)
    print(f"{out}: {tot_impl}/{tot_used} ({pct:.1f}%), {len(libs)} libraries, {len(game_rows)} games")


if __name__ == "__main__":
    main()
