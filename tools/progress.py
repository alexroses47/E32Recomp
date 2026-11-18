#!/usr/bin/env python3
"""Progress page for E32Recomp / Página de progreso de E32Recomp.

Two grids, one square per function:
  1. Symbian functions imported by the tracked games (games/<game>.tsv) and whether the runtime implements
     them (STUBS in e32recomp/e32emu.py); library sizes from third_party/symbian-defs/*.def.
  2. Functions of each game discovered so far and the furthest stage they reached
     (games/<game>_functions.tsv, from e32recomp/game_functions.py).
Writes index.html, progress.json and progress.svg (the Symbian grid, used by the README).

Usage / Uso: python3 tools/progress.py [out_dir]   (default: docs/). No dependencies.
"""
import glob
import html
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
REPO = "https://github.com/alexroses47/E32Recomp"
SQ, GAP, COLS = 12, 2, 69
C_IMPL, C_TODO = "#2ea043", "#8c959f"
STAGES = [("verified", "#2ea043", "verified against the original / verificada con el original"),
          ("reimplemented", "#d29922", "reimplemented in the port / reimplementada en el port"),
          ("studied", "#388bfd", "studied (decompiled and read) / estudiada (decompilada y leída)"),
          ("discovered", "#8c959f", "discovered (RTTI / vtables) / descubierta (RTTI / vtables)")]


def implemented_symbols():
    src = open(os.path.join(ROOT, "e32recomp", "e32emu.py"), encoding="utf-8").read()
    block = src[src.index("STUBS = {"):]
    block = block[:block.index("\n}\n")]
    return set(re.findall(r'^\s+"([^"]+)":', block, re.M))


def def_table(lib):
    """symbol -> readable name (the comment of the .def line), and the export count."""
    path = os.path.join(ROOT, "third_party", "symbian-defs", lib + ".def")
    names, n = {}, 0
    if not os.path.exists(path):
        return names, None
    for line in open(path, encoding="latin-1"):
        m = re.match(r"^\s*(\S+)\s+@\s*\d+[^;]*(?:;\s*(.*))?$", line)
        if m:
            n += 1
            names[m.group(1)] = (m.group(2) or m.group(1)).strip()
    return names, n


def demangle(names):
    """Readable C++ names with c++filt (macOS and GitHub runners have it); unchanged if missing."""
    import subprocess
    mangled = sorted({n for n in names if n.startswith("_Z")})
    if not mangled:
        return {}
    try:
        res = subprocess.run(["c++filt"], input="\n".join(mangled), capture_output=True, text=True, timeout=30)
        return dict(zip(mangled, res.stdout.splitlines()))
    except (OSError, subprocess.SubprocessError):
        return {}


def game_names():
    return sorted({os.path.basename(p)[:-4] for p in glob.glob(os.path.join(ROOT, "games", "*.tsv"))
                   if not p.endswith("_functions.tsv")})


def imports(game):
    rows = []
    for line in open(os.path.join(ROOT, "games", game + ".tsv"), encoding="utf-8"):
        if line.startswith("#") or not line.strip():
            continue
        kind, dll, ordinal, sym = line.rstrip("\n").split("\t")
        if kind == "func":
            rows.append((dll, sym))
    return rows


def functions(game):
    path = os.path.join(ROOT, "games", game + "_functions.tsv")
    if not os.path.exists(path):
        return []
    out = []
    for line in open(path, encoding="utf-8"):
        if line.startswith("#") or not line.strip():
            continue
        addr, name, stage = line.rstrip("\n").split("\t")
        out.append((addr, name, stage))
    return out


def grid(groups, title=None):
    """groups: [(label, [(color, tooltip), ...])]; returns an inline SVG with one square per item."""
    parts, y = [], 0
    width = COLS * (SQ + GAP)
    if title:
        parts.append(f'<text x="0" y="12" font-size="13" font-weight="bold">{html.escape(title)}</text>')
        y = 18
    for label, items in groups:
        if label:
            parts.append(f'<text x="0" y="{y + 11}" font-size="11">{html.escape(label)}</text>')
            y += 15
        for i, (color, tip) in enumerate(items):
            x = (i % COLS) * (SQ + GAP)
            yy = y + (i // COLS) * (SQ + GAP)
            parts.append(f'<rect x="{x}" y="{yy}" width="{SQ}" height="{SQ}" fill="{color}"><title>{html.escape(tip)}</title></rect>')
        y += ((len(items) + COLS - 1) // COLS) * (SQ + GAP) + 6
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{y}" viewBox="0 0 {width} {y}" '
            f'font-family="sans-serif">{"".join(parts)}</svg>')


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "docs")
    os.makedirs(out, exist_ok=True)
    impl = implemented_symbols()
    games = game_names()
    used = defaultdict(set)
    for g in games:
        for dll, sym in imports(g):
            used[dll].add(sym)

    readable = demangle({s for v in used.values() for s in v})
    libs, sym_groups, missing = [], [], []
    for dll in sorted(used, key=str.lower):
        names, exports = def_table(dll)
        for s in used[dll]:
            if names.get(s, s).startswith("_Z") and s in readable:
                names[s] = readable[s]
        syms = sorted(used[dll], key=lambda s: (s not in impl, names.get(s, s).lower()))
        done = [s for s in syms if s in impl]
        libs.append({"library": dll, "implemented": len(done), "used": len(syms), "exports": exports})
        sym_groups.append((f"{dll} — {len(done)}/{len(syms)}",
                           [(C_IMPL if s in impl else C_TODO, f"{dll}: {names.get(s, s)}" + (" ✓" if s in impl else ""))
                            for s in syms]))
        todo = [names.get(s, s) for s in syms if s not in impl]
        if todo:
            missing.append((dll, todo))
    tot_used = sum(l["used"] for l in libs)
    tot_impl = sum(l["implemented"] for l in libs)
    pct = 100.0 * tot_impl / tot_used if tot_used else 0.0

    game_data = []
    for g in games:
        fn = functions(g)
        cnt = Counter(s for _, _, s in fn)
        imp = imports(g)
        n_imp = len({s for _, s in imp})
        n_ok = len({s for _, s in imp if s in impl})
        game_data.append({"game": g, "imports": n_imp, "imports_implemented": n_ok,
                          "functions": len(fn), "stages": {k: cnt.get(k, 0) for k, _, _ in STAGES}, "_fn": fn})

    # progress.svg (README): the Symbian grid without labels, with the percentage
    flat = [item for _, items in sym_groups for item in items]
    svg = grid([("", flat)], title=f"E32Recomp: {tot_impl}/{tot_used} Symbian functions implemented ({pct:.1f}%)")
    open(os.path.join(out, "progress.svg"), "w", encoding="utf-8").write(svg)

    data = {"generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), "percent": round(pct, 2),
            "implemented": tot_impl, "used": tot_used, "libraries": libs,
            "games": [{k: v for k, v in g.items() if k != "_fn"} for g in game_data]}
    json.dump(data, open(os.path.join(out, "progress.json"), "w"), indent=1)

    def legend(entries):
        return " ".join(f'<span class="lg"><i style="background:{c}"></i>{html.escape(t)}</span>' for c, t in entries)

    lib_rows = "".join(
        f'<tr><td>{html.escape(l["library"])}</td><td>{l["implemented"]}</td><td>{l["used"]}</td>'
        f'<td>{l["exports"] if l["exports"] is not None else "?"}</td>'
        f'<td>{100.0 * l["implemented"] / l["used"]:.0f}%</td></tr>' for l in libs)
    miss_rows = "".join(f'<tr><td>{html.escape(d)}</td><td class="names"><code>{html.escape(", ".join(t))}</code></td></tr>'
                        for d, t in missing)
    game_html = ""
    for g in game_data:
        st = g["stages"]
        found = g["functions"]
        groups = []
        for key, color, _ in STAGES:
            items = [(color, f"{a} {n} — {key}") for a, n, s in g["_fn"] if s == key]
            if items:
                groups.append((f"{key} — {len(items)}", items))
        game_html += f"""
<h2>Game: {html.escape(g["game"])} / Juego</h2>
<table><tr><th>Measure / Medida</th><th>Count</th><th>Of</th></tr>
<tr><td>Symbian imports implemented by the runtime / importaciones implementadas</td><td>{g["imports_implemented"]}</td><td>{g["imports"]}</td></tr>
<tr><td>Functions discovered / funciones descubiertas</td><td>{found}</td><td>–</td></tr>
<tr><td>Studied (decompiled and read) or further / estudiadas o más</td><td>{st["studied"] + st["reimplemented"] + st["verified"]}</td><td>{found}</td></tr>
<tr><td>Reimplemented in a native port or further / reimplementadas o más</td><td>{st["reimplemented"] + st["verified"]}</td><td>{found}</td></tr>
<tr><td>Verified against the original / verificadas con el original</td><td>{st["verified"]}</td><td>{found}</td></tr>
</table>
<p>{legend([(c, t) for _, c, t in STAGES])}</p>
{grid(groups)}
"""

    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>E32Recomp progress</title>
<style>body{{font-family:sans-serif;max-width:1000px;margin:auto;padding:16px;background:#fff;color:#1f2328}}
img,svg{{max-width:100%;height:auto}}table{{border-collapse:collapse;width:100%;margin:8px 0}}th,td{{border:1px solid #ccc;padding:2px 8px}}
td+td,th+th{{text-align:right}}td.names{{text-align:left}}code{{font-size:12px}}svg text{{fill:currentColor}}
.lg{{display:inline-block;margin-right:14px;font-size:13px}}.lg i{{display:inline-block;width:10px;height:10px;margin-right:4px;vertical-align:-1px}}
@media(prefers-color-scheme:dark){{body{{background:#0d1117;color:#e6edf3}}th,td{{border-color:#30363d}}a{{color:#58a6ff}}}}</style>
</head><body>
<h1>Progress / Progreso</h1>
<p><b>E32Recomp</b>: static recompilation + runtime for native ports of Symbian games (experimental). /
recompilación estática + runtime para ports nativos de juegos de Symbian (experimental).</p>
{grid(sym_groups, title=f"Symbian functions used by the games: {tot_impl}/{tot_used} implemented ({pct:.1f}%)")}
<p>{legend([(C_IMPL, "implemented by the runtime / implementada"), (C_TODO, "not yet / pendiente")])}
Hover a square to see the function. / Pasa el ratón por un cuadro para ver la función.</p>
<p>Generated by <a href="{REPO}/blob/main/tools/progress.py">tools/progress.py</a> after every push to <code>main</code>, daily,
and when the Pages workflow is run manually ({data["generated"]}). Raw numbers: <a href="progress.json">progress.json</a>.</p>
<h2>Symbian libraries / Bibliotecas de Symbian</h2>
<table><tr><th>Library</th><th>Implemented</th><th>Used by games</th><th>Exports</th><th>%</th></tr>{lib_rows}</table>
<p>A Symbian function counts as implemented when the runtime (<code>e32recomp/e32emu.py</code>, <code>STUBS</code>) provides
it, so original code that calls it can run. <i>Used by games</i> counts only the functions imported by the tracked games
(<code>games/</code>), not every export of the library; <i>Exports</i> is the size of the library from its
<code>.def</code> table. / Una función cuenta como implementada cuando el runtime la proporciona; <i>Used by games</i> solo
cuenta las que importan los juegos de referencia.</p>
<h3>Not implemented yet / Pendientes</h3>
<table>{miss_rows}</table>
{game_html}
<p>Game functions: <i>discovered</i> means found through the executable's RTTI and vtables or analysed; the total
grows as more of the game is explored, so it is not the number of functions in the executable. A function is
<i>reimplemented</i> when a rule of a native port cites its address, and <i>verified</i> when that rule is checked
against the original (differential test or trace). Only addresses and names are published, never code. /
Funciones del juego: <i>descubiertas</i> por la RTTI y las vtables o analizadas; el total crece al explorar más.
Solo se publican direcciones y nombres, nunca código.</p>
</body></html>
"""
    open(os.path.join(out, "index.html"), "w", encoding="utf-8").write(page)
    print(f"{out}: {tot_impl}/{tot_used} ({pct:.1f}%), {len(libs)} libraries, games: "
          + ", ".join(f'{g["game"]} {g["functions"]} functions' for g in game_data))


if __name__ == "__main__":
    main()
