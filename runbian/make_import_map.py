#!/usr/bin/env python3
"""Resolve the imports of an uncompressed (ELF-derived) E32Image to symbol names.

Each import entry is an offset into the code section. The word there holds the
ordinal, and the word before it is the stub `ldr pc, [pc, #-4]` (0xe51ff004),
so the callable stub lives at entry_vma - 4.

Entries not preceded by the stub are data imports (typeinfo/vtables referenced
from the game's own RTTI), so the entry word itself is the reference.

Outputs:
  imports.tsv  kind \t entry_vma \t dll \t ordinal \t symbol   (kind: func|data; consumed by the Ghidra script)
  data.bin     initialised data section (to map at iDataBase)

Usage: make_import_map.py unpacked.exe defs_dir out_dir
"""
import os
import re
import struct
import sys

STUB = 0xE51FF004
DEF_LINE = re.compile(r'^\s*(\S+)\s+@\s*(\d+)')


def load_def(path):
    table = {}
    if not os.path.exists(path):
        return table
    with open(path, encoding='latin-1') as f:
        for line in f:
            m = DEF_LINE.match(line)
            if m:
                table[int(m.group(2))] = m.group(1)
    return table


def main():
    exe, defs_dir, out_dir = sys.argv[1:4]
    d = open(exe, 'rb').read()
    u = lambda o: struct.unpack_from('<I', d, o)[0]
    if u(0x1C) != 0:
        sys.exit('image is still compressed; run e32_unpack.py first')
    code_off, code_base = u(0x64), u(0x4C)
    data_off, data_size = u(0x68), u(0x34)
    imp, ndll = u(0x6C), u(0x54)

    rows, missing = [], 0
    p = imp + 4
    for _ in range(ndll):
        name_off, count = struct.unpack_from('<II', d, p)
        offsets = struct.unpack_from(f'<{count}I', d, p + 8)
        p += 8 + 4 * count
        full = d[imp + name_off:d.index(b'\0', imp + name_off)].decode()
        dll = full.split('{')[0]
        table = load_def(os.path.join(defs_dir, dll + '.def'))
        for off in offsets:
            word = u(code_off + off)
            ordinal = word & 0xFFFF
            kind = 'func' if u(code_off + off - 4) == STUB else 'data'
            sym = table.get(ordinal)
            if sym is None:
                missing += 1
                sym = f'{dll}_ord{ordinal}'
            rows.append((code_base + off, kind, dll, ordinal, sym))

    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, 'imports.tsv'), 'w') as f:
        for vma, kind, dll, ordinal, sym in sorted(rows):
            f.write(f'{kind}\t{vma:#x}\t{dll}\t{ordinal}\t{sym}\n')
    with open(os.path.join(out_dir, 'data.bin'), 'wb') as f:
        f.write(d[data_off:data_off + data_size])
    nfunc = sum(r[1] == 'func' for r in rows)
    print(f'{len(rows)} imports ({nfunc} func, {len(rows) - nfunc} data), {len(rows) - missing} named, {missing} unresolved')


if __name__ == '__main__':
    main()
