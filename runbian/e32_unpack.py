#!/usr/bin/env python3
"""Decompress a Symbian 9.x E32Image compressed with BytePair (KUidCompressionBytePair).

Layout after the header (header size == iCodeOffset):
  [code block]  u32 compressed_size, u32 uncompressed_size, u16 num_pages, u16 page_sizes[num_pages], pages...
  [rest block]  same index format for everything after the code (data, imports, relocations)
Each page decompresses to at most 4096 bytes.

Output: an uncompressed E32Image (compression type cleared) that standard tools can parse.
Usage: e32_unpack.py input.exe output.exe
"""
import struct
import sys

PAGE = 0x1000
KUidCompressionBytePair = 0x102822AA


def bytepair_page(src: bytes) -> bytes:
    pos = 0
    num_tokens = src[pos]; pos += 1
    if num_tokens == 0:
        return src[pos:]
    marker = src[pos]; pos += 1
    lut0 = list(range(256))
    lut1 = [0] * 256
    if num_tokens < 32:
        for _ in range(num_tokens):
            b = src[pos]; lut0[b] = src[pos + 1]; lut1[b] = src[pos + 2]; pos += 3
    else:
        mask = src[pos:pos + 32]; pos += 32
        for b in range(256):
            if mask[b >> 3] & (1 << (b & 7)):
                lut0[b] = src[pos]; lut1[b] = src[pos + 1]; pos += 2
    out = bytearray()
    while pos < len(src):
        b = src[pos]; pos += 1
        if b == marker:
            out.append(src[pos]); pos += 1
            continue
        stack = [b]
        while stack:
            t = stack.pop()
            if lut0[t] == t:          # not a token: literal byte
                out.append(t)
            else:                     # token: expand pair (first byte first)
                stack.append(lut1[t])
                stack.append(lut0[t])
    return bytes(out)


def unpack_block(d: bytes, off: int):
    csize, usize, npages = struct.unpack_from('<IIH', d, off)
    sizes = struct.unpack_from(f'<{npages}H', d, off + 10)
    pos = off + 10 + 2 * npages
    out = bytearray()
    for i, s in enumerate(sizes):
        page = bytepair_page(d[pos:pos + s])
        expected = min(PAGE, usize - i * PAGE)
        if len(page) != expected:
            raise ValueError(f'page {i}: got {len(page)} bytes, expected {expected}')
        out += page
        pos += s
    if pos - off != csize:                 # compressed size includes the index
        raise ValueError(f'compressed size mismatch: {pos - off} vs {csize}')
    return bytes(out), pos


def main():
    d = open(sys.argv[1], 'rb').read()
    comp = struct.unpack_from('<I', d, 0x1C)[0]
    if comp != KUidCompressionBytePair:
        sys.exit(f'not BytePair-compressed (type {comp:#x})')
    hdr_size = struct.unpack_from('<I', d, 0x64)[0]   # iCodeOffset
    total = struct.unpack_from('<I', d, 0x7C)[0]       # iUncompressedSize
    code, pos = unpack_block(d, hdr_size)
    rest, pos = unpack_block(d, pos)
    body = code + rest
    if len(body) != total:
        raise ValueError(f'body {len(body):#x} != iUncompressedSize {total:#x}')
    hdr = bytearray(d[:hdr_size])
    struct.pack_into('<I', hdr, 0x1C, 0)               # mark as uncompressed
    open(sys.argv[2], 'wb').write(bytes(hdr) + body)
    print(f'ok: code {len(code):#x}, rest {len(rest):#x}, total {hdr_size + total:#x} bytes')


if __name__ == '__main__':
    main()
