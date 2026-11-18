#!/usr/bin/env python3
"""RunbIan HLE runtime, stage 0: runs functions of a Symbian E32 executable with Unicorn.
Etapa 0 del runtime: ejecuta funciones de un ejecutable E32 de Symbian con Unicorn.

Loads an uncompressed E32 image (runbian/e32_unpack.py) at the requested bases, applies its relocations,
replaces Symbian imports with Python implementations (HLE) and lets you call a function by its link address
with a prepared state. Used to compare a port's code with the original, function by function.

Implemented imports (STUBS below; tools/progress.py counts them): EABI soft-float with exact float32
rounding (dfpaeabi), integer division (drtaeabi), memcpy/memset/memclr, sqrtf/sinf/cosf/atan2f... (libm),
new/delete with its own heap. Any other import stops execution with an error naming it.
Cualquier otra importación detiene la ejecución con un error que la nombra.
"""
import math
import struct

from unicorn import Uc, UcError, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP,
                               UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR)

LINK_CODE = 0x8000
LINK_DATA = 0x400000
HOOKS = 0x70000000        # una palabra por importación: dirección a la que salta el stub
RETURN = 0x7F000000       # dirección de retorno: al llegar aquí la llamada termina
STACK_TOP = 0x7E000000
HEAP = 0x60000000
PAGE = 0x1000


def f32(x):
    return struct.unpack("<f", struct.pack("<f", x))[0]


def bits(x):
    return struct.unpack("<I", struct.pack("<f", x))[0]


def fl(u):
    return struct.unpack("<f", struct.pack("<I", u & 0xFFFFFFFF))[0]


def align(x, a=PAGE):
    return (x + a - 1) & ~(a - 1)


class EmuError(Exception):
    pass


class E32Emu:
    def __init__(self, exe_path, imports_tsv, code_base=LINK_CODE, data_base=LINK_DATA):
        self.img = open(exe_path, "rb").read()
        u = lambda o: struct.unpack_from("<I", self.img, o)[0]
        self.code_size, self.data_size, self.bss_size = u(0x30), u(0x34), u(0x44)
        self.link_code, self.link_data = u(0x4C), u(0x50)
        code_off, data_off = u(0x64), u(0x68)
        code_reloc, data_reloc = u(0x70), u(0x74)
        self.code_base, self.data_base = code_base, data_base
        self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        mu = self.mu
        mu.mem_map(code_base, align(self.code_size))
        mu.mem_map(data_base, align(self.data_size + self.bss_size))
        mu.mem_map(HOOKS, PAGE * 4)
        mu.mem_map(RETURN, PAGE)
        mu.mem_map(STACK_TOP - 0x100000, 0x100000)
        mu.mem_map(HEAP, 0x400000)
        code = bytearray(self.img[code_off:code_off + self.code_size])
        data = bytearray(self.img[data_off:data_off + self.data_size])
        self.relocs = 0
        self._relocate(code, data, code_reloc, base=code_base, link=self.link_code)
        if data_reloc and self.data_size:
            self._relocate(code, data, data_reloc, base=data_base, link=self.link_data)
        # importaciones: cada palabra de importación pasa a apuntar a su gancho
        self.stub_names = {}
        for line in open(imports_tsv, encoding="utf-8"):
            kind, addr, dll, ordinal, sym = line.rstrip("\n").split("\t")
            off = int(addr, 16) - self.link_code
            if kind == "func":
                hook = HOOKS + 4 * len(self.stub_names)
                self.stub_names[hook] = sym
                struct.pack_into("<I", code, off, hook)
            else:
                struct.pack_into("<I", code, off, HOOKS + PAGE * 3)   # objetos de datos: zona vacía
        mu.mem_write(code_base, bytes(code))
        mu.mem_write(data_base, bytes(data))
        self.heap_next = HEAP
        self.overrides = {}     # dirección (de enlace) -> función Python que sustituye a una interna
        self.calls = []         # registro de stubs llamados
        mu.hook_add(UC_HOOK_CODE, self._on_hook, begin=HOOKS, end=HOOKS + PAGE * 4)
        mu.hook_add(UC_HOOK_CODE, self._on_return, begin=RETURN, end=RETURN + 4)
        mu.hook_add(UC_HOOK_MEM_UNMAPPED, self._on_unmapped)
        self._override_hook = None

    # ------------------------------------------------------------------ carga
    def _relocate(self, code, data, off, base, link):
        """E32: u32 tamaño, u32 nº; bloques {u32 página, u32 tamaño, u16 entradas}. Tipo en 4 bits altos:
        1 = apunta al código, 2 = a los datos, 3 = deducido por el valor."""
        size, count = struct.unpack_from("<II", self.img, off)
        p, end = off + 8, off + 8 + size
        target = code if link == self.link_code else data
        dcode = self.code_base - self.link_code
        ddata = self.data_base - self.link_data
        while p < end:
            page, bsize = struct.unpack_from("<II", self.img, p)
            n = (bsize - 8) // 2
            for e in struct.unpack_from("<%dH" % n, self.img, p + 8):
                typ, o = e >> 12, e & 0xFFF
                if typ == 0:
                    continue
                a = page + o
                v = struct.unpack_from("<I", target, a)[0]
                if typ == 3:
                    typ = 1 if self.link_code <= v < self.link_code + self.code_size else 2
                v += dcode if typ == 1 else ddata
                struct.pack_into("<I", target, a, v & 0xFFFFFFFF)
                self.relocs += 1
            p += bsize

    # ------------------------------------------------------------------ direcciones
    def code_addr(self, link_addr):
        return link_addr - self.link_code + self.code_base

    def data_addr(self, link_addr):
        return link_addr - self.link_data + self.data_base

    # ------------------------------------------------------------------ memoria
    def alloc(self, size, fill=0):
        a = self.heap_next
        self.heap_next = align(a + size, 8)
        self.mu.mem_write(a, bytes([fill]) * size)
        return a

    def write_u32(self, a, v): self.mu.mem_write(a, struct.pack("<I", v & 0xFFFFFFFF))
    def read_u32(self, a): return struct.unpack("<I", self.mu.mem_read(a, 4))[0]
    def write_f32(self, a, v): self.mu.mem_write(a, struct.pack("<f", v))
    def read_f32(self, a): return struct.unpack("<f", self.mu.mem_read(a, 4))[0]
    def write_u8(self, a, v): self.mu.mem_write(a, bytes([v & 0xFF]))
    def read_u8(self, a): return self.mu.mem_read(a, 1)[0]
    def write_floats(self, a, vals): self.mu.mem_write(a, struct.pack("<%df" % len(vals), *vals))
    def read_floats(self, a, n): return list(struct.unpack("<%df" % n, self.mu.mem_read(a, 4 * n)))

    # ------------------------------------------------------------------ llamadas
    def override(self, link_addr, fn):
        """Sustituye una función interna (dirección de enlace) por `fn(emu) -> valor de r0`."""
        a = self.code_addr(link_addr) & ~1
        self.overrides[a] = fn
        if self._override_hook is None:
            self._override_hook = self.mu.hook_add(UC_HOOK_CODE, self._on_override)

    def call(self, link_addr, args=(), thumb=False, max_insns=2_000_000):
        mu = self.mu
        regs = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3]
        sp = STACK_TOP - 0x1000
        stack_args = list(args[4:])
        sp -= 4 * len(stack_args)
        for i, v in enumerate(stack_args):
            self.write_u32(sp + 4 * i, v)
        for r, v in zip(regs, list(args[:4]) + [0] * (4 - min(4, len(args)))):
            mu.reg_write(r, v & 0xFFFFFFFF)
        mu.reg_write(UC_ARM_REG_SP, sp)
        mu.reg_write(UC_ARM_REG_LR, RETURN)
        start = self.code_addr(link_addr) | (1 if thumb else 0)
        self.calls = []
        self.error = None
        try:
            mu.emu_start(start, RETURN, count=max_insns)
        except UcError as e:
            pc = mu.reg_read(UC_ARM_REG_PC)
            raise EmuError(f"{e} en pc={pc:#x} (enlace {pc - self.code_base + self.link_code:#x})") from None
        if self.error:
            raise EmuError(self.error)
        if mu.reg_read(UC_ARM_REG_PC) != RETURN:
            raise EmuError(f"no volvió: pc={mu.reg_read(UC_ARM_REG_PC):#x} (¿bucle o límite de instrucciones?)")
        return mu.reg_read(UC_ARM_REG_R0), mu.reg_read(UC_ARM_REG_R1)

    def _ret(self, r0=None, r1=None):
        mu = self.mu
        if r0 is not None:
            mu.reg_write(UC_ARM_REG_R0, r0 & 0xFFFFFFFF)
        if r1 is not None:
            mu.reg_write(UC_ARM_REG_R1, r1 & 0xFFFFFFFF)
        lr = mu.reg_read(UC_ARM_REG_LR)
        cpsr = mu.reg_read(UC_ARM_REG_CPSR)
        if lr & 1:
            mu.reg_write(UC_ARM_REG_CPSR, cpsr | 0x20)
        else:
            mu.reg_write(UC_ARM_REG_CPSR, cpsr & ~0x20)
        mu.reg_write(UC_ARM_REG_PC, lr & ~1)

    def _set_flags(self, n, z, c, v):
        cpsr = self.mu.reg_read(UC_ARM_REG_CPSR) & 0x0FFFFFFF
        cpsr |= (n << 31) | (z << 30) | (c << 29) | (v << 28)
        self.mu.reg_write(UC_ARM_REG_CPSR, cpsr)

    def _on_return(self, mu, addr, size, user):
        mu.emu_stop()

    def _on_unmapped(self, mu, access, addr, size, value, user):
        pc = mu.reg_read(UC_ARM_REG_PC)
        self.error = f"acceso a memoria no preparada {addr:#x} (pc enlace {pc - self.code_base + self.link_code:#x})"
        return False

    def _on_override(self, mu, addr, size, user):
        fn = self.overrides.get(addr)
        if fn:
            r = fn(self)
            self._ret(r if r is not None else None)

    def _on_hook(self, mu, addr, size, user):
        name = self.stub_names.get(addr)
        if name is None:
            self.error = f"salto a una importación de datos ({addr:#x})"
            mu.emu_stop()
            return
        self.calls.append(name)
        fn = STUBS.get(name)
        if fn is None:
            self.error = f"importación sin stub: {name}"
            mu.emu_stop()
            return
        fn(self)

    # registros como enteros / floats
    def r(self, i):
        return self.mu.reg_read([UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3][i])

    def rf(self, i):
        return fl(self.r(i))


# ---------------------------------------------------------------------- stubs de Symbian
def _fop(op):
    def stub(e):
        a, b = e.rf(0), e.rf(1)
        try:
            v = op(a, b)
        except ZeroDivisionError:
            v = math.copysign(math.inf, a) * math.copysign(1, b) if a != 0 else math.nan
        except OverflowError:
            v = math.inf
        e._ret(bits(f32(v)) if not math.isnan(v) else 0x7FC00000)
    return stub


def _cmp_flags(e, a, b):
    # EABI __aeabi_cfcmple: Z = (a == b); C = 0 si a < b; desordenado (NaN): Z = 0, C = 1
    if math.isnan(a) or math.isnan(b):
        e._set_flags(0, 0, 1, 0)
    else:
        e._set_flags(0, int(a == b), int(not a < b), 0)


def _cfcmple(e):
    _cmp_flags(e, e.rf(0), e.rf(1)); e._ret()


def _cfrcmple(e):
    _cmp_flags(e, e.rf(1), e.rf(0)); e._ret()


def _fcmp(pred):
    def stub(e):
        a, b = e.rf(0), e.rf(1)
        e._ret(int(not (math.isnan(a) or math.isnan(b)) and pred(a, b)))
    return stub


def _i2f(e):
    v = e.r(0)
    e._ret(bits(f32(v - (1 << 32) if v & 0x80000000 else v)))


def _ui2f(e):
    e._ret(bits(f32(e.r(0))))


def _f2iz(e):
    v = e.rf(0)
    if math.isnan(v):
        e._ret(0); return
    v = max(-2147483648, min(2147483647, int(v)))
    e._ret(v & 0xFFFFFFFF)


def _f2uiz(e):
    v = e.rf(0)
    e._ret(0 if math.isnan(v) or v < 0 else min(0xFFFFFFFF, int(v)))


def _d(e, lo, hi):
    return struct.unpack("<d", struct.pack("<II", e.r(lo), e.r(hi)))[0]


def _ret_d(e, v):
    lo, hi = struct.unpack("<II", struct.pack("<d", v))
    e._ret(lo, hi)


def _f2d(e):
    _ret_d(e, e.rf(0))


def _d2f(e):
    e._ret(bits(f32(_d(e, 0, 1))))


def _idiv(e):
    a, b = e.r(0), e.r(1)
    a = a - (1 << 32) if a & 0x80000000 else a
    b = b - (1 << 32) if b & 0x80000000 else b
    if b == 0:
        e._ret(0); return
    q = abs(a) // abs(b) * (1 if (a < 0) == (b < 0) else -1)
    e._ret(q, a - q * b)


def _uidiv(e):
    a, b = e.r(0), e.r(1)
    if b == 0:
        e._ret(0); return
    e._ret(a // b, a % b)


def _memcpy(e):
    d, s, n = e.r(0), e.r(1), e.r(2)
    if n:
        e.mu.mem_write(d, bytes(e.mu.mem_read(s, n)))
    e._ret(d)


def _memset(e):
    # __aeabi_memset(dest, n, c)
    d, n, c = e.r(0), e.r(1), e.r(2)
    if n:
        e.mu.mem_write(d, bytes([c & 0xFF]) * n)
    e._ret(d)


def _memclr(e):
    d, n = e.r(0), e.r(1)
    if n:
        e.mu.mem_write(d, b"\0" * n)
    e._ret(d)


def _libm(fn):
    def stub(e):
        e._ret(bits(f32(fn(e.rf(0)))))
    return stub


def _atan2f(e):
    e._ret(bits(f32(math.atan2(e.rf(0), e.rf(1)))))


def _new(e):
    e._ret(e.alloc(max(4, e.r(0))))


def _delete(e):
    e._ret()


STUBS = {
    "__aeabi_fadd": _fop(lambda a, b: a + b),
    "__aeabi_fsub": _fop(lambda a, b: a - b),
    "__aeabi_frsub": _fop(lambda a, b: b - a),
    "__aeabi_fmul": _fop(lambda a, b: a * b),
    "__aeabi_fdiv": _fop(lambda a, b: a / b),
    "__aeabi_cfcmple": _cfcmple,
    "__aeabi_cfcmpeq": _cfcmple,
    "__aeabi_cfrcmple": _cfrcmple,
    "__aeabi_fcmplt": _fcmp(lambda a, b: a < b),
    "__aeabi_fcmple": _fcmp(lambda a, b: a <= b),
    "__aeabi_fcmpgt": _fcmp(lambda a, b: a > b),
    "__aeabi_fcmpge": _fcmp(lambda a, b: a >= b),
    "__aeabi_fcmpeq": _fcmp(lambda a, b: a == b),
    "__aeabi_i2f": _i2f,
    "__aeabi_ui2f": _ui2f,
    "__aeabi_f2iz": _f2iz,
    "__aeabi_f2uiz": _f2uiz,
    "__aeabi_f2d": _f2d,
    "__aeabi_d2f": _d2f,
    "__aeabi_idiv": _idiv,
    "__aeabi_idivmod": _idiv,
    "__aeabi_uidiv": _uidiv,
    "__aeabi_uidivmod": _uidiv,
    "__aeabi_memcpy": _memcpy,
    "__aeabi_memcpy4": _memcpy,
    "__aeabi_memcpy8": _memcpy,
    "__aeabi_memmove": _memcpy,
    "__aeabi_memset": _memset,
    "__aeabi_memclr": _memclr,
    "__aeabi_memclr4": _memclr,
    "memcpy": _memcpy,
    "sqrtf": _libm(lambda x: math.sqrt(x) if x >= 0 else math.nan),
    "sinf": _libm(math.sin),
    "cosf": _libm(math.cos),
    "atan2f": _atan2f,
    "_Znwj": _new,          # operator new(unsigned int)
    "_Znaj": _new,          # operator new[](unsigned int)
    "_ZdlPv": _delete,      # operator delete(void*)
    "_ZdaPv": _delete,      # operator delete[](void*)
    "fabsf": _libm(abs),
    "floorf": _libm(math.floor),
    "acosf": _libm(lambda x: math.acos(max(-1.0, min(1.0, x)))),
    "atanf": _libm(math.atan),
    "tanf": _libm(math.tan),
}
