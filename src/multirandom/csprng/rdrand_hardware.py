"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.csprng.rdrand_hardware
Description:
The CPU's own entropy instructions, called the way a C compiler would:
:func:`rdrand_u64`/:func:`rdseed_u64` run tiny x86-64 shellcode stubs
(``rdrand rax`` / ``rdseed rax`` with a bounded retry loop) through
``ctypes`` on a ``PAGE_EXECUTE_READWRITE`` page, and
:func:`rdrand_available`/:func:`rdseed_available` read the feature bits
straight from CPUID (leaf 1, ECX bit 30 for RDRAND; leaf 7, EBX bit 18
for RDSEED).  On top sit :class:`RDRANDRandom` and :class:`RDSEEDRandom`
-- ``random.Random``-shaped hardware TRNGs.

The two instructions differ in purpose: RDRAND is the *conditioned*
output of the chip's entropy pipeline (AES-CBC-MAC / CTR_DRBG inside the
silicon), ready in a handful of cycles; RDSEED is the *raw* entropy
source, meant for seeding other generators (it self-throttles when the
hardware entropy pool is drained -- hence its wider retry budget).

Availability is probed, never assumed: on machines (or Pythons - 32-bit
builds are excluded) without the instructions the module reports
``False`` and the classes raise ``RuntimeError`` on use; the battery
skips rather than fails.  Two checks, because CPUID alone can lie: some
hypervisors pass the feature bit through but trap the instruction itself
(STATUS_ILLEGAL_INSTRUCTION), so "available" means the stub really
executed once.  Windows x64 only for now (the stubs use the Windows
calling convention: the out pointer arrives in RCX).

These are true hardware sources: like the OS-level CSPRNGs they have no
seed and no restorable state.  Trusting them blindly is a policy choice -
the silicon's conditioning is opaque; paranoid designs XOR RDRAND with an
OS source (see the docs).

Run this module to execute its assert-based self-checks::

    py -3 -m multirandom.csprng.rdrand_hardware
"""
from __future__ import annotations

import ctypes
import struct
import sys

try:
    from .os_random import _OSRandom
except ImportError:                          # running as a plain script
    from os_random import _OSRandom


# --- the machine stubs (Windows x64 calling convention) ----------------------
#
# rdrand_u64 (rdseed: the F0 modrm byte becomes F8):
#
#   41 BA C8 00 00 00    mov  r10d, 200        ; retry budget
#   F3 48 0F C7 F0       rdrand rax            ; rdseed: ...C7 F8
#   72 08                jb   got              ; CF=1 -> the value is valid
#   49 FF CA             dec  r10
#   75 F4                jnz  loop
#   31 C0                xor  eax, eax         ; exhausted: return 0
#   C3                   ret
#   got:
#   48 89 01             mov  [rcx], rax       ; store the 64 bits
#   B8 01 00 00 00       mov  eax, 1           ; return 1
#   C3                   ret

_RDRAND_SHELLCODE = bytes.fromhex(
    "41BAC8000000"      # mov r10d, 200
    "F3480FC7F0"        # rdrand rax
    "7208"              # jb got
    "49FFCA"            # dec r10
    "75F4"              # jnz loop
    "31C0"              # xor eax, eax
    "C3"                # ret
    "488901"            # got: mov [rcx], rax
    "B801000000"        # mov eax, 1
    "C3")               # ret

_RDSEED_SHELLCODE = bytes.fromhex(
    "41BAC8000000"      # mov r10d, 200
    "F3480FC7F8"        # rdseed rax
    "720849FFCA75F431C0C3488901B801000000C3")

#
# cpuid into a 12-byte buffer (EBX, ECX, EDX); the leaf is patched in:
#
#   53                push rbx
#   B8 01 00 00 00    mov  eax, leaf
#   4C 8B D9          mov  r11, rcx        ; save the out pointer
#   31 C9             xor  ecx, ecx        ; subleaf 0 (leaf 7 needs it)
#   0F A2             cpuid
#   41 89 1B          mov  [r11], ebx
#   41 89 4B 04       mov  [r11+4], ecx
#   41 89 53 08       mov  [r11+8], edx
#   31 C0             xor  eax, eax
#   5B                pop  rbx
#   C3                ret

_MEM_COMMIT_RESERVE = 0x3000
_PAGE_EXECUTE_READWRITE = 0x40
_MEM_RELEASE = 0x8000

_WIN64 = sys.platform == "win32" and ctypes.sizeof(ctypes.c_void_p) == 8

# Execution-probe results (None = not probed yet; CPUID can lie on some
# hypervisors, so "available" means the instruction actually executed).
_RDRAND_PROBE = None
_RDSEED_PROBE = None


def _run_shellcode(code, func_type, out):
    """Copy ``code`` onto an executable page and call it with ``out``."""
    kernel32 = ctypes.windll.kernel32
    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                      ctypes.c_uint32, ctypes.c_uint32]
    kernel32.VirtualFree.restype = ctypes.c_int
    kernel32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                     ctypes.c_uint32]
    page = kernel32.VirtualAlloc(None, len(code),
                                 _MEM_COMMIT_RESERVE, _PAGE_EXECUTE_READWRITE)
    if not page:
        raise MemoryError("VirtualAlloc failed for the machine stub")
    try:
        ctypes.memmove(page, code, len(code))
        func = ctypes.cast(page, func_type)
        return func(out)
    finally:
        kernel32.VirtualFree(page, 0, _MEM_RELEASE)


def _cpuid(leaf):
    """(ebx, ecx, edx) of ``cpuid`` with EAX=leaf, ECX=0, via a stub."""
    if not _WIN64:
        return None
    code = bytes.fromhex(
        "53"                                    # push rbx
        + f"B8{leaf:02x}000000"                 # mov eax, leaf
        + "4C8BD9"                              # mov r11, rcx  (save out ptr)
        + "31C9" "0FA2"                         # xor ecx, ecx; cpuid
        + "41891B" "41894B04" "41895308"        # mov [r11],ebx/ecx/edx
        + "31C0" "5B" "C3")                     # xor eax,eax; pop rbx; ret
    buf = (ctypes.c_uint32 * 3)()
    ok = _run_shellcode(code, ctypes.CFUNCTYPE(ctypes.c_int,
                                               ctypes.POINTER(ctypes.c_uint32)), buf)
    if ok != 0:
        return None
    return buf[0], buf[1], buf[2]


def rdrand_available():
    """RDRAND usable here: CPUID leaf 1 ECX bit 30 AND the instruction
    actually executing (a bare probe - CPUID alone can lie)."""
    global _RDRAND_PROBE
    if not _WIN64:
        return False
    if _RDRAND_PROBE is None:
        regs = _cpuid(1)
        _RDRAND_PROBE = bool(regs and regs[1] & (1 << 30)) and \
            _probe_instruction(_RDRAND_SHELLCODE)
    return _RDRAND_PROBE


def rdseed_available():
    """RDSEED usable here: CPUID leaf 7 EBX bit 18 AND the instruction
    actually executing (a bare probe - CPUID alone can lie)."""
    global _RDSEED_PROBE
    if not _WIN64:
        return False
    if _RDSEED_PROBE is None:
        regs = _cpuid(7)
        _RDSEED_PROBE = bool(regs and regs[0] & (1 << 18)) and \
            _probe_instruction(_RDSEED_SHELLCODE)
    return _RDSEED_PROBE


def _probe_instruction(shellcode):
    """Execute the stub once: True only if the instruction really ran
    (ctypes turns a hardware #UD into an OSError, which we read as "the
    CPUID bit lies - the instruction is not usable here")."""
    out = ctypes.c_uint64()
    try:
        return _run_shellcode(shellcode, ctypes.CFUNCTYPE(
            ctypes.c_int, ctypes.POINTER(ctypes.c_uint64)), ctypes.byref(out)) == 1
    except OSError:
        return False


def rdrand_u64():
    """One 64-bit RDRAND value; RuntimeError after 200 retries."""
    if not _WIN64:
        raise RuntimeError("RDRAND: needs 64-bit Python on Windows")
    out = ctypes.c_uint64()
    ok = _run_shellcode(_RDRAND_SHELLCODE, ctypes.CFUNCTYPE(
        ctypes.c_int, ctypes.POINTER(ctypes.c_uint64)), ctypes.byref(out))
    if not ok:
        raise RuntimeError("RDRAND failed to deliver a value (200 retries)")
    return out.value


def rdseed_u64():
    """One 64-bit RDSEED value; RuntimeError after 200 retries."""
    if not _WIN64:
        raise RuntimeError("RDSEED: needs 64-bit Python on Windows")
    out = ctypes.c_uint64()
    ok = _run_shellcode(_RDSEED_SHELLCODE, ctypes.CFUNCTYPE(
        ctypes.c_int, ctypes.POINTER(ctypes.c_uint64)), ctypes.byref(out))
    if not ok:
        raise RuntimeError("RDSEED failed to deliver a value (200 retries)")
    return out.value


def _hw_bytes(u64, n):
    """``n`` bytes of hardware entropy, 8 bytes per instruction."""
    out = bytearray()
    while len(out) < n:
        out += struct.pack("<Q", u64())
    return bytes(out[:n])


def rdrand_bytes(n):
    """``n`` bytes straight from the CPU's conditioned RDRAND pipeline."""
    return _hw_bytes(rdrand_u64, n)


def rdseed_bytes(n):
    """``n`` bytes straight from the CPU's raw RDSEED entropy source."""
    return _hw_bytes(rdseed_u64, n)


class _HardwareRandom(_OSRandom):
    """Base for the CPU entropy instructions: like the OS sources - live
    entropy, no seeding, no restorable state - but with no fallback: when
    the instruction is missing, using it raises (silently swapping in
    ``os.urandom`` would misreport the source)."""

    instruction = "hardware"

    @classmethod
    def available(cls):
        raise NotImplementedError

    @classmethod
    def u64(cls):
        raise NotImplementedError

    def _urandom_bytes(self, n):
        if not self.available():
            raise RuntimeError(
                f"{self.instruction} is not available on this CPU/Python build")
        return _hw_bytes(self.u64, n)


class RDRANDRandom(_HardwareRandom):
    """The Intel/AMD ``RDRAND`` instruction: the chip's *conditioned* output
    (a hardware DRBG fed by the entropy pipeline).  On Windows x64."""
    source_name = "CPU RDRAND"
    instruction = "RDRAND"

    @classmethod
    def available(cls):
        return rdrand_available()

    @classmethod
    def u64(cls):
        return rdrand_u64()


class RDSEEDRandom(_HardwareRandom):
    """The Intel/AMD ``RDSEED`` instruction: *raw* entropy from the silicon
    entropy pool, meant for seeding other generators.  On Windows x64."""
    source_name = "CPU RDSEED"
    instruction = "RDSEED"

    @classmethod
    def available(cls):
        return rdseed_available()

    @classmethod
    def u64(cls):
        return rdseed_u64()


HW_GENERATORS = [RDRANDRandom, RDSEEDRandom]


if __name__ == "__main__":
    print("=" * 70)
    print("rdrand_hardware - the CPU entropy instructions self-check battery")
    print("=" * 70)

    if not _WIN64:
        print(f"[skip] not Windows x64 (platform={sys.platform}, "
              f"pointer={ctypes.sizeof(ctypes.c_void_p) * 8} bit) - "
              "the machine stubs are Windows-only")
        print("-" * 70)
        print("All rdrand_hardware checks passed (nothing to exercise here)!")
        raise SystemExit(0)

    # --- 1. CPUID feature flags + the execution probe -------------------------
    rdrand_ok = rdrand_available()
    rdseed_ok = rdseed_available()
    leaf1 = _cpuid(1)
    leaf7 = _cpuid(7)
    assert leaf1 is not None, "the CPUID stub must run on Windows x64"
    if rdrand_ok:
        assert leaf1[1] & (1 << 30), "RDRAND works but CPUID hides the bit?!"
        assert rdrand_u64() != rdrand_u64(), "available means usable"
    if rdseed_ok:
        assert leaf7[0] & (1 << 18), "RDSEED works but CPUID hides the bit?!"
        assert rdseed_u64() != rdseed_u64(), "available means usable"
    # availability must never out-run what the CPU really does
    if not (leaf1[1] & (1 << 30)):
        assert not rdrand_ok, "claimed RDRAND without the CPUID bit"
    if not (leaf7[0] & (1 << 18)):
        assert not rdseed_ok, "claimed RDSEED without the CPUID bit"
    print(f"[1] CPUID: RDRAND bit={'set' if leaf1[1] & (1 << 30) else 'clear'}, "
          f"RDSEED bit={'set' if leaf7[0] & (1 << 18) else 'clear'}; "
          f"usable: RDRAND={'yes' if rdrand_ok else 'no'}, "
          f"RDSEED={'yes' if rdseed_ok else 'no'}: OK")

    # --- 2. the instructions themselves (only when the CPU has them) ----------
    if rdrand_ok:
        v1, v2 = rdrand_u64(), rdrand_u64()
        assert v1 != v2, "RDRAND repeated an exact 64-bit value (impossible)"
        b = rdrand_bytes(40)
        assert len(b) == 40
        ones = bin(int.from_bytes(rdrand_bytes(4096), "big")).count("1")
        assert 15100 < ones < 17700, f"RDRAND bit balance looks broken ({ones})"
        print(f"[2] RDRAND: 64-bit draws differ; 4096 bytes '{ones} ones/32768': OK")
    else:
        print("[2] RDRAND: not present on this CPU - skipped (never asserted)")

    if rdseed_ok:
        v1, v2 = rdseed_u64(), rdseed_u64()
        assert v1 != v2, "RDSEED repeated an exact 64-bit value (impossible)"
        b = rdseed_bytes(24)
        assert len(b) == 24
        print("[3] RDSEED: draws differ, byte counts exact: OK")
    else:
        print("[3] RDSEED: not present on this CPU - skipped (never asserted)")

    # --- 4. the random.Random shape (availability-gated) -----------------------
    for cls, ok in ((RDRANDRandom, rdrand_ok), (RDSEEDRandom, rdseed_ok)):
        if not ok:
            try:
                cls().randbytes(8)
            except RuntimeError:
                pass
            else:
                raise AssertionError(f"{cls.__name__} must refuse when absent")
            continue
        g = cls()
        r1, r2 = g.randbytes(32), g.randbytes(32)
        assert r1 != r2
        for k in (1, 7, 64):
            assert 0 <= g.getrandbits(k) < (1 << k)
        assert 0.0 <= g.random() < 1.0
        assert 0 <= g.choice(range(50)) < 50
        try:
            g.getstate()
        except NotImplementedError:
            pass
        else:
            raise AssertionError(f"{cls.__name__} must not pretend to be restorable")
        g.seed("anything")             # a no-op, not an error
        print(f"  {cls.__name__}: OK (source = {cls.source_name})")
    print("[4] random.Random-shaped hardware TRNGs, gated on availability: OK")

    print("-" * 70)
    print("All rdrand_hardware checks passed!")
