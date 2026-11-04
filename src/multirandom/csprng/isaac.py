"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.csprng.isaac
Description:
Bob Jenkins' ISAAC (Indirection, Shift, Accumulate, Add, Count, 1996) as
written in the author's ``readable.c``: separate state (``mm``) and output
(``randrsl``) arrays, indirect indices at bits 2..9 (x) and 10..17 (y),
shift sequence 13/6/2/16, a once-per-block counter, and an 8288-bit
internal state.  A cousin of RC4 in spirit -- an array scramble that
refills a results block each pass -- with a formal average-cycle-length
argument of about 2^8295 values.

Jenkins never published an official seeding routine ("the encryption of
the seed") beyond ``randinit``; this library feeds the seed into 256
little-endian words first (like the x86 reference), zero-padded with
SHA-256, then runs his ``randinit(flag=1)`` verbatim.

Every DRBG here is a ``random.Random`` subclass, so ``.random()``,
``.randint()``, ``.choice()``, ``.shuffle()`` ... all work on top of the
cryptographic core.  Deterministic from an explicit seed; live OS entropy
when you pass ``None``.

Run this module to execute its assert-based self-checks::

    py -3 -m multirandom.csprng.isaac
"""
from __future__ import annotations

import hashlib
import struct

try:
    from ._drbg_base import _DrbgBase
except ImportError:                          # running as a plain script
    from _drbg_base import _DrbgBase


def _isaac_mix8(a, b, c, d, e, f, g, h):
    """Jenkins' 8-word mix, used by randinit().  All mod 2^32."""
    M = 0xFFFFFFFF
    a = a ^ ((b << 11) & M); d = (d + a) & M; b = (b + c) & M
    b = b ^ (c >> 2);        e = (e + b) & M; c = (c + d) & M
    c = c ^ ((d << 8) & M);  f = (f + c) & M; d = (d + e) & M
    d = d ^ (e >> 16);       g = (g + d) & M; e = (e + f) & M
    e = e ^ ((f << 10) & M); h = (h + e) & M; f = (f + g) & M
    f = f ^ (g >> 4);        a = (a + f) & M; g = (g + h) & M
    g = g ^ ((h << 8) & M);  b = (b + g) & M; h = (h + a) & M
    h = h ^ (a >> 9);        c = (c + h) & M; a = (a + b) & M
    return a, b, c, d, e, f, g, h


class ISAACRandom(_DrbgBase):
    """Bob Jenkins' ISAAC (Indirection, Shift, Accumulate, Add, Count) as
    written in the author's ``readable.c``: separate state (``mm``) and
    output (``randrsl``) arrays, indirect indices at bits 2..9 (x) and
    10..17 (y), shift sequence 13/6/2/16, a once-per-block counter, and an
    8288-bit internal state.

    Jenkins never published an official seeding routine ("the encryption of
    the seed") beyond ``randinit``; this library feeds the seed into 256
    little-endian words first (like the x86 reference), zero-padded with
    SHA-256, then runs his ``randinit(flag=1)`` verbatim."""
    _SIZE = 256
    _MASK = 0xFFFFFFFF

    def seed(self, a=None, version=2):
        material = self._seed_material(a)
        blob = bytearray()
        i = 0
        while len(blob) < 1024:
            blob += hashlib.sha256(material + i.to_bytes(4, "big")).digest()
            i += 1
        self._rsl = list(struct.unpack("<256I", bytes(blob[:1024])))
        self._randinit()

    def _randinit(self):
        """randinit(flag=1) from readable.c: scramble, two mixing passes over
        the seed, then one isaac() to load the first results block."""
        rsl = self._rsl
        self._aa = self._bb = self._cc = 0
        self._mm = [0] * self._SIZE
        a = b = c = d = e = f = g = h = 0x9E3779B9   # the golden ratio
        for _ in range(4):
            a, b, c, d, e, f, g, h = _isaac_mix8(a, b, c, d, e, f, g, h)
        for i in range(0, 256, 8):                  # fill mm[] with the seed
            a = (a + rsl[i]) & self._MASK
            b = (b + rsl[i + 1]) & self._MASK
            c = (c + rsl[i + 2]) & self._MASK
            d = (d + rsl[i + 3]) & self._MASK
            e = (e + rsl[i + 4]) & self._MASK
            f = (f + rsl[i + 5]) & self._MASK
            g = (g + rsl[i + 6]) & self._MASK
            h = (h + rsl[i + 7]) & self._MASK
            a, b, c, d, e, f, g, h = _isaac_mix8(a, b, c, d, e, f, g, h)
            self._mm[i:i + 8] = [a, b, c, d, e, f, g, h]
        for i in range(0, 256, 8):                  # second pass: seed reaches all of mm
            a = (a + self._mm[i]) & self._MASK
            b = (b + self._mm[i + 1]) & self._MASK
            c = (c + self._mm[i + 2]) & self._MASK
            d = (d + self._mm[i + 3]) & self._MASK
            e = (e + self._mm[i + 4]) & self._MASK
            f = (f + self._mm[i + 5]) & self._MASK
            g = (g + self._mm[i + 6]) & self._MASK
            h = (h + self._mm[i + 7]) & self._MASK
            a, b, c, d, e, f, g, h = _isaac_mix8(a, b, c, d, e, f, g, h)
            self._mm[i:i + 8] = [a, b, c, d, e, f, g, h]
        self._isaac()                               # first results block is ready
        self._pos = 0

    def _isaac(self):
        """One isaac() pass: advances aa/bb/cc, refills mm, and fills the
        current randrsl (256 fresh 32-bit results)."""
        mm = self._mm
        rsl = self._rsl
        M = self._MASK
        a = self._aa
        c = self._cc = (self._cc + 1) & M
        b = (self._bb + c) & M
        for i in range(256):
            x = mm[i]
            m4 = i & 3
            if m4 == 0:
                a = a ^ ((a << 13) & M)
            elif m4 == 1:
                a = a ^ (a >> 6)
            elif m4 == 2:
                a = a ^ ((a << 2) & M)
            else:
                a = a ^ (a >> 16)
            a = (mm[(i + 128) % 256] + a) & M
            mm[i] = y = (mm[(x >> 2) % 256] + a + b) & M
            rsl[i] = b = (mm[(y >> 10) % 256] + x) & M
        self._aa = a
        self._bb = b

    def _word(self):
        """Next 32-bit result; refills the 256-word output block when dry."""
        pos = self._pos
        if pos == 256:
            self._isaac()
            pos = 0
        self._pos = pos + 1
        return self._rsl[pos]

    def _block(self):
        """A full output block: 256 results, little-endian bytes (the format
        of the C reference's randrsl on x86)."""
        return struct.pack("<256I", *[self._word() for _ in range(256)])

    def getstate(self):
        return (self._aa, self._bb, self._cc, tuple(self._mm),
                tuple(self._rsl), self._pos)

    def setstate(self, state):
        self._aa, self._bb, self._cc, mm, rsl, self._pos = state
        self._mm = list(mm)
        self._rsl = list(rsl)


if __name__ == "__main__":
    print("=" * 70)
    print("isaac - Bob Jenkins' ISAAC self-check battery")
    print("=" * 70)

    # --- 1. Jenkins' own reference vector ("ISAAC and RC4", 1996) --------------
    # an all-zero state after ten isaac() calls lands on aa=d4d3f473,
    # bb=902c0691, cc=0000000a.
    z = ISAACRandom.__new__(ISAACRandom)
    z._aa = z._bb = z._cc = 0
    z._rsl = [0] * 256
    z._pos = 0
    z._mm = [0] * 256
    for _ in range(10):
        z._isaac()
    assert z._aa == 0xD4D3F473, f"ISAAC aa mismatch: {z._aa:08x}"
    assert z._bb == 0x902C0691, f"ISAAC bb mismatch: {z._bb:08x}"
    assert z._cc == 10, f"ISAAC cc mismatch: {z._cc}"
    print("[1] zero-state after ten isaac() calls: aa=d4d3f473 bb=902c0691: OK")

    # --- 2. the reference stream (seed-1), pinned -------------------------------
    pin = "c352a4166a61063835dfa12c358def772549369a4b481445f8d29967fc1fad60"
    a = ISAACRandom("seed-1").randbytes(32)
    assert a.hex() == pin, f"ISAACRandom('seed-1') drifted: {a.hex()}"
    b = ISAACRandom("seed-1").randbytes(32)
    assert a == b, "not deterministic for a fixed seed"
    assert a != ISAACRandom("seed-2").randbytes(32), "ignores the seed"
    print("[2] ISAACRandom('seed-1') first 32 bytes match the pinned stream: OK")

    # --- 3. the machine shape: 256-word blocks, cc counts passes -----------------
    g = ISAACRandom("shape")
    assert g._SIZE == 256 and len(g._mm) == 256 and len(g._rsl) == 256
    cc0 = g._cc
    g.randbytes(1024)                          # exactly one full results block
    assert g._cc == cc0, "the 256 ready words are consumed lazily (no refill yet)"
    g.randbytes(4)                             # spill past the block: refill NOW
    assert g._cc == cc0 + 1, "the first word past a block burns an isaac() pass"
    print("[3] 256-word blocks; cc counts isaac() passes: OK")

    # --- 4. state round-trip (mm AND randrsl AND position) -----------------------
    g = ISAACRandom("round-trip")
    g.randbytes(100)
    state = g.getstate()
    expected = g.randbytes(64)
    clone = ISAACRandom("round-trip")
    clone.setstate(state)
    assert clone.randbytes(64) == expected, "state round-trip broken"
    # mid-block state capture: the 8288-bit state includes where we are in rsl
    g = ISAACRandom("mid-block")
    for _ in range(125):
        g._word()                          # 125 words into the 256-word block
    assert 0 < g._pos < 256, "the capture is not mid-block"
    state = g.getstate()
    expected = g.randbytes(16)
    clone = ISAACRandom("mid-block")
    clone.setstate(state)
    assert clone.randbytes(16) == expected, "mid-block state round-trip broken"
    print("[4] setstate replays the stream, mid-block position included: OK")

    # --- 5. the whole random.Random API + bit balance ----------------------------
    g = ISAACRandom("api")
    for k in (1, 7, 33, 128):
        assert 0 <= g.getrandbits(k) < (1 << k)
    assert all(0.0 <= g.random() < 1.0 for _ in range(200))
    assert 0 <= g.choice(range(100)) < 100
    ones = bin(int.from_bytes(ISAACRandom("api").randbytes(4096), "big")).count("1")
    assert 15800 < ones < 17000, f"bit balance looks broken ({ones} ones)"
    print(f"[5] python API sane; 4096 bytes '{ones} ones/32768' balance: OK")

    print("-" * 70)
    print("All isaac checks passed!")
