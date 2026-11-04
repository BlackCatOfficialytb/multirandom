"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.csprng.ansi_x931
Description:
ANSI X9.31-AES128 -- the reticent-but-mandatory random number generator
of the banking world (ANS X9.17 (1985) with DES, restated as X9.31 with
AES in 1998; it survived in payment HSMs, EMV key ceremonies and old
PKI infrastructure long after NIST deprecated it in favour of the SP
800-90A family).  One output block is::

    I  = E(K, DT)          # DT: date/time vector, never repeated
    O  = E(K, I xor V)     # the output
    V' = E(K, O xor I)     # the next V

The AES is the installed crypto library's (see
``multirandom.csprng._aes``).  The battery hand-computes the triple
against raw single-block ECB calls, so the shape is proven rather than
trusted.

History note worth keeping: X9.31 lived in the era of vendor trust, and
at least two embedded implementations (Fortinet, Juniper) shipped it
with a hard-coded private "static key" -- the exact failure mode proper
entropy hygiene exists to prevent.  Kept here as a legacy curiosity with
its cycle structure intact; use OS random sources (or the SP 800-90A
modules here) for anything real.

Every DRBG here is a ``random.Random`` subclass, so ``.random()``,
``.randint()``, ``.choice()``, ``.shuffle()`` ... all work on top of the
cryptographic core.  Deterministic from an explicit seed (the date/time
vector starts from a seed-derived, still strictly-increasing counter);
live OS entropy when you pass ``None``.

Run this module to execute its assert-based self-checks::

    py -3 -m multirandom.csprng.ansi_x931
"""
from __future__ import annotations

import hashlib
import time

try:
    from ._drbg_base import _DrbgBase
    from ._aes import _Aes
except ImportError:                          # running as a plain script
    from _drbg_base import _DrbgBase
    from _aes import _Aes


class AnsiX931DRBG(_DrbgBase):
    """ANSI X9.31-AES128: I = E(K, DT), output O = E(K, I xor V),
    V' = E(K, O xor I), with a strictly increasing date/time vector.
    Deterministic from an explicit seed; live OS entropy when unseeded."""

    def seed(self, a=None, version=2):
        material = self._seed_material(a)
        self._key = hashlib.sha256(material + b"x931 key").digest()[:16]
        self._v = hashlib.sha256(material + b"x931 v").digest()[:16]
        # The date/time vector: 128 bits, never repeated.  Unseeded it
        # starts at the wall clock (so two live instances never collide);
        # seeded it starts at a seed-derived constant so runs are
        # reproducible -- it still only ever moves forward, one per block.
        if a is None:
            self._dt = time.time_ns()
        else:
            self._dt = int.from_bytes(
                hashlib.sha256(material + b"x931 dt").digest()[:8], "big")
        self._reseed_counter = 1
        self._aes = _Aes(self._key)

    def reseed(self, entropy=None, additional=b""):
        self.seed(self._seed_material(entropy) + bytes(additional))

    def _block(self):
        self._dt = (self._dt + 1) % (1 << 128)
        dt = self._dt.to_bytes(16, "big")
        aes = self._aes
        i = aes.encrypt_block(dt)                                   # E(K, DT)
        o = aes.encrypt_block(
            bytes(x ^ y for x, y in zip(i, self._v)))               # E(K, I^V)
        self._v = aes.encrypt_block(
            bytes(x ^ y for x, y in zip(o, i)))                     # E(K, O^I)
        return o

    def getstate(self):
        return (self._key, self._v, self._dt, self._reseed_counter,
                self._personalization)

    def setstate(self, state):
        (self._key, self._v, self._dt, self._reseed_counter,
         self._personalization) = state
        self._aes = _Aes(self._key)



def main():
    print("=" * 70)
    print("ansi_x931 - ANSI X9.31-AES128 self-check battery")
    print("=" * 70)

    # --- 1. the X9.31 cycle, hand-computed against raw ECB --------------------
    key = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
    v0 = bytes.fromhex("112233445566778899aabbccddeeff00")
    g = AnsiX931DRBG.__new__(AnsiX931DRBG)     # wire the state by hand
    g._key, g._v, g._dt, g._aes = key, v0, 0, _Aes(key)
    dt = 1
    i = _Aes(key).encrypt_block(dt.to_bytes(16, "big"))
    o = _Aes(key).encrypt_block(bytes(a ^ b for a, b in zip(i, v0)))
    v1 = _Aes(key).encrypt_block(bytes(a ^ b for a, b in zip(o, i)))
    assert g._block() == o, "output block != E(K, E(K, DT) xor V)"
    assert g._v == v1, "V' != E(K, O xor I)"
    # ... and a second step chains on the updated V
    i2 = _Aes(key).encrypt_block((dt + 1).to_bytes(16, "big"))
    o2 = _Aes(key).encrypt_block(bytes(a ^ b for a, b in zip(i2, v1)))
    assert g._block() == o2, "the X9.31 cycle broke on step two"
    print("[1] I = E(K, DT); O = E(K, I^V); V' = E(K, O^I), hand-chained: OK")

    # --- 2. the reference stream (seed-1), pinned ------------------------------
    pin = "bacc0163fe2e2ce7edcf7aa4ff0be9ec39cc0302f0a7da0d0e44d064c7311fb9"
    a = AnsiX931DRBG("seed-1").randbytes(32)
    assert a.hex() == pin, f"AnsiX931DRBG('seed-1') drifted: {a.hex()}"
    b = AnsiX931DRBG("seed-1").randbytes(32)
    assert a == b, "not deterministic for a fixed seed"
    assert a != AnsiX931DRBG("seed-2").randbytes(32), "ignores the seed"
    print("[2] AnsiX931DRBG('seed-1') first 32 bytes match the pinned stream: OK")

    # --- 3. the date/time vector never repeats ---------------------------------
    g = AnsiX931DRBG("dt discipline")
    seen = []
    for _ in range(50):
        g._block()
        seen.append(g._dt)
    assert all(b > a for a, b in zip(seen, seen[1:])), "DT is not strictly increasing"
    assert len(set(seen)) == 50, "a DT value repeated"
    # two live instances must not share a DT base either
    x, y = AnsiX931DRBG(), AnsiX931DRBG()
    assert x._dt != y._dt, "two unseeded instances started at the same DT"
    print("[3] DT strictly increases per block; live instances never collide: OK")

    # --- 4. reseeding with fixed entropy is reproducible ------------------------
    x = AnsiX931DRBG("factory")
    x.randbytes(32)
    x.reseed("deterministic entropy")
    y = AnsiX931DRBG("factory")
    y.randbytes(32)
    y.reseed("deterministic entropy")
    assert x.randbytes(48) == y.randbytes(48), "reseed is not reproducible"
    z = AnsiX931DRBG("factory")
    z.randbytes(32)
    z.reseed("different entropy")
    assert z.randbytes(48) != x.randbytes(48), "different entropy, same stream?"
    print("[4] reseed() deterministic with fixed entropy, varies otherwise: OK")

    # --- 5. state round-trip + personalization ----------------------------------
    g = AnsiX931DRBG("round-trip")
    g.randbytes(100)
    state = g.getstate()
    expected = g.randbytes(64)
    clone = AnsiX931DRBG("round-trip")
    clone.setstate(state)
    assert clone.randbytes(64) == expected, "state round-trip broken"
    assert AnsiX931DRBG("seed-1", personalization=b"app-id").randbytes(16) != \
        AnsiX931DRBG("seed-1").randbytes(16), "personalization ignored"
    print("[5] setstate replays the stream; personalization shifts it: OK")

    # --- 6. the whole random.Random API + bit balance ----------------------------
    g = AnsiX931DRBG("api")
    for k in (1, 7, 33, 128):
        assert 0 <= g.getrandbits(k) < (1 << k)
    assert all(0.0 <= g.random() < 1.0 for _ in range(200))
    assert 0 <= g.choice(range(100)) < 100
    ones = bin(int.from_bytes(AnsiX931DRBG("api").randbytes(4096), "big")).count("1")
    assert 15800 < ones < 17000, f"bit balance looks broken ({ones} ones)"
    print(f"[6] python API sane; 4096 bytes '{ones} ones/32768' balance: OK")

    print("-" * 70)
    print("All ansi_x931 checks passed!")


if __name__ == "__main__":
    main()
