"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.csprng.blum_blum_shub
Description:
The Blum Blum Shub generator (Lenore Blum, Manuel Blum & Michael Shub,
1986) -- the slowest respectable random number generator in the
literature, and the one with the cleanest security story: predicting its
output is provably as hard as factoring ``n = p * q`` (an attacker who
can predict the next low bit can, by repeated bisection, recover the
quadratic residue, and with it factor n).  One bit per squaring::

    x' = x * x  mod n        output: x' mod 2 (the low bit)

with ``p`` and ``q`` Blum primes (both ``3 mod 4``, so ``-1`` is a
non-residue mod n and squaring is a permutation on the residues).  Each
squaring hides the previous state behind a modular square root -- which
is exactly as hard as factoring n.  The price: ONE bit per expensive
modular multiply, where CTR_DRBG produces 128 bits per block.  Kept for
the history (it predates and shaped the modern DRBG world) and for
teaching the quadratic-residue argument; for real work, use the OS
sources or the SP 800-90A modules in this package.

``BlumBlumShub.generate`` makes a keypair with Miller-Rabin, using an
injectable ``random.Random`` so runs are reproducible in the battery.
This module stays in csprng because its security is a theorem, not a
recommendation: the theorem's assumptions are exactly what a real
adversary gets to choose against.

Every DRBG here is a ``random.Random`` subclass, so ``.random()``,
``.randint()``, ``.choice()``, ``.shuffle()`` ... all work on top of the
core.  Deterministic from an explicit seed; live OS entropy when you
pass ``None``.

Run this module to execute its assert-based self-checks::

    py -3 -m multirandom.csprng.blum_blum_shub
"""
from __future__ import annotations

import hashlib
import math
import random

try:
    from ._drbg_base import _DrbgBase
except ImportError:                          # running as a plain script
    from _drbg_base import _DrbgBase


# --- the number theory --------------------------------------------------------

def _is_probable_prime(n, rng=None, rounds=24):
    """Miller-Rabin, self-contained (no external prime library)."""
    if n < 4 or n % 2 == 0:
        return n in (2, 3)
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    bases = list(range(2, min(n - 2, 40)))       # deterministic bases first
    if rng is not None and n > 60:
        bases = [rng.randrange(2, n - 1) for _ in range(rounds)]
    for a in bases:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits, rng):
    """A random ``bits``-bit prime congruent to 3 (mod 4)."""
    while True:
        p = rng.getrandbits(bits) | (1 << (bits - 1)) | 3
        if _is_probable_prime(p, rng):
            return p


# --- the generator ------------------------------------------------------------

class BlumBlumShub(_DrbgBase):
    """The Blum Blum Shub generator: ``x' = x^2 mod n``, one low bit per
    step, ``n = p * q`` from two distinct Blum primes (``3 mod 4``).

    Deterministic from an explicit seed (which must be coprime to n --
    the standard's rule); live OS entropy when you pass ``None``.
    :meth:`generate` builds the prime pair with Miller-Rabin under an
    injectable ``random.Random``."""

    _block_bits = 128                # one _block(): 128 squarings -> 16 bytes

    def __init__(self, seed=None, p=None, q=None, personalization=b""):
        if p is None or q is None:
            raise ValueError(
                "pass the Blum primes p and q (BlumBlumShub.generate makes them)")
        p, q = int(p), int(q)
        for name, prime in (("p", p), ("q", q)):
            if prime < 7:
                raise ValueError(f"{name} must be a prime >= 7")
            if prime % 4 != 3:
                raise ValueError(f"{name} = {prime} is not a Blum prime (3 mod 4)")
            if not _is_probable_prime(prime):
                raise ValueError(f"{name} = {prime} is not prime")
        if p == q:
            raise ValueError("p and q must be distinct")
        self._p, self._q, self._n = p, q, p * q
        super().__init__(seed, personalization)

    @classmethod
    def generate(cls, seed=None, bits=512, rng=None, personalization=b""):
        """Build the generator with a fresh prime pair (``bits`` per prime).

        ``rng`` is the Miller-Rabin/prime-drawing randomness - pass a
        seeded ``random.Random`` for reproducible keypairs; the default
        is ``random.SystemRandom``."""
        rng = random.SystemRandom() if rng is None else rng
        while True:
            p = _generate_prime(bits, rng)
            q = _generate_prime(bits, rng)
            if p != q:
                return cls(seed, p=p, q=q, personalization=personalization)

    def seed(self, a=None, version=2):
        if isinstance(a, int) and not isinstance(a, bool):
            s = int(a) % self._n
        else:
            material = self._seed_material(a)
            s = int.from_bytes(hashlib.sha256(material).digest(), "big") % self._n
        while s < 2 or math.gcd(s, self._n) != 1:   # the standard's seed rule
            s = (s + 1) % self._n
        self._x = s
        self._reseed_counter = 1

    def reseed(self, entropy=None, additional=b""):
        material = self._seed_material(entropy) + bytes(additional)
        s = int.from_bytes(hashlib.sha256(material).digest(), "big") % self._n
        while s < 2 or math.gcd(s, self._n) != 1:
            s = (s + 1) % self._n
        self._x = s
        self._reseed_counter = 1

    def roll(self):
        """One squaring: advance the state, return the low bit (0/1)."""
        self._x = (self._x * self._x) % self._n
        return self._x & 1

    def _block(self):
        """16 bytes = the next 128 low bits (first bit is the MSB)."""
        x = self._x
        n = self._n
        word = 0
        for i in range(self._block_bits):
            x = (x * x) % n
            word = (word << 1) | (x & 1)
        self._x = x
        return word.to_bytes(self._block_bits // 8, "big")

    def getstate(self):
        return (self._x, self._p, self._q, self._reseed_counter,
                self._personalization)

    def setstate(self, state):
        (self._x, self._p, self._q, self._reseed_counter,
         self._personalization) = state
        self._n = self._p * self._q



def main():
    print("=" * 70)
    print("blum_blum_shub - the factoring-hard generator self-check battery")
    print("=" * 70)

    # --- 1. THE textbook example, hand-verified: n = 11 * 19 = 209, seed 3 ----
    # x: 3 -> 9 -> 81 -> 82 -> 36 -> 42 -> 92 -> 104 -> 157 -> 196 -> 169
    # low bits of the successive squares: 1 1 0 0 0 0 0 1 0 1
    g = BlumBlumShub(seed=3, p=11, q=19)
    assert g._n == 209
    assert g._x == 3
    xs = [g._x]
    for _ in range(10):
        g.roll()
        xs.append(g._x)
    assert xs == [3, 9, 81, 82, 36, 42, 92, 104, 157, 196, 169], \
        f"the textbook x-stream drifted: {xs}"
    g = BlumBlumShub(seed=3, p=11, q=19)
    bits = [g.roll() for _ in range(10)]
    assert bits == [1, 1, 0, 0, 0, 0, 0, 1, 0, 1], f"bit stream drifted: {bits}"
    # and the same stream, byte-packed MSB-first as _block delivers it:
    # bits 1..16 are 11000001 01101100 -> 0xC1 0x6C
    g = BlumBlumShub(seed=3, p=11, q=19)
    assert g.randbytes(2) == bytes([0b11000001, 0b01101100]), \
        f"packed bytes drifted: {g.randbytes(2).hex()}"
    print("[1] n = 209, s = 3: x-stream and low bits match the textbook: OK")

    # --- 2. the Blum rules: p, q must be distinct primes, 3 mod 4 -------------
    for bad in (dict(p=13, q=19), dict(p=11, q=13)):      # 13 is 1 mod 4
        try:
            BlumBlumShub(seed=3, **bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"a non-Blum prime pair was accepted: {bad}")
    try:
        BlumBlumShub(seed=3, p=11, q=11)                   # distinct
    except ValueError:
        pass
    else:
        raise AssertionError("p == q accepted")
    try:
        BlumBlumShub(seed=3, p=15, q=19)                   # 15 not prime
    except ValueError:
        pass
    else:
        raise AssertionError("a composite was accepted")
    # the seed rule: gcd(seed, n) == 1 - a bad seed is BUMPED, not refused
    g = BlumBlumShub(seed=11, p=11, q=19)              # seed shares the factor 11
    assert g._x == 12, f"seed 11 must bump to a coprime state, got {g._x}"
    assert math.gcd(g._x, g._n) == 1, "the bumped seed is still not coprime"
    try:
        BlumBlumShub(seed=3)
    except ValueError:
        pass
    else:
        raise AssertionError("constructing without primes must be refused")
    print("[2] Blum rules enforced; bad seed bumped coprime; text KAT live: OK")

    # --- 3. keypair generation: deterministic under an injected rng ------------
    rng = random.Random(42)
    g = BlumBlumShub.generate(seed="material", bits=64, rng=random.Random(42))
    g2 = BlumBlumShub.generate(seed="material", bits=64, rng=random.Random(42))
    assert g._n == g2._n, "the seeded keypair is not reproducible"
    assert g._p % 4 == 3 and g._q % 4 == 3, "generate returned non-Blum primes"
    assert g._p != g._q and g._p * g._q == g._n
    assert g._p.bit_length() == 64 and g._q.bit_length() == 64
    assert g.randbytes(16) == g2.randbytes(16), "same n, same seed, same stream?"
    h = BlumBlumShub.generate(seed="material", bits=64, rng=random.Random(43))
    assert h._n != g._n, "a different rng gave the same keypair"
    print("[3] Miller-Rabin keypairs: seeded rng reproducible, 3 mod 4, distinct: OK")

    # --- 4. state round-trip + personalization ---------------------------------
    g = BlumBlumShub.generate(seed="round-trip", bits=64, rng=random.Random(7))
    g.randbytes(64)
    state = g.getstate()
    expected = g.randbytes(32)
    clone = BlumBlumShub.generate(seed="round-trip", bits=64, rng=random.Random(7))
    clone.setstate(state)
    assert clone.randbytes(32) == expected, "state round-trip broken"
    # int seeds go DIRECT to x (textbook-honest), so personalization can only
    # shift hashed seeds: string/bytes/None route through _seed_material.
    a = BlumBlumShub(seed="3", p=11, q=19)
    b = BlumBlumShub(seed="3", p=11, q=19, personalization=b"app-id")
    assert a.randbytes(16) != b.randbytes(16), "personalization ignored"
    assert a.randbytes(16) == BlumBlumShub(seed="3", p=11, q=19).randbytes(16), \
        "hashed-seed determinism broke"
    print("[4] setstate replays the stream; personalization shifts it: OK")

    # --- 5. the whole random.Random API + balance -------------------------------
    g = BlumBlumShub.generate(seed="api", bits=64, rng=random.Random(9))
    for k in (1, 7, 33, 128):
        assert 0 <= g.getrandbits(k) < (1 << k)
    assert all(0.0 <= g.random() < 1.0 for _ in range(100))
    assert 0 <= g.choice(range(100)) < 100
    ones = bin(int.from_bytes(
        BlumBlumShub.generate(seed="api", bits=64, rng=random.Random(9)).randbytes(2048),
        "big")).count("1")
    assert 7900 < ones < 8500, f"bit balance looks broken ({ones} ones/16384)"
    print(f"[5] python API sane; 2048 bytes '{ones} ones/16384' balance: OK")

    print("-" * 70)
    print("All blum_blum_shub checks passed!")


if __name__ == "__main__":
    main()
