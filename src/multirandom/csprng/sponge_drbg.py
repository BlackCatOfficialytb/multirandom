"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.csprng.sponge_drbg
Description:
A sponge-mode DRBG built on a from-scratch Keccak-f[1600] permutation.

The permutation is transcribed from the Keccak reference (theta/rho/pi/
chi/iota, 24 rounds, the 24 hardwired round constants and the flat
rotation-offset table), and the battery pins it against ``hashlib``'s
production implementations of the very same permutation -- SHA3-256,
SHA3-512 and SHAKE-128 across three different rates and multi-block
absorbs/squeezes -- so the transcription is proven, not trusted.

No standard crypto library exposes the *raw* Keccak-f[1600] permutation
(only the fixed hash constructions on top of it), which is why this one
is written from scratch; everything above it stays honest to the sponge
world: absorb the seed material, then squeeze output blocks,
``reseed()`` absorbing fresh entropy at any moment.

Every DRBG here is a ``random.Random`` subclass, so ``.random()``,
``.randint()``, ``.choice()``, ``.shuffle()`` ... all work on top of the
cryptographic core.  Deterministic from an explicit seed; live OS entropy
when you pass ``None``.

Run this module to execute its assert-based self-checks::

    py -3 -m multirandom.csprng.sponge_drbg
"""
from __future__ import annotations

import hashlib

try:
    from ._drbg_base import _DrbgBase
except ImportError:                          # running as a plain script
    from _drbg_base import _DrbgBase


_M64 = (1 << 64) - 1

# The 24 Keccak-f[1600] round constants (iota), from the reference.
_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

# Flat rotation offsets, indexed by lane i = x + 5*y (the reference's own
# flat table): flat[x + 5*y] == rho(x, y).
_KECCAK_RHO = [
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
]


def _rotl64(x, n):
    return ((x << n) | (x >> (64 - n))) & _M64


def _keccak_f1600(lanes):
    """The Keccak-f[1600] permutation in place: 25 lanes, lane (x, y) at
    index x + 5*y, 24 rounds of theta/rho/pi/chi/iota."""
    for rc in _KECCAK_RC:
        # theta
        c = [lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20]
             for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                lanes[x + 5 * y] ^= d[x]
        # rho + pi: B[y, 2x+3y] = rot(A[x, y], r[x, y])
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = \
                    _rotl64(lanes[x + 5 * y], _KECCAK_RHO[x + 5 * y])
        # chi
        for x in range(5):
            for y in range(5):
                lanes[x + 5 * y] = b[x + 5 * y] ^ \
                    ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
        # iota
        lanes[0] ^= rc


def _keccak_sponge(data, rate_bytes, domain_byte, out_len):
    """Raw sponge over Keccak-f[1600]: multi-rate pad (``domain_byte`` then
    zeros, the last byte OR'd with 0x80), absorb in ``rate_bytes`` chunks,
    then squeeze ``out_len`` bytes."""
    lanes = [0] * 25
    padded = bytearray(data)
    padded.append(domain_byte)
    while len(padded) % rate_bytes:
        padded.append(0)
    padded[-1] |= 0x80
    for off in range(0, len(padded), rate_bytes):
        blk = padded[off:off + rate_bytes]
        for i in range(rate_bytes // 8):
            lanes[i] ^= int.from_bytes(blk[8 * i:8 * i + 8], "little")
        _keccak_f1600(lanes)
    out = bytearray()
    while len(out) < out_len:
        for i in range(rate_bytes // 8):
            out += lanes[i].to_bytes(8, "little")
        _keccak_f1600(lanes)
    return bytes(out[:out_len])


class SpongeDRBG(_DrbgBase):
    """Sponge-mode DRBG on Keccak-f[1600]: SHA3-256's 136-byte rate, SHAKE's
    0x1F domain byte.  Seed material is absorbed; every generate call
    squeezes one block; ``reseed()`` absorbs fresh entropy at any moment.
    Deterministic from an explicit seed; live OS entropy when unseeded."""

    _rate = 136                     # SHA3-256's rate (capacity 512 bits)
    _block_bytes = 32

    def _absorb(self, material):
        """Absorb material into the current state (Keccak multi-rate pad)."""
        rate = self._rate
        padded = bytearray(bytes(material))
        padded.append(0x1F)
        while len(padded) % rate:
            padded.append(0)
        padded[-1] |= 0x80
        lanes = self._lanes
        for off in range(0, len(padded), rate):
            blk = padded[off:off + rate]
            for i in range(rate // 8):
                lanes[i] ^= int.from_bytes(blk[8 * i:8 * i + 8], "little")
            _keccak_f1600(lanes)

    def seed(self, a=None, version=2):
        self._lanes = [0] * 25
        self._absorb(self._seed_material(a))
        self._reseed_counter = 1

    def reseed(self, entropy=None, additional=b""):
        # absorb the fresh entropy straight into the current state
        self._absorb(self._seed_material(entropy) + bytes(additional))
        self._reseed_counter = 1

    def _block(self):
        # squeeze one block: the lanes' low `rate` bytes, then permute
        lanes = self._lanes
        out = bytearray()
        for i in range(self._rate // 8):
            out += lanes[i].to_bytes(8, "little")
        _keccak_f1600(lanes)
        return bytes(out[:self._block_bytes])

    def getstate(self):
        return (tuple(self._lanes), self._reseed_counter)

    def setstate(self, state):
        lanes, self._reseed_counter = state
        self._lanes = list(lanes)


if __name__ == "__main__":
    print("=" * 70)
    print("sponge_drbg - Keccak-f[1600] sponge DRBG self-check battery")
    print("=" * 70)

    # --- 1. THE permutation KAT: hashlib runs the same Keccak-f[1600] ---------
    # SHAKE-128: rate 168, domain 0x1F.  Multi-block absorbs and squeezes.
    for msg in (b"", b"abc", b"keccak transcription check" * 5):
        mine = _keccak_sponge(msg, 168, 0x1F, 200)
        assert mine == hashlib.shake_128(msg).digest(200), \
            "our Keccak-f[1600] disagrees with hashlib.shake_128"
    # SHA3-256: rate 136, domain 0x06.
    for msg in (b"", b"abc", b"sponge" * 40):
        assert _keccak_sponge(msg, 136, 0x06, 32) == hashlib.sha3_256(msg).digest(), \
            "our Keccak-f[1600] disagrees with hashlib.sha3_256"
    # SHA3-512: rate 72, domain 0x06 - a third rate through the same permutation.
    for msg in (b"", b"abc", b"r" * 250):
        assert _keccak_sponge(msg, 72, 0x06, 64) == hashlib.sha3_512(msg).digest(), \
            "our Keccak-f[1600] disagrees with hashlib.sha3_512"
    # domain-byte discipline: the pad really does distinguish the domains
    assert _keccak_sponge(b"abc", 136, 0x06, 32) != _keccak_sponge(b"abc", 136, 0x1F, 32)
    print("[1] Keccak-f[1600] == hashlib (SHAKE-128, SHA3-256, SHA3-512; 3 rates): OK")

    # --- 2. the reference stream (seed-1), pinned ------------------------------
    pin = "72acc59a1d4538745c8ff2d64b4c3ceb7c7c77661cfe506a165ee10aca21b8fd"
    a = SpongeDRBG("seed-1").randbytes(32)
    assert a.hex() == pin, f"SpongeDRBG('seed-1') drifted: {a.hex()}"
    b = SpongeDRBG("seed-1").randbytes(32)
    assert a == b, "not deterministic for a fixed seed"
    assert a != SpongeDRBG("seed-2").randbytes(32), "ignores the seed"
    print("[2] SpongeDRBG('seed-1') first 32 bytes match the pinned stream: OK")

    # --- 3. absorb/squeeze mechanics: squeezing drains, reseeding refills ------
    g = SpongeDRBG("mechanics")
    first = g.randbytes(32)
    state_mid = g.getstate()                # squeezed state is NOT the fresh state
    second = g.randbytes(32)
    assert first != second, "squeezing must permute between blocks"
    clone = SpongeDRBG("mechanics")
    clone.setstate(state_mid)
    assert clone.randbytes(32) == second, "squeezed state not restorable"
    # reseed with the SAME fixed entropy must land on the same fresh stream
    x = SpongeDRBG("factory")
    x.randbytes(16)
    x.reseed("deterministic entropy")
    y = SpongeDRBG("factory")
    y.randbytes(16)
    y.reseed("deterministic entropy")
    assert x.randbytes(48) == y.randbytes(48), "reseed is not reproducible"
    z = SpongeDRBG("factory")
    z.randbytes(16)
    z.reseed("different entropy")
    assert z.randbytes(48) != x.randbytes(48), "different entropy, same stream?"
    print("[3] squeeze drains deterministically; reseed absorbs reproducibly: OK")

    # --- 4. state round-trip + personalization ----------------------------------
    g = SpongeDRBG("round-trip")
    g.randbytes(100)
    state = g.getstate()
    expected = g.randbytes(64)
    clone = SpongeDRBG("round-trip")
    clone.setstate(state)
    assert clone.randbytes(64) == expected, "state round-trip broken"
    assert SpongeDRBG("seed-1", personalization=b"app-id").randbytes(16) != \
        SpongeDRBG("seed-1").randbytes(16), "personalization ignored"
    print("[4] setstate replays the stream; personalization shifts it: OK")

    # --- 5. the whole random.Random API + bit balance ----------------------------
    g = SpongeDRBG("api")
    for k in (1, 7, 33, 128):
        assert 0 <= g.getrandbits(k) < (1 << k)
    assert all(0.0 <= g.random() < 1.0 for _ in range(200))
    assert 0 <= g.choice(range(100)) < 100
    ones = bin(int.from_bytes(SpongeDRBG("api").randbytes(4096), "big")).count("1")
    assert 15800 < ones < 17000, f"bit balance looks broken ({ones} ones)"
    print(f"[5] python API sane; 4096 bytes '{ones} ones/32768' balance: OK")

    print("-" * 70)
    print("All sponge_drbg checks passed!")
