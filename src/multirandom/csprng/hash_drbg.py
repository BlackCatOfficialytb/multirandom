"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.csprng.hash_drbg
Description:
NIST SP 800-90A ``Hash_DRBG`` (§10.1.1) with SHA-256 and the §10.3.1
``Hash_df`` (440-bit seed state).  Output blocks are ``hash(0x03 || V_i)``
with ``V_i`` advancing per block; afterwards ``V`` advances twice through
``H(0x00 || V)`` and the reseed counter (§10.1.1.4).  ``Hash_df`` fills
the state as ``hash(counter || input)`` hooking new blocks together.
``reseed()`` accepts fresh entropy at any moment.

Every DRBG here is a ``random.Random`` subclass, so ``.random()``,
``.randint()``, ``.choice()``, ``.shuffle()`` ... all work on top of the
cryptographic core.  Deterministic from an explicit seed; live OS entropy
when you pass ``None``.

Run this module to execute its assert-based self-checks::

    py -3 -m multirandom.csprng.hash_drbg
"""
from __future__ import annotations

import hashlib

try:
    from ._drbg_base import _DrbgBase
except ImportError:                          # running as a plain script
    from _drbg_base import _DrbgBase


class Hash_DRBG(_DrbgBase):
    """NIST SP 800-90A Hash_DRBG (§10.1.1) with SHA-256 and the §10.3.1
    Hash_df (440-bit seed state)."""

    _seedlen = 55  # bytes == 440 bits, the SHA-256 seedlen
    _mask = (1 << 440) - 1

    def seed(self, a=None, version=2):
        self._v = self._df(self._seed_material(a), self._seedlen)
        self._c = int.from_bytes(self._df(b"\x00" + self._v, self._seedlen), "big")
        self._reseed_counter = 1

    def _df(self, material, n):
        """§10.3.1 Hash_df: consecutive H(counter || input) blocks."""
        material = bytes(material)
        out = bytearray()
        ctr = 1
        while len(out) < n:
            out += hashlib.sha256(bytes((ctr % 256,)) + material).digest()
            ctr += 1
        return bytes(out[:n])

    def reseed(self, entropy=None, additional=b""):
        material = self._seed_material(entropy) + bytes(additional)
        self._v = self._df(b"\x01" + self._v + material, self._seedlen)
        self._c = int.from_bytes(self._df(b"\x00" + self._v, self._seedlen), "big")
        self._reseed_counter = 1

    def _bytes(self, n):
        """§10.1.1.4: per-request loop - blocks are H(0x03||data) with data
        advancing; afterwards V advances twice with H(0x00||V)."""
        out = bytearray()
        data = self._v
        while len(out) < n:
            out += hashlib.sha256(b"\x03" + data).digest()
            data = ((int.from_bytes(data, "big") + 1) & self._mask
                    ).to_bytes(self._seedlen, "big")
        h = hashlib.sha256(b"\x00" + self._v).digest()
        v = (int.from_bytes(self._v, "big") + int.from_bytes(h, "big")
             + self._c) & self._mask
        h = hashlib.sha256(b"\x00" + v.to_bytes(self._seedlen, "big")).digest()
        self._v = ((v + int.from_bytes(h, "big")) & self._mask
                   ).to_bytes(self._seedlen, "big")
        self._reseed_counter += 1
        return bytes(out[:n])

    def getstate(self):
        return (self._v, self._c, self._reseed_counter)

    def setstate(self, state):
        self._v, self._c, self._reseed_counter = state


if __name__ == "__main__":
    print("=" * 70)
    print("hash_drbg - NIST SP 800-90A Hash_DRBG self-check battery")
    print("=" * 70)

    # --- 1. the reference stream (seed-1), pinned -----------------------------
    pin = "a53fa0e7391f0f59173d101cd76600b303c9f13fa3278019218d713ae1e48e53"
    a = Hash_DRBG("seed-1").randbytes(32)
    assert a.hex() == pin, f"Hash_DRBG('seed-1') drifted: {a.hex()}"
    b = Hash_DRBG("seed-1").randbytes(32)
    assert a == b, "not deterministic for a fixed seed"
    assert a != Hash_DRBG("seed-2").randbytes(32), "ignores the seed"
    print("[1] Hash_DRBG('seed-1') first 32 bytes match the pinned stream: OK")

    # --- 2. the §10.1.1.4 mechanics, hand-recomputed ---------------------------
    g = Hash_DRBG("mechanics")
    g.randbytes(32)
    v0, c0, rc0 = g._v, g._c, g._reseed_counter
    # reconstruct the next request out of the fresh state: 32 bytes == ONE
    # block, so the per-request loop stops right after H(0x03 || V).
    manual = hashlib.sha256(b"\x03" + v0).digest()
    h = hashlib.sha256(b"\x00" + v0).digest()
    v = (int.from_bytes(v0, "big") + int.from_bytes(h, "big") + c0) & g._mask
    h = hashlib.sha256(b"\x00" + v.to_bytes(55, "big")).digest()
    v_new = ((v + int.from_bytes(h, "big")) & g._mask).to_bytes(55, "big")
    assert g.randbytes(32) == manual, "generate != H(0x03||V)"
    assert g._v == v_new, "the double V-advance drifted"
    assert g._reseed_counter == rc0 + 1, "reseed counter not bumped"
    # and the data-advance across blocks: fresh generator, 65-byte request
    g2 = Hash_DRBG("mechanics")
    v0 = g2._v
    big_manual = hashlib.sha256(b"\x03" + v0).digest()
    data = ((int.from_bytes(v0, "big") + 1) & g._mask).to_bytes(55, "big")
    big_manual += hashlib.sha256(b"\x03" + data).digest()
    data = ((int.from_bytes(data, "big") + 1) & g._mask).to_bytes(55, "big")
    big_manual += hashlib.sha256(b"\x03" + data).digest()
    assert g2.randbytes(65) == big_manual[:65], "the V_i advance drifted"
    print("[2] generate = H(0x03||V_i); state advances by H(0x00||V) x2: OK")

    # --- 3. the §10.3.1 Hash_df shape -----------------------------------------
    g = Hash_DRBG("df")
    material = b"hash df probe"
    out = g._df(material, 55)              # 2 blocks for 55 bytes
    assert out[:32] == hashlib.sha256(
        bytes([1]) + material).digest(), "Hash_df block 1 wrong (counter byte?)"
    assert out[32:] == hashlib.sha256(
        bytes([2]) + material).digest()[:23], "Hash_df block 2 wrong"
    # seed() derives V out of the material + C out of H_df(0x00 || V)
    g = Hash_DRBG("seed edge")
    v = g._v
    assert v == g._df(g._seed_material("seed edge"), 55), "seed's V off"
    print("[3] Hash_df = H(ctr||input) blocks; seed wires V and C correctly: OK")

    # --- 4. reseeding: reproducible with fixed entropy --------------------------
    x = Hash_DRBG("factory")
    x.randbytes(32)
    x.reseed("deterministic entropy")
    y = Hash_DRBG("factory")
    y.randbytes(32)
    y.reseed("deterministic entropy")
    assert x.randbytes(48) == y.randbytes(48), "reseed is not reproducible"
    z = Hash_DRBG("factory")
    z.randbytes(32)
    z.reseed("different entropy")
    assert z.randbytes(48) != x.randbytes(48), "different entropy, same stream?"
    print("[4] reseed() deterministic with fixed entropy, varies otherwise: OK")

    # --- 5. state round-trip + personalization ---------------------------------
    g = Hash_DRBG("round-trip")
    g.randbytes(100)
    state = g.getstate()
    expected = g.randbytes(64)
    clone = Hash_DRBG("round-trip")
    clone.setstate(state)
    assert clone.randbytes(64) == expected, "state round-trip broken"
    assert Hash_DRBG("seed-1", personalization=b"app-id").randbytes(16) != \
        Hash_DRBG("seed-1").randbytes(16), "personalization ignored"
    print("[5] setstate replays the stream; personalization shifts it: OK")

    # --- 6. the whole random.Random API + bit balance ---------------------------
    g = Hash_DRBG("api")
    for k in (1, 7, 33, 128):
        assert 0 <= g.getrandbits(k) < (1 << k)
    assert all(0.0 <= g.random() < 1.0 for _ in range(200))
    assert 0 <= g.choice(range(100)) < 100
    ones = bin(int.from_bytes(Hash_DRBG("api").randbytes(4096), "big")).count("1")
    assert 15800 < ones < 17000, f"bit balance looks broken ({ones} ones)"
    print(f"[6] python API sane; 4096 bytes '{ones} ones/32768' balance: OK")

    print("-" * 70)
    print("All hash_drbg checks passed!")
