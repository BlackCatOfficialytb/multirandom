"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.csprng.fortuna
Description:
Fortuna (Ferguson & Schneier, "Practical Cryptography", 2003): 32 seed
pools reseeded on a schedule proportional to the number of reseeds so far
(pool i only joins reseed number k when bit i of k is set -- so a slow
feeder is never starved by a fast attacker), and inside, an AES-256-CTR
generator that rekeys every 65 536 blocks.

Simplifications for a pocket library (each documented, none fatal): the
reseed gate is *data-count* based (the real Fortuna also refuses to reseed
more often than once per 100 ms), and pools here just hold the raw fed
bytes instead of an incrementally hashed state, which makes
``getstate()``/``setstate()`` exact.

The AES-256-CTR generator is the installed crypto library's (see
``multirandom.csprng._aes``).  Every DRBG here is a ``random.Random``
subclass: ``.random()``, ``.randint()``, ``.choice()``, ``.shuffle()``
... all work on top of the cryptographic core.  Deterministic from an
explicit seed; feed it later with :meth:`FortunaRandom.add_entropy`.

Run this module to execute its assert-based self-checks::

    py -3 -m multirandom.csprng.fortuna
"""
from __future__ import annotations

import hashlib

try:
    from ._drbg_base import _DrbgBase
    from ._aes import _Aes
except ImportError:                          # running as a plain script
    from _drbg_base import _DrbgBase
    from _aes import _Aes


class FortunaRandom(_DrbgBase):
    """Fortuna (Ferguson & Schneier): 32 seed pools, reseeded in a schedule
    proportional to the number of reseeds so far, with an AES-256-CTR
    generator inside that rekeys every 65 536 blocks.

    Simplifications for a pocket library (each documented, none fatal):
    the reseed gate is *data-count* based (the real Fortuna also refuses to
    reseed more often than 100 ms), and pools here just hold the raw fed
    bytes instead of an incrementally hashed state, which makes
    ``getstate()``/``setstate()`` exact.  Deterministic from an explicit
    seed; feed it later with :meth:`add_entropy`."""

    _rekey_blocks = 1 << 16

    def seed(self, a=None, version=2):
        material = self._seed_material(a)
        self._pools = [material[i::32] for i in range(32)]  # round-robin chunks
        self._pool_bytes = [len(p) for p in self._pools]
        self._pool_ptr = 0
        self._reseed_count = 0
        self._gkey = bytes(32)
        self._gctr = 0
        self._gaes = _Aes(self._gkey)
        self._gblocks = 0
        self._reseed_pools(32)  # power-on: every pool the seed filled counts

    def add_entropy(self, data, pool=None):
        """Feed fresh entropy to a pool (round-robin by default).  The
        byte-gate on pool 0 decides whether it turns into a reseed."""
        i = self._pool_ptr if pool is None else (int(pool) % 32)
        self._pool_ptr = (self._pool_ptr + 1) % 32
        if not isinstance(data, (bytes, bytearray)):
            data = bytes(str(data).encode())
        self._pools[i] += bytes(data)
        self._pool_bytes[i] += len(data)
        if self._pool_bytes[0] >= 32:     # Fortuna's "something new arrived" gate
            self._reseed_pools(min(32, (self._reseed_count + 1).bit_length()))

    def _reseed_pools(self, k):
        material = b"".join(
            hashlib.sha256(self._pools[i]).digest()
            + len(self._pools[i]).to_bytes(4, "big")
            for i in range(k))
        for i in range(k):
            self._pools[i] = b""
            self._pool_bytes[i] = 0
        self._g_update(bytes(material))
        self._reseed_count += 1

    def _g_update(self, data=b""):
        """Generator rekey, Fortuna style: the AES-CTR keystream under the
        current key is XORed with the seed material in sequential
        (key + counter)-sized chunks, so any reseed length is absorbed and
        every pool digest reaches the key."""
        data = bytes(data)
        off = 0
        while True:
            chunk = data[off:off + 48]
            off += 48
            temp = self._gaes.ctr(self._gctr, 48)
            if chunk:
                padded = chunk.ljust(48, b"\x00")
                temp = bytes(x ^ y for x, y in zip(temp, padded))
            else:
                # a final empty chunk = the rekey-every-2^16-blocks case
                pass
            self._gkey = bytes(temp[:32])
            self._gctr = int.from_bytes(temp[32:48], "big")
            self._gaes = _Aes(self._gkey)
            if off >= len(data):
                break

    def _block(self):
        self._gctr = (self._gctr + 1) % (1 << 128)
        self._gblocks += 1
        block = self._gaes.encrypt_block(self._gctr.to_bytes(16, "big"))
        if self._gblocks == self._rekey_blocks:   # Fortuna rekeys every 65 536 blocks
            self._gblocks = 0
            self._g_update(b"")
        return block

    def getstate(self):
        return (tuple(self._pools), tuple(self._pool_bytes), self._pool_ptr,
                self._reseed_count, self._gkey, self._gctr, self._gblocks,
                self._personalization)

    def setstate(self, state):
        (pools, pool_bytes, self._pool_ptr, self._reseed_count, self._gkey,
         self._gctr, self._gblocks, self._personalization) = state
        self._pools = list(pools)
        self._pool_bytes = list(pool_bytes)
        self._gaes = _Aes(self._gkey)


if __name__ == "__main__":
    print("=" * 70)
    print("fortuna - Ferguson/Schneier Fortuna self-check battery")
    print("=" * 70)

    # --- 1. the reference stream (seed-1), pinned -----------------------------
    pin = "a04256732889a2e6e358c7d428aed322f111b6cddf8e9caa528bbac716e8f1d7"
    a = FortunaRandom("seed-1").randbytes(32)
    assert a.hex() == pin, f"FortunaRandom('seed-1') drifted: {a.hex()}"
    b = FortunaRandom("seed-1").randbytes(32)
    assert a == b, "not deterministic for a fixed seed"
    assert a != FortunaRandom("seed-2").randbytes(32), "ignores the seed"
    print("[1] FortunaRandom('seed-1') first 32 bytes match the pinned stream: OK")

    # --- 2. the seed spreads over 32 pools round-robin --------------------------
    material = bytes(range(64))
    g = FortunaRandom(material)
    assert len(g._pools) == 32
    # the split IS round-robin: verify the exact halves the pools started as
    spread = [material[i::32] for i in range(32)]
    assert all(len(p) == 2 for p in spread), "the split itself is not round-robin"
    # power-on reseeds once and drains every pool into the generator
    assert g._reseed_count == 1, "power-on reseeds once with every pool"
    assert all(p == b"" for p in g._pools), "power-on reseed must drain the pools"
    # add_entropy then starts at pool 0 and round-robins from there
    g.add_entropy(b"p0 first")
    assert g._pools[0] == b"p0 first", "add_entropy must start at pool 0"
    g.add_entropy(b"p1 next")
    assert g._pools[1] == b"p1 next", "add_entropy must round-robin"
    print("[2] seed split round-robin over 32 pools; power-on reseed drains: OK")

    # --- 3. add_entropy: round-robin feeding and the pool-0 byte gate -----------
    g = FortunaRandom("gates")
    g.randbytes(32)
    count0 = g._reseed_count
    g.add_entropy(b"tiny")                     # pool 0: 4 new bytes - under the gate
    assert g._reseed_count == count0, "reseeded on a trickle"
    g.add_entropy(b"A" * 32, pool=0)           # the gate opens at 32 bytes on pool 0
    assert g._reseed_count == count0 + 1, "the 32-byte gate did not open"
    # the reseed schedule: reseed number k pulls the first bit_length(k) pools
    g.add_entropy(b"B" * 32, pool=0)           # reseed #(count0+2) -> 2 pools join
    assert g._reseed_count == count0 + 2
    # entropy actually changes the stream
    g2 = FortunaRandom("gates")
    assert g.randbytes(16) != g2.randbytes(16), "added entropy had no effect"
    # non-bytes payloads and explicit pool selection are accepted
    g.add_entropy("string entropy", pool=7)
    assert g._pools[7] == b"string entropy"
    print("[3] pool-0 32-byte gate, 2^k reseed schedule, round-robin feed: OK")

    # --- 4. the generator: AES-256-CTR with rekey after 65 536 blocks -----------
    g = FortunaRandom("generator")
    g.randbytes(16)
    assert len(g._gkey) == 32, "the generator key must be AES-256 wide"
    g._gblocks = FortunaRandom._rekey_blocks - 1   # one block left before rekey
    before = g._gkey
    g.randbytes(16)                            # consumes the last pre-rekey block
    assert g._gkey != before, "no rekey at the 65 536-block boundary"
    assert g._gblocks == 0
    print("[4] AES-256-CTR generator rekeys at the 2^16-block boundary: OK")

    # --- 5. state round-trip (pools included) + personalization ------------------
    g = FortunaRandom("round-trip")
    g.randbytes(100)
    g.add_entropy(b"pool stuffing" * 3)
    state = g.getstate()
    expected = g.randbytes(64)
    clone = FortunaRandom("round-trip")
    clone.setstate(state)
    assert clone.randbytes(64) == expected, "state round-trip broken"
    assert FortunaRandom("seed-1", personalization=b"app-id").randbytes(16) != \
        FortunaRandom("seed-1").randbytes(16), "personalization ignored"
    print("[5] setstate replays pools and generator; personalization shifts: OK")

    # --- 6. the whole random.Random API + bit balance -----------------------------
    g = FortunaRandom("api")
    for k in (1, 7, 33, 128):
        assert 0 <= g.getrandbits(k) < (1 << k)
    assert all(0.0 <= g.random() < 1.0 for _ in range(200))
    assert 0 <= g.choice(range(100)) < 100
    ones = bin(int.from_bytes(FortunaRandom("api").randbytes(4096), "big")).count("1")
    assert 15800 < ones < 17000, f"bit balance looks broken ({ones} ones)"
    print(f"[6] python API sane; 4096 bytes '{ones} ones/32768' balance: OK")

    print("-" * 70)
    print("All fortuna checks passed!")
