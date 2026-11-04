"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.csprng.yarrow
Description:
Yarrow-160 (Kelsey, Schneier & Ferguson, 1999) -- Fortuna's predecessor,
which ran as FreeBSD's ``/dev/random`` for years: two entropy pools (fast
and slow) with separate thresholds, SHA-1 reseeding, and an AES-192-CTR
generator keyed with the zero-padded 160-bit Yarrow key.  Kept as a
legacy curiosity -- the first rule of Yarrow is to upgrade to Fortuna.

Simplified against the paper: reseeding triggers as soon as the fast pool
has 64 bytes (or the slow pool 160), with Yarrow's refinement of waiting
a full generated chunk dropped.

The AES-192-CTR generator is the installed crypto library's (see
``multirandom.csprng._aes``).  Every DRBG here is a ``random.Random``
subclass: ``.random()``, ``.randint()``, ``.choice()``, ``.shuffle()``
... all work on top of the cryptographic core.  Deterministic from an
explicit seed; feed it later with :meth:`YarrowRandom.add_entropy`.

Run this module to execute its assert-based self-checks::

    py -3 -m multirandom.csprng.yarrow
"""
from __future__ import annotations

import hashlib

try:
    from ._drbg_base import _DrbgBase
    from ._aes import _Aes
except ImportError:                          # running as a plain script
    from _drbg_base import _DrbgBase
    from _aes import _Aes


class YarrowRandom(_DrbgBase):
    """Yarrow-160, Fortuna's predecessor (FreeBSD ran it as ``/dev/random``
    for years): two pools (fast, slow), SHA-1 reseeding and an AES-192-CTR
    generator keyed with the zero-padded 160-bit Yarrow key.  Kept as a
    legacy curiosity - the first rule of Yarrow is to upgrade to Fortuna.

    Simplified against the paper: reseeding triggers as soon as the fast
    pool has 64 bytes (or the slow pool 160), with Yarrow's refinement of
    waiting a full generated chunk dropped."""

    _fast_threshold = 64
    _slow_threshold = 160

    def seed(self, a=None, version=2):
        material = self._seed_material(a)
        half = len(material) // 2
        self._fast = material[:half]
        self._slow = material[half:]
        self._fast_have = 0
        self._slow_have = 0
        self._reseed_counter = 0
        self._key_bytes = b"\x00" * 20
        self._reseed()  # power-on reseed, pools otherwise still empty

    def add_entropy(self, data, source="fast"):
        """Feed bytes to the "fast" pool (default) or the "slow" pool."""
        if source not in ("fast", "slow"):
            raise ValueError("source must be 'fast' or 'slow'")
        if not isinstance(data, (bytes, bytearray)):
            data = bytes(str(data).encode())
        if source == "fast":
            self._fast += bytes(data)
            self._fast_have += len(data)
        else:
            self._slow += bytes(data)
            self._slow_have += len(data)
        if (source == "fast" and self._fast_have >= self._fast_threshold) or \
           (source == "slow" and self._slow_have >= self._slow_threshold):
            self._reseed()

    def _reseed(self):
        fast_d = hashlib.sha1(self._fast + b"|yarrow fast").digest()
        slow_d = hashlib.sha1(self._slow + b"|yarrow slow").digest()
        self._key_bytes = hashlib.sha1(
            self._key_bytes + fast_d + slow_d).digest()   # the 160-bit Yarrow key
        self._aes = _Aes(self._key_bytes + b"\x00" * 4)   # ... inside AES-192
        self._ctr = 0
        self._fast = b""
        self._slow = b""
        self._fast_have = 0
        self._slow_have = 0
        self._reseed_counter += 1

    def _block(self):
        block = self._aes.encrypt_block(self._ctr.to_bytes(16, "big"))
        self._ctr = (self._ctr + 1) % (1 << 128)
        return block

    def getstate(self):
        return (self._key_bytes, self._ctr, self._fast, self._slow,
                self._fast_have, self._slow_have, self._reseed_counter,
                self._personalization)

    def setstate(self, state):
        (self._key_bytes, self._ctr, self._fast, self._slow, self._fast_have,
         self._slow_have, self._reseed_counter, self._personalization) = state
        self._aes = _Aes(self._key_bytes + b"\x00" * 4)



def main():
    print("=" * 70)
    print("yarrow - Yarrow-160 self-check battery")
    print("=" * 70)

    # --- 1. the reference stream (seed-1), pinned -----------------------------
    pin = "7acae1cd7855752a4e3209acf29877f460f61ae70da5a0b81b8a8839174a1f95"
    a = YarrowRandom("seed-1").randbytes(32)
    assert a.hex() == pin, f"YarrowRandom('seed-1') drifted: {a.hex()}"
    b = YarrowRandom("seed-1").randbytes(32)
    assert a == b, "not deterministic for a fixed seed"
    assert a != YarrowRandom("seed-2").randbytes(32), "ignores the seed"
    print("[1] YarrowRandom('seed-1') first 32 bytes match the pinned stream: OK")

    # --- 2. the two pools split the seed; power-on reseed runs ------------------
    material = b"\x00" * 40
    # the power-on reseed must digest BOTH halves of the seed: derive the
    # expected power-on key by hand (zero key || fast || slow -> SHA-1)
    fast, slow = material[:20], material[20:]
    expected_key = hashlib.sha1(
        b"\x00" * 20
        + hashlib.sha1(fast + b"|yarrow fast").digest()
        + hashlib.sha1(slow + b"|yarrow slow").digest()).digest()
    g = YarrowRandom(material)
    assert g._key_bytes == expected_key, "the seed's two halves did not reach the key"
    assert g._reseed_counter == 1, "power-on reseed missing"
    assert g._fast == b"" and g._slow == b"", "power-on reseed must drain the pools"
    assert len(g._key_bytes) == 20, "the Yarrow key is 160-bit"
    print("[2] fast/slow pools split the seed; power-on reseed drains them: OK")

    # --- 3. the thresholds: fast 64 bytes, slow 160, wrong source refused -------
    g = YarrowRandom("thresholds")
    g.randbytes(32)
    count = g._reseed_counter
    g.add_entropy(b"X" * 63)                   # one byte short: no reseed
    assert g._reseed_counter == count
    g.add_entropy(b"X")                        # 64 reached: fast reseed
    assert g._reseed_counter == count + 1
    assert g._fast_have == 0 and g._fast == b"", "the fast pool must drain"
    g.add_entropy(b"S" * 159, source="slow")   # one byte short: no reseed
    assert g._reseed_counter == count + 1
    g.add_entropy(b"S", source="slow")         # 160 reached: slow reseed
    assert g._reseed_counter == count + 2
    try:
        g.add_entropy(b"x", source="sideways")
    except ValueError:
        pass
    else:
        raise AssertionError("a bogus pool name was accepted")
    print("[3] fast/slow thresholds 64/160 gate reseeds; bad source refused: OK")

    # --- 4. the AES-192 generator inside ----------------------------------------
    g = YarrowRandom("generator")
    g.randbytes(16)
    assert len(g._aes._key) == 24, "the generator must run AES-192 (20B key + pad)"
    assert g._aes._key[20:] == bytes(4), "the 160-bit key pads with zeros"
    print("[4] generator is the 160-bit key zero-padded into AES-192: OK")

    # --- 5. state round-trip + personalization -----------------------------------
    g = YarrowRandom("round-trip")
    g.randbytes(100)
    g.add_entropy(b"stuffing", source="slow")
    state = g.getstate()
    expected = g.randbytes(64)
    clone = YarrowRandom("round-trip")
    clone.setstate(state)
    assert clone.randbytes(64) == expected, "state round-trip broken"
    assert YarrowRandom("seed-1", personalization=b"app-id").randbytes(16) != \
        YarrowRandom("seed-1").randbytes(16), "personalization ignored"
    print("[5] setstate replays pools and generator; personalization shifts: OK")

    # --- 6. the whole random.Random API + bit balance -----------------------------
    g = YarrowRandom("api")
    for k in (1, 7, 33, 128):
        assert 0 <= g.getrandbits(k) < (1 << k)
    assert all(0.0 <= g.random() < 1.0 for _ in range(200))
    assert 0 <= g.choice(range(100)) < 100
    ones = bin(int.from_bytes(YarrowRandom("api").randbytes(4096), "big")).count("1")
    assert 15800 < ones < 17000, f"bit balance looks broken ({ones} ones)"
    print(f"[6] python API sane; 4096 bytes '{ones} ones/32768' balance: OK")

    print("-" * 70)
    print("All yarrow checks passed!")


if __name__ == "__main__":
    main()
