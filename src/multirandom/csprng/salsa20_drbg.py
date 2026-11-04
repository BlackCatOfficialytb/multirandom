"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.csprng.salsa20_drbg
Description:
Counter-mode DRBG on the DJB Salsa20 core: 256-bit key, 64-bit nonce,
64-bit block counter, 20 rounds.  The core below is DJB's ``Salsa20``
double-round transcription (column rounds then row rounds, the z1..z0
quarter-round sequence), fed the same "expand 32-byte k" constants
ChaCha20 descends from.  Salsa20 - the eSTREAM portfolio cipher that
predates ChaCha20 and differs from it only in the round function's
orientation.

Every DRBG here is a ``random.Random`` subclass, so ``.random()``,
``.randint()``, ``.choice()``, ``.shuffle()`` ... all work on top of the
cryptographic core.  Deterministic from an explicit seed; live OS entropy
when you pass ``None``.

Run this module to execute its assert-based self-checks::

    py -3 -m multirandom.csprng.salsa20_drbg
"""
from __future__ import annotations

import hashlib
import struct

try:
    from ._drbg_base import _DrbgBase, _rotl32
except ImportError:                          # running as a plain script
    from _drbg_base import _DrbgBase, _rotl32


_CHACHA_CONST = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)


def _salsa_qr(w, a, b, c, d):
    """One Salsa20 quarter-round (DJB's z1..z0 sequence)."""
    w[b] = w[b] ^ _rotl32((w[a] + w[d]) & 0xFFFFFFFF, 7)
    w[c] = w[c] ^ _rotl32((w[b] + w[a]) & 0xFFFFFFFF, 9)
    w[d] = w[d] ^ _rotl32((w[c] + w[b]) & 0xFFFFFFFF, 13)
    w[a] = w[a] ^ _rotl32((w[d] + w[c]) & 0xFFFFFFFF, 18)


class Salsa20DRBG(_DrbgBase):
    """Counter-mode DRBG on the DJB Salsa20 core: 256-bit key, 64-bit nonce,
    64-bit block counter, 20 rounds.  Deterministic from an explicit seed."""

    def seed(self, a=None, version=2):
        material = self._seed_material(a)
        self._key = hashlib.sha256(material + b"salsa20-drbg key").digest()
        self._nonce = hashlib.sha256(material + b"salsa20-drbg nonce").digest()[:8]
        self._ctr = 1

    def _block(self):
        w = [_CHACHA_CONST[0]]                    # x0: "expa"
        w += list(struct.unpack("<4I", self._key[:16]))
        w.append(_CHACHA_CONST[1])                # x5: "nd 3"
        w += list(struct.unpack("<2I", self._nonce))
        w += [self._ctr & 0xFFFFFFFF, (self._ctr >> 32) & 0xFFFFFFFF]
        w.append(_CHACHA_CONST[2])                # x10: "2-by"
        w += list(struct.unpack("<4I", self._key[16:]))
        w.append(_CHACHA_CONST[3])                # x15: "te k"
        work = w[:]
        for _ in range(10):                       # 10 double rounds = 20 rounds
            _salsa_qr(work, 0, 4, 8, 12)
            _salsa_qr(work, 5, 9, 13, 1)
            _salsa_qr(work, 10, 14, 2, 6)
            _salsa_qr(work, 15, 3, 7, 11)
            _salsa_qr(work, 0, 1, 2, 3)
            _salsa_qr(work, 5, 6, 7, 4)
            _salsa_qr(work, 10, 11, 8, 9)
            _salsa_qr(work, 15, 12, 13, 14)
        self._ctr = (self._ctr + 1) % (1 << 64)
        return struct.pack("<16I", *[(x + y) & 0xFFFFFFFF for x, y in zip(work, w)])

    def getstate(self):
        return (self._key, self._nonce, self._ctr)

    def setstate(self, state):
        self._key, self._nonce, self._ctr = state



def main():
    print("=" * 70)
    print("salsa20_drbg - DJB Salsa20 core DRBG self-check battery")
    print("=" * 70)

    # --- 1. the core shape: constants, then the diagonal/column rounds --------
    assert _CHACHA_CONST == (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)
    assert struct.pack("<4I", *_CHACHA_CONST) == b"expand 32-byte k"
    g = Salsa20DRBG.__new__(Salsa20DRBG)     # feed the state by hand
    g._key, g._nonce, g._ctr = bytes(32), bytes(8), 0
    block = g._block()
    assert len(block) == 64 and any(block), "the all-zero state must not stall"
    assert g._ctr == 1, "the 64-bit counter must advance per block"
    # a different counter must give a different block (it lives IN the state)
    g2 = Salsa20DRBG.__new__(Salsa20DRBG)
    g2._key, g2._nonce, g2._ctr = bytes(32), bytes(8), 1
    assert g2._block() != block, "counter ignored"
    print("[1] core wired: 'expand 32-byte k' constants, 64-byte blocks, ctr: OK")

    # --- 2. the reference stream (seed-1), pinned ------------------------------
    pin = "ffa04fe059372a7edf50c1332d4a7ca8f8ac913dfc3c85577a8469b5d9646984"
    a = Salsa20DRBG("seed-1").randbytes(32)
    assert a.hex() == pin, f"Salsa20DRBG('seed-1') drifted: {a.hex()}"
    b = Salsa20DRBG("seed-1").randbytes(32)
    assert a == b, "not deterministic for a fixed seed"
    assert a != Salsa20DRBG("seed-2").randbytes(32), "ignores the seed"
    # the sibling ChaCha20 DRBG must not echo it (different round function)
    from multirandom.csprng.chacha20_drbg import ChaCha20DRBG
    assert a != ChaCha20DRBG("seed-1").randbytes(32), "salsa == chacha?!"
    print("[2] Salsa20DRBG('seed-1') pinned; distinct from the ChaCha20 core: OK")

    # --- 3. the 64-bit counter counts: 65 bytes eats two blocks ----------------
    g = Salsa20DRBG("counter")
    g.randbytes(64)
    assert g._ctr == 2, "one block must move the counter 1 -> 2"
    g.randbytes(1)
    assert g._ctr == 3, "a 1-byte request still burns a whole 64-byte block"
    print("[3] 64-bit block counter advances 1 per 64-byte block: OK")

    # --- 4. state round-trip + personalization ---------------------------------
    g = Salsa20DRBG("round-trip")
    g.randbytes(100)
    state = g.getstate()
    expected = g.randbytes(64)
    clone = Salsa20DRBG("round-trip")
    clone.setstate(state)
    assert clone.randbytes(64) == expected, "state round-trip broken"
    assert Salsa20DRBG("seed-1", personalization=b"app-id").randbytes(16) != \
        Salsa20DRBG("seed-1").randbytes(16), "personalization ignored"
    print("[4] setstate replays the stream; personalization shifts it: OK")

    # --- 5. the whole random.Random API + bit balance ---------------------------
    g = Salsa20DRBG("api")
    for k in (1, 7, 33, 128):
        assert 0 <= g.getrandbits(k) < (1 << k)
    assert all(0.0 <= g.random() < 1.0 for _ in range(200))
    assert 0 <= g.choice(range(100)) < 100
    ones = bin(int.from_bytes(Salsa20DRBG("api").randbytes(4096), "big")).count("1")
    assert 15800 < ones < 17000, f"bit balance looks broken ({ones} ones)"
    print(f"[5] python API sane; 4096 bytes '{ones} ones/32768' balance: OK")

    print("-" * 70)
    print("All salsa20_drbg checks passed!")


if __name__ == "__main__":
    main()
