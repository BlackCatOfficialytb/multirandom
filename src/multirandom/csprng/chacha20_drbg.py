"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.csprng.chacha20_drbg
Description:
Counter-mode DRBG on the RFC 8439 ChaCha20 block function: a SHA-256
derived 256-bit key, the RFC's 96-bit nonce and 32-bit block counter.
The quarter-round/double-round core below is the RFC's ``chacha_block``
transcribed word for word (10 double rounds = the 20 in ChaCha20), and
the battery pins it against the RFC 8439 section 2.3.2 known-answer
vector - cross-checked against the installed crypto library's ChaCha20.

Every DRBG here is a ``random.Random`` subclass, so ``.random()``,
``.randint()``, ``.choice()``, ``.shuffle()`` ... all work on top of the
cryptographic core.  Deterministic from an explicit seed; live OS entropy
when you pass ``None``.

Run this module to execute its assert-based self-checks::

    py -3 -m multirandom.csprng.chacha20_drbg
"""
from __future__ import annotations

import hashlib
import struct

try:
    from ._drbg_base import _DrbgBase, _rotl32
except ImportError:                          # running as a plain script
    from _drbg_base import _DrbgBase, _rotl32


_CHACHA_CONST = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)


def _chacha_qr(w, a, b, c, d):
    """One ChaCha quarter-round on words ``a, b, c, d`` (RFC 8439)."""
    w[a] = (w[a] + w[b]) & 0xFFFFFFFF
    w[d] = _rotl32(w[d] ^ w[a], 16)
    w[c] = (w[c] + w[d]) & 0xFFFFFFFF
    w[b] = _rotl32(w[b] ^ w[c], 12)
    w[a] = (w[a] + w[b]) & 0xFFFFFFFF
    w[d] = _rotl32(w[d] ^ w[a], 8)
    w[c] = (w[c] + w[d]) & 0xFFFFFFFF
    w[b] = _rotl32(w[b] ^ w[c], 7)


class ChaCha20DRBG(_DrbgBase):
    """Counter-mode DRBG on the RFC 8439 ChaCha20 block function: a SHA-256
    derived 256-bit key, the RFC's 96-bit nonce and 32-bit block counter.
    Deterministic from an explicit seed; live OS entropy when unseeded."""

    def seed(self, a=None, version=2):
        material = self._seed_material(a)
        self._key = hashlib.sha256(material + b"chacha20-drbg key").digest()
        self._nonce = hashlib.sha256(material + b"chacha20-drbg nonce").digest()[:12]
        self._ctr = 1  # RFC 8439 message-counter convention

    def _block(self):
        w = list(_CHACHA_CONST)
        w += list(struct.unpack("<8I", self._key))
        w.append(self._ctr & 0xFFFFFFFF)
        w += list(struct.unpack("<3I", self._nonce))
        work = w[:]
        for _ in range(10):  # 10 double rounds == the 20 standard ChaCha rounds
            _chacha_qr(work, 0, 4, 8, 12)
            _chacha_qr(work, 1, 5, 9, 13)
            _chacha_qr(work, 2, 6, 10, 14)
            _chacha_qr(work, 3, 7, 11, 15)
            _chacha_qr(work, 0, 5, 10, 15)
            _chacha_qr(work, 1, 6, 11, 12)
            _chacha_qr(work, 2, 7, 8, 13)
            _chacha_qr(work, 3, 4, 9, 14)
        self._ctr = (self._ctr + 1) % (1 << 32)   # wraps only after 128 TiB
        return struct.pack("<16I", *[(x + y) & 0xFFFFFFFF for x, y in zip(work, w)])

    def getstate(self):
        return (self._key, self._nonce, self._ctr)

    def setstate(self, state):
        self._key, self._nonce, self._ctr = state



def main():
    print("=" * 70)
    print("chacha20_drbg - RFC 8439 ChaCha20 DRBG self-check battery")
    print("=" * 70)

    # --- 1. RFC 8439 section 2.3.2 block-function known-answer test -----------
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    g = ChaCha20DRBG.__new__(ChaCha20DRBG)     # wire the RFC's state by hand
    g._key, g._nonce, g._ctr = key, nonce, 1
    ks = g._block()
    rfc = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e")
    assert ks == rfc, "the ChaCha20 block function left the RFC's rails"
    # cross-check against the installed crypto library's ChaCha20 (same RFC
    # construction: 96-bit nonce, 32-bit counter; block 1 = seek to byte 64)
    try:
        from Crypto.Cipher import ChaCha20 as _lib_chacha
    except ImportError:
        try:
            from Cryptodome.Cipher import ChaCha20 as _lib_chacha
        except ImportError:
            _lib_chacha = None
    if _lib_chacha is not None:
        ref = _lib_chacha.new(key=key, nonce=nonce)
        ref.seek(64)
        assert ref.encrypt(b"\x00" * 64) == rfc, "library disagrees with the RFC vector"
        print("[1] RFC 8439 2.3.2 KAT + library cross-check: OK")
    else:
        print("[1] RFC 8439 2.3.2 KAT (no library available for cross-check): OK")

    # --- 2. the reference stream (seed-1), pinned ------------------------------
    pin = "81271bef23e50353417a5188359c215e3da6edb04405909517e03674b388ee79"
    a = ChaCha20DRBG("seed-1").randbytes(32)
    assert a.hex() == pin, f"ChaCha20DRBG('seed-1') drifted: {a.hex()}"
    b = ChaCha20DRBG("seed-1").randbytes(32)
    assert a == b, "not deterministic for a fixed seed"
    assert a != ChaCha20DRBG("seed-2").randbytes(32), "ignores the seed"
    print("[2] ChaCha20DRBG('seed-1') first 32 bytes match the pinned stream: OK")

    # --- 3. the counter really counts: 65 bytes eats two blocks -----------------
    g = ChaCha20DRBG("counter")
    g.randbytes(64)
    ctr1 = g._ctr
    assert ctr1 == 2, "one block must move the RFC counter 1 -> 2"
    g.randbytes(1)
    assert g._ctr == 3, "a 1-byte request still burns a whole 64-byte block"
    assert ChaCha20DRBG("counter").randbytes(65) == \
        ChaCha20DRBG("counter").randbytes(65), "determinism broke across blocks"
    print("[3] 32-bit block counter advances 1 per 64-byte block: OK")

    # --- 4. state round-trip + personalization ----------------------------------
    g = ChaCha20DRBG("round-trip")
    g.randbytes(100)
    state = g.getstate()
    expected = g.randbytes(64)
    clone = ChaCha20DRBG("round-trip")
    clone.setstate(state)
    assert clone.randbytes(64) == expected, "state round-trip broken"
    assert ChaCha20DRBG("seed-1", personalization=b"app-id").randbytes(16) != \
        ChaCha20DRBG("seed-1").randbytes(16), "personalization ignored"
    print("[4] setstate replays the stream; personalization shifts it: OK")

    # --- 5. the whole random.Random API + bit balance ----------------------------
    g = ChaCha20DRBG("api")
    for k in (1, 7, 33, 128):
        assert 0 <= g.getrandbits(k) < (1 << k)
    assert all(0.0 <= g.random() < 1.0 for _ in range(200))
    assert 0 <= g.choice(range(100)) < 100
    ones = bin(int.from_bytes(ChaCha20DRBG("api").randbytes(4096), "big")).count("1")
    assert 15800 < ones < 17000, f"bit balance looks broken ({ones} ones)"
    print(f"[5] python API sane; 4096 bytes '{ones} ones/32768' balance: OK")

    print("-" * 70)
    print("All chacha20_drbg checks passed!")


if __name__ == "__main__":
    main()
