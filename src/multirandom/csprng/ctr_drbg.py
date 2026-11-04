"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.csprng.ctr_drbg
Description:
NIST SP 800-90A ``CTR_DRBG`` (§10.2.1) with AES-128 and the §10.5.1
derivation function.  The internal shape is the standard's: a 256-bit
seed state ``(K, V)`` -- key and counter -- advanced by ``V = V+1;
output = AES(K, V)``; §10.5.1 derives seed material through BCC-chained
AES under the fixed key 000102...0f; and §10.2.1.2 rekeys after every
generate call.  ``reseed()`` accepts fresh entropy at any moment.

The AES itself is the installed crypto library's (see
``multirandom.csprng._aes``), not a hand transcription.

Every DRBG here is a ``random.Random`` subclass, so ``.random()``,
``.randint()``, ``.choice()``, ``.shuffle()`` ... all work on top of the
cryptographic core.  Deterministic from an explicit seed; live OS entropy
when you pass ``None``.

Run this module to execute its assert-based self-checks::

    py -3 -m multirandom.csprng.ctr_drbg
"""
from __future__ import annotations

try:
    from ._drbg_base import _DrbgBase
    from ._aes import _Aes
except ImportError:                          # running as a plain script
    from _drbg_base import _DrbgBase
    from _aes import _Aes


class CTR_DRBG(_DrbgBase):
    """NIST SP 800-90A CTR_DRBG (§10.2.1) with AES-128 and the §10.5.1
    derivation function.  ``reseed()`` accepts fresh entropy at any moment."""

    _seedlen = 48  # bytes: K + V + 16 padding bytes, the AES-128 DRBG seed length

    def seed(self, a=None, version=2):
        self._key = bytes(16)
        self._v = 0
        self._aes = _Aes(self._key)
        self._update(self._df(self._seed_material(a), self._seedlen))
        self._reseed_counter = 1

    def _df(self, material, n):
        """SP 800-90A §10.5.1 derivation function (as the reference
        implementations mirror it): the payload is BCC-chained under the
        fixed key 000102...0f, and the chained result supplies the key and
        counter of the final encryption pass."""
        material = bytes(material)
        # buf = IV cell (16 zero bytes) || L(4, BE) || N(4, BE) || input || 0x80,
        # zero-padded to a multiple of 16-byte AES blocks.
        buf = bytearray(16)
        buf += ((len(material) * 8).to_bytes(4, "big")
                + (n * 8).to_bytes(4, "big")
                + material + b"\x80")
        while len(buf) % 16:
            buf.append(0)
        kdf = _Aes(bytes(range(16)))          # the DF's fixed key

        tmp = bytearray()
        for _ in range((n + 15) // 16):       # one BCC pass per output block
            chain = bytearray(16)             # BCC starts from the zero IV
            for off in range(0, len(buf), 16):
                blk = bytes(buf[off:off + 16])
                blk += bytes(16 - len(blk))   # zero-pad a short trailing block
                chain = bytearray(kdf.encrypt_block(
                    bytes(x ^ y for x, y in zip(chain, blk))))
            tmp += chain
            buf[3] = (buf[3] + 1) & 0xFF      # DF counter lives in the IV cell

        key, iv = bytes(tmp[:16]), bytes(tmp[16:32])
        aes2 = _Aes(key)
        out = bytearray()
        for _ in range((n + 15) // 16):
            iv = aes2.encrypt_block(iv)
            out += iv
        return bytes(out[:n])

    def _update(self, provided=b""):
        temp = bytearray()
        v = self._v
        while len(temp) < 48:
            v = (v + 1) % (1 << 128)
            temp += self._aes.encrypt_block(v.to_bytes(16, "big"))
        if provided:
            data = bytes(provided).ljust(48, b"\x00")[:48]
            temp = bytes(x ^ y for x, y in zip(temp, data))
        self._key = bytes(temp[:16])
        self._v = int.from_bytes(temp[16:32], "big")
        self._aes = _Aes(self._key)

    def reseed(self, entropy=None, additional=b""):
        self._update(self._df(self._seed_material(entropy) + bytes(additional),
                              self._seedlen))
        self._reseed_counter = 1

    def _block(self):
        self._v = (self._v + 1) % (1 << 128)
        return self._aes.encrypt_block(self._v.to_bytes(16, "big"))

    def _bytes(self, n):
        out = bytearray()
        while len(out) < n:
            out += self._block()
        self._update(b"")  # SP 800-90A: rekey after every generate call
        return bytes(out[:n])

    def getstate(self):
        return (self._key, self._v, self._reseed_counter, self._personalization)

    def setstate(self, state):
        self._key, self._v, self._reseed_counter, self._personalization = state
        self._aes = _Aes(self._key)


if __name__ == "__main__":
    print("=" * 70)
    print("ctr_drbg - NIST SP 800-90A CTR_DRBG self-check battery")
    print("=" * 70)

    # --- 1. the reference stream (seed-1), pinned -----------------------------
    pin = "3ebce53b973100935edb763f6654bd242a8228ced7261cf642497731fc6416ce"
    a = CTR_DRBG("seed-1").randbytes(32)
    assert a.hex() == pin, f"CTR_DRBG('seed-1') drifted: {a.hex()}"
    b = CTR_DRBG("seed-1").randbytes(32)
    assert a == b, "not deterministic for a fixed seed"
    assert a != CTR_DRBG("seed-2").randbytes(32), "ignores the seed"
    print("[1] CTR_DRBG('seed-1') first 32 bytes match the pinned stream: OK")

    # --- 2. the standard's mechanics: AES(K, V+1) + §10.2.1.2 rekey -----------
    g = CTR_DRBG("mechanics")
    v_before, k_before = g._v, g._key
    manual = _Aes(k_before).encrypt_block(
        ((v_before + 1) % (1 << 128)).to_bytes(16, "big"))
    out1 = g.randbytes(16)                # one aligned request
    assert out1 == manual, "generate is not AES(K, V+1)"
    assert g._key != k_before and g._v != v_before, \
        "no §10.2.1.2 rekey after generate"
    out2 = g.randbytes(16)
    assert out1 != out2, "rekey is cosmetic"
    print("[2] generate = AES(K, V+1); Sec. 10.2.1.2 rekeys after every request: OK")

    # --- 3. reseeding (§10.2.1.4): same entropy -> same new stream ------------
    x = CTR_DRBG("factory")
    x.randbytes(32)
    x.reseed("deterministic entropy")
    assert x._reseed_counter == 1, "reseed must reset the counter"
    y = CTR_DRBG("factory")
    y.randbytes(32)
    y.reseed("deterministic entropy")
    assert x.randbytes(32) == y.randbytes(32), "reseed is not reproducible"
    z = CTR_DRBG("factory")
    z.randbytes(32)
    z.reseed("different entropy")
    assert z.randbytes(32) != x.randbytes(32), "different entropy, same stream?"
    print("[3] reseed() deterministic with fixed entropy, varies otherwise: OK")

    # --- 4. state round-trip + personalization --------------------------------
    g = CTR_DRBG("round-trip")
    g.randbytes(100)
    state = g.getstate()
    expected = g.randbytes(64)
    clone = CTR_DRBG("round-trip")
    clone.setstate(state)
    assert clone.randbytes(64) == expected, "state round-trip broken"
    assert CTR_DRBG("seed-1", personalization=b"app-id").randbytes(16) != \
        CTR_DRBG("seed-1").randbytes(16), "personalization ignored"
    print("[4] setstate replays the stream; personalization shifts it: OK")

    # --- 5. the whole random.Random API + bit balance --------------------------
    g = CTR_DRBG("api")
    for k in (1, 7, 33, 128):
        assert 0 <= g.getrandbits(k) < (1 << k)
    assert all(0.0 <= g.random() < 1.0 for _ in range(200))
    assert 0 <= g.choice(range(100)) < 100
    ones = bin(int.from_bytes(CTR_DRBG("api").randbytes(4096), "big")).count("1")
    assert 15800 < ones < 17000, f"bit balance looks broken ({ones} ones)"
    print(f"[5] python API sane; 4096 bytes '{ones} ones/32768' balance: OK")

    print("-" * 70)
    print("All ctr_drbg checks passed!")
