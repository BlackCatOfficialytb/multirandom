"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.csprng.hmac_drbg
Description:
NIST SP 800-90A ``HMAC_DRBG`` (§10.1.2) with SHA-256: the HMAC/CTR shape
where the 512-bit seed state ``(K, V)`` is reworked through two HMAC masks
keyed by ``K`` per update, and generate steps are plain ``V = HMAC(K, V)``
with one per-request update at the end (§10.1.2.5).  It is the DRBG used
by plenty of real-world software (OpenSSL, the Web Crypto ...
implementations frequently cast Hash_DRBG aside in favour of it).

Every DRBG here is a ``random.Random`` subclass, so ``.random()``,
``.randint()``, ``.choice()``, ``.shuffle()`` ... all work on top of the
cryptographic core.  Deterministic from an explicit seed; live OS entropy
when you pass ``None``.  ``reseed()`` accepts fresh entropy at any moment.

Run this module to execute its assert-based self-checks::

    py -3 -m multirandom.csprng.hmac_drbg
"""
from __future__ import annotations

import hmac as _hmac

try:
    from ._drbg_base import _DrbgBase
except ImportError:                          # running as a plain script
    from _drbg_base import _DrbgBase


class HMAC_DRBG(_DrbgBase):
    """NIST SP 800-90A HMAC_DRBG (§10.1.2) with SHA-256."""

    def seed(self, a=None, version=2):
        self._k = b"\x00" * 32
        self._v = b"\x01" * 32
        self._reseed_counter = 0
        self._update(self._seed_material(a))
        self._reseed_counter = 1

    def _mac(self, data):
        return _hmac.new(self._k, data, "sha256").digest()

    def _update(self, provided=b""):
        provided = bytes(provided)
        self._k = self._mac(self._v + b"\x00" + provided)
        self._v = self._mac(self._v)
        if provided:
            self._k = self._mac(self._v + b"\x01" + provided)
            self._v = self._mac(self._v)

    def reseed(self, entropy=None, additional=b""):
        self._update(self._seed_material(entropy) + bytes(additional))
        self._reseed_counter = 1

    def _block(self):
        self._v = self._mac(self._v)
        return self._v

    def _bytes(self, n):
        out = bytearray()
        while len(out) < n:
            out += self._block()
        self._update()  # one key/nonce update per generate call (§10.1.2.5)
        return bytes(out[:n])

    def getstate(self):
        return (self._k, self._v, self._reseed_counter)

    def setstate(self, state):
        self._k, self._v, self._reseed_counter = state


if __name__ == "__main__":
    print("=" * 70)
    print("hmac_drbg - NIST SP 800-90A HMAC_DRBG self-check battery")
    print("=" * 70)

    # --- 1. the reference stream (seed-1), pinned -----------------------------
    pin = "055472a2f4beeaa9e0dceaad99c5b837e560face6b55b7362445511ff5a01220"
    a = HMAC_DRBG("seed-1").randbytes(32)
    assert a.hex() == pin, f"HMAC_DRBG('seed-1') drifted: {a.hex()}"
    b = HMAC_DRBG("seed-1").randbytes(32)
    assert a == b, "not deterministic for a fixed seed"
    assert a != HMAC_DRBG("seed-2").randbytes(32), "ignores the seed"
    print("[1] HMAC_DRBG('seed-1') first 32 bytes match the pinned stream: OK")

    # --- 2. the §10.1.2 mechanics: update() masks both halves of the state ----
    g = HMAC_DRBG("mechanics")
    g.randbytes(32)
    k1, v1 = g._k, g._v
    out = g.randbytes(32)
    assert g._k != k1 and g._v != v1, "the per-generate update did not run"
    # generate is literally V = HMAC(K, V), block by block
    h = HMAC_DRBG("mechanics")
    h.randbytes(32)
    manual = h._mac(h._v) + h._mac(h._mac(h._v))
    assert h.randbytes(64) == manual, "generate != HMAC(K, HMAC(K, V))"
    print("[2] generate is Sec. 10.1.1.4's V = HMAC(K, V); update runs per request: OK")

    # --- 3. reseeding (§10.1.2.4): reproducible with fixed entropy ------------
    x = HMAC_DRBG("factory")
    x.randbytes(32)
    x.reseed("deterministic entropy")
    y = HMAC_DRBG("factory")
    y.randbytes(32)
    y.reseed("deterministic entropy")
    assert x.randbytes(48) == y.randbytes(48), "reseed is not reproducible"
    z = HMAC_DRBG("factory")
    z.randbytes(32)
    z.reseed("different entropy")
    assert z.randbytes(48) != x.randbytes(48), "different entropy, same stream?"
    print("[3] reseed() deterministic with fixed entropy, varies otherwise: OK")

    # --- 4. state round-trip + personalization --------------------------------
    g = HMAC_DRBG("round-trip")
    g.randbytes(100)
    state = g.getstate()
    expected = g.randbytes(64)
    clone = HMAC_DRBG("round-trip")
    clone.setstate(state)
    assert clone.randbytes(64) == expected, "state round-trip broken"
    assert HMAC_DRBG("seed-1", personalization=b"app-id").randbytes(16) != \
        HMAC_DRBG("seed-1").randbytes(16), "personalization ignored"
    print("[4] setstate replays the stream; personalization shifts it: OK")

    # --- 5. the whole random.Random API + bit balance --------------------------
    g = HMAC_DRBG("api")
    for k in (1, 7, 33, 128):
        assert 0 <= g.getrandbits(k) < (1 << k)
    assert all(0.0 <= g.random() < 1.0 for _ in range(200))
    assert 0 <= g.choice(range(100)) < 100
    ones = bin(int.from_bytes(HMAC_DRBG("api").randbytes(4096), "big")).count("1")
    assert 15800 < ones < 17000, f"bit balance looks broken ({ones} ones)"
    print(f"[5] python API sane; 4096 bytes '{ones} ones/32768' balance: OK")

    print("-" * 70)
    print("All hmac_drbg checks passed!")
