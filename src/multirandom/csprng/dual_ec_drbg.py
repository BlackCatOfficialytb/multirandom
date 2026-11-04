"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.csprng.dual_ec_drbg
Description:
The *deliberately backdoored* NIST SP 800-90A DRBG (§10.4, withdrawn from
the standard in 2014): :class:`Dual_EC_DRBG`, reproduced here with its own
backdoored point pair under a fixed demo secret multiplier -- exploit
included -- because a warning you can *demonstrate* is worth three you can
merely print.  Shumow & Ferguson showed the design in 2007; the 2013
Snowden disclosures filled in the rest.  Never use it for real randomness
(the runtime warning says so).

Machine shape: internal state ``s``; each output block is the top
``256 - truncate_bits`` bits of ``x(s*P)``, then the state advances to
``x(s*Q)``.  THE BACKDOOR: whoever picked the public constants ``P`` and
``Q`` with a secret multiplier ``d`` (``Q = d*P``) can undo the truncation
by brute-forcing the deleted low bits and multiplying by ``d`` --
:meth:`Dual_EC_DRBG.reveal` does exactly that, and the battery shows it
live.  The P-256 arithmetic is this module's own Jacobian implementation,
and stays one: no standard crypto library exposes scalar multiplication
without demanding a real key pair, and a backdoor demo needs only the
curve mathematics.

The default ``truncate_bits=16`` matches the standard: recovering the next
state costs about 2**15 scalar multiplications - instant in C, sluggish
in pure Python - so pass ``truncate_bits=8`` to watch the backdoor live
in this module's self-checks.

Every DRBG here is a ``random.Random`` subclass, so ``.random()``,
``.randint()``, ``.choice()``, ``.shuffle()`` ... all work on top of the
cryptographic core.  Deterministic from an explicit seed; live OS entropy
when you pass ``None``.

Unsecure- or backdoor-related warnings here are governed by one global
switch in the package root::

    import multirandom
    multirandom.ignore_unsecure_prng_warning_do_not_set_to_true_unless_you_know_how_risky_it_is

``False`` (the default) sends those warnings to the console; ``True``
silences them.

Run this module to execute its assert-based self-checks::

    py -3 -m multirandom.csprng.dual_ec_drbg
"""
from __future__ import annotations

import hashlib
import os
import warnings

try:
    from ._drbg_base import _DrbgBase, _warn_unsecure
except ImportError:                          # running as a plain script
    from _drbg_base import _DrbgBase, _warn_unsecure


# ---------------------------------------------------------------------------
# Elliptic-curve plumbing for the backdoored DRBG (NIST P-256 / secp256r1)
# ---------------------------------------------------------------------------

_P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
_P256_A = _P256_P - 3
_P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
_P256_GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
_P256_GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
_P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551


def _ec_dbl(X, Y, Z, p, a):
    """Jacobian double; Z == 0 means the point at infinity."""
    if Z == 0 or Y == 0:
        return (1, 1, 0)
    y2 = (Y * Y) % p
    s = (4 * X * y2) % p
    m = (3 * X * X + a * (Z * Z) ** 2) % p
    x3 = (m * m - 2 * s) % p
    y3 = (m * (s - x3) - 8 * y2 * y2) % p
    return (x3, y3, (2 * Y * Z) % p)


def _ec_add(X1, Y1, Z1, X2, Y2, Z2, p):
    """Jacobian add of two *different* points (neither at infinity).  Returns
    None to signal "these are the same affine point - use doubling instead"."""
    if Z1 == 0:
        return (X2, Y2, Z2)
    if Z2 == 0:
        return (X1, Y1, Z1)
    z1 = (Z1 * Z1) % p
    z2 = (Z2 * Z2) % p
    u1 = (X1 * z2) % p
    u2 = (X2 * z1) % p
    s1 = (Y1 * Z2 * z2) % p          # Y1 * Z2^3
    s2 = (Y2 * Z1 * z1) % p          # Y2 * Z1^3
    h = (u2 - u1) % p
    r = (s2 - s1) % p
    if h == 0:
        if r == 0:
            return None              # same point -> double
        return (1, 1, 0)             # negatives -> infinity
    h2 = (h * h) % p
    u1h2 = (u1 * h2) % p
    x3 = (r * r - h2 * h - 2 * u1h2) % p
    y3 = (r * (u1h2 - x3) - s1 * (h * h2)) % p
    return (x3, y3, (h * Z1 * Z2) % p)


def _ec_mul_point(k, x, y, p, a):
    """Affine point k*(x, y) as a (X, Y) tuple -- None for k == 0 (infinity)."""
    k = int(k)
    if k <= 0:
        return None
    rx, ry, rz = 1, 1, 0
    for bit in bin(k)[2:]:
        rx, ry, rz = _ec_dbl(rx, ry, rz, p, a)
        if bit == "1":
            if rz == 0:
                rx, ry, rz = x, y, 1
            else:
                t = _ec_add(rx, ry, rz, x, y, 1, p)
                if t is None:        # r == g -> double instead
                    rx, ry, rz = _ec_dbl(rx, ry, rz, p, a)
                else:
                    rx, ry, rz = t
    if rz == 0:
        return None
    zi = pow(rz, -1, p)
    zi2 = (zi * zi) % p
    return ((rx * zi2) % p, (ry * zi2 * zi) % p)


class Dual_EC_DRBG(_DrbgBase):
    """The *deliberately backdoored* NIST DRBG (SP 800-90A §10.4, withdrawn
    from the standard in 2014).

    Machine shape: internal state ``s``; each output block is the top
    ``256 - truncate_bits`` bits of ``x(s*P)``, then the state advances to
    ``x(s*Q)``.  THE BACKDOOR: whoever picked the public constants P and Q
    with a secret multiplier ``d`` (Q = d*P) can undo the truncation by
    brute-forcing the deleted low bits and multiplying by ``d`` --
    :meth:`reveal` does exactly that.  Shumow & Ferguson showed the design
    in 2007; the 2013 Snowden disclosures filled in the rest.  Reproduced
    here with its own backdoored pair under a fixed secret multiplier,
    exploit included,
    because a warning you can *demonstrate* is worth three you can merely
    print.  Never use it for real randomness (the runtime warning says so).

    The default ``truncate_bits=16`` matches the standard: recovering the
    next state costs about 2**15 scalar multiplications - instant in C,
    sluggish in pure Python - so pass ``truncate_bits=8`` to watch the
    backdoor live in this module's self-checks.
    """

    _p = _P256_P
    _a = _P256_A
    _b = _P256_B
    _gx = _P256_GX
    _gy = _P256_GY
    _n = _P256_N

    # The secret multiplier with which "they" built the backdoor.  A fixed
    # value keeps demo runs reproducible; in the scandal the NSA picked Q
    # once, for everyone, forever.
    _SECRET_D = (int.from_bytes(
        hashlib.sha256(
            b"Dual_EC_DRBG demo secret multiplier (Shumow, Ferguson, 2007)"
        ).digest(), "big") % (_P256_N - 1)) + 1

    # Q = d * P: the backdoored public point (one scalar multiplication at import).
    _q_point = None  # replaced immediately after the class body

    _warned = False

    def __init__(self, seed=None, truncate_bits=16, personalization=b""):
        if not Dual_EC_DRBG._warned:
            Dual_EC_DRBG._warned = True
            _warn_unsecure(
                "Dual_EC_DRBG is deliberately backdoored: whoever knows the secret"
                " multiplier d (Q = d*P) can predict every future output from a"
                " single block. NIST withdrew it in 2014. Use SecretsRandom instead.")
        if not (0 < truncate_bits < 64 and (256 - truncate_bits) % 8 == 0):
            raise ValueError("truncate_bits must leave a whole number of output bytes")
        self.gauss_next = None
        self.truncate_bits = int(truncate_bits)
        self._personalization = bytes(personalization)
        self.seed(seed)

    @classmethod
    def _fresh_nonzero_state(cls):
        """Defensive fallback for the (astronomically improbable) cases where a
        scalar lands on zero or infinity."""
        for _ in range(8):
            s = int.from_bytes(
                hashlib.sha256(os.urandom(32)).digest(), "big") % cls._n
            if s:
                return s
        return 1

    def seed(self, a=None, version=2):
        s = int.from_bytes(
            self._df(self._seed_material(a), 32), "big") % Dual_EC_DRBG._n
        if s == 0:
            s = 1
        pt = _ec_mul_point(s, Dual_EC_DRBG._gx, Dual_EC_DRBG._gy,
                           Dual_EC_DRBG._p, Dual_EC_DRBG._a)
        self._s = pt[0] if pt is not None else self._fresh_nonzero_state()

    def _df(self, material, n):
        """Small Hash_df (§10.3.1) to turn seed material into a scalar."""
        material = bytes(material)
        out = bytearray()
        ctr = 1
        while len(out) < n:
            out += hashlib.sha256(bytes((ctr % 256,)) + material).digest()
            ctr += 1
        return bytes(out[:n])

    def _block(self):
        """One output block: high bits of x(s*P); state advances to x(s*Q)."""
        s = self._s
        if not s:
            s = self._fresh_nonzero_state()
            self._s = s
        p, a = Dual_EC_DRBG._p, Dual_EC_DRBG._a
        pt = _ec_mul_point(s, Dual_EC_DRBG._gx, Dual_EC_DRBG._gy, p, a)   # s*P
        if pt is None:          # s * P hit infinity (probability ~2^-256)
            s = self._fresh_nonzero_state()
            self._s = s
            pt = _ec_mul_point(s, Dual_EC_DRBG._gx, Dual_EC_DRBG._gy, p, a)
        x = pt[0]
        q = Dual_EC_DRBG._q_point
        nq = _ec_mul_point(s, q[0], q[1], p, a)                          # s*Q
        self._s = nq[0] if nq is not None else self._fresh_nonzero_state()
        return (x >> self.truncate_bits).to_bytes(
            (256 - self.truncate_bits) // 8, "big")

    def reveal(self, output, known_next=None, d=None):
        """Exploit the NSA backdoor: turn ONE output block into the NEXT
        internal state (Shumow-Ferguson).  Guess the truncated low bits of
        x(s*P), lift the candidate to a curve point T (which is then +s*P or
        -s*P) and use x(d*T) == x(s*Q): the next full state.  Passing the
        *next* observed block as ``known_next`` verifies the answer (with 16
        deleted bits there are about 2^15 on-curve candidates and exactly
        one matches).  Needs the secret multiplier ``d`` - it defaults to
        this implementation's demo constant; without it the result is just
        arithmetic noise.  Raises RuntimeError if no candidate matches."""
        cls = Dual_EC_DRBG
        d = cls._SECRET_D if d is None else int(d)
        p, a, b = cls._p, cls._a, cls._b
        tb = self.truncate_bits
        hi = int.from_bytes(bytes(output), "big")
        target = None if known_next is None else int.from_bytes(bytes(known_next), "big")
        for guess in range(1 << tb):
            X = (hi << tb) | guess
            y2 = (X * X % p * X + a * X + b) % p
            y = pow(y2, (p + 1) // 4, p)   # p = 3 mod 4: the sqrt always exists
            if (y * y - y2) % p:           # not a valid x-coordinate; keep guessing
                continue
            s_next = _ec_mul_point(d, X, y, p, a)
            if s_next is None:
                continue
            if target is None:
                return s_next[0]           # unverified candidate
            px = _ec_mul_point(s_next[0], cls._gx, cls._gy, p, a)
            if px is not None and (px[0] >> tb) == target:
                return s_next[0]
        raise RuntimeError("Dual_EC reversal failed: no candidate matched the next block")

    def getstate(self):
        return (self._s,)

    def setstate(self, state):
        (self._s,) = state


# Q = d * P for the backdoored pair (computed once at import).
Dual_EC_DRBG._q_point = _ec_mul_point(
    Dual_EC_DRBG._SECRET_D, _P256_GX, _P256_GY, _P256_P, _P256_A)


if __name__ == "__main__":
    print("=" * 70)
    print("dual_ec_drbg - the backdoored DRBG self-check battery")
    print("=" * 70)

    # --- 1. P-256 domain sanity: G on the curve, Q on the curve, n*G = O ------
    p256p, p256a, p256b = _P256_P, _P256_A, _P256_B
    assert (_P256_GY * _P256_GY - (_P256_GX ** 3 + p256a * _P256_GX + p256b)) % p256p == 0, \
        "the base point is not on the curve (P-256 parameters look wrong)"
    qx, qy = Dual_EC_DRBG._q_point
    assert (qy * qy - (qx ** 3 + p256a * qx + p256b)) % p256p == 0, \
        "Q = d*P is not on the curve (the backdoor pair is broken)"
    neg_g = _ec_mul_point(_P256_N - 1, _P256_GX, _P256_GY, p256p, p256a)
    assert neg_g is not None and neg_g[0] == _P256_GX, \
        "(n-1)*G != -G: scalar multiplication or curve order is off"
    print("[1] P-256 curve/scalar sanity (G, Q = d*P on-curve; (n-1)*G = -G): OK")

    # --- 2. the reference stream (seed-1, 8-bit truncation), pinned -----------
    pin = "393ed5b4510bbbc843d70fe9e07cf904228053f4e8ea589ce2d17e1492060704"
    a = Dual_EC_DRBG("seed-1", truncate_bits=8).randbytes(32)
    assert a.hex() == pin, f"Dual_EC_DRBG('seed-1') drifted: {a.hex()}"
    b = Dual_EC_DRBG("seed-1", truncate_bits=8).randbytes(32)
    assert a == b, "not deterministic for a fixed seed"
    assert a != Dual_EC_DRBG("seed-2", truncate_bits=8).randbytes(32)
    g = Dual_EC_DRBG("seed-1", truncate_bits=8)
    g.randbytes(31)
    state = g.getstate()
    expected = g.randbytes(31)
    clone = Dual_EC_DRBG("seed-1", truncate_bits=8)
    clone.setstate(state)
    assert clone.randbytes(31) == expected, "state round-trip broken"
    for k in (1, 33):
        assert 0 <= g.getrandbits(k) < (1 << k)
    ones = bin(int.from_bytes(
        Dual_EC_DRBG("seed-1", truncate_bits=8).randbytes(124), "big")).count("1")
    assert 400 <= ones <= 600, \
        f"bit balance looks broken ({ones} ones out of 992)"
    print("[2] stream pinned; determinism, sensitivity, state round-trip: OK")

    # --- 3. THE BACKDOOR, LIVE: one block + the secret d -> full prediction ---
    victim = Dual_EC_DRBG("demo victim key", truncate_bits=8)
    first = victim.randbytes(31)     # r_0 = high bits of x(s_0 * P)
    second = victim.randbytes(31)    # r_1
    third = victim.randbytes(31)     # r_2
    s1 = victim.reveal(first, known_next=second)   # attack, verified against r_1
    predictor = Dual_EC_DRBG.__new__(Dual_EC_DRBG)
    predictor.gauss_next = None
    predictor.truncate_bits = 8
    predictor._s = s1
    assert predictor.randbytes(31) == second, "backdoor: next block mispredicted"
    assert predictor.randbytes(31) == third, "backdoor: following block mispredicted"
    print("[3] backdoor reversed from ONE block (Q = d*P did what NSA built it for): OK")

    # --- 4. standard truncation still runs (no attack demo - 2^15 EC mults) ---
    g = Dual_EC_DRBG("standard truncation")   # truncate_bits=16 default
    first = g.randbytes(31)
    second = g.randbytes(31)
    assert first != second
    assert len(Dual_EC_DRBG("x").randbytes(31)) == 31
    # 16-bit truncation leaves 30 whole bytes -> the request size consumes
    # a whole number of blocks; a 96-byte request is a clean multi-block ask
    assert g.randbytes(96) is not None
    print("[4] default 16-bit truncation runs (block width 30 bytes + 1 bit): OK")

    print("-" * 70)
    print("All dual_ec_drbg checks passed!")
