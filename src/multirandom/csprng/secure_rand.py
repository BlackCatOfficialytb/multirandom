"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.csprng.secure_rand
Description:
Cryptographic random generators ("csprng").

Three families live in this module:

1. OS-level CSPRNGs - the sources you should actually use:
   :class:`SecretsRandom` (the ``secrets`` module), :class:`OSURandom`
   (``os.urandom``), :class:`GetRandomRandom` (Linux ``getrandom(2)``),
   :class:`BCryptGenRandomRandom` (Windows ``BCryptGenRandom``) and
   :class:`SecRandomCopyBytesRandom` (Apple ``SecRandomCopyBytes``).  The
   ctypes ones fall back gracefully to ``os.urandom`` (the very same kernel
   entropy pool) when the native API is not reachable on the running platform.

2. NIST SP 800-90A DRBGs: :class:`CTR_DRBG` (AES-128), :class:`HMAC_DRBG`
   and :class:`Hash_DRBG` (SHA-256) - plus the infamous *backdoored*
   :class:`Dual_EC_DRBG`, kept deliberately: it warns loudly and shows how
   its backdoor is exploited with :meth:`Dual_EC_DRBG.reveal`.

3. Stream/accumulator designs: :class:`ChaCha20DRBG`, :class:`Salsa20DRBG`,
   :class:`FortunaRandom` and its legacy predecessor :class:`YarrowRandom`,
   plus :class:`ISAACRandom` (Bob Jenkins' ISAAC, transcribed from the
   author's ``readable.c``).

Every DRBG class is a ``random.Random`` subclass, so ``.random()``,
``.randint()``, ``.choice()``, ``.shuffle()`` ... all work on top of the
cryptographic core.  Everything without a restorable state (the OS-level
sources) behaves like ``random.SystemRandom``: seeding is a no-op and
``getstate()``/``setstate()`` raise ``NotImplementedError``.

Unsecure- or backdoor-related warnings here are governed by one global
switch in the package root::

    import multirandom
    multirandom.ignore_unsecure_prng_warning_do_not_set_to_true_unless_you_know_how_risky_it_is = True

``False`` (the default) sends those warnings to the console; ``True``
silences them.

Run this module to execute its assert-based self-checks::

    py -3 -m multirandom.csprng.secure_rand
"""
from __future__ import annotations

import ctypes
import hashlib
import hmac
import os
import random
import secrets
import struct
import sys
import warnings

try:
    from .. import _warn_unsecure            # governed by the global warning flag
except ImportError:                          # running as a plain script
    def _warn_unsecure(message, stacklevel=3):
        warnings.warn(message, stacklevel=stacklevel)


# ---------------------------------------------------------------------------
# A miniature AES (encryption only), used by CTR_DRBG / Fortuna / Yarrow
# ---------------------------------------------------------------------------

def _gmul(a, b):
    """Multiply in GF(2^8) mod x^8 + x^4 + x^3 + x + 1 (the AES polynomial)."""
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
    return r


def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _make_sbox():
    """Build the AES S-box from its definition: multiplicative inverse in
    GF(2^8) followed by the affine map s^(s<<<1)^(s<<<2)^(s<<<3)^(s<<<4)^(63).
    Constructing it (instead of typing in the table) makes transcription
    mistakes impossible; the FIPS-197 known-answer test in ``__main__`` then
    confirms the result."""
    sbox = [0] * 256
    for x in range(256):
        inv = 0
        if x:
            for y in range(1, 256):
                if _gmul(x, y) == 1:
                    inv = y
                    break
        sbox[x] = (inv ^ _rotl8(inv, 1) ^ _rotl8(inv, 2)
                   ^ _rotl8(inv, 3) ^ _rotl8(inv, 4) ^ 0x63) & 0xFF
    return sbox


_SBOX = _make_sbox()


class _Aes:
    """Self-contained AES encryptor (128/192/256-bit keys, 16-byte blocks),
    plus a CTR keystream helper.  Written for clarity, not speed."""

    def __init__(self, key):
        key = bytes(key)
        nk = len(key) // 4
        try:
            rounds = {4: 10, 6: 12, 8: 14}[nk]
        except KeyError:
            raise ValueError("AES key must be 16, 24 or 32 bytes") from None
        rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
                0x6C, 0xD8, 0xAB, 0x4D]
        w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        i = nk
        while i < 4 * (rounds + 1):
            t = list(w[i - 1])
            if i % nk == 0:                       # RotWord + SubWord + Rcon
                t = [_SBOX[t[1]], _SBOX[t[2]], _SBOX[t[3]], _SBOX[t[0]]]
                t[0] ^= rcon[i // nk - 1]
            elif nk > 6 and i % nk == 4:          # extra SubWord for AES-256
                t = [_SBOX[b] for b in t]
            w.append([w[i - nk][j] ^ t[j] for j in range(4)])
            i += 1
        self.rounds = rounds
        self._rk = [bytes(b for word in w[4 * r:4 * r + 4] for b in word)
                    for r in range(rounds + 1)]

    def encrypt_block(self, block):
        block = bytes(block)
        if len(block) != 16:
            raise ValueError("AES blocks are 16 bytes")
        st = list(block)
        rk = self._rk
        for i, b in enumerate(rk[0]):             # AddRoundKey(0)
            st[i] ^= b
        for rnd in range(1, self.rounds):
            st = [_SBOX[b] for b in st]           # SubBytes
            # ShiftRows: out[4c+r] = old[4*((c+r) mod 4)+r]
            st = [st[4 * ((i // 4 + i % 4) % 4) + i % 4] for i in range(16)]
            out = [0] * 16                        # MixColumns
            for c in range(4):
                s0, s1, s2, s3 = st[4 * c:4 * c + 4]
                out[4 * c + 0] = _gmul(s0, 2) ^ _gmul(s1, 3) ^ s2 ^ s3
                out[4 * c + 1] = s0 ^ _gmul(s1, 2) ^ _gmul(s2, 3) ^ s3
                out[4 * c + 2] = s0 ^ s1 ^ _gmul(s2, 2) ^ _gmul(s3, 3)
                out[4 * c + 3] = _gmul(s0, 3) ^ s1 ^ s2 ^ _gmul(s3, 2)
            st = out
            for i, b in enumerate(rk[rnd]):       # AddRoundKey
                st[i] ^= b
        st = [_SBOX[b] for b in st]               # final round: no MixColumns
        st = [st[4 * ((i // 4 + i % 4) % 4) + i % 4] for i in range(16)]
        for i, b in enumerate(rk[self.rounds]):
            st[i] ^= b
        return bytes(st)

    def ctr(self, counter, n):
        """`n` bytes of AES-CTR keystream for a 128-bit big-endian counter."""
        out = bytearray()
        while len(out) < n:
            out += self.encrypt_block(counter.to_bytes(16, "big"))
            counter = (counter + 1) % (1 << 128)
        return bytes(out[:n])


# ---------------------------------------------------------------------------
# OS-level CSPRNGs
# ---------------------------------------------------------------------------

class _OSRandom(random.Random):
    """Base class for non-deterministic OS sources: behaves like
    ``random.SystemRandom`` - live entropy, no seeding, no restorable state."""

    source_name = "operating system"

    def __init__(self):
        self.gauss_next = None

    def seed(self, a=None, version=2):
        pass  # OS entropy exists whether you like it or not

    def getstate(self):
        raise NotImplementedError(
            f"{type(self).__name__} draws live OS entropy and cannot be restored")

    def setstate(self, state):
        raise NotImplementedError(
            f"{type(self).__name__} draws live OS entropy and cannot be restored")

    def _urandom_bytes(self, n):
        raise NotImplementedError

    def getrandbytes(self, n):
        """Raw bytes from the underlying OS source."""
        return self._urandom_bytes(n)

    def randbytes(self, n):
        return self._urandom_bytes(n)

    def getrandbits(self, k):
        if k < 0:
            raise ValueError("number of bits must be non-negative")
        if k == 0:
            return 0
        nb = (k + 7) // 8
        return int.from_bytes(self._urandom_bytes(nb), "big") >> (nb * 8 - k)

    def random(self):
        return self.getrandbits(53) / (1 << 53)


class OSURandom(_OSRandom):
    """``random.Random`` API over plain ``os.urandom`` - the always-there baseline."""
    source_name = "os.urandom"

    def _urandom_bytes(self, n):
        return os.urandom(n)


class SecretsRandom(_OSRandom):
    """``random.Random`` API over the ``secrets`` module (itself ``os.urandom``
    based), plus that module's ``token_`` helpers."""
    source_name = "secrets"

    def _urandom_bytes(self, n):
        return secrets.token_bytes(n)

    def token_bytes(self, n=32):
        return secrets.token_bytes(n)

    def token_hex(self, n=32):
        return secrets.token_hex(n)

    def token_urlsafe(self, n=32):
        return secrets.token_urlsafe(n)


class GetRandomRandom(_OSRandom):
    """Linux ``getrandom(2)``: the syscall flavour of ``/dev/urandom`` used
    with ``GRND_NONBLOCK`` so it never stalls a fully seeded pool.  If
    Python's ``os.getrandom`` is absent (or the formal syscall fails), it
    goes through ctypes ``libc.getrandom``, and as a last resort falls back
    to ``os.urandom`` - identical pool, only the syscall differs."""
    source_name = "Linux getrandom"

    _libc = None
    _libc_tried = False

    def _urandom_bytes(self, n):
        try:
            data = os.getrandom(n, flags=os.GRND_NONBLOCK)
            if len(data) == n:
                return data
        except (AttributeError, OSError):
            pass
        if GetRandomRandom._libc is None and not GetRandomRandom._libc_tried:
            GetRandomRandom._libc_tried = True
            try:
                GetRandomRandom._libc = ctypes.CDLL(None)  # Unix: the main program
            except (OSError, AttributeError, TypeError):
                GetRandomRandom._libc = False  # e.g. Windows: fall back below
        if GetRandomRandom._libc:
            buf = ctypes.create_string_buffer(n)
            try:
                got = GetRandomRandom._libc.getrandom(buf, ctypes.c_size_t(n), 0)
            except AttributeError:
                got = None
            if got == n:
                return buf.raw
        return os.urandom(n)  # same kernel pool, portable path


class BCryptGenRandomRandom(_OSRandom):
    """Windows ``BCryptGenRandom`` via ctypes (``bcrypt.dll``) with
    ``BCRYPT_USE_SYSTEM_PREFERRED_RNG``.  On any other platform - or if
    bcrypt.dll is unavailable - it falls back to ``os.urandom``."""
    source_name = "Windows BCryptGenRandom"

    def _urandom_bytes(self, n):
        if sys.platform == "win32":
            try:
                buf = ctypes.create_string_buffer(n)
                status = ctypes.windll.bcrypt.BCryptGenRandom(None, buf, n, 2)
                if status == 0:  # STATUS_SUCCESS
                    return buf.raw
            except (OSError, AttributeError):
                pass
        return os.urandom(n)


class SecRandomCopyBytesRandom(_OSRandom):
    """Apple ``SecRandomCopyBytes`` (``kSecRandomDefault``) via ctypes against
    ``libSystem.B.dylib``.  Falls back to ``os.urandom`` elsewhere."""
    source_name = "Apple SecRandomCopyBytes"

    _lib = None

    def _urandom_bytes(self, n):
        if sys.platform == "darwin":
            lib = SecRandomCopyBytesRandom._lib
            if lib is None:
                try:
                    lib = SecRandomCopyBytesRandom._lib = ctypes.CDLL(
                        "/usr/lib/libSystem.B.dylib")
                except (OSError, AttributeError):
                    SecRandomCopyBytesRandom._lib = False
                    lib = False
            if lib:
                buf = ctypes.create_string_buffer(n)
                if lib.SecRandomCopyBytes(0, ctypes.c_size_t(n), buf) == 0:
                    return buf.raw
        return os.urandom(n)


# ---------------------------------------------------------------------------
# Seedable DRBG base (a deterministic CSPRNG core behind the full random API)
# ---------------------------------------------------------------------------

class _DrbgBase(random.Random):
    """Common plumbing for the seedable cryptographic generators: full
    ``random.Random`` API, deterministic from an explicit seed, live OS
    entropy when you leave it to chance and pass ``None``."""

    def __init__(self, seed=None, personalization=b""):
        self.gauss_next = None
        self._personalization = bytes(personalization)
        self.seed(seed)

    def _seed_material(self, a):
        if a is None:
            a = os.urandom(48)
        a = a if isinstance(a, (bytes, bytearray)) else str(a).encode()
        a = bytes(a)
        if self._personalization:
            a += self._personalization
        return a

    def randbytes(self, n):
        return self._bytes(n)

    def getrandbytes(self, n):
        """Raw output of the DRBG (alias mirroring the other modules here)."""
        return self._bytes(n)

    def getrandbits(self, k):
        if k < 0:
            raise ValueError("number of bits must be non-negative")
        if k == 0:
            return 0
        nb = (k + 7) // 8
        return int.from_bytes(self._bytes(nb), "big") >> (nb * 8 - k)

    def random(self):
        # 53 significant bits, same resolution as random.Random.random().
        return (int.from_bytes(self._bytes(8), "big") >> 11) / (1 << 53)

    def _bytes(self, n):
        out = bytearray()
        while len(out) < n:
            out += self._block()
        return bytes(out[:n])

    def _block(self):
        raise NotImplementedError


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


class HMAC_DRBG(_DrbgBase):
    """NIST SP 800-90A HMAC_DRBG (§10.1.2) with SHA-256."""

    def seed(self, a=None, version=2):
        self._k = b"\x00" * 32
        self._v = b"\x01" * 32
        self._reseed_counter = 0
        self._update(self._seed_material(a))
        self._reseed_counter = 1

    def _mac(self, data):
        return hmac.new(self._k, data, "sha256").digest()

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


# ---------------------------------------------------------------------------
# Elliptic-curve plumbing for the backdoored DRBG
# ---------------------------------------------------------------------------

# NIST P-256 ("secp256r1") domain parameters.
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


# ---------------------------------------------------------------------------
# Stream-drums: ChaCha20 and Salsa20 counter-mode DRBGs
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Pool-based accumulators: Fortuna, and its legacy predecessor Yarrow
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# ISAAC (Bob Jenkins, 1996), transcribed faithfully from readable.c
# ---------------------------------------------------------------------------

def _isaac_mix8(a, b, c, d, e, f, g, h):
    """Jenkins' 8-word mix, used by randinit().  All mod 2^32."""
    M = 0xFFFFFFFF
    a = a ^ ((b << 11) & M); d = (d + a) & M; b = (b + c) & M
    b = b ^ (c >> 2);        e = (e + b) & M; c = (c + d) & M
    c = c ^ ((d << 8) & M);  f = (f + c) & M; d = (d + e) & M
    d = d ^ (e >> 16);       g = (g + d) & M; e = (e + f) & M
    e = e ^ ((f << 10) & M); h = (h + e) & M; f = (f + g) & M
    f = f ^ (g >> 4);        a = (a + f) & M; g = (g + h) & M
    g = g ^ ((h << 8) & M);  b = (b + g) & M; h = (h + a) & M
    h = h ^ (a >> 9);        c = (c + h) & M; a = (a + b) & M
    return a, b, c, d, e, f, g, h


class ISAACRandom(_DrbgBase):
    """Bob Jenkins' ISAAC (Indirection, Shift, Accumulate, Add, Count) as
    written in the author's ``readable.c``: separate state (``mm``) and
    output (``randrsl``) arrays, indirect indices at bits 2..9 (x) and
    10..17 (y), shift sequence 13/6/2/16, a once-per-block counter, and an
    8288-bit internal state.

    Jenkins never published an official seeding routine ("the encryption of
    the seed") beyond ``randinit``; this library feeds the seed into 256
    little-endian words first (like the x86 reference), zero-padded with
    SHA-256, then runs his ``randinit(flag=1)`` verbatim."""
    _SIZE = 256
    _MASK = 0xFFFFFFFF

    def seed(self, a=None, version=2):
        material = self._seed_material(a)
        blob = bytearray()
        i = 0
        while len(blob) < 1024:
            blob += hashlib.sha256(material + i.to_bytes(4, "big")).digest()
            i += 1
        self._rsl = list(struct.unpack("<256I", bytes(blob[:1024])))
        self._randinit()

    def _randinit(self):
        """randinit(flag=1) from readable.c: scramble, two mixing passes over
        the seed, then one isaac() to load the first results block."""
        rsl = self._rsl
        self._aa = self._bb = self._cc = 0
        self._mm = [0] * self._SIZE
        a = b = c = d = e = f = g = h = 0x9E3779B9   # the golden ratio
        for _ in range(4):
            a, b, c, d, e, f, g, h = _isaac_mix8(a, b, c, d, e, f, g, h)
        for i in range(0, 256, 8):                  # fill mm[] with the seed
            a = (a + rsl[i]) & self._MASK
            b = (b + rsl[i + 1]) & self._MASK
            c = (c + rsl[i + 2]) & self._MASK
            d = (d + rsl[i + 3]) & self._MASK
            e = (e + rsl[i + 4]) & self._MASK
            f = (f + rsl[i + 5]) & self._MASK
            g = (g + rsl[i + 6]) & self._MASK
            h = (h + rsl[i + 7]) & self._MASK
            a, b, c, d, e, f, g, h = _isaac_mix8(a, b, c, d, e, f, g, h)
            self._mm[i:i + 8] = [a, b, c, d, e, f, g, h]
        for i in range(0, 256, 8):                  # second pass: seed reaches all of mm
            a = (a + self._mm[i]) & self._MASK
            b = (b + self._mm[i + 1]) & self._MASK
            c = (c + self._mm[i + 2]) & self._MASK
            d = (d + self._mm[i + 3]) & self._MASK
            e = (e + self._mm[i + 4]) & self._MASK
            f = (f + self._mm[i + 5]) & self._MASK
            g = (g + self._mm[i + 6]) & self._MASK
            h = (h + self._mm[i + 7]) & self._MASK
            a, b, c, d, e, f, g, h = _isaac_mix8(a, b, c, d, e, f, g, h)
            self._mm[i:i + 8] = [a, b, c, d, e, f, g, h]
        self._isaac()                               # first results block is ready
        self._pos = 0

    def _isaac(self):
        """One isaac() pass: advances aa/bb/cc, refills mm, and fills the
        current randrsl (256 fresh 32-bit results)."""
        mm = self._mm
        rsl = self._rsl
        M = self._MASK
        a = self._aa
        c = self._cc = (self._cc + 1) & M
        b = (self._bb + c) & M
        for i in range(256):
            x = mm[i]
            m4 = i & 3
            if m4 == 0:
                a = a ^ ((a << 13) & M)
            elif m4 == 1:
                a = a ^ (a >> 6)
            elif m4 == 2:
                a = a ^ ((a << 2) & M)
            else:
                a = a ^ (a >> 16)
            a = (mm[(i + 128) % 256] + a) & M
            mm[i] = y = (mm[(x >> 2) % 256] + a + b) & M
            rsl[i] = b = (mm[(y >> 10) % 256] + x) & M
        self._aa = a
        self._bb = b

    def _word(self):
        """Next 32-bit result; refills the 256-word output block when dry."""
        pos = self._pos
        if pos == 256:
            self._isaac()
            pos = 0
        self._pos = pos + 1
        return self._rsl[pos]

    def _block(self):
        """A full output block: 256 results, little-endian bytes (the format
        of the C reference's randrsl on x86)."""
        return struct.pack("<256I", *[self._word() for _ in range(256)])

    def getstate(self):
        return (self._aa, self._bb, self._cc, tuple(self._mm),
                tuple(self._rsl), self._pos)

    def setstate(self, state):
        self._aa, self._bb, self._cc, mm, rsl, self._pos = state
        self._mm = list(mm)
        self._rsl = list(rsl)


# ---------------------------------------------------------------------------
# Public lists
# ---------------------------------------------------------------------------

DRBG_GENERATORS = [
    CTR_DRBG, HMAC_DRBG, Hash_DRBG, Dual_EC_DRBG,
    ChaCha20DRBG, Salsa20DRBG, FortunaRandom, YarrowRandom, ISAACRandom,
]

OS_GENERATORS = [
    SecretsRandom, OSURandom, GetRandomRandom,
    BCryptGenRandomRandom, SecRandomCopyBytesRandom,
]

__all__ = [
    "SecretsRandom", "OSURandom", "GetRandomRandom",
    "BCryptGenRandomRandom", "SecRandomCopyBytesRandom",
    "CTR_DRBG", "HMAC_DRBG", "Hash_DRBG", "Dual_EC_DRBG",
    "ChaCha20DRBG", "Salsa20DRBG", "FortunaRandom", "YarrowRandom", "ISAACRandom",
    "DRBG_GENERATORS", "OS_GENERATORS",
]


# ---------------------------------------------------------------------------
# Self-checks: run with `py -3 -m multirandom.csprng.secure_rand`
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # --- AES known-answer tests (FIPS-197, keys 000102..., plaintext 001122...) ---
    fips_pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert _Aes(bytes(range(16))).encrypt_block(fips_pt) \
        == bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"), "AES-128 KAT failed"
    assert _Aes(bytes(range(24))).encrypt_block(fips_pt) \
        == bytes.fromhex("dda97ca4864cdfe06eaf70a0ec0d7191"), "AES-192 KAT failed"
    assert _Aes(bytes(range(32))).encrypt_block(fips_pt) \
        == bytes.fromhex("8ea2b7ca516745bfeafc49904b496089"), "AES-256 KAT failed"
    print("AES 128/192/256 known-answer tests: OK")

    # --- ISAAC reference check: an all-zero state after ten isaac() calls ---
    # gives aa=d4d3f473, bb=902c0691, cc=0000000a (Jenkins, "ISAAC and RC4", 1996).
    z = ISAACRandom.__new__(ISAACRandom)
    z._aa = z._bb = z._cc = 0
    z._rsl = [0] * 256
    z._pos = 0
    z._mm = [0] * 256
    for _ in range(10):
        z._isaac()
    assert z._aa == 0xD4D3F473, f"ISAAC aa mismatch: {z._aa:08x}"
    assert z._bb == 0x902C0691, f"ISAAC bb mismatch: {z._bb:08x}"
    assert z._cc == 10, f"ISAAC cc mismatch: {z._cc}"
    print("ISAAC reference state after ten zero-state calls: OK")

    # --- P-256 domain sanity: G on the curve, Q = d*P on the curve, n*G = O ---
    p256p, p256a, p256b = _P256_P, _P256_A, _P256_B
    assert (_P256_GY * _P256_GY - (_P256_GX ** 3 + p256a * _P256_GX + p256b)) % p256p == 0, \
        "the base point is not on the curve (P-256 parameters look wrong)"
    qx, qy = Dual_EC_DRBG._q_point
    assert (qy * qy - (qx ** 3 + p256a * qx + p256b)) % p256p == 0, \
        "Q = d*P is not on the curve (the backdoor pair is broken)"
    neg_g = _ec_mul_point(_P256_N - 1, _P256_GX, _P256_GY, p256p, p256a)
    assert neg_g is not None and neg_g[0] == _P256_GX, \
        "(n-1)*G != -G: scalar multiplication or curve order is off"
    print("P-256 curve/scalar sanity: OK")

    # --- the global unsecure-warning flag ---
    try:
        import multirandom
    except ImportError:
        pass  # running as a plain script: the fallback shim has no flag
    else:
        flag_name = ("ignore_unsecure_prng_warning_do_not_set_to_true_unless_"
                     "you_know_how_risky_it_is")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            multirandom._warn_unsecure("flag check: shown by default")
            setattr(multirandom, flag_name, True)
            multirandom._warn_unsecure("flag check: ignored when True")
            setattr(multirandom, flag_name, False)
        shown = [str(w.message) for w in caught]
        assert any("shown by default" in m for m in shown), \
            "the global flag failed: warnings must show by default"
        assert not any("ignored when True" in m for m in shown), \
            "the global flag failed: setting it to True must silence warnings"
        print("global warning flag: False warns, True silences: OK")

    # --- the seedable DRBG battery ---
    for cls in DRBG_GENERATORS:
        a = cls("seed-1").randbytes(32)
        b = cls("seed-1").randbytes(32)
        assert a == b, f"{cls.__name__} is not deterministic for a fixed seed"
        assert a != cls("seed-2").randbytes(32), f"{cls.__name__} ignores the seed"
        g = cls("seed-1")
        g.randbytes(16)
        state = g.getstate()
        expected = g.randbytes(8)
        clone = cls("seed-1")
        clone.setstate(state)
        assert clone.randbytes(8) == expected, f"{cls.__name__} state round-trip broken"
        for k in (1, 7, 33, 128):
            assert 0 <= g.getrandbits(k) < (1 << k), \
                f"{cls.__name__} getrandbits({k}) out of range"
        assert all(0.0 <= g.random() < 1.0 for _ in range(200))
        assert 0 <= g.choice(range(100)) < 100
        ones = bin(int.from_bytes(cls("seed-1").randbytes(8192), "big")).count("1")
        assert 31488 < ones < 34048, \
            f"{cls.__name__} bit balance looks broken ({ones} ones out of 65536)"
        if cls is Dual_EC_DRBG:
            print(f"{cls.__name__}: OK (standard 16-bit truncation; live demo below)")
        else:
            print(f"{cls.__name__}: OK")

    # --- Dual_EC_DRBG specifics (small truncation so the demo stays snappy) ---
    a = Dual_EC_DRBG("seed-1", truncate_bits=8).randbytes(31)
    assert a == Dual_EC_DRBG("seed-1", truncate_bits=8).randbytes(31)
    assert a != Dual_EC_DRBG("seed-2", truncate_bits=8).randbytes(31)
    g = Dual_EC_DRBG("seed-1", truncate_bits=8)
    g.randbytes(31)
    state = g.getstate()
    expected = g.randbytes(31)
    clone = Dual_EC_DRBG("seed-1", truncate_bits=8)
    clone.setstate(state)
    assert clone.randbytes(31) == expected, "Dual_EC_DRBG state round-trip broken"
    for k in (1, 33):
        assert 0 <= g.getrandbits(k) < (1 << k)
    ones = bin(int.from_bytes(
        Dual_EC_DRBG("seed-1", truncate_bits=8).randbytes(124), "big")).count("1")
    assert 400 <= ones <= 600, \
        f"Dual_EC_DRBG bit balance looks broken ({ones} ones out of 992)"
    print("Dual_EC_DRBG: OK (determinism, sensitivity, state round-trip)")

    # --- THE BACKDOOR, LIVE: one output block + the secret d -> full prediction ---
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
    print("Dual_EC_DRBG backdoor reversed from one block: OK (Q = d*P did what NSA built it for)")

    # --- the OS-level sources ---
    for cls in OS_GENERATORS:
        g = cls()
        r1 = g.randbytes(32)
        r2 = g.randbytes(32)
        assert r1 != r2, f"{cls.__name__} repeated the exact same 32 OS bytes (impossible)"
        for k in (1, 7, 64):
            assert 0 <= g.getrandbits(k) < (1 << k), \
                f"{cls.__name__} getrandbits({k}) out of range"
        assert 0.0 <= g.random() < 1.0
        assert 0 <= g.choice(range(50)) < 50
        ones = bin(int.from_bytes(g.randbytes(4096), "big")).count("1")
        assert 15100 < ones < 17700, \
            f"{cls.__name__} bit balance looks broken ({ones} ones)"
        try:
            g.getstate()
        except NotImplementedError:
            pass
        else:
            raise AssertionError(f"{cls.__name__} must not pretend to be restorable")
        print(f"{cls.__name__}: OK (source = {cls.source_name})")

    print("All cryptographic generator checks passed!")
