"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.csprng.os_random
Description:
The OS-level CSPRNGs -- the sources you should actually use -- behind the
full ``random.Random`` API, behaving like ``random.SystemRandom``: live
entropy, seeding is a no-op, and ``getstate()``/``setstate()`` raise
``NotImplementedError`` (there is no restorable state; that is the
point).

* :class:`SecretsRandom` -- the ``secrets`` module, plus its
  ``token_bytes``/``token_hex``/``token_urlsafe`` helpers.
* :class:`OSURandom` -- plain ``os.urandom``, the always-there baseline.
* :class:`GetRandomRandom` -- Linux ``getrandom(2)`` with
  ``GRND_NONBLOCK`` (ctypes ``libc.getrandom`` fallback, then
  ``os.urandom``: the very same kernel pool, only the syscall differs).
* :class:`BCryptGenRandomRandom` -- Windows ``BCryptGenRandom`` via
  ctypes (``bcrypt.dll``, ``BCRYPT_USE_SYSTEM_PREFERRED_RNG``).
* :class:`SecRandomCopyBytesRandom` -- Apple ``SecRandomCopyBytes``
  (``kSecRandomDefault``) via ctypes against ``libSystem.B.dylib``.

The ctypes ones fall back gracefully to ``os.urandom`` when the native
API is not reachable on the running platform.

Run this module to execute its assert-based self-checks::

    py -3 -m multirandom.csprng.os_random
"""
from __future__ import annotations

import ctypes
import os
import random
import secrets
import sys


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


OS_GENERATORS = [
    SecretsRandom, OSURandom, GetRandomRandom,
    BCryptGenRandomRandom, SecRandomCopyBytesRandom,
]


if __name__ == "__main__":
    print("=" * 70)
    print("os_random - the OS-level CSPRNGs self-check battery")
    print("=" * 70)

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
        try:
            g.setstate(())
        except NotImplementedError:
            pass
        else:
            raise AssertionError(f"{cls.__name__} must not pretend to be restorable")
        g.seed("anything")             # a no-op, not an error
        print(f"  {cls.__name__}: OK (source = {cls.source_name})")

    # --- SecretsRandom's secrets-module extras ---------------------------------
    s = SecretsRandom()
    assert len(s.token_bytes(16)) == 16
    assert len(s.token_hex(16)) == 32 and all(
        c in "0123456789abcdef" for c in s.token_hex(16))
    assert len(s.token_urlsafe(16)) >= 16
    print("SecretsRandom token_bytes/token_hex/token_urlsafe: OK")

    print("-" * 70)
    print("All os_random checks passed!")
