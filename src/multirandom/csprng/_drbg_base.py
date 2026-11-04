"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.csprng._drbg_base
Description:
The plumbing every seedable DRBG in ``multirandom.csprng`` builds on:
:class:`_DrbgBase`, a ``random.Random`` subclass that turns an internal
``_block()`` (one chunk of DRBG core output) into the full CPython random
API -- ``random()``, ``getrandbits()``, ``randbytes()``, and everything
downstream (``choice``/``shuffle``/``gauss``...).  Seeded explicitly the
output is deterministic; seeded ``None`` it draws live OS entropy.  This
module used to live inline in ``secure_rand.py``; it stayed here when the
module was split into one file per CSPRNG method.

Unsecure- or backdoor-related warnings are governed by one global switch
in the package root::

    import multirandom
    multirandom.ignore_unsecure_prng_warning_do_not_set_to_true_unless_you_know_how_risky_it_is

``False`` (the default) sends those warnings to the console; ``True``
silences them.

Run this module to execute its assert-based self-checks -- including the
generic seedable-DRBG battery swept over every concrete generator in the
package::

    py -3 -m multirandom.csprng._drbg_base
"""
from __future__ import annotations

import os
import random
import warnings

try:
    from .. import _warn_unsecure            # governed by the global warning flag
except ImportError:                          # running as a plain script
    def _warn_unsecure(message, stacklevel=3):
        # Same contract as the package root's helper: silenced by the global
        # flag even when this module is executed outside the package.
        try:
            import multirandom
            if multirandom.ignore_unsecure_prng_warning_do_not_set_to_true_unless_you_know_how_risky_it_is:
                return
        except (ImportError, AttributeError):
            pass
        warnings.warn(message, stacklevel=stacklevel)


def _rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


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


if __name__ == "__main__":
    # The generic seedable-DRBG battery: swept over every concrete DRBG the
    # package ships.  Behaviour-specific checks (KATs, pool gates, the
    # backdoor demo...) live in each generator's own module battery.
    print("=" * 70)
    print("_drbg_base - generic battery over every seedable DRBG")
    print("=" * 70)

    from multirandom.csprng import DRBG_GENERATORS, Dual_EC_DRBG

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
            print(f"  {cls.__name__}: OK (standard 16-bit truncation; demo in dual_ec_drbg)")
        else:
            print(f"  {cls.__name__}: OK")

    # --- the global unsecure-warning flag ------------------------------------
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

    print("-" * 70)
    print("All _drbg_base checks passed!")
