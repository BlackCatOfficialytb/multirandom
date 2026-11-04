"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.csprng
Description:
Cryptographically strong randomness ("csprng") -- one module per method:

1. OS-level CSPRNGs - the sources you should actually use
   (:mod:`multirandom.csprng.os_random`): :class:`SecretsRandom` (the
   ``secrets`` module), :class:`OSURandom` (``os.urandom``),
   :class:`GetRandomRandom` (Linux ``getrandom(2)``),
   :class:`BCryptGenRandomRandom` (Windows ``BCryptGenRandom``) and
   :class:`SecRandomCopyBytesRandom` (Apple ``SecRandomCopyBytes``).  The
   ctypes ones fall back gracefully to ``os.urandom`` (the very same kernel
   entropy pool) when the native API is not reachable on the running
   platform.

2. NIST SP 800-90A DRBGs: :class:`CTR_DRBG` (AES-128, via the crypto
   library), :class:`HMAC_DRBG` and :class:`Hash_DRBG` (SHA-256) - plus the
   infamous *backdoored* :class:`Dual_EC_DRBG`, kept deliberately: it warns
   loudly and shows how its backdoor is exploited with
   ``Dual_EC_DRBG.reveal`` (its own module: ``dual_ec_drbg``).

3. Stream/accumulator designs: :class:`ChaCha20DRBG`
   (``chacha20_drbg``), :class:`Salsa20DRBG` (``salsa20_drbg``),
   :class:`FortunaRandom` (``fortuna``) and its legacy predecessor
   :class:`YarrowRandom` (``yarrow``), plus :class:`ISAACRandom`
   (``isaac`` - Bob Jenkins' ISAAC, transcribed from the author's
   ``readable.c``).

Every DRBG class is a ``random.Random`` subclass, so ``.random()``,
``.randint()``, ``.choice()``, ``.shuffle()`` ... all work on top of the
cryptographic core.  Everything without a restorable state (the OS-level
sources) behaves like ``random.SystemRandom``: seeding is a no-op and
``getstate()``/``setstate()`` raise ``NotImplementedError``.

The raw AES used by CTR_DRBG / Fortuna / Yarrow comes from an installed
crypto library (pycryptodome / pycryptodomex, with ``cryptography`` as a
fallback) - see :mod:`multirandom.csprng._aes`; the shared ``random.Random``
plumbing of the seedable DRBGs lives in
:mod:`multirandom.csprng._drbg_base`.

Unsecure- or backdoor-related warnings here are governed by one global
switch in the package root::

    import multirandom
    multirandom.ignore_unsecure_prng_warning_do_not_set_to_true_unless_you_know_how_risky_it_is

``False`` (the default) sends those warnings to the console; ``True``
silences them.
"""
from .os_random import (
    SecretsRandom, OSURandom, GetRandomRandom,
    BCryptGenRandomRandom, SecRandomCopyBytesRandom,
)
from .ctr_drbg import CTR_DRBG
from .hmac_drbg import HMAC_DRBG
from .hash_drbg import Hash_DRBG
from .dual_ec_drbg import Dual_EC_DRBG
from .chacha20_drbg import ChaCha20DRBG
from .salsa20_drbg import Salsa20DRBG
from .fortuna import FortunaRandom
from .yarrow import YarrowRandom
from .isaac import ISAACRandom

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
