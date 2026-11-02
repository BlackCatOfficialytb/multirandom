"""Hash-based pseudo-random generators.

Each generator runs a counter through a cryptographic hash: H(seed || counter).
This is the classic counter-mode hash DRBG construction (the same idea as NIST's
Hash_DRBG, without the derivation function or reseeding). It is deterministic and
portable, but it is NOT a replacement for a vetted CSPRNG -- and MD5/SHA-1 are
included only to show why broken hashes must not be used for randomness.
"""
import hashlib
import os
import random

class HashRandom(random.Random):
    """`random.Random` API backed by H(seed || counter) instead of Mersenne Twister.

    Subclasses set `hash_name`; everything else (choice, shuffle, sample, gauss,
    randint, ...) is inherited from `random.Random` and consumes `getrandbits()`.
    """
    hash_name = "sha256"

    def __init__(self, seed=None):
        self.seed(seed)
        self.gauss_next = None

    def seed(self, a=None, version=2):
        if a is None:
            a = os.urandom(32)
        self._seed = a if isinstance(a, bytes) else str(a).encode()
        self._counter = 0

    def _digest(self):
        h = hashlib.new(self.hash_name)
        h.update(self._seed)
        h.update(self._counter.to_bytes(8, "big"))
        self._counter += 1
        return h.digest()

    def _bytes(self, n):
        out = bytearray()
        while len(out) < n:
            out += self._digest()
        return bytes(out[:n])

    def getrandbytes(self, n):
        """Raw hash output; kept for compatibility with the original module."""
        return self._bytes(n)

    def randbytes(self, n):
        return self._bytes(n)

    def getrandbits(self, k):
        if k < 0:
            raise ValueError("number of bits must be non-negative")
        if k == 0:
            return 0
        n = (k + 7) // 8
        return int.from_bytes(self._bytes(n), "big") >> (n * 8 - k)

    def random(self):
        # 53 significant bits, same resolution as random.Random.random().
        return (int.from_bytes(self._bytes(8), "big") >> 11) / (1 << 53)

    def getstate(self):
        return (self._seed, self._counter)

    def setstate(self, state):
        self._seed, self._counter = state

class _XofRandom(HashRandom):
    """Base for extendable-output functions (SHAKE), which need an explicit length."""
    block_size = 64

    def _digest(self):
        h = hashlib.new(self.hash_name)
        h.update(self._seed)
        h.update(self._counter.to_bytes(8, "big"))
        self._counter += 1
        return h.digest(self.block_size)

class MD5Random(HashRandom):
    """Educational only: MD5 is broken, never use it where randomness matters."""
    hash_name = "md5"

class SHA1Random(HashRandom):
    """Educational only: SHA-1 is broken, never use it where randomness matters."""
    hash_name = "sha1"

class SHA224Random(HashRandom):
    hash_name = "sha224"

class SHA256Random(HashRandom):
    hash_name = "sha256"

class SHA384Random(HashRandom):
    hash_name = "sha384"

class SHA512Random(HashRandom):
    hash_name = "sha512"

class SHA3_224Random(HashRandom):
    hash_name = "sha3_224"

class SHA3_256Random(HashRandom):
    hash_name = "sha3_256"

class SHA3_384Random(HashRandom):
    hash_name = "sha3_384"

class SHA3_512Random(HashRandom):
    hash_name = "sha3_512"

class BLAKE2bRandom(HashRandom):
    hash_name = "blake2b"

class BLAKE2sRandom(HashRandom):
    hash_name = "blake2s"

class SHAKE128Random(_XofRandom):
    hash_name = "shake_128"

class SHAKE256Random(_XofRandom):
    hash_name = "shake_256"

HASH_GENERATORS = [
    MD5Random, SHA1Random, SHA224Random, SHA256Random, SHA384Random, SHA512Random,
    SHA3_224Random, SHA3_256Random, SHA3_384Random, SHA3_512Random,
    BLAKE2bRandom, BLAKE2sRandom, SHAKE128Random, SHAKE256Random,
]

if __name__ == "__main__":
    streams = {}
    for cls in HASH_GENERATORS:
        a = cls(42).randbytes(32)
        b = cls(42).randbytes(32)
        c = cls(43).randbytes(32)
        assert a == b, f"{cls.__name__} is not deterministic for a fixed seed"
        assert a != c, f"{cls.__name__} ignores the seed"
        assert len(cls(42).randbytes(17)) == 17, f"{cls.__name__} randbytes length is wrong"
        streams[cls.__name__] = a
        print(f"{cls.__name__}: OK")
    assert len(set(streams.values())) == len(streams), "different hashes produced the same stream"

    # random() must stay in [0, 1); getrandbits(k) must fit in k bits.
    gen = SHA256Random("test")
    assert all(0.0 <= gen.random() < 1.0 for _ in range(1000))
    assert all(gen.getrandbits(k) < (1 << k) for k in (1, 7, 8, 33, 64, 128))

    # Monobit sanity: ~50% of output bits set over 100 KB.
    ones = bin(int.from_bytes(SHA256Random(1).randbytes(100_000), "big")).count("1")
    assert 397_000 < ones < 403_000, f"bit balance looks broken ({ones} ones)"

    # getstate/setstate must round-trip.
    g1 = BLAKE2bRandom(7)
    g1.randbytes(16)
    state = g1.getstate()
    expected = g1.randbytes(8)
    g2 = BLAKE2bRandom(7)
    g2.setstate(state)
    assert g2.randbytes(8) == expected

    print("All hash generator checks passed!")
