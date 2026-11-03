# Cryptographic randomness (`csprng`)

The generators to actually guard things with, plus deliberately broken ones
that teach.

- [`secure_rand`](#secure_rand) — OS-level CSPRNGs, NIST SP 800-90A DRBGs, stream-cipher DRBGs, Fortuna/Yarrow/ISAAC
- [`sha_rand`](#sha_rand) — hash-based counter-mode DRBGs (14 hashes)
- [`original_random`](#original_random) — passthrough wrapper

Everything in this package is a `random.Random` subclass unless noted, so
`.random()`, `.randint()`, `.choice()`, `.shuffle()`, ... all work.

## `secure_rand`

Three sub-families: OS sources, seedable DRBGs, and pool/stream designs.

### OS-level CSPRNGs

Live, non-deterministic kernel entropy. They behave like
`random.SystemRandom`: `seed()` is a no-op and
`getstate()`/`setstate()` raise `NotImplementedError`. The ctypes-backed ones
fall back to `os.urandom` — the very same kernel entropy pool — when the
native API is not reachable on the running platform.

| Class | Source | Works on |
|---|---|---|
| `SecretsRandom` | the `secrets` module | everywhere (adds `token_bytes` / `token_hex` / `token_urlsafe`) |
| `OSURandom` | plain `os.urandom` | everywhere |
| `GetRandomRandom` | Linux `getrandom(2)` syscall (tries `os.getrandom`, then ctypes `libc`) | Linux |
| `BCryptGenRandomRandom` | Windows `BCryptGenRandom` (`BCRYPT_USE_SYSTEM_PREFERRED_RNG`) | Windows |
| `SecRandomCopyBytesRandom` | Apple `SecRandomCopyBytes` via `libSystem.B.dylib` | macOS |

```python
from multirandom.csprng.secure_rand import SecretsRandom

gen = SecretsRandom()
gen.token_hex(32)        # e.g. '4bd6b8767e026e39d71dcc9e99f0eb3d0ec217c48a5555d2fbdf99adc8852cbd'
gen.randbytes(16)        # raw bytes
gen.randint(1, 6)        # full random.Random API
```

### Seedable DRBGs

Deterministic from an explicit seed; live OS entropy when constructed without
one. Most accept `personalization=b"..."` to mix in per-instance context. All
implement `reseed()` where the standard defines one, plus
`getrandbytes(n)` for raw output and `getstate()`/`setstate()` round-trips.

| Class | Standard | Core |
|---|---|---|
| `CTR_DRBG` | SP 800-90A §10.2.1 + §10.5.1 DF | AES-128 in counter mode, rekeys after every generate |
| `HMAC_DRBG` | SP 800-90A §10.1.2 | HMAC-SHA-256 |
| `Hash_DRBG` | SP 800-90A §10.1.1 | SHA-256, 440-bit state, Hash_df |
| `Dual_EC_DRBG` | SP 800-90A §10.4 (**withdrawn**) | NIST P-256 — **backdoored on purpose** |

```python
from multirandom.csprng.secure_rand import CTR_DRBG

drbg = CTR_DRBG("my secret seed")
drbg.randbytes(32).hex()
drbg.reseed(b"fresh entropy")          # pull new entropy in at any moment
```

#### The backdoor, live: `Dual_EC_DRBG`

Each output block is the top `256 - truncate_bits` bits of `x(s*P)` on NIST
P-256; the state advances to `x(s*Q)`. Whoever built the public point with a
secret multiplier `d` (`Q = d*P`) can undo the truncation: brute-force the
deleted low bits, lift the candidate back onto the curve, multiply by `d` —
that lands on `x(s*Q)`, the *next* internal state. This is the
Shumow–Ferguson attack (2007); the class warns about it on first use.

```python
victim = Dual_EC_DRBG("demo victim key", truncate_bits=8)
first, second, third = victim.randbytes(31), victim.randbytes(31), victim.randbytes(31)

s1 = victim.reveal(first, known_next=second)   # one block -> next state
predictor = Dual_EC_DRBG.__new__(Dual_EC_DRBG) # a fresh "attacker" shell
predictor.truncate_bits = 8
predictor._s = s1
assert predictor.randbytes(31) == second       # predicted the future
assert predictor.randbytes(31) == third        # ...and the block after it
```

- Default `truncate_bits=16` matches the standard; recovering a state then
  costs ~2**15 scalar multiplications (instant in C, sluggish in pure Python).
  `truncate_bits=8` keeps the live demo snappy.
- `reveal(output, known_next=None, d=None)`: with `known_next` the recovered
  state is verified against the observed next block; `d` defaults to this
  implementation's fixed demo constant (`Dual_EC_DRBG._SECRET_D`).

> [!WARNING]
> `Dual_EC_DRBG` is *the* cautionary tale of standardised backdoors — a
> warning you can demonstrate is worth three you can merely print. Never use
> it for real randomness; the runtime warning says so too.

### Stream-cipher and accumulator designs

| Class | Design | Notes |
|---|---|---|
| `ChaCha20DRBG` | RFC 8439 ChaCha20 block function, counter mode | SHA-256-derived key + RFC 96-bit nonce |
| `Salsa20DRBG` | DJB Salsa20 core, counter mode | 256-bit key, 64-bit nonce + counter |
| `FortunaRandom` | Ferguson & Schneier Fortuna | 32 seed pools, AES-256-CTR, rekeys every 65536 blocks |
| `YarrowRandom` | Yarrow-160 (Fortuna's predecessor) | fast/slow pools, SHA-1 reseed, AES-192-CTR (legacy curiosity) |
| `ISAACRandom` | Bob Jenkins' ISAAC | transcribed from the author's `readable.c`, validated against his reference vectors |

```python
from multirandom.csprng.secure_rand import FortunaRandom, ChaCha20DRBG

fort = FortunaRandom("seed material")
fort.add_entropy(b"user typed this")     # feed pools, keep using it
fort.add_entropy(b"more data", pool=3)   # or target a specific pool

chacha = ChaCha20DRBG()                  # unseeded = live os.urandom entropy
```

Fortuna's reseed gate is the classic one: pool 0 reaching 32 bytes triggers a
reseed proportional to `reseed_count`. Pools here hold raw fed bytes rather
than incremental hashes, which keeps `getstate()` exact (documented
simplification).

## `sha_rand`

Counter-mode hash DRBGs — `H(seed || counter)` — behind the full
`random.Random` API, with `getrandbytes(n)` and exact state round-trips
(`getstate()` = `(seed, counter)`).

| Group | Classes |
|---|---|
| SHA-2 | `SHA224Random`, `SHA256Random`, `SHA384Random`, `SHA512Random` |
| SHA-3 | `SHA3_224Random`, `SHA3_256Random`, `SHA3_384Random`, `SHA3_512Random` |
| Extendable output | `SHAKE128Random`, `SHAKE256Random` (64-byte blocks) |
| BLAKE2 | `BLAKE2bRandom`, `BLAKE2sRandom` |
| Legacy, educational only | `MD5Random`, `SHA1Random` |

```python
from multirandom.csprng.sha_rand import BLAKE2bRandom

gen = BLAKE2bRandom("my seed")
gen.randbytes(16).hex()   # deterministic; reversible only by knowing the seed
```

> [!WARNING]
> `MD5Random` and `SHA1Random` are included as exhibits: both hashes are
> cryptographically broken, and their presence in a randomness stack is a
> bug magnet. These counter-mode constructions are honest deterministic
> derivatives, but they are not vetted DRBGs — see `secure_rand` for those.

## `original_random`

```python
from multirandom.csprng.original_random import random, randint, choice
```

A one-line passthrough (`from random import *`) to Python's built-in
Mersenne Twister, kept so the `csprng` package can be imported wholesale when
bundling "everything random".

## Where to go next

- [True randomness (`trng`)](trng.md) — when you want the universe, not a keystream
- [Unsecure PRNGs (`prng_unsecure`)](prng_unsecure.md) — the educational contrast
- [Self-checks](self-checks.md) — `py -3 -m multirandom.csprng.secure_rand` verifies this whole page
