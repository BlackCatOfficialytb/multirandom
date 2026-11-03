# Self-checks

Every generator module ships an assert-based battery. Run one, run all —
a green run means the generators behave: deterministic under fixed seeds,
seed-sensitive, state-restorable where promised, and statistically sane.

## Cryptographic package

```bash
py -3 -m multirandom.csprng.secure_rand          # (PYTHONPATH=src, or after pip install)
py -3 -m multirandom.csprng.sha_rand
```

`secure_rand` verifies, in order:

1. **AES known-answer tests** — FIPS-197 vectors for 128/192/256-bit keys
   (the miniature AES is built from its definition, not a typed-in S-box)
2. **ISAAC reference state** — Jenkins' all-zero-state check
   (`aa=d4d3f473`, `bb=902c0691`, `cc=10` after ten calls)
3. **P-256 sanity** — generator on the curve, `Q = d*P` on the curve,
   `(n-1)*G = -G`
4. **the global warning flag** — warnings show when `False`, stay silent when
   `True`
5. **the DRBG battery** — for every seedable generator
   (`CTR_DRBG`, `HMAC_DRBG`, `Hash_DRBG`, `Dual_EC_DRBG`, `ChaCha20DRBG`,
   `Salsa20DRBG`, `FortunaRandom`, `YarrowRandom`, `ISAACRandom`):
   - deterministic for a fixed seed
   - sensitive to a different seed
   - `getstate()`/`setstate()` round-trip
   - `getrandbits(k)` in range; `random()` in `[0, 1)`; `choice()`
   - bit balance over 8 KB of output
6. **`Dual_EC_DRBG` specifics** — small-truncation battery, then the backdoor
   demonstrated live: `reveal()` recovers the next state from one block, and
   the predictor reproduces the following blocks
7. **the OS-level sources** — `SecretsRandom`, `OSURandom`, `GetRandomRandom`,
   `BCryptGenRandomRandom`, `SecRandomCopyBytesRandom`: two draws differ,
   bits balanced, and state restoration correctly refused

`sha_rand` verifies all 14 hash generators: fixed-seed determinism, seed
sensitivity, distinct streams across hashes, `random()`/`getrandbits()`
bounds, 100 KB bit balance, `getstate()`/`setstate()` round-trip.

## Unsecure package

```bash
py -3 -m multirandom.prng_unsecure.xor_shift
```

That walks through:

1. **reference vectors** — output of every generator class matches the
   official C implementations
2. **reversibility** — `reverse_roll()` round-trips `Xorshift32/64/128`
3. **equivalent attacks** — feedback / increments / doubling / GF(2) matrix
   all undo `Xorshift32`, for every seed up to 64 and every shift/width
4. **all 18 generators** — distinct outputs within 64 rolls, surviving
   all-zero seeds

## Interactive / networked modules

These are not assert batteries — they need you or the internet:

```bash
py -3 -m multirandom.trng.rand_via_clicks    # waits for your actual mouse clicks
```

The rest are best exercised inline:

```python
import asyncio
from multirandom.trng.rand_using_online_api import fetch_qrng_anu_integers
print(asyncio.run(fetch_qrng_anu_integers(8)))     # network + quantum hardware
```

The weather module is a hybrid — offline asserts plus a live harvest attempt
(that degrades to `os.urandom` gracefully when the network is down):

```bash
py -3 -m multirandom.trng.weather_rand
```

## What a failure means

- `AssertionError: ... is not deterministic for a fixed seed` — the generator
  leaks non-seed entropy into its stream
- `AssertionError: ... ignores the seed` — different seeds collided (a real
  bug, e.g. seed material never reaching the core)
- `AssertionError: ... state round-trip broken` — output depended on state
  not captured in `getstate()`
- `AssertionError: ... bit balance looks broken` — statistical imbalance in
  the raw output bits

> [!TIP]
> Run the two csprng batteries after touching `csprng/`, and `xor_shift`
> after touching generator `__init__`s — the batteries introspect signatures
> and would notice.

## Where to go next

- [Getting started](getting-started.md)
- [Package index](index.md)
