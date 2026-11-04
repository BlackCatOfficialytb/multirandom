# Self-checks

Every generator module ships an assert-based battery. Run one, run all —
a green run means the generators behave: deterministic under fixed seeds,
seed-sensitive, state-restorable where promised, and statistically sane.

## Cryptographic package

```bash
py -3 -m multirandom.csprng._drbg_base           # (PYTHONPATH=src, or after pip install)
py -3 -m multirandom.csprng._aes                 # FIPS-197 known-answer tests
py -3 -m multirandom.csprng.sha_rand
```

`_drbg_base` sweeps every seedable DRBG; `_aes` verifies the library AES
against FIPS-197. Each generator module also runs its own battery, e.g.:

```bash
py -3 -m multirandom.csprng.sponge_drbg          # Keccak-f[1600] pinned vs hashlib
py -3 -m multirandom.csprng.ansi_x931            # hand-computed X9.31 triples
py -3 -m multirandom.csprng.blum_blum_shub       # the textbook n = 11*19 example
py -3 -m multirandom.csprng.rdrand_hardware      # skipped where the CPU can't execute
```

The DRBG sweep verifies, in order:

1. **the DRBG battery** — for every seedable generator
   (`CTR_DRBG`, `HMAC_DRBG`, `Hash_DRBG`, `Dual_EC_DRBG`, `ChaCha20DRBG`,
   `Salsa20DRBG`, `FortunaRandom`, `YarrowRandom`, `ISAACRandom`,
   `SpongeDRBG`, `AnsiX931DRBG`):
   - deterministic for a fixed seed
   - sensitive to a different seed
   - `getstate()`/`setstate()` round-trip
   - `getrandbits(k)` in range; `random()` in `[0, 1)`; `choice()`
   - bit balance over 8 KB of output
2. **`Dual_EC_DRBG` specifics** — small-truncation battery, then the backdoor
   demonstrated live: `reveal()` recovers the next state from one block, and
   the predictor reproduces the following blocks
3. **the OS-level sources** — `SecretsRandom`, `OSURandom`, `GetRandomRandom`,
   `BCryptGenRandomRandom`, `SecRandomCopyBytesRandom`: two draws differ,
   bits balanced, and state restoration correctly refused
4. **the global warning flag** — warnings show when `False`, stay silent when
   `True`

`sha_rand` verifies all 14 hash generators: fixed-seed determinism, seed
sensitivity, distinct streams across hashes, `random()`/`getrandbits()`
bounds, 100 KB bit balance, `getstate()`/`setstate()` round-trip.

## Unsecure package

```bash
py -3 -m multirandom.prng_unsecure.xor_shift
py -3 -m multirandom.prng_unsecure.mersenne_twister
py -3 -m multirandom.prng_unsecure.flash_player_prng      # ~10 s (runs the real attack)
```

That walks through:

1. **reference vectors** — output of every generator class matches the
   official C implementations
2. **reversibility** — `reverse_roll()` round-trips `Xorshift32/64/128`
3. **equivalent attacks** — feedback / increments / doubling / GF(2) matrix
   all undo `Xorshift32`, for every seed up to 64 and every shift/width
4. **all 18 generators** — distinct outputs within 64 rolls, surviving
   all-zero seeds

`flash_player_prng` adds:

1. **structural constants** — XOR mask, 31-bit `kRandomPureMax`, the `* 71`,
   the obfuscated polynomial constants and the `60492497` magic, each checked
   against the avmplus source or its arithmetic identity
2. **7 known vectors** — exact streams for fixed `u_value`s, including the
   `u_value == 0` degenerate fixed point
3. **10k draws** — always on the 31-bit grid, deterministic, state-sensitive
4. **kernel roundtrips** — `poly^-1` (bit-reversal DFS) and `*71^-1`
   (`solve_multi_reverse`) return their true inputs
5. **the CVE-2017-3000 chain** — `recover_state_from_output` rebuilds
   `0x12345678` (and its LFSR twin) from ONE draw `0x39f5743c`, then predicts
   the stream correctly
6. **the warning switch** — one warning per process, silenced by the global
   flag

`mersenne_twister` adds:

1. **official vector** — `init_genrand(5489)` reproduces the canonical
   10-output sequence
2. **CPython parity** — `from_key` streams equal `random.Random(n)`
   (`getrandbits(32)` and `random()`) for 9 int seeds, incl. multi-word ones
3. **10k draws** — deterministic, on the 32-bit grid, seed-sensitive;
   10k `genrand_res53` doubles in [0, 1)
4. **state round-trip** — `getstate()`/`setstate()` (plus bogus-state
   rejection)
5. **temper ⇄ untemper** — full 32-bit bijection over 30k samples + edges
6. **the 624-output clone** — the state is recovered from any consecutive
   window (5 strided starts tested) and predicts 300 future draws each time

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
> Run `multirandom.csprng._drbg_base` (and `sha_rand`) after touching
> `csprng/`, and `xor_shift`
> after touching generator `__init__`s — the batteries introspect signatures
> and would notice.

## Where to go next

- [Getting started](getting-started.md)
- [Package index](index.md)
