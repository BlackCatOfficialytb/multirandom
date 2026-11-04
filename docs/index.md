# MultiRandom 🎲 — Documentation

One random-number package, several philosophies of chance. MultiRandom gathers
true physical entropy, cryptographically strong generators, and educational
(broken-on-purpose) PRNGs behind familiar `random.Random` APIs.

## The three families

| Package | Path | Trust level | Use it for |
|---|---|---|---|
| `trng` | `multirandom.trng` | physical / hardware entropy | games, demos, sampling reality |
| `csprng` | `multirandom.csprng` | cryptographically strong | secrets, tokens, keys, gambling |
| `prng_unsecure` | `multirandom.prng_unsecure` | **not** cryptographically secure | education, speed, procedural content |

Start here:

- **[Getting started](getting-started.md)** — installation, quickstart, which generator to pick
- **[True randomness (`trng`)](trng.md)** — mouse clicks, quantum APIs, microphones, weather
- **[Cryptographic randomness (`csprng`)](csprng.md)** — OS CSPRNGs, NIST DRBGs, Fortuna, ISAAC, hash DRBGs
- **[Unsecure PRNGs (`prng_unsecure`)](prng_unsecure.md)** — XorShift/Xoshiro, LCGs, and their reversal attacks
- **[Self-checks](self-checks.md)** — assert batteries that verify every generator

## The global unsecure-prng warning switch

Everything in `prng_unsecure/` and the deliberately backdoored `Dual_EC_DRBG`
warns the first time it is constructed. One package-root variable controls
those warnings:

```python
import multirandom

multirandom.ignore_unsecure_prng_warning_do_not_set_to_true_unless_you_know_how_risky_it_is = True
```

- `False` (the default): every unsecure-PRNG warning goes to the console.
- `True`: the warnings are ignored (not printed) — risk is all yours.

> [!WARNING]
> Setting it to `True` does not make any generator safer. LCGs remain
> reversible and `Dual_EC_DRBG` remains backdoored; the variable only silences
> the console.

## Project layout

```text
multirandom/
└── src/
    └── multirandom/
        ├── trng/               # True / Physical Entropy
        │   ├── rand_via_clicks.py        # Human-in-the-loop entropy
        │   ├── rand_using_online_api.py  # Quantum & Hardware APIs (ANU QRNG, Random.org, Roll-API)
        │   ├── rand_using_real_random.py # Microphone entropy (real-random, optional extra)
        │   └── weather_rand.py           # Open-Meteo weather-based entropy
        ├── csprng/             # Cryptographically Strong Randomness
        │   ├── os_random.py              # OS CSPRNGs (secrets, urandom, getrandom, BCrypt, SecRandom)
        │   ├── ctr_drbg.py / hmac_drbg.py / hash_drbg.py   # NIST SP 800-90A
        │   ├── dual_ec_drbg.py           # the backdoored DRBG, live
        │   ├── chacha20_drbg.py / salsa20_drbg.py          # stream-cipher DRBGs
        │   ├── fortuna.py / yarrow.py / isaac.py           # pools and the classics
        │   ├── sponge_drbg.py            # Keccak-f[1600] sponge DRBG (from scratch)
        │   ├── ansi_x931.py              # ANS X9.17/X9.31, the banking generator
        │   ├── blum_blum_shub.py         # factoring-hard, one bit per squaring
        │   ├── rdrand_hardware.py        # RDRAND / RDSEED CPU instructions
        │   ├── _aes.py                   # the library AES (FIPS-197 KATs)
        │   ├── sha_rand.py               # MD5, SHA-1/2/3, BLAKE2, SHAKE hash DRBGs
        │   └── original_random.py        # Passthrough wrapper for random.Random
        └── prng_unsecure/      # UNSECURE mathematical PRNGs
            ├── xor_shift.py              # XorShift & Xoshiro family (18 generators)
            ├── mersenne_twister.py       # MT19937 + the 624-output clone attack
            ├── lcg.py                    # Linear Congruential Generators (LCGs)
            ├── flash_player_prng.py      # Flash Player Math.random() + its reversal attacks
            ├── randu.py                  # IBM's RANDU, the 15-planes generator
            ├── middle_square.py          # von Neumann's middle square + MSWS
            ├── doom_prng.py              # Doom's 256-entry lookup table
            ├── splitmix64.py             # SplitMix64, inverted exactly
            ├── lagged_fibonacci.py       # BSD-style LF(31, 3); last j outputs = state
            ├── pcg.py                    # O'Neill's PCG32, closed-form jump
            └── v8_xorshift128plus.py     # Math.random()'s engine + the GF(2) seed solve
```

## License

Apache License 2.0 — see [LICENSE](https://github.com/BlackCatOfficialytb/multirandom/blob/main/LICENSE).
