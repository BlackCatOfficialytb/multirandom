# MultiRandom 🎲

A comprehensive library for exploring and generating randomness across the spectrum—from true physical entropy to mathematical pseudo-randomness and everything in between.

## 🌟 Overview

**MultiRandom** is designed for developers, researchers, and hobbyists who want to understand high-quality randomness. It provides tools to fetch random data from quantum sources, physical human interaction, and modern mathematical algorithms.

> [!WARNING]
> **Security Note**: This library contains both "True" and "Pseudo" random sources. While some sources (like QRNG) are highly secure, others (like LCGs) are provided for educational purposes and include **reverse logic** to demonstrate their insecurity. Always use the appropriate generator for your use case.

---

## 📚 Full Documentation

Deep-dive docs live in [`docs/`](docs/):

| Page | Contents |
|---|---|
| [Getting started](docs/getting-started.md) | installation, quickstart, which generator to pick |
| [True randomness (`trng`)](docs/trng.md) | mouse clicks, quantum APIs, microphone, weather |
| [Cryptographic randomness (`csprng`)](docs/csprng.md) | OS CSPRNGs, NIST DRBGs, the Dual_EC backdoor demo, Keccak sponge, Blum Blum Shub, RDRAND |
| [Unsecure PRNGs (`prng_unsecure`)](docs/prng_unsecure.md) | XorShift/Xoshiro, LCGs, Doom, PCG32, V8's Math.random, and their reversal attacks |
| [Self-checks](docs/self-checks.md) | the assert batteries verifying every generator |

---

## 🏗 Project Structure

```text
multirandom/
└── src/
    └── multirandom/
        ├── trng/               # True / Physical Entropy
        │   ├── rand_via_clicks.py        # Human-in-the-loop entropy
        │   ├── rand_using_online_api.py  # Quantum & Hardware APIs (ANU QRNG, Roll-API)
        │   ├── rand_using_real_random.py # Microphone entropy (real-random)
        │   └── weather_rand.py           # Open-Meteo weather entropy (large unhashed seeds)
        ├── csprng/             # Cryptographically Strong Randomness
        │   ├── os_random.py              # OS CSPRNGs (secrets, urandom, getrandom, BCrypt, SecRandom)
        │   ├── ctr_drbg.py / hmac_drbg.py / hash_drbg.py   # NIST SP 800-90A DRBGs
        │   ├── dual_ec_drbg.py           # the backdoored DRBG, live
        │   ├── chacha20_drbg.py / salsa20_drbg.py          # stream-cipher DRBGs
        │   ├── fortuna.py / yarrow.py / isaac.py           # pools and the classics
        │   ├── sponge_drbg.py            # Keccak-f[1600] sponge DRBG (from scratch)
        │   ├── ansi_x931.py              # ANS X9.17/X9.31, the banking generator
        │   ├── blum_blum_shub.py         # factoring-hard, one bit per squaring
        │   ├── rdrand_hardware.py        # RDRAND / RDSEED CPU instructions
        │   ├── _aes.py                   # the library AES (FIPS-197 KATs)
        │   ├── sha_rand.py               # MD5, SHA-1/2/3, BLAKE2, SHAKE PRNGs
        │   └── original_random.py        # Wrapper for Python's built-in random
        └── prng_unsecure/      # Mathematical Randomness (UNSECURE PRNGs)
            ├── xor_shift.py              # XorShift & Xoshiro Family
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

---

## 🛠 Features & Usage

### 1. Human-in-the-loop Entropy (`trng`)
Uses `pyautogui` and Windows API to capture sub-microsecond timing jitter and spatial coordinates from physical mouse clicks.

```python
from multirandom.trng.rand_via_clicks import RealRandomUsingBetweenMixedClicks

# Requires a sequence of Left -> Right -> Middle clicks to seed
gen = RealRandomUsingBetweenMixedClicks()
print(gen.random())
```

### 2. Physical & Hardware APIs (`trng`)
Fetch "True" randomness from remote physical processes.

- **Australian National University (ANU)**: Quantum vacuum noise via QRNG.
- **Random.org**: Atmospheric noise.
- **Roll-API**: Physical dice rolling hardware.
- **Microphone**: Ambient audio noise via [`real-random`](https://pypi.org/project/real-random/) (optional extra).
- **Weather Entropy**: (In development) Fetching randomness from real-time weather stations.

```python
from multirandom.trng.rand_using_real_random import MicrophoneRandom

gen = MicrophoneRandom()   # captures ~1-2 s of ambient audio
print(gen.random())
gen.reseed()               # capture fresh entropy on demand
```

### 3. Bit-Shift Generators (`prng_unsecure`)
Implementations of the most popular mathematical generators used in modern systems.

- **Original XorShift**: `Xorshift32` / `Xorshift64` / `Xorshift128`, each with `reverse_roll()` to demonstrate mathematical reversibility. `Xorshift32` also inverts via increasing increments (`reverse_roll_increments()`), shift doubling (`reverse_roll_doubling()`) and GF(2) matrix inversion (`reverse_roll_matrix()`) — all equivalent.
- **Scrambled Variants**: Xorwow (CUDA), Xorshift\* & Xorshift1024\* (Vigna), Xorshift+ (V8/Webkit).
- **Modern Xoshiro**: Xoshiro128 `+`/`++`/`**`, Xoshiro256 `+`/`++`/`**`, Xoroshiro64 `*`/`**`, Xoroshiro128 `+`/`++`/`**` (Minecraft Java 1.18+ uses `++`).

Run `python -m multirandom.prng_unsecure.xor_shift` to check every generator against reference vectors.

### 4. Mathematical LCGs (`prng_unsecure`)
Classic Linear Congruential Generators with customizable shift parameters. Includes `reverse_roll()` methods to demonstrate the insecurity of simple modular arithmetic.

### 5. Iconic & historic PRNGs (`prng_unsecure`)
The famous, the infamous, and the ones running inside your favourite games —
each module ships its reference vectors and its own reversal.

- **IBM's RANDU** (`randu`): the 15-planes generator; one output recovers the seed via the modular inverse of 65539.
- **Middle Square** (`middle_square`): von Neumann's 1949 idea, plus the MSWS variant.
- **Doom's RNG** (`doom_prng`): the 256-entry lookup table behind every shotgun spread, increment-then-index; one draw pins the index.
- **SplitMix64** (`splitmix64`): the seeding engine behind xoshiro; the mixer is inverted exactly from one output.
- **Lagged Fibonacci** (`lagged_fibonacci`): the BSD `random()`-style LF(31, 3); the last j outputs ARE the state.
- **PCG32** (`pcg`): O'Neill's permutation-on-an-LCG — the "good" end, with a closed-form `jump()` for a billion outputs in one call.
- **V8's XorShift128+** (`v8_xorshift128plus`): JavaScript's `Math.random()` engine; five consecutive doubles recover the exact 128-bit seed by GF(2) elimination.

```python
from multirandom.prng_unsecure.doom_prng import DoomRandom
from multirandom.prng_unsecure.v8_xorshift128plus import V8XorShift128Plus

doom = DoomRandom()
doom.P_Random()                     # the same table the game rolls

v8 = V8XorShift128Plus(seed="demo")
clone = V8XorShift128Plus.from_outputs([v8.random() for _ in range(5)])
clone.getstate() == v8.getstate()   # True: Math.random, predicted exactly
```

### 6. Hash-based Generators (`csprng`)
Counter-mode hash DRBGs: `H(seed || counter)` drives the full `random.Random` API.

- **SHA-2**: SHA-224, SHA-256, SHA-384, SHA-512
- **SHA-3**: SHA3-224, SHA3-256, SHA3-384, SHA3-512
- **Extendable output**: SHAKE-128, SHAKE-256
- **BLAKE2**: BLAKE2b, BLAKE2s
- **Legacy (educational only)**: MD5, SHA-1

```python
from multirandom.csprng.sha_rand import BLAKE2bRandom

gen = BLAKE2bRandom("my seed")
print(gen.randbytes(16).hex(), gen.random(), gen.choice(["a", "b"]))
```

### 7. Cryptographically Strong Generators (`csprng`)
The ones to actually guard things with, plus deliberately broken ones that teach.

**OS-level CSPRNGs** (live entropy, behave like `random.SystemRandom` — seeding
is a no-op and state cannot be restored):

| Class | Source |
|---|---|
| `SecretsRandom` | the `secrets` module (+ `token_bytes` / `token_hex` / `token_urlsafe`) |
| `OSURandom` | plain `os.urandom` |
| `GetRandomRandom` | Linux `getrandom(2)` |
| `BCryptGenRandomRandom` | Windows `BCryptGenRandom` |
| `SecRandomCopyBytesRandom` | Apple `SecRandomCopyBytes` |

The ctypes ones fall back to `os.urandom` (the same kernel entropy pool) when
the native API is not reachable on the running platform.

**NIST SP 800-90A DRBGs** (seedable, deterministic from an explicit seed, full
`random.Random` API with `getrandbits` / `randbytes` / `choice` / `shuffle` ...):

- `CTR_DRBG` – AES-128 with the §10.5.1 derivation function
- `HMAC_DRBG` – HMAC-SHA-256
- `Hash_DRBG` – SHA-256 with Hash_df (440-bit state)
- `Dual_EC_DRBG` — *deliberately backdoored*, kept as a teaching exhibit

**Stream / accumulator / sponge designs**: `ChaCha20DRBG`, `Salsa20DRBG`
(counter-mode DRBGs on the two classic stream ciphers), `FortunaRandom`
(32 seed pools + AES-256-CTR, rekey every 65536 blocks,
`add_entropy(data, pool)`) and its legacy predecessor `YarrowRandom`
(fast/slow pools, AES-192-CTR), `ISAACRandom` (Bob Jenkins' ISAAC, validated
against his reference vectors), `SpongeDRBG` (a sponge-mode DRBG on a
hand-transcribed Keccak-f[1600], pinned against `hashlib`), and
`AnsiX931DRBG` (the banking world's ANS X9.17/X9.31 generator).

**Factoring-hard and hardware**: `BlumBlumShub`
(x' = x² mod n — one provably factoring-hard bit per squaring, genuine Blum
primes enforced by a self-contained Miller-Rabin) and the CPU's own entropy
instructions `RDRANDRandom` / `RDSEEDRandom` (x86-64 shellcode through
ctypes, probed availability).

```python
from multirandom.csprng import SecretsRandom, CTR_DRBG, Dual_EC_DRBG

gen = SecretsRandom()
print(gen.token_hex(32))            # live kernel entropy

drbg = CTR_DRBG("my secret seed")   # deterministic; also reseeds:
drbg.reseed(b"fresh entropy")
print(drbg.randbytes(32).hex())
```

#### The backdoor, live

`Dual_EC_DRBG` reproduces the withdrawn NIST design: outputs are the high bits
of `x(s*P)` on NIST P-256, the state advances to `x(s*Q)` — and whoever built
`Q = d*P` knows `d`. `.reveal(one_block)` brute-forces the truncated bits and
recovers the *next* internal state with the secret multiplier:

```python
victim = Dual_EC_DRBG("demo victim key", truncate_bits=8)
first, second, third = victim.randbytes(31), victim.randbytes(31), victim.randbytes(31)

s1 = victim.reveal(first, known_next=second)   # Shumow–Ferguson attack
predictor = Dual_EC_DRBG.__new__(Dual_EC_DRBG)
predictor.truncate_bits = 8
predictor._s = s1
assert predictor.randbytes(31) == second       # predicted the future
assert predictor.randbytes(31) == third        # ...and the block after it
```

The default `truncate_bits=16` matches the standard (recovering a state costs
about 2**15 curve multiplications — instant in C, slow in pure Python); the
module ships with this demo running in its own self-checks at
`truncate_bits=8`. It warns on first use. Never use it for real randomness.

```python
# Run the DRBG sweep: python -m multirandom.csprng._drbg_base
```

### The global unsecure-prng warning switch
Everything in `prng_unsecure/` and the backdoored `Dual_EC_DRBG` warns the first
time it is constructed. One package-root variable controls those warnings:

```python
import multirandom

multirandom.ignore_unsecure_prng_warning_do_not_set_to_true_unless_you_know_how_risky_it_is = True
```

- `False` (the default): every unsecure-PRNG warning goes to the console.
- `True`: the warnings are ignored (not printed) — risk is all yours.

---

## 🚀 Installation & Setup

### Requirements
- Python 3.9+
- Dependencies listed in `requirements.txt` (e.g., `pyautogui`, `aiohttp`, `pycryptodome`)

### Installation
```bash
pip install -r requirements.txt

# Optional: microphone entropy source (adds numpy + sounddevice)
pip install "multirandom[microphone]"
```

### Usage
```python
from multirandom.prng_unsecure.xor_shift import Xorshift32

# Create a 32-bit XorShift generator
gen = Xorshift32(seed=12345)
print(gen.roll())
```

---

## 📺 Educational Resources
This project focuses on the limits of computer-generated randomness. For more context, check out:
- [Why computers can't generate truly random numbers](https://youtu.be/XDsYPXRCXAs?si=oDaFsqZyNJWVXwEi)

---

## 📜 License
Licensed under the [Apache License 2.0](LICENSE).
