# Getting started

## Requirements

- Python 3.9+
- Core dependencies (installed automatically with pip): `aiohttp`, `pyautogui`, `geopy`
- Optional: the [microphone extra](#optional-extras) for `trng.rand_using_real_random`

## Installation

From a checkout of the repository:

```bash
git clone https://github.com/BlackCatOfficialytb/multirandom
cd multirandom
pip install -r requirements.txt
pip install -e .            # or: PYTHONPATH=src python ...
```

Without installing, the package also runs straight from the source tree:

```bash
# Linux/macOS
PYTHONPATH=src python -c "from multirandom.prng_unsecure.xor_shift import Xorshift32"

# Windows PowerShell
$env:PYTHONPATH = "src"; py -3 -c "from multirandom.prng_unsecure.xor_shift import Xorshift32"
```

### Optional extras

```bash
pip install "multirandom[microphone]"   # adds real-random (ambient audio entropy)
```

## Which generator should I use?

| You need... | Use | Module |
|---|---|---|
| Anything that must stay secret | `SecretsRandom` | `csprng.secure_rand` |
| A seedable, reproducible crypto stream | `CTR_DRBG`, `ChaCha20DRBG`, `FortunaRandom` | `csprng.secure_rand` |
| Live OS entropy behind `random.Random` | `BCryptGenRandomRandom` (Windows), `GetRandomRandom` (Linux), ... | `csprng.secure_rand` |
| Deterministic hashing of a seed | `SHA256Random`, `BLAKE2bRandom`, ... | `csprng.sha_rand` |
| Entropy from the real world | `MicrophoneRandom`, `RandomUsingOpenMeteoAPI`, online APIs | `trng.*` |
| Human-in-the-loop seeding | `RealRandomUsingBetweenMixedClicks` | `trng.rand_via_clicks` |
| Fast, game-grade pseudo-randomness | `Xoshiro256PlusPlus`, `Xoshiro128StarStar`, ... | `prng_unsecure.xor_shift` |
| Understanding *why* the above fail | `LCGs`, `Xorshift32.reverse_roll()` | `prng_unsecure.*` |

> [!WARNING]
> Only `csprng` generators are suitable for cryptography, gambling, or anything
> with leaderboards. LCGs and XorShift/Xoshiro are educational pseudo-random
> generators whose state can be recovered from a few outputs — by design, the
> package ships their reversal logic side by side.

## Quickstart

```python
from multirandom.csprng.secure_rand import SecretsRandom, CTR_DRBG

gen = SecretsRandom()
print(gen.token_hex(32))            # live kernel entropy, 64 hex chars

drbg = CTR_DRBG("my secret seed")   # deterministic crypto stream
print(drbg.randbytes(16).hex())

from multirandom.prng_unsecure.xor_shift import Xorshift32

gen = Xorshift32(seed=12345)        # fast, NOT secure — good for games
print(gen.roll())                   # a 32-bit step of the register
```

## Warnings

Constructing a `prng_unsecure` generator or `Dual_EC_DRBG` prints a warning the
first time (per process). Silence or review them via the package-root switch:

```python
import multirandom
multirandom.ignore_unsecure_prng_warning_do_not_set_to_true_unless_you_know_how_risky_it_is = False  # default: console warns
# multirandom.ignore_unsecure_prng_warning_do_not_set_to_true_unless_you_know_how_risky_it_is = True  # silence (still just as risky)
```

## Next steps

- [True randomness (`trng`)](trng.md)
- [Cryptographic randomness (`csprng`)](csprng.md)
- [Unsecure PRNGs (`prng_unsecure`)](prng_unsecure.md)
- [Self-checks](self-checks.md) — every module ships an assert battery
