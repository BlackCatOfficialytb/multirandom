# True randomness (`trng`)

Sources that pull entropy from the physical world: your mouse, distant quantum
hardware, ambient sound, and the weather.

## Mouse clicks — `rand_via_clicks`

Each generator seeds from the *nanosecond-scale timing jitter* between your
mouse clicks, plus the cursor coordinates at click time. This is
human-in-the-loop entropy: constructing the generator blocks until you
actually click the required buttons.

> [!NOTE]
> Windows-only: button state is polled through the Win32 `GetAsyncKeyState`
> API, with `pyautogui` reading the cursor position.

| Class | Required clicks to seed |
|---|---|
| `RealRandomUsingBetweenLeftClicks` | 2 left clicks |
| `RealRandomUsingBetweenRightClicks` | 2 right clicks |
| `RealRandomUsingBetweenMiddleClicks` | 2 middle clicks |
| `RealRandomUsingBetweenMixedClicks` | Left → Right → Middle |

```python
from multirandom.trng.rand_via_clicks import RealRandomUsingBetweenMixedClicks

gen = RealRandomUsingBetweenMixedClicks()  # waits for Left -> Right -> Middle
print(gen.random())
```

Pass an explicit seed (`RealRandomUsingBetweenMixedClicks(42)`) to skip the
clicks and get a normal `random.Random` stream.

The module also exposes the low-level helpers
`is_left_click_pressed()` / `is_right_click_pressed()` /
`is_middle_click_pressed()` and `get_click_data(button_check_func)` returning
`(perf_counter_timestamp, cursor_position)`.

Run `py -3 -m multirandom.trng.rand_via_clicks` to be walked through a live
click capture.

## Physical & online APIs — `rand_using_online_api`

Async functions on top of `aiohttp`; every call reaches real hardware or
physical processes on the internet. They return plain Python values, not
`random.Random` streams:

| Function | Source | Returns |
|---|---|---|
| `fetch_random_org_integers(num, min_val, max_val)` | [Random.org](https://www.random.org) atmospheric noise (text API) | `list[int]` |
| `fetch_qrng_anu_integers(num)` | [ANU QRNG](https://qrng.anu.edu.au) — quantum vacuum shot noise | `list[int]` (uint8s) |
| `fetch_roll_api_result()` | [Roll-API](https://roll.lastgimbus.com) — physical dice-rolling robot | `int` or `None` |

```python
import asyncio
from multirandom.trng.rand_using_online_api import fetch_qrng_anu_integers

print(asyncio.run(fetch_qrng_anu_integers(8)))   # 8 bytes of quantum noise
```

> [!NOTE]
> API availability changes without notice; `fetch_roll_api_result()` in
> particular returns `None` when the endpoint layout does not match. Treat all
> three as best-effort.

## Microphone — `rand_using_real_random` (optional extra)

Wraps the [`real-random`](https://pypi.org/project/real-random/) package,
which records 1–2 s of ambient audio and hashes it with SHA-256:

```bash
pip install "multirandom[microphone]"
```

```python
from multirandom.trng.rand_using_real_random import MicrophoneRandom, microphone_seed

gen = MicrophoneRandom()   # captures ambient noise on construction (~1-2 s)
print(gen.random())
gen.reseed()               # capture fresh audio whenever you want

print(microphone_seed())   # one capture, one float in [0, 1)
```

`MicrophoneRandom` is a `random.Random` subclass: one capture seeds a local
Mersenne Twister stream. The module also lazily re-exports `real_random()`,
`real_random_int(...)`, `real_random_float(...)`, `real_random_choice(...)`
and `real_random_string(...)` — those capture fresh audio per call.

## Weather — `weather_rand`

`RandomUsingOpenMeteoAPI` seeds a Mersenne Twister from Open-Meteo weather
observations blended with `os.urandom`. One call harvests much more than the
original snapshot: the **complete hourly arrays** (29 variables — temperature,
dew point, apparent temperature, precipitation/rain/showers/snowfall/snow
depth, pressure MSL + surface, cloud cover low/mid/high, visibility, CAPE,
wind speed/gusts/direction, 80 m temperature, soil temperature & moisture,
shortwave/direct/diffuse radiation, vapour-pressure deficit, UV index), the
**daily aggregates** (19 more variables) and the response metadata, across a
rolling window (`forecast_days=3` + `past_days=2` by default, configurable),
for up to 12 random locations and moments — ~3 500 real-world readings
(~29 KB of raw material) per fetch.

The readings are combined **without cryptographic hashing**:

1. **lossless packing** — every measurement contributes its exact IEEE-754
   bytes to a "tape" (nothing collapses into a digest);
2. **von Neumann conditioning** — tape bits are debiased pairwise
   (01 → 1, 10 → 0, 00/11 dropped), the classic technique for physical noise;
3. **reversible wide fold** — the tape and the debiased pool are folded into a
   big-integer state with a splitmix-derived odd multiplier and a
   chunk-dependent bit rotation per step (an invertible fold, not a hash).

```python
from multirandom.trng.weather_rand import RandomUsingOpenMeteoAPI

gen = RandomUsingOpenMeteoAPI()      # seeds itself from weather on start
print(gen.random())
gen.reseed_from_weather()            # reseed later from fresh weather data
gen.seed(42)                         # or with a fixed seed
```

Building blocks:

- `OpenMeteoAPI` — the entropy source alone; `await .get_seed(seed_bytes=64)`
  returns the large unhashed seed. **Scale is yours**: `seed_bytes` is
  64 (512 bits) by default and goes up to 1024 (8192 bits) — versus the old
  256-bit SHA-256 digest. If every fetch fails, it falls back to raw
  `os.urandom` (no time hash either). An assert battery ships with the
  module:
  `py -3 -m multirandom.trng.weather_rand` (offline asserts + live harvest
  attempt).
- Location selection: random global spots (`use_random_location`,
  `num_random_locations`), your current spot (`use_current_location`, first
  via [ipinfo.io](https://ipinfo.io), then geopy), random moments of the past
  week (`use_random_time`).
- `RandomUsingOpenMeteoAPI(auto_seed=True, seed_bytes=64)` then XORs the
  weather seed with same-width `os.urandom` noise — a perfect blend that
  needs no hashing — and hands the whole wide integer to Mersenne Twister's
  state loader.

> [!WARNING]
> Weather entropy is *public*: an adversary with the same API can replay your
> inputs, and a guessable location narrows the search space further. The XOR
> blend with `os.urandom` keeps the final seed unpredictable, but the weather
> part alone is not a secret. Fun for demos; use `csprng` for real security.

Dependencies: `aiohttp` (installed) and `geopy` (installed as a core
dependency; used only for the geocoding fallback).

## Where to go next

- [Cryptographic randomness (`csprng`)](csprng.md) — the sources to actually guard things with
- [Self-checks](self-checks.md)
