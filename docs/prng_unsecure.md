# Unsecure PRNGs (`prng_unsecure`)

Educational pseudo-random generators — fast, deterministic, and *reversibly*
insecure on purpose. The package ships each generator together with the
mathematics that breaks it.

> [!WARNING]
> None of these are safe for cryptography, gambling, or anything with
> leaderboards. Every constructor warns once per process; see the
> [global warning switch](index.md#the-global-unsecure-prng-warning-switch).

## XorShift & Xoshiro — `xor_shift`

18 generators, from Marsaglia's original registers to Vigna's modern
scramblers. Core method: `roll()` — one step, one output. Plain-seed classes
classes take a `seed` int; the multi-word ones take a `seeds` list (and
generate one from OS entropy if you don't).

| Family | Classes |
|---|---|
| Original XorShift | `Xorshift32`, `Xorshift64`, `Xorshift128` |
| Scrambled variants | `Xorwow` (CUDA), `XorshiftStar` & `Xorshift1024Star` (Vigna), `XorshiftPlus` (V8/WebKit) |
| Xoshiro 256 | `Xoshiro256Plus`, `Xoshiro256PlusPlus`, `Xoshiro256StarStar` |
| Xoshiro 128 | `Xoshiro128Plus`, `Xoshiro128PlusPlus`, `Xoshiro128StarStar` |
| Xoroshiro 64 | `Xoroshiro64Star`, `Xoroshiro64StarStar` |
| Xoroshiro 128 | `Xoroshiro128Plus`, `Xoroshiro128PlusPlus`, `Xoroshiro128StarStar` (Minecraft Java 1.18+) |

```python
from multirandom.prng_unsecure.xor_shift import Xorshift32, Xoshiro256PlusPlus

gen = Xorshift32(seed=12345)
print(gen.roll())                              # a raw 32-bit register step

bigger = Xoshiro256PlusPlus(seeds=[1, 2, 3, 4])
print([bigger.roll() for _ in range(5)])       # five 64-bit outputs
```

The C reference test vectors are mirrored in
[`REFERENCE_VECTORS`](https://github.com/rust-random/rngs); the module's
self-check reproduces every one of them.

### `Xorshift32` — a full anatomy of an attack

Every Xorshift step is linear over GF(2), so it can be *undone* several
equivalent ways — all four are implemented and verified against each other:

| Method | Idea |
|---|---|
| `reverse_roll()` | classic fixed-shift feedback loop |
| `reverse_roll_increments()` | XOR the final value at s, 2s, 3s, ... |
| `reverse_roll_doubling()` | XOR the intermediate value at s, 2s, 4s, ... |
| `reverse_roll_matrix()` | GF(2) matrix inversion (`gf2_inverse_matrix`) |

```python
gen = Xorshift32(seed=42)
gen.roll()
gen.reverse_roll()
assert gen.state == 42
```

Standalone helpers are exported too: `reverse_xor_lshift` /
`reverse_xor_rshift`, `increments_xor_lshift` / `increments_xor_rshift`,
`doubling_xor_lshift` / `doubling_xor_rshift`, and `gf2_inverse_matrix`.

## Mersenne Twister — `mersenne_twister`

The MT19937 from Matsumoto & Nishimura's `mt19937ar.c` — the PRNG that has
driven Python's `random` module for two decades — rebuilt together with the
textbook attack that kills it after 624 observed outputs.

```python
from multirandom.prng_unsecure.mersenne_twister import MersenneTwister

gen = MersenneTwister(5489)              # the classic Knuth init
print(gen.roll())                        # genrand_int32: one tempered word
print(gen.random())                      # genrand_res53: 53-bit double

cp = MersenneTwister.from_key([5489])    # init_by_array: CPython-compatible
```

`from_key` reproduces `random.Random(n)` streams byte-for-byte (the module
battery checks 9 int seeds, including multi-word ones). The state indexes and
masks match CPython's, so `getstate()`/`setstate()` speak the same layout.

### The attack — 624 outputs are the whole state

The tempering `(y>>11) ^ (y<<7 & 0x9d2c5680) ^ (y<<15 & 0xefc60000) ^ (y>>18)`
is XOR-linear, **not a hash**: `untemper()` inverts it in microseconds, and 624
untempered outputs *are* the internal state — no matter where the 624-window
starts (the battery clones from strided windows and predicts 300 future draws
each time).

```python
from multirandom.prng_unsecure.mersenne_twister import (
    MersenneTwister, clone_rng_from_outputs, untemper,
)

clone = clone_rng_from_outputs(observed_words)   # the real generator, cloned
print(clone.roll())                              # the true next draw, forever
print(hex(untemper(observed_words[0])))          # one state word, from one output
```

Recovers, predicts and replays a stream of period 2^19937 — the reason a
one-way CSPRNG (see [csprng](csprng.md)) exists at all.

## LCGs — `lcg`

`LCGs` implements linear congruential generators exactly as they are written
in textbooks: the forward formula is user-supplied, so nothing is hidden.

| Arg | Meaning |
|---|---|
| `rules` (required) | forward formula acting on state `s`, e.g. `"(s * a + c) % d"` |
| `reverse_rules` | the inverse formula — passing it *is* the exercise, e.g. `"((s - c) * pow(a, -1, d)) % d"` |
| `s` | the state (seed); randomised by default |
| `a`, `b`, `c`, `d` | multiplier / legacy slot / increment / modulus (defaults 10 / 3 / 5 / 25565) |

```python
from multirandom.prng_unsecure.lcg import LCGs

# (a, d) must be coprime for the modular multiplicative inverse to exist:
g = LCGs("(s * a + c) % d", "((s - c) * pow(a, -1, d)) % d",
         s=7, a=3, c=5, d=10007)
print(g.roll())            # advance: (7*3 + 5) % 10007 -> 26
print(g.reverse_roll())    # walk backwards: 7 — the state is fully known
print(g.randint())         # the raw state integer
print(g.random())          # a bit, derived from the roll
```

Without `reverse_rules`, `reverse_roll()` raises `ValueError` — the generator
keeps the one-way mask off deliberately. Given a few consecutive outputs, the
state (and hence every past and future output) can always be recovered via the
modular multiplicative inverse; the module just makes the recovery explicit.

## Flash Player — `flash_player_prng`

A verbatim re-implementation of Adobe Flash Player's `Math.random()` PRNG —
the avmplus `core/MathUtils.cpp` pipeline (`RandomFastNext` →
`RandomPureHasher` → `GenerateRandomNumber`), including the reversal attacks
that ended it, transcribed from the working exploit.

The generator: a 32-bit LFSR state `u_value` (XOR mask `0x48000000`, a
maximal `2^31 − 1` sequence) is stepped, multiplied by the prime 71, hashed
twice through `((x << 13) ^ x) − (x >> 21)` around Flash's obfuscated
third-order polynomial (`0x3d73` / `0xc0ae5` / `0x2df722f3`), and cut to its
low 31 bits — so at most ~`2^31` distinct values exist and the state hides
nothing.

```python
from multirandom.prng_unsecure.flash_player_prng import FlashPRNGSimulator

sim = FlashPRNGSimulator(0x12345678)
print(sim.generate_random_number())   # one Math.random() draw, 31 bits
print(sim.random())                   # the real float: draw / 2**31
```

### The attack — one observed value recovers the full state

The reversal kernels are transcribed verbatim from
[CVE-2017-3000](https://github.com/dangokyo/CVE-2017-3000)'s `Exploiter.as`
and invert the pipeline one stage at a time, from the observed constant
backwards:

| Pipeline stage | Kernel |
|---|---|
| outer XOR-shift wrap | `solve_hash_reverse` |
| the polynomial | `solve_bit_reverse` (bit-by-bit DFS — every bit *k* of `poly` depends only on input bits ≤ *k*) |
| inner XOR-shift wrap | `solve_hash_reverse` |
| the `* 71` | `solve_multi_reverse` (`71 * 60492497 == 2^32 − 9`) |

`recover_state_from_output` wires the chain together with the exploit's
`matchTarget`-style forward verification (~`2^21` loop steps per
hash-reversal, the CVE's original speed; [eprint
2019/086](https://eprint.iacr.org/2019/086) trims the same pipeline to
O(2^11)):

```python
states = recover_state_from_output(0x39F5743C, next_output=0x5C477E4E)
print([hex(s) for s in states])
# ['0x82345679', '0x12345678'] - stream-identical LFSR twins

future = FlashPRNGSimulator(states[-1])
print([hex(future.generate_random_number()) for _ in range(3)])
# ['0x39f5743c', '0x5c477e4e', '0x40e12d70'] - the whole future stream
```

With the state back, Flash's constant blinding — the anti-JIT-spraying
mitigation the PRNG was built for — dies with it. `match_target(state,
rounds, target)` verifies candidates the way the exploit does.

`flash_rand_and_reverse.py` (the old placeholder) is gone from the tree; the
working Flash Player PRNG and its reversal attacks live in
`flash_player_prng.py` above.

## IBM's RANDU — `randu`

The most infamous PRNG ever shipped: `x' = 65539 * x mod 2^31` with
65539 = 2^16 + 3, so triples `(x1, x2, x3)` satisfy
`x3 == 6*x2 - 9*x1 (mod 2^31)` and collapse onto 15 parallel planes —
Marsaglia's "random numbers fall mainly in the planes" (1968). One output
recovers the previous state (and the seed) via the modular multiplicative
inverse.

```python
from multirandom.prng_unsecure.randu import RANDU

gen = RANDU(seed=1)
clone = RANDU.from_outputs([gen.roll()])   # one draw is one full recovery
```

## Middle Square — `middle_square`

Von Neumann's 1949 proposal: square the seed, keep the middle digits. It
degenerates to zero (and short cycles) quickly — which is the lesson — plus
the modern MSWS (middle square Weyl sequence) variant that actually works.

## Doom — `doom_prng`

The generator behind every shotgun spread in Doom (1993): one 256-byte
lookup table (transcribed verbatim from Id's `m_random.c`) and an index that
walks it, increment first. Period exactly 256; the table is not even a
permutation. `P_SubRandom()` is the source's own `P_Random() - P_Random()`
spread — which, eating two draws per call, only ever visits even indexes and
carries an exact ±12.171875 mean bias. One observed draw pins the index to
the table positions containing that byte; `from_outputs` refuses ambiguous
leaks instead of guessing.

```python
from multirandom.prng_unsecure.doom_prng import DoomRandom

doom = DoomRandom()
doom.P_Random()                       # 8 — rndtable[1], increment-then-index
clone = DoomRandom.from_outputs([8, 109, 220])
```

## SplitMix64 — `splitmix64`

Steele, Lea & Flood's counter-based mixer (the recommended seeding engine of
the xoshiro family): a golden-ratio counter through two multiply-xorshift
rounds. A pure counter under a known mixer — the n-th output is computable
directly as `splitmix64_mix(s0 + n * 0x9E3779B97F4A7C15)`, and `from_outputs`
inverts the mixer exactly from one observed word.

```python
from multirandom.prng_unsecure.splitmix64 import SplitMix64

sim = SplitMix64(0)
sim.next_u64()        # 16294208416658607535 — the canonical seed-0 stream
clone = SplitMix64.from_outputs([0xE220A83976B7AF3D])
```

## Lagged Fibonacci — `lagged_fibonacci`

The family inside BSD libc's `random()`: `w[i] = w[i-j] ± w[i-k] mod 2^32`,
preset to the BSD-style LF(31, 3) with a MINSTD (16807) warmup filling the
state. The additive structure leaves the state naked: the last `j`
consecutive full-width outputs ARE the current state, in generation order.

```python
from multirandom.prng_unsecure.lagged_fibonacci import LaggedFibonacci

gen = LaggedFibonacci("seed")             # LF(31, 3), MINSTD warmup
clone = LaggedFibonacci.from_outputs([gen.roll() for _ in range(31)])
```

## PCG32 — `pcg`

Melissa O'Neill's PCG32 (2014): a 64-bit LCG with a 64-bit stream id under
the XSH-RR output permutation. Statistically excellent — and still listed
unsecure, because the core is affine and the seed is recoverable in practice.
The honest catch is documented in the module: `from_outputs` is deliberately
absent (the permutation hides 32 state bits per draw, ~2^32 brute force per
word); what IS provided is `from_state` for leaked raw state and a
closed-form `jump()` that skips a billion outputs in one multiply.

```python
from multirandom.prng_unsecure.pcg import PCG32

g = PCG32(seed=42, seq=54)      # the Rosetta Code vector
g.jump(1_000_000_000)           # a billion outputs, one call
```

## V8's Math.random — `v8_xorshift128plus`

The xorshift128+ engine behind `Math.random()` in Chromium and Node: two
64-bit words, all shifts and xors, with V8's exact `ToDouble` (the new
state0's low 52 mantissa bits on the [1, 2) exponent). Successive floats
expose the low 52 bits of successive state words — every bit a linear
function over GF(2) — so five consecutive `Math.random` outputs are 260
linear equations. `from_outputs` runs the step symbolically on 128
bit-masks, Gaussian-eliminates, and hands back the exact generator.

```python
from multirandom.prng_unsecure.v8_xorshift128plus import V8XorShift128Plus

v8 = V8XorShift128Plus(seed="demo")
clone = V8XorShift128Plus.from_outputs([v8.random() for _ in range(5)])
assert clone.getstate() == v8.getstate()   # Math.random, predicted exactly
```

## Where to go next

- [Cryptographic randomness (`csprng`)](csprng.md) — what to use where it matters
- [Self-checks](self-checks.md) — every module ships its own assert battery:
  `py -3 -m multirandom.prng_unsecure.v8_xorshift128plus` solves Math.random
  live; `...doom_prng` replays the lookup table; `...pcg` races the jump.
