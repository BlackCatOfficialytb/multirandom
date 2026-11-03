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

## LCGs — `rand_using_virt_lcg`

`LCGs` implements linear congruential generators exactly as they are written
in textbooks: the forward formula is user-supplied, so nothing is hidden.

| Arg | Meaning |
|---|---|
| `rules` (required) | forward formula acting on state `s`, e.g. `"(s * a + c) % d"` |
| `reverse_rules` | the inverse formula — passing it *is* the exercise, e.g. `"((s - c) * pow(a, -1, d)) % d"` |
| `s` | the state (seed); randomised by default |
| `a`, `b`, `c`, `d` | multiplier / legacy slot / increment / modulus (defaults 10 / 3 / 5 / 25565) |

```python
from multirandom.prng_unsecure.rand_using_virt_lcg import LCGs

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

## Coming soon

`flash_rand_and_reverse.py` — specialized PRNGs (placeholder in the tree).

## Where to go next

- [Cryptographic randomness (`csprng`)](csprng.md) — what to use where it matters
- [Self-checks](self-checks.md) — `py -3 -m multirandom.prng_unsecure.xor_shift` verifies all 18 generators
