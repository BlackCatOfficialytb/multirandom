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

## Coming soon

`flash_rand_and_reverse.py` remains the placeholder it always was (it prints
`coming soon :/`); the working Flash Player PRNG and its reversal attacks live
in `flash_player_prng.py` above, and further specialized PRNGs will land in
its own module when ready.

## Where to go next

- [Cryptographic randomness (`csprng`)](csprng.md) — what to use where it matters
- [Self-checks](self-checks.md) — `py -3 -m multirandom.prng_unsecure.xor_shift` verifies all 18 generators
