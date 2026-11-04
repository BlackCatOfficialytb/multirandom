"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.prng_unsecure.flash_player_prng
Description:
A faithful reimplementation of Adobe Flash Player's ``Math.random()`` PRNG and
the attacks that broke it.

The generator lives in avmplus ``core/MathUtils.cpp`` (``RandomFastNext`` /
``RandomPureHasher`` / ``GenerateRandomNumber`` / ``MathUtils::random()``,
L1620-L1723): a 32-bit LFSR state (``TRandomFast.uValue``, seeded from the
performance counter, XOR mask ``0x48000000``, sequence length ``2^31 - 1``) is
stepped, multiplied by the prime ``71`` and pushed through an XOR-shift wrap
around a third-order odd polynomial; only the low 31 bits (``kRandomPureMax``)
survive, so ``Math.random()`` can take at most ~2 ** 31 values and the state
hides nothing. Flash shipped this design with obfuscated polynomial constants
(``0x3d73`` / ``0xc0ae5`` / ``-0x2df722f3`` -- the avmplus repository carries
the old Graphics Gems values ``15731`` / ``789221`` / ``1376312589`` instead),
which did not save it:

* CVE-2017-3000 (dangokyo ``Exploiter.as``) recovers the inner LFSR state from
  a single observed constant, bypassing Flash's constant blinding anti-JIT
  spraying mitigation;
* George Teseleanu, "Reinterpreting and Improving the Cryptanalysis of the
  Flash Player PRNG", Cryptology ePrint Archive 2019/086, C2SI 2019 -- shows
  the construction stays weak for any parameters and improves seed recovery to
  O(2^11).

Arithmetic is transcribed as shipped: :class:`FlashPRNGSimulator` carries the
forward pipeline (``random_fast_next`` -> ``random_pure_hash((x * 71) mod 2^32)``
-> ``& 0x7fffffff``), plus the matching ``Math.random()`` bridge. The reversal
kernels are ported from ``Exploiter.as`` verbatim: ``solve_hash_reverse`` and
``solve_bit_reverse`` (completed with the ``solve_bit_reverse`` driver), plus
the missing ``solve_multi_reverse`` and ``match_target`` drivers, and the
high-level :func:`recover_state_from_output` attack that rebuilds the LFSR
state (up to its stream-identical LFSR twin) from ONE 31-bit ``Math.random()``
value and predicts the complete future stream. Insecure by design:
constructing the simulator warns once per process via the package's global
warning flag.

Run this module to execute its assert-based self-checks::

    py -3 -m multirandom.prng_unsecure.flash_player_prng
"""
import warnings

# Safety Warnings -- routed through the package's global warning flag
# multirandom.ignore_unsecure_prng_warning_do_not_set_to_true_unless_you_know_how_risky_it_is
try:
    from .. import _warn_unsecure
except ImportError:  # running as a plain script
    def _warn_unsecure(message, stacklevel=3):
        # Same contract as the package root's helper: silenced by the global
        # flag even when this module is executed outside the package.
        try:
            import multirandom
            if multirandom.ignore_unsecure_prng_warning_do_not_set_to_true_unless_you_know_how_risky_it_is:
                return
        except (ImportError, AttributeError):
            pass
        warnings.warn(message, stacklevel=stacklevel)


# --- Constants straight from the C source (avmplus /core/MathUtils.cpp) ------
# core/MathUtils.h L43: #define kRandomPureMax 0x7FFFFFFFL
K_RANDOM_PURE_MAX = 0x7FFFFFFF
# core/MathUtils.cpp L1555-L1562: Random_Xor_Masks -- entry [29] is picked by
# RandomFastInit (L1586-L1597) for a 2^31 - 1 long sequence.
K_RANDOM_XOR_MASK = 0x48000000
K_SEQUENCE_LENGTH = (1 << 31) - 1
# core/MathUtils.cpp L1697: aNum = RandomPureHasher(aNum * 71L);
K_STATE_MULTIPLIER = 71
# Flash Player's shipped (obfuscated) replacements for the Graphics Gems
# coefficients c1/c2/c3 in RandomPureHasher (L1544-L1546: 15731/789221/...):
K_POLY_C3 = 0x3D73
K_POLY_C2 = 0xC0AE5
K_POLY_C1 = 0x2DF722F3
# Exploiter.as solveMultiReverse magic number: 2**32 % 71 == 9, hence
# k = (2**32 - 9) / 71 -- 71 * k = 2**32 - 9 exactly.
K_MULTI_REVERSE_71_INVERSE_STEP = 60492497

_FLASH_UNSECURE_WARNING = (
    "FlashPRNGSimulator reproduces Adobe Flash Player's Math.random(), one of "
    "the most attackable PRNGs in history: its full state is recoverable from "
    "a single 31-bit output (CVE-2017-3000; eprint 2019/086). Fine for a "
    "history lesson - never for guarding anything.")

_flash_warning_state = {"warned": False}


class FlashPRNGSimulator:
    """
    Adobe Flash Player's ``Math.random()`` PRNG, transcribed verbatim.

    State: the unsigned 32-bit ``u_value`` (the ``TRandomFast.uValue`` field of
    the shipped implementation).

    One value = :meth:`random_fast_next` (LFSR step of a maximal 2^31 - 1
    sequence) -> :meth:`random_pure_hash` of ``state * 71 mod 2^32`` (double
    XOR-shift wrap around a third-order odd polynomial) -> keep the low 31
    bits (``kRandomPureMax``). The degree-3 polynomial is built from the
    obfuscated constants Flash shipped (``0x3d73`` / ``0xc0ae5`` /
    ``0x2df722f3``); see the avmplus sources for the original ones.

    Constructing warns once per process (governed by the package's global
    warning flag).
    """

    def __init__(self, u_value: int):
        """Initialize the generator from any 64-bit int (masked to 32 bits)."""
        if not _flash_warning_state["warned"]:
            _flash_warning_state["warned"] = True
            _warn_unsecure(_FLASH_UNSECURE_WARNING)
        self.u_value = u_value & 0xFFFFFFFF

    def poly(self, seed: int) -> int:
        """The obfuscated third-order odd polynomial ``seed^3 * c3 ...``.

        Perlin-style "better than linear" hashing of the wrapped seed:
        ``(seed * (seed^2 * 0x3d73 + 0xc0ae5) - 0x2df722f3) & 0x7fffffff`` plus
        the seed back again (avmplus ``RandomPureHasher`` L1671-L1680 calls
        through the ``c1``/``c2``/``c3`` macros).
        """
        seed = seed & 0xFFFFFFFF
        ans = (seed * seed) & 0xFFFFFFFF
        ans = (ans * 0x3d73) & 0xFFFFFFFF
        ans = (ans + 0xc0ae5) & 0xFFFFFFFF
        ans = (seed * ans) & 0xFFFFFFFF
        ans = (ans - 0x2df722f3) & 0xFFFFFFFF
        ans = ans & 0x7fffffff
        ans = (ans + seed) & 0xFFFFFFFF
        return ans

    def random_fast_next(self) -> int:
        """The ``TRandomFast`` LFSR step (avmplus ``RandomFastNext`` L1620-1625).

        ``u_value = (u_value >> 1) ^ 0x48000000`` when odd, plain
        ``u_value >> 1`` otherwise; returns the new state. Maximal period of
        ``2^31 - 1`` values.
        """
        if self.u_value & 1:
            self.u_value = ((self.u_value >> 1) ^ 0x48000000) & 0xFFFFFFFF
        else:
            self.u_value = (self.u_value >> 1) & 0xFFFFFFFF
        return self.u_value

    def random_pure_hash(self, seed: int) -> int:
        """The double-wrap pure hasher (avmplus ``RandomPureHasher`` L1662-1688).

        ``(seed << 13) ^ seed - (seed >> 21)``, through :meth:`poly`, and the
        same wrap once more -- "a hash: it will not work well if you pass its
        own output in as the next input" (avmplus L1642).
        """
        seed = seed & 0xFFFFFFFF
        t1 = (((seed << 13) & 0xFFFFFFFF) ^ seed) & 0xFFFFFFFF
        val = (t1 - (seed >> 21)) & 0xFFFFFFFF

        ans = self.poly(val)

        t2 = (((ans << 13) & 0xFFFFFFFF) ^ ans) & 0xFFFFFFFF
        final_val = (t2 - (ans >> 21)) & 0xFFFFFFFF
        return final_val & 0xFFFFFFFF

    def generate_random_number(self) -> int:
        """One ``Math.random()`` draw: a 31-bit integer in ``[0, 2^31)``.

        avmplus ``GenerateRandomNumber`` L1690-L1703: ``RandomFastNext()``,
        ``RandomPureHasher(a_num * 71)``, ``& kRandomPureMax``. The final mask
        throws away the top bit -- the very lost bit the reversal attacks
        must brute-force.
        """
        a_num = self.random_fast_next()
        a_num = self.random_pure_hash((a_num * 71) & 0xFFFFFFFF)
        return a_num & 0x7fffffff

    def random(self) -> float:
        """``Math.random()`` itself: the draw divided by ``2^31``
        (avmplus ``MathUtils::random()`` L1719-L1721) -- a float in [0.0, 1.0)."""
        return self.generate_random_number() / (K_RANDOM_PURE_MAX + 1.0)


# --- Reversing and Solving Helpers (Ported from Exploiter.as, CVE-2017-3000)
# The attack inverts the pipeline one stage at a time, from the observed
# constant backwards:  outer wrap -> poly -> inner wrap -> *71 -> LFSR state.

def solve_hash_reverse(target: int) -> list[int]:
    """Recover every candidate input of the XOR-shift wrap kernel.

    ``Exploiter.as`` ``solveHashReverse`` (verbatim): finds all 32-bit *value*
    with ``((value << 13) ^ value) - (value >> 21) == target`` by noting the
    wrap's low 11 bits satisfy ``lo == (up + (target & 0x7ff)) & 0x7ff`` (so
    ``up`` alone forces ``lo``), then scanning only the 10 middle bits.
    Same "I am just lazy here" double loop as the ActionScript original.
    """
    ans = []
    tmp = []
    # Reversing the hash bits step by step
    for up_part in range(0x800):
        for lo_part in range(0x800):
            if ((up_part + (target & 0x7ff)) & 0x7ff) == lo_part:
                tmp.append((up_part << 21) + lo_part)

    for val_item in tmp:
        for mi_part in range(0x400):
            value = val_item + (mi_part << 11)
            t = (((value << 13) ^ value) - (value >> 21)) & 0xFFFFFFFF
            if t == (target & 0xFFFFFFFF):
                ans.append(value)
                break
    return ans


def solve_bit_reverse_helper(target: int, target_bit: int, ans: list[int], sol: int, prng_sim: FlashPRNGSimulator):
    """``Exploiter.as`` ``solveBitReverseHelper`` (verbatim).

    DFS that rebuilds the polynomial's input bit by bit from the least
    significant upwards: every bit of :meth:`FlashPRNGSimulator.poly`'s result
    depends only on the input's bits *below or equal* to it (mod-2^32
    multiplication/subtraction structs carry upward only), so fixing each bit
    locally is sound. ``ans`` collects every solution with
    ``poly(sol) == target``.
    """
    if target_bit == 32:
        ans.append(sol)
        return

    # Try bit 0
    tmp = sol + (0 << target_bit)
    if (prng_sim.poly(tmp) & (1 << target_bit)) == (target & (1 << target_bit)):
        solve_bit_reverse_helper(target, target_bit + 1, ans, tmp, prng_sim)

    # Try bit 1
    tmp = sol + (1 << target_bit)
    if (prng_sim.poly(tmp) & (1 << target_bit)) == (target & (1 << target_bit)):
        solve_bit_reverse_helper(target, target_bit + 1, ans, tmp, prng_sim)


def solve_bit_reverse(target: int, prng_sim: FlashPRNGSimulator) -> list[int]:
    """Driver for the bit-reversal DFS (``Exploiter.as`` ``solveBitReverse``).

    Returns every ``x`` with ``prng_sim.poly(x & 0xFFFFFFFF) == target`` (the
    polynomial is not injective, so several solutions may come back).
    """
    ans = []
    solve_bit_reverse_helper(target & 0xFFFFFFFF, 0, ans, 0, prng_sim)
    return ans


def solve_multi_reverse(target: int) -> list[int]:
    """Recover pre-71 candidates of the multiply step (``solveMultiReverse``).

    ``Exploiter.as`` verbatim. ``create states u`` (32-bit) with
    ``u * 71 == target`` as 32-bit integers, i.e. ``71 * u = target + i * 2^32``
    for one exact ``i < 71``. Because ``2^32 % 71 == 9`` and
    ``71 * 60492497 == 2^32 - 9``, the candidate odd part reduces to
    ``t = 60492497 * i + q + (i * 9 + r) / 71``. Only one ``i`` in the loop can
    satisfy ``(i * 9 + r) % 71 == 0`` (9 and 71 are coprime), so exactly one
    ``t`` exists -- equal to the plain ``target * pow(71, -1, 2**32)`` shortcut.
    Forwards both LFSR-twin predecessors ``(t << 1)`` and
    ``((t ^ 0x48000000) << 1) + 1`` of
    :meth:`FlashPRNGSimulator.random_fast_next`, since the lost top bit and
    parity are indistinguishable from the outside.
    """
    ans = []
    target &= 0xFFFFFFFF
    r = target % 71
    q = (target - r) // 71
    for i in range(71):
        if (i * 9 + r) % 71 == 0:
            t = 60492497 * i
            t = t + q
            t = t + (i * 9 + r) // 71
            ans.append((((t ^ 0x48000000) << 1) + 1) & 0xFFFFFFFF)
            ans.append((t << 1) & 0xFFFFFFFF)
    return ans


def match_target(u_value: int, rounds: int, target: int) -> bool:
    """Forward-verification of a candidate state (``Exploiter.as`` ``matchTarget``).

    Builds :class:`FlashPRNGSimulator`(u_value), draws ``rounds`` numbers and
    reports whether the last one equals ``target`` -- exactly how the exploit
    tells the true recovered LFSR state from garbage candidates.
    """
    rg = FlashPRNGSimulator(u_value)
    ans = 0
    for _ in range(rounds):
        ans = rg.generate_random_number()
    return ans == target


def recover_state_from_output(
    first_output: int,
    next_output: int | None = None,
) -> list[int]:
    """Run the full CVE-2017-3000-style state-recovery attack in Python.

    Given ONE observed ``Math.random()`` draw (31 bits; the C code mask
    destroys bit 31), reconstructs every LFSR state whose future stream starts
    with it. The lost top bit of the doubled draw is brute-forced the same way
    ``Exploiter.as.reverseConstant`` does (``constant1 ^ 0x80000000``), then
    the chain walks backwards stage by stage::

        solve_hash_reverse      # undo the outer XOR-shift wrap
        solve_bit_reverse       # undo the poly (bit-by-bit DFS)
        solve_hash_reverse      # undo the inner XOR-shift wrap
        solve_multi_reverse     # undo the * 71, restore the LFSR state

    Every candidate is then confirmed against the observed draw (and, when
    given, ``next_output``) via :func:`match_target`. Returns the verified
    states, lowest first. Streaming-identical LFSR twins legitimately
    survive (same ``u_value >> 1``, different top bit) -- all of them predict
    the same future, indistinguishably from the real Flash Player.

    Complexity: ~2 * 2048 * 1024 loop steps per hash-reversal call (O(2^21),
    the original CVE speed; eprint 2019/086 cuts this to O(2^11) but keeps
    the same pipeline).
    """
    first_output &= K_RANDOM_PURE_MAX
    candidates: list[int] = []
    for h3 in (first_output, (first_output ^ 0x80000000) & 0xFFFFFFFF):
        for h2 in solve_hash_reverse(h3):
            for h1 in solve_bit_reverse(h2, FlashPRNGSimulator(0)):
                for m in solve_hash_reverse(h1):
                    candidates.extend(solve_multi_reverse(m))

    verified = []
    for state in dict.fromkeys(candidates):  # dedupe, keep order
        if match_target(state, 1, first_output) and (
            next_output is None or match_target(state, 2, next_output & K_RANDOM_PURE_MAX)
        ):
            verified.append(state)
    return verified


# Output of the transcribed pipeline for fixed states (deterministic pure
# arithmetic, verified against the reference sources).
KNOWN_VECTORS = {
    0x12345678: [0x39F5743C, 0x5C477E4E, 0x40E12D70,
                 0x320EB66E, 0x7E32FB21, 0x2D02B3AB],
    0x00000001: [0x12D1C59D, 0x27F52817, 0x7AEC2911],
    0x00000002: [0x45350789, 0x12D1C59D, 0x27F52817],
    0xDEADBEEF: [0x20B50B25, 0x7ADD46D2, 0x3D70F878],
    0xFFFFFFFF: [0x2E9681D0, 0x2288CE81, 0x3677E747],
    0x80000000: [0x6EE6D8FF, 0x3ADD31C8, 0x724312E3],
    # u_value == 0 is the degenerate fixed point: TRandomFastInit would
    # reseed it, but a manually-constructed 0 state loops forever.
    0x00000000: [0x49A97A7D] * 5,
}



def main():
    print("=" * 70)
    print("flash_player_prng - Flash Player Math.random() self-check battery")
    print("=" * 70)

    _flag_name = ("multirandom."
                  "ignore_unsecure_prng_warning_do_not_set_to_true_unless_you_know_how_risky_it_is")

    # --- 1. structural constants, straight from the source files -----------
    assert K_RANDOM_PURE_MAX == 0x7FFFFFFF == (1 << 31) - 1
    assert K_SEQUENCE_LENGTH == (1 << 31) - 1
    assert K_RANDOM_XOR_MASK == 0x48000000          # Random_Xor_Masks[29]
    assert K_STATE_MULTIPLIER == 71                  # GenerateRandomNumber: * 71L
    assert K_POLY_C3 == 0x3D73 and K_POLY_C2 == 0xC0AE5 and K_POLY_C1 == 0x2DF722F3
    # Exploiter.as solveMultiReverse magic: 2**32 % 71 == 9
    assert (1 << 32) % 71 == 9
    assert K_MULTI_REVERSE_71_INVERSE_STEP == ((1 << 32) - 9) // 71
    assert 71 * K_MULTI_REVERSE_71_INVERSE_STEP == (1 << 32) - 9
    print("[1] structural constants match avmplus core/MathUtils.cpp: OK")

    # --- 2. known vectors for fixed states (deterministic pipeline) --------
    for seed, expected in KNOWN_VECTORS.items():
        got = []
        sim = FlashPRNGSimulator(seed)
        for _ in range(len(expected)):
            got.append(sim.generate_random_number())
        assert got == expected, f"seed {seed:#x}: got {[hex(x) for x in got]}"
    print("[2] known vectors for 7 states reproduce exactly: OK")

    # --- 3. output contract: always 31 bits; deterministic; seed-sensitive -
    sim_a = FlashPRNGSimulator(0x12345678)
    sim_b = FlashPRNGSimulator(0x12345678)
    stream_a = [sim_a.generate_random_number() for _ in range(10_000)]
    stream_b = [sim_b.generate_random_number() for _ in range(10_000)]
    assert all(0 <= v < (1 << 31) for v in stream_a), "output escaped 31 bits"
    assert stream_a == stream_b, "same state gave different streams"
    other = FlashPRNGSimulator(0x12345679)
    assert other.generate_random_number() != stream_a[0], "not seed sensitive"
    print("[3] 10k draws: 31-bit grid, deterministic, state-sensitive: OK")

    # --- 4. Math.random() bridge (avmplus MathUtils::random() L1719) -------
    sim = FlashPRNGSimulator(0x12345678)
    rnd = [sim.random() for _ in range(1_000)]
    assert all(0.0 <= x < 1.0 for x in rnd), "Math.random() left [0, 1)"
    assert rnd[0] == KNOWN_VECTORS[0x12345678][0] / (1 << 31)
    print("[4] Math.random() float bridge == draw / 2**31: OK")

    # --- 5. kernel roundtrips: every stage of the pipeline inverts ---------
    sim = FlashPRNGSimulator(0xDEADBEEF)
    # poly^-1 (cheap DFS):solve_bit_reverse returns solutions containing x
    for probe_state in (0, 1, 0x12345678 ^ 0x9E3779B9):
        x = sim.poly(probe_state)
        assert probe_state in solve_bit_reverse(x, FlashPRNGSimulator(0)), \
            f"poly^-1 lost {probe_state:#x}"
    # *71^-1: solve_multi_reverse recovers the LFSR predecessor
    inv71 = pow(71, -1, 1 << 32)                     # the O(1) shortcut
    for probe_state in (0x12345678, 0xDEADBEEF, 0x1, 0x80000001):
        sim = FlashPRNGSimulator(probe_state)
        a_num = sim.random_fast_next()
        m = (a_num * 71) & 0xFFFFFFFF
        assert probe_state in solve_multi_reverse(m), \
            f"*71^-1 lost state {probe_state:#x}"
        assert (m * inv71) & 0xFFFFFFFF == a_num     # unique modular solution
    print("[5] poly^-1 (DFS) and *71^-1 (multi_reverse) roundtrips: OK")

    # --- 6. THE attack: full state recovery from ONE Math.random() draw ----
    print("[6] running the full CVE-2017-3000 chain (this takes ~10 s) ...")
    state = 0x12345678
    sim = FlashPRNGSimulator(state)
    r1, r2, r3, r4 = (sim.generate_random_number() for _ in range(4))
    states = recover_state_from_output(r1, next_output=r2)
    assert state in states, f"TRUE LFSR STATE LOST: {[hex(s) for s in states]}"
    assert all(match_target(s, 1, r1) and match_target(s, 2, r2) for s in states)
    for cand in states:                              # all survivors predict alike
        future = FlashPRNGSimulator(cand)
        replay = [future.generate_random_number() for _ in range(4)]
        assert replay == [r1, r2, r3, r4], \
            f"state {cand:#x} deviates from the real future"
    assert sorted(states) == sorted([0x12345678, 0x82345679]), \
        f"unexpected survivor set: {[hex(s) for s in states]}"
    print(f"[6] state {state:#x} recovered from one draw {r1:#x}; "
          f"survivors {[hex(s) for s in states]} all predict r3={r3:#x}, r4={r4:#x}: OK")

    # --- 7. prediction: the recovered state reproduces the whole stream ----
    predicted = []
    future = FlashPRNGSimulator(states[0])
    for _ in range(7):
        predicted.append(future.generate_random_number())
    truth = FlashPRNGSimulator(state)
    observed = [truth.generate_random_number() for _ in range(7)]
    assert predicted == observed, "recovered state diverged from the true stream"
    print("[7] 7 draws replayed identically from the recovered state: OK")

    # --- 8. the once-per-process warning, and the global silencer ---------
    try:
        import multirandom
    except ImportError:                              # running as a plain script
        multirandom = None
    _flag_name = ("multirandom."
                  "ignore_unsecure_prng_warning_do_not_set_to_true_unless_you_know_how_risky_it_is")
    if multirandom is None:
        print(f"[8] global-flag test skipped (plain script; run via "
              f"py -3 -m multirandom.prng_unsecure.flash_player_prng to test it)")
    else:
        flag = multirandom.ignore_unsecure_prng_warning_do_not_set_to_true_unless_you_know_how_risky_it_is
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                _flash_warning_state["warned"] = False
                FlashPRNGSimulator(0xBAD)
                _flash_warning_state["warned"] = True
            assert any(_FLASH_UNSECURE_WARNING in str(w.message) for w in caught), \
                "unsecure warning went missing"

            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                multirandom.ignore_unsecure_prng_warning_do_not_set_to_true_unless_you_know_how_risky_it_is = True
                _flash_warning_state["warned"] = False
                FlashPRNGSimulator(0xBAD)
                assert not caught, "global flag failed to silence the warning"
        finally:
            _flash_warning_state["warned"] = True
            multirandom.ignore_unsecure_prng_warning_do_not_set_to_true_unless_you_know_how_risky_it_is = flag
        print(f"[8] warning fires once, silenced by {_flag_name} = True: OK")

    print("-" * 70)
    print("All flash_player_prng checks passed!")


if __name__ == "__main__":
    main()
