"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.prng_unsecure.splitmix64
Description:
Steele, Lea & Flood's SplitMix64 (2014, splittable random; popularized by
Vigna's xoshiro paper as the recommended *seeding* engine): a pure
counter-based mixer::

    state += 0x9E3779B97F4A7C15              # the golden ratio, mod 2^64
    z = state
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
    z = (z ^ (z >> 27)) * 0x94D049BB133111EB
    return z ^ (z >> 31)

two multiplicative-xor rounds in reverse-strength order, one output per
state increment, bijection all the way down: every one of the 2^64 states
starts a stream of 2^64 distinct outputs.  SplitMix64 is what serious
generators (xoshiro256**, PCG's seeding tests) use to expand a single
integer seed into full state -- NOT what they use to generate: it is a
pure counter under a known mixer, so the state after ``n`` steps is
``s0 + n * gamma`` with no entropy ever stirred in -- one observed output
pins the whole stream, and the n-th future output is computable directly
without touching the generator.  Kept here for the history, for the
seeding idiom, and because its reversal is the cleanest in the family:
:meth:`SplitMix64.from_outputs` inverts both multiplies (Newton's inverse
mod 2^64) and the xorshifts around them -- one observed output is one
exact state.

Run this module to execute its assert-based self-checks::

    py -3 -m multirandom.prng_unsecure.splitmix64
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


_SPLITMIX64_MODULUS = 2 ** 64
GOLDEN_GAMMA = 0x9E3779B97F4A7C15   # the golden ratio conjugate (gamma, "γ")
MIX_MUL_1 = 0xBF58476D1CE4E5B9     # after the >>30 xorshift
MIX_MUL_2 = 0x94D049BB133111EB     # after the >>27 xorshift

_SPLITMIX64_UNSECURE_WARNING = (
    "SplitMix64 is a pure counter under a known mixer -- a single observed "
    "output pins the whole stream (from_outputs recovers it exactly) and "
    "future outputs are computable directly. It is a seeding engine, not a "
    "generator. For actual randomness use csprng.")

_splitmix64_warning_state = {"warned": False}


def _inv_shift(x: int, s: int) -> int:
    """Invert ``x ^= x >> s`` over 64-bit words: x>>s ^ x>>2s ^ x>>4s ..."""
    x ^= x >> s
    x ^= x >> (2 * s)
    x ^= x >> (4 * s)
    return x & (_SPLITMIX64_MODULUS - 1)


def _unmix(y: int) -> int:
    """The exact inverse of the SplitMix64 output mixer: y -> state."""
    y &= _SPLITMIX64_MODULUS - 1
    z = _inv_shift(y, 31)                       # undo z ^= z >> 31
    z = z * pow(MIX_MUL_2, -1, _SPLITMIX64_MODULUS) % _SPLITMIX64_MODULUS
    z = _inv_shift(z, 27)                       # undo z ^= z >> 27
    z = z * pow(MIX_MUL_1, -1, _SPLITMIX64_MODULUS) % _SPLITMIX64_MODULUS
    z = _inv_shift(z, 30)                       # undo z ^= z >> 30
    return z


def splitmix64_mix(state: int) -> int:
    """The mixer alone: one SplitMix64 output word from a given state value."""
    z = (state + GOLDEN_GAMMA) & (_SPLITMIX64_MODULUS - 1)
    z = ((z ^ (z >> 30)) * MIX_MUL_1) & (_SPLITMIX64_MODULUS - 1)
    z = ((z ^ (z >> 27)) * MIX_MUL_2) & (_SPLITMIX64_MODULUS - 1)
    return z ^ (z >> 31)


class SplitMix64:
    """
    The SplitMix64 counter-mixer, one 64-bit output per golden-ratio step.

    ``next_u64()``/``roll()`` advance the counter and return the full
    64-bit word; ``random()`` is Vigna's 53-bit double conversion,
    ``(word >> 11) * 2^-53``; ``jump(n)`` skips a million cheques in one
    multiply.  Constructing warns once per process (governed by the
    package's global warning flag).
    """

    def __init__(self, seed: int = 0):
        if not _splitmix64_warning_state["warned"]:
            _splitmix64_warning_state["warned"] = True
            _warn_unsecure(_SPLITMIX64_UNSECURE_WARNING)
        self._counter = int(seed) & (_SPLITMIX64_MODULUS - 1)

    def next_u64(self) -> int:
        """Advance by the golden ratio, then run the mixer (the splitmix step)."""
        self._counter = (self._counter + GOLDEN_GAMMA) & (_SPLITMIX64_MODULUS - 1)
        return splitmix64_mix(self._counter - GOLDEN_GAMMA)

    roll = next_u64  # the package-common alias for the same operation

    def jump(self, n: int) -> None:
        """Skip ``n`` outputs in O(1): the counter is (s0 + n * gamma) mod 2^64."""
        self._counter = (self._counter + n * GOLDEN_GAMMA) & (_SPLITMIX64_MODULUS - 1)

    def random(self) -> float:
        """Vigna's 53-bit double conversion: (next_u64() >> 11) * 2^-53."""
        return (self.next_u64() >> 11) * (2.0 ** -53)

    def getrandbits(self, k: int) -> int:
        """``k`` bits stitched from successive 64-bit words, high bits first."""
        if k < 0:
            raise ValueError("number of bits must be non-negative")
        if k == 0:
            return 0
        words = (k + 63) // 64
        value = 0
        for _ in range(words):
            value = (value << 64) | self.next_u64()
        return value >> (words * 64 - k)

    def randbytes(self, n: int) -> bytes:
        """``n`` bytes of output, little-endian per 64-bit word."""
        out = bytearray()
        while len(out) < n:
            out += self.next_u64().to_bytes(8, "little")
        return bytes(out[:n])

    def getstate(self) -> tuple:
        """Raw state: the golden-ratio counter."""
        return (self._counter,)

    def setstate(self, state: tuple) -> None:
        """Restore ``(counter,)``; validates the 64-bit counter grid."""
        (counter,) = state
        self._counter = int(counter) & (_SPLITMIX64_MODULUS - 1)

    @classmethod
    def from_outputs(cls, outputs) -> "SplitMix64":
        """Rebuild the generator behind a leak -- positioned right after the
        last observed output.

        ``outputs``: one or more consecutive full 64-bit words.  The mixer
        is a bijection, so ``_unmix(words[0])`` lands on the first state
        (``s0 + gamma``); consistency across all observed words is proven
        by the golden-ratio walk between them.
        """
        words = [int(w) & (_SPLITMIX64_MODULUS - 1) for w in outputs]
        if not words:
            raise ValueError("need at least one observed output")
        if not _splitmix64_warning_state["warned"]:
            _splitmix64_warning_state["warned"] = True
            _warn_unsecure(_SPLITMIX64_UNSECURE_WARNING)
        states = [_unmix(w) for w in words]
        for a, b in zip(states, states[1:]):
            if b != (a + GOLDEN_GAMMA) & (_SPLITMIX64_MODULUS - 1):
                raise ValueError(
                    "the observed outputs are not consecutive SplitMix64 words")
        gen = cls.__new__(cls)
        gen._counter = states[-1]
        return gen


if __name__ == "__main__":
    print("=" * 70)
    print("splitmix64 - Steele/Lea/Flood's SplitMix64 self-check battery")
    print("=" * 70)

    # --- 1. the published anchors ---------------------------------------------
    assert GOLDEN_GAMMA == 0x9E3779B97F4A7C15, "the golden-ratio gamma drifted"
    assert splitmix64_mix(1477776061723855037) == 1985237415132408290, \
        "the xoshiro paper's worked example drifted"
    sim = SplitMix64(0)
    got = [sim.next_u64() for _ in range(5)]
    expected = [16294208416658607535, 7960286522194355700, 487617019471545679,
                17909611376780542444, 1961750202426094747]
    assert got == expected, f"the canonical seed-0 stream drifted: {got}"
    assert SplitMix64(0).next_u64() == expected[0], "fresh instances disagree"
    print("[1] xoshiro paper anchor + canonical seed-0 stream, exact: OK")

    # --- 2. the mixer's inverse is exact ----------------------------------------
    mask = _SPLITMIX64_MODULUS - 1
    for probe in (0, 1, 2, mask, 1985237415132408290,
                  12345678901234567890, 0xDEADBEEFCAFEBABE):
        # splitmix64_mix includes the gamma increment, so its exact inverse
        # lands one step ahead: unmix(mix(s)) == s + gamma
        assert _unmix(splitmix64_mix(probe)) == (probe + GOLDEN_GAMMA) & mask, \
            f"mix/unmix is not an exact inverse pair for {probe:#x}"
    print("[2] _unmix inverts the mixer exactly (edge vectors included): OK")

    # --- 3. THE attack: one output -> one exact state -----------------------------
    sim = SplitMix64(0x123456789)
    leak = [sim.next_u64() for _ in range(4)]
    clone = SplitMix64.from_outputs(leak)
    future = [sim.next_u64() for _ in range(50)]
    assert [clone.next_u64() for _ in range(50)] == future, "clone diverged"
    # one output even recovers the COUNTER before the first increment
    assert (_unmix(leak[0]) - GOLDEN_GAMMA) & (_SPLITMIX64_MODULUS - 1) == \
        0x123456789, "seed recovery through the mixer failed"
    # non-consecutive observed words are detectable
    try:
        SplitMix64.from_outputs([leak[0], leak[2]])
    except ValueError:
        pass
    else:
        raise AssertionError("a gapped leak must be refused")
    try:
        SplitMix64.from_outputs([])
    except ValueError:
        pass
    else:
        raise AssertionError("an empty leak must be refused")
    print("[3] from_outputs recovers state and seed; gapped leaks refused: OK")

    # --- 4. jump(): a million outputs in one multiply ------------------------------
    sim = SplitMix64(7)
    for _ in range(1_000_000):
        sim.next_u64()
    slow_state = sim.getstate()
    sim2 = SplitMix64(7)
    sim2.jump(1_000_000)
    assert sim2.getstate() == slow_state, "jump() is not n steps"
    # jump lands on the same future stream
    assert [sim.next_u64() for _ in range(10)] == \
           [sim2.next_u64() for _ in range(10)], "jump broke the stream"
    print("[4] jump(1_000_000) == one million steps, identical futures: OK")

    # --- 5. determinism, sensitivity, state round-trip, API ------------------------
    a, b = SplitMix64(42), SplitMix64(42)
    assert [a.next_u64() for _ in range(10_000)] == \
           [b.next_u64() for _ in range(10_000)], "not deterministic"
    assert SplitMix64(43).next_u64() != SplitMix64(42).next_u64(), \
        "not seed sensitive"
    sim = SplitMix64(42)
    for _ in range(500):
        sim.next_u64()
    snapshot = sim.getstate()
    ahead = [sim.next_u64() for _ in range(100)]
    sim.setstate(snapshot)
    assert [sim.next_u64() for _ in range(100)] == ahead, "state round-trip broken"
    floats = []
    gf = SplitMix64(9)                       # ONE generator for all draws
    for _ in range(1000):
        floats.append(gf.random())
    assert all(0.0 <= x < 1.0 for x in floats), "random() escaped [0, 1)"
    for k in (1, 7, 64, 100):
        assert 0 <= SplitMix64(3).getrandbits(k) < (1 << k), \
            f"getrandbits({k}) out of range"
    blob = SplitMix64(5).randbytes(33)
    assert len(blob) == 33
    assert SplitMix64(5).randbytes(33) == blob, "randbytes not deterministic"
    print("[5] deterministic, sensitive, state round-trip, API sane: OK")

    # --- 6. the counter-based signature ----------------------------------------------
    # the n-th output is mix(s0 + n*gamma) -- computable DIRECTLY, no iteration
    sim = SplitMix64(0xFEED)
    sim.jump(1_000_000)
    millionth = sim.next_u64()                  # n = 1_000_001
    direct = splitmix64_mix((0xFEED + 1_000_000 * GOLDEN_GAMMA)
                            & (_SPLITMIX64_MODULUS - 1))
    assert millionth == direct, "the direct counter-form broke"
    sim2 = SplitMix64(0xFEED)
    sim2.jump(3)
    assert sim2.next_u64() == splitmix64_mix(
        (0xFEED + 3 * GOLDEN_GAMMA) & (_SPLITMIX64_MODULUS - 1)), \
        "the direct counter-form broke at n = 4"
    ones = bin(int.from_bytes(SplitMix64(1).randbytes(4096), "big")).count("1")
    assert 15000 < ones < 17800, f"bit balance looks broken ({ones} ones)"
    print(f"[6] n-th output == mix(s0 + n*gamma) directly at n = 4 and 10^6+1; "
          f"4096 bytes '{ones} ones/32768' balance: OK")

    # --- 7. the once-per-process warning, and the global silencer --------------------
    _flag_name = ("multirandom."
                  "ignore_unsecure_prng_warning_do_not_set_to_true_unless_you_know_how_risky_it_is")
    try:
        import multirandom
    except ImportError:                              # running as a plain script
        multirandom = None
    if multirandom is None:
        print("[7] global-flag test skipped (plain script)")
    else:
        flag = getattr(multirandom, _flag_name.split(".", 1)[1])
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                _splitmix64_warning_state["warned"] = False
                SplitMix64(3)
                _splitmix64_warning_state["warned"] = True
            assert any(_SPLITMIX64_UNSECURE_WARNING in str(w.message)
                       for w in caught), "unsecure warning went missing"
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                setattr(multirandom, _flag_name.split(".", 1)[1], True)
                _splitmix64_warning_state["warned"] = False
                SplitMix64(3)
                _splitmix64_warning_state["warned"] = True
                assert not caught, "global flag failed to silence the warning"
        finally:
            _splitmix64_warning_state["warned"] = True
            setattr(multirandom, _flag_name.split(".", 1)[1], flag)
        print(f"[7] warning fires once, silenced by {_flag_name} = True: OK")

    print("-" * 70)
    print("All splitmix64 checks passed!")
