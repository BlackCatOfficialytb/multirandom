"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.prng_unsecure.randu
Description:
IBM's RANDU (1966) -- quite possibly the most infamous PRNG ever shipped.
One multiply and one mask::

    x' = 65539 * x  mod 2**31,        65539 = 2**16 + 3

IBM's scientific libraries distributed it for over a decade, and its
multiplier could not have been worse chosen: because 65539 = 2^16 + 3, three
consecutive outputs satisfy ``x3 == 6*x2 - 9*x1 (mod 2^31)`` exactly, so the
triples ``(x1, x2, x3)`` collapse onto 15 parallel planes instead of filling
the cube -- George Marsaglia's famous "random numbers fall mainly in the
planes" (1968). A Monte Carlo simulation built on RANDU quietly lost whole
dimensions of its sample space.

The reversal attack is trivial: 65539 is odd, so it is invertible mod 2^31,
and ONE observed output recovers the previous state (and the seed) by a
modular multiplicative inverse. :meth:`RANDU.from_outputs` rebuilds the
generator from a leaked run.

Run this module to execute its assert-based self-checks::

    py -3 -m multirandom.prng_unsecure.randu
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


RANDU_MULTIPLIER = 65539          # 2**16 + 3 -- the mistake heard round the world
RANDU_MODULUS = 2 ** 31           # IBM System/360 word with the sign bit spared
RANDU_DEFAULT_SEED = 1

_RANDU_UNSECURE_WARNING = (
    "RANDU is the 1960s IBM generator whose triples collapse onto 15 planes "
    "(65539 = 2^16 + 3), and one observed output recovers the whole state "
    "via a modular inverse. For cryptography use csprng.")

_randu_warning_state = {"warned": False}


def plane_defect(x1: int, x2: int, x3: int) -> int:
    """The 15-planes identity defect: 0 for genuine RANDU triples.

    ``65539**2 == 6*65539 - 9 (mod 2**31)``, so every consecutive RANDU
    triple satisfies ``x3 == 6*x2 - 9*x1 (mod 2**31)`` -- the entire sample
    space lives on 15 parallel planes instead of filling the cube.
    """
    return (6 * x2 - 9 * x1 - x3) % RANDU_MODULUS


def recover_seed_from_output(output: int) -> int:
    """Recover the seed that produced ``output`` as its first draw.

    65539 is odd, hence invertible mod 2^31: one output is the whole state.
    """
    return (output * pow(RANDU_MULTIPLIER, -1, RANDU_MODULUS)) % RANDU_MODULUS


class RANDU:
    """
    IBM's RANDU: ``x' = 65539 * x mod 2^31``, the 15-plane generator.

    ``roll()`` advances the state and returns it (the classic 31-bit output
    grid); ``random()`` maps it into [0, 1) at 2^31 resolution. Seeds must be
    odd -- an even seed collapses the stream into an even-only chain.

    Constructing warns once per process (governed by the package's global
    warning flag).
    """

    def __init__(self, seed: int = RANDU_DEFAULT_SEED):
        seed = int(seed)
        if not 1 <= seed < RANDU_MODULUS:
            raise ValueError(f"seed must be in [1, {RANDU_MODULUS - 1}], got {seed}")
        if seed % 2 == 0:
            raise ValueError("RANDU seeds must be odd (an even seed decays "
                             "into an even-only chain)")
        if not _randu_warning_state["warned"]:
            _randu_warning_state["warned"] = True
            _warn_unsecure(_RANDU_UNSECURE_WARNING)
        self._state = seed

    def seed(self, seed: int = RANDU_DEFAULT_SEED) -> None:
        """Re-seed with an odd 31-bit value."""
        seed = int(seed)
        if not 1 <= seed < RANDU_MODULUS or seed % 2 == 0:
            raise ValueError("RANDU seeds must be odd and in [1, 2^31 - 1]")
        self._state = seed

    def roll(self) -> int:
        """One step: ``x' = 65539 * x mod 2^31`` (always an odd output)."""
        self._state = (RANDU_MULTIPLIER * self._state) % RANDU_MODULUS
        return self._state

    generate = roll  # the historical name for the same operation

    def random(self) -> float:
        """The state as a double in [0, 1) -- 2^31 resolution."""
        return self._state / RANDU_MODULUS

    def getstate(self) -> tuple:
        """Raw state: the current 31-bit word."""
        return (self._state,)

    def setstate(self, state: tuple) -> None:
        """Restore ``(state,)``; validates the odd 31-bit grid."""
        (word,) = state
        word = int(word)
        if not 0 <= word < RANDU_MODULUS or word % 2 == 0:
            raise ValueError("RANDU state must be an odd 31-bit integer")
        self._state = word

    @classmethod
    def from_outputs(cls, outputs) -> "RANDU":
        """Rebuild the generator behind a leak -- from ONE output onward.

        ``outputs``: one or more consecutive draws. The clone is positioned
        right after the last observed value, so its next ``roll()`` is the
        victim's next draw; ``recover_seed_from_output(outputs[0])`` gives
        the original seed instead.
        """
        outputs = list(outputs)
        if not outputs:
            raise ValueError("need at least one observed output")
        gen = cls.__new__(cls)
        gen._state = int(outputs[-1]) % RANDU_MODULUS
        if not _randu_warning_state["warned"]:
            _randu_warning_state["warned"] = True
            _warn_unsecure(_RANDU_UNSECURE_WARNING)
        return gen



def main():
    print("=" * 70)
    print("randu - IBM RANDU self-check battery")
    print("=" * 70)

    # --- 1. the algebra of the collapse -------------------------------------
    assert RANDU_MULTIPLIER == 2 ** 16 + 3
    assert RANDU_MODULUS == 2 ** 31
    assert pow(RANDU_MULTIPLIER, 2, RANDU_MODULUS) == (6 * RANDU_MULTIPLIER - 9) % RANDU_MODULUS, \
        "65539^2 must equal 6*65539 - 9 mod 2^31 -- the 15-plane identity"
    assert plane_defect(65539, 393225, 1769499) == 0
    print("[1] 65539 = 2^16 + 3; 65539^2 == 6*65539 - 9 (mod 2^31): OK")

    # --- 2. the reference stream ---------------------------------------------
    sim = RANDU(1)
    got = [sim.roll() for _ in range(6)]
    expected = [65539, 393225, 1769499, 7077969, 26542323, 95552217]
    assert got == expected, f"RANDU(1) diverged: {got}"
    assert all(v % 2 == 1 for v in got), "RANDU outputs must be odd"
    print("[2] RANDU(1) first 6 outputs match the reference stream: OK")

    # --- 3. THE 15 planes, counted -------------------------------------------
    sim = RANDU(0x0DDB1A5E5299 & 0x7FFFFFFF | 1)
    triples = [(sim.roll(), sim.roll(), sim.roll()) for _ in range(1000)]
    for x1, x2, x3 in triples:
        assert plane_defect(x1, x2, x3) == 0, "plane identity broken"
    planes = {(6 * x2 - 9 * x1 - x3) // RANDU_MODULUS for x1, x2, x3 in triples}
    assert len(planes) <= 15, f"more than 15 planes?! {sorted(planes)}"
    assert all(-9 <= k <= 5 for k in planes), "planes escaped the possible range"
    print(f"[3] 1000 consecutive triples satisfy the identity exactly; they "
          f"occupy {len(planes)} of the 15 possible planes: OK")

    # --- 4. THE attack: one output -> the seed -------------------------------
    sim = RANDU(0x1234567)
    first = sim.roll()
    assert recover_seed_from_output(first) == 0x1234567, "seed recovery failed"
    second = sim.roll()
    clone = RANDU.from_outputs([first, second])
    future = [sim.roll() for _ in range(50)]
    assert [clone.roll() for _ in range(50)] == future, "clone diverged"
    assert RANDU.from_outputs([first]).roll() == second
    print("[4] one output -> seed via modular inverse; from_outputs clones: OK")

    # --- 5. determinism, sensitivity, state round-trip -----------------------
    a, b = RANDU(12345), RANDU(12345)
    assert [a.roll() for _ in range(10_000)] == [b.roll() for _ in range(10_000)]
    assert RANDU(12347).roll() != RANDU(12345).roll(), "not seed sensitive"
    floats = [RANDU(12345).random() for _ in range(1_000)]
    assert all(0.0 <= x < 1.0 for x in floats)
    sim = RANDU(12345)
    for _ in range(500):
        sim.roll()
    snapshot = sim.getstate()
    ahead = [sim.roll() for _ in range(100)]
    sim.setstate(snapshot)
    assert [sim.roll() for _ in range(100)] == ahead, "state round-trip broken"
    for bad_seed in (0, 2, RANDU_MODULUS, -1):
        try:
            RANDU(bad_seed)
        except ValueError:
            pass
        else:
            raise AssertionError(f"seed {bad_seed} accepted")
    print("[5] 10k draws deterministic, odd-grid, [0,1) floats, state round-trip: OK")

    # --- 6. the once-per-process warning, and the global silencer ------------
    _flag_name = ("multirandom."
                  "ignore_unsecure_prng_warning_do_not_set_to_true_unless_you_know_how_risky_it_is")
    try:
        import multirandom
    except ImportError:                              # running as a plain script
        multirandom = None
    if multirandom is None:
        print("[6] global-flag test skipped (plain script)")
    else:
        flag = getattr(multirandom, _flag_name.split(".", 1)[1])
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                _randu_warning_state["warned"] = False
                RANDU(3)
                _randu_warning_state["warned"] = True
            assert any(_RANDU_UNSECURE_WARNING in str(w.message) for w in caught), \
                "unsecure warning went missing"
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                setattr(multirandom, _flag_name.split(".", 1)[1], True)
                _randu_warning_state["warned"] = False
                RANDU(3)
                _randu_warning_state["warned"] = True
                assert not caught, "global flag failed to silence the warning"
        finally:
            _randu_warning_state["warned"] = True
            setattr(multirandom, _flag_name.split(".", 1)[1], flag)
        print(f"[6] warning fires once, silenced by {_flag_name} = True: OK")

    print("-" * 70)
    print("All randu checks passed!")


if __name__ == "__main__":
    main()
