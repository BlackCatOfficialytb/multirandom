"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.prng_unsecure.middle_square
Description:
John von Neumann's middle-square method (1946-49) -- the very first
computerized PRNG, run for Monte Carlo work on the ENIAC -- plus Bernard
Widynski's modern fix, the Middle-Square Weyl Sequence (arXiv:1704.00358,
2017).

:class:`MiddleSquare` keeps an n-digit number, squares it, and takes the
middle n digits of the 2n-digit product (``1234: 1234^2 = 1522756`` ->
padded ``01522756`` -> ``5227``). It dies on its own two feet: any run that
hits all-zero digits stays there forever (the "zero mechanism"), and most
seeds fall into short cycles -- the module ships a cycle finder
(:meth:`MiddleSquare.find_cycle`) to watch it happen.

:class:`MSWS` is Widynski's revised algorithm: square x, add an odd Weyl
constant ``w += s`` so zeros restart instead of trapping, keep the middle 32
of the 64 bits. ``s = 0xb5ad4eceda1ce2a9`` passes BigCrush; period 2^64 for
every odd ``s``. :class:`MSWS64` is the paper's two-stream XOR version
(second constant ``0x278c5a4d8419fe6b``).

Run this module to execute its assert-based self-checks::

    py -3 -m multirandom.prng_unsecure.middle_square
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


_M64 = (1 << 64) - 1

# Widynski, arXiv:1704.00358: the canonical Weyl constants (both odd).
MSWS_WEYL_S = 0xB5AD4ECEDA1CE2A9       # msws32's s (also msws64's s1)
MSWS64_WEYL_S2 = 0x278C5A4D8419FE6B    # msws64's second stream (paper v7)

_MIDDLE_SQUARE_UNSECURE_WARNING = (
    "Middle-square is von Neumann's 1946 generator: it collapses into zero "
    "loops and short cycles (that's the point of this module). MSWS fixes "
    "it but is still a 64-bit-state PRNG unsuitable for cryptography.")

_middle_square_warning_state = {"warned": False}


def _emit_warning() -> None:
    if not _middle_square_warning_state["warned"]:
        _middle_square_warning_state["warned"] = True
        _warn_unsecure(_MIDDLE_SQUARE_UNSECURE_WARNING)


def middle_square_map(value: int, width: int = 4) -> int:
    """One middle-square step: square, pad to 2n digits, take the middle n.

    Works for any ``width >= 1`` (the middle slice is always taken from the
    zero-padded 2n-digit product). von Neumann's classic run used 4 digits
    (later 38-bit words).
    """
    if width < 1:
        raise ValueError("width must be >= 1")
    product = value * value
    padded = str(product).zfill(2 * width)
    middle = padded[width // 2 : width // 2 + width]
    return int(middle)


class MiddleSquare:
    """
    The 1946 original: middle-n-digits of the square (n digits of state).

    Deterministic, seed-sensitive, and honest about its vice: most seeds
    collapse into short cycles or the zero trap (``0000 -> 0000`` for good
    -- von Neumann kept it for Monte Carlo work anyway because failures were
    loud enough to notice). :meth:`find_cycle` measures the fate of a seed:
    the pre-period (steps until the repeat) and the cycle itself.

    Constructing warns once per process (governed by the package's global
    warning flag).
    """

    def __init__(self, seed: int = 1234, width: int = 4):
        _emit_warning()
        self.seed(seed, width)

    def seed(self, seed: int = 1234, width: int = 4) -> None:
        """Re-seed with a ``width``-digit number (or its prefix)."""
        if width < 1 or width > 9:
            raise ValueError("width must be in [1, 9]")
        seed = int(seed)
        limit = 10 ** width
        if not 0 <= seed < limit:
            raise ValueError(f"seed must be a {width}-digit number "
                             f"(0 <= seed < {limit}), got {seed}")
        self._width = width
        self._x = seed

    def roll(self) -> int:
        """One step: square the state, keep the middle ``width`` digits."""
        self._x = middle_square_map(self._x, self._width)
        return self._x

    generate = roll  # von Neumann would call it "the next random number"

    def random(self) -> float:
        """The state on a [0, 1) grid of 10**width cells."""
        return self.roll() / 10 ** self._width

    def find_cycle(self, limit: int = 100_000) -> tuple:
        """Walk to the first repeat: returns ``(cycle, prelude)``.

        Deterministic finite state space => every orbit eventually loops.
        ``cycle`` is the repeating block, ``prelude`` the tail that leads
        into it (``prelude[0]`` is the original state). The battery pins
        von Neumann's classic examples (1234 wanders, 3792 is a fixed
        point). Raises RuntimeError past ``limit`` steps.
        """
        seen = {}
        orbit = []
        x = self._x
        while x not in seen:
            seen[x] = len(orbit)
            orbit.append(x)
            x = middle_square_map(x, self._width)
            if len(seen) > limit:
                raise RuntimeError(f"no cycle within {limit} steps")
        cut = seen[x]
        return orbit[cut:], orbit[:cut]  # (cycle, prelude)

    def getstate(self) -> tuple:
        """Raw state: ``(state, width)``."""
        return (self._x, self._width)

    def setstate(self, state: tuple) -> None:
        """Restore ``(state, width)``."""
        word, width = state
        self._x = int(word)
        self._width = int(width)


class MSWS:
    """
    Widynski's Middle-Square Weyl Sequence (the EPFL-listed msws32).

    Verbatim from arXiv:1704.00358::

        uint64_t x = 0, w = 0, s = 0xb5ad4eceda1ce2a9;
        inline static uint32_t msws() {
           x *= x; x += (w += s); return x = (x>>32) | (x<<32);
        }

    The square is tempered by an ever-stepping odd Weyl term ``w``, so the
    zero mechanism of the plain middle-square cannot trap it; the middle 32
    bits come out as a uint32 while the full rotated word stays as state
    (64-bit state per stream, period >= 2^64 for any odd ``s``).

    Constructing warns once per process (governed by the package's global
    warning flag).
    """

    def __init__(self, x: int = 0, w: int = 0, s: int = MSWS_WEYL_S):
        if s % 2 == 0 or not 0 <= s <= _M64:
            raise ValueError("the Weyl constant s must be an odd 64-bit value")
        _emit_warning()
        self._x = int(x) & _M64
        self._w = int(w) & _M64
        self._s = int(s) & _M64

    def roll(self) -> int:
        """One step, verbatim: square, add the stepped Weyl, rotate 32."""
        self._x = (self._x * self._x) & _M64
        self._w = (self._w + self._s) & _M64
        self._x = (self._x + self._w) & _M64
        self._x = (self._x >> 32) | ((self._x << 32) & _M64)
        return self._x & 0xFFFFFFFF      # the uint32 of the C listing

    generate = roll

    def random(self) -> float:
        """Widynski's float recipe: state / 2^64."""
        return self.roll() / (1 << 64)

    def getstate(self) -> tuple:
        """Raw state: ``(x, w)`` (s is the stream identity)."""
        return (self._x, self._w)

    def setstate(self, state: tuple) -> None:
        """Restore ``(x, w)``."""
        x, w = state
        self._x = int(x) & _M64
        self._w = int(w) & _M64


class MSWS64:
    """
    The paper's ILP msws64: two msws streams XORed into one 64-bit word.

    Verbatim arithmetic from arXiv:1704.00358v7 (constants s1/s2 from its
    seed table)::

        x1 *= x1; xx = x1 += (w1 += s1); x1 = (x1 >> 32) | (x1 << 32);
        x2 *= x2;      x2 += (w2 += s2); x2 = (x2 >> 32) | (x2 << 32);
        return xx ^ x2;

    Note the asymmetry the paper embraces for ILP: ``xx`` is x1's value
    BEFORE the rotate, while ``x2`` enters the XOR AFTER its rotate.

    Constructing warns once per process (governed by the package's global
    warning flag).
    """

    def __init__(self, s1: int = MSWS_WEYL_S, s2: int = MSWS64_WEYL_S2):
        for name, s in (("s1", s1), ("s2", s2)):
            if s % 2 == 0 or not 0 <= s <= _M64:
                raise ValueError(f"the Weyl constant {name} must be an odd 64-bit value")
        _emit_warning()
        self._s1, self._s2 = int(s1), int(s2)
        self._x1 = self._w1 = self._x2 = self._w2 = 0

    def roll(self) -> int:
        """One step of the two-stream XOR (v7's ILP listing)."""
        x1 = (self._x1 * self._x1) & _M64
        self._w1 = (self._w1 + self._s1) & _M64
        x1 = (x1 + self._w1) & _M64
        xx = x1
        self._x1 = (x1 >> 32) | ((x1 << 32) & _M64)
        x2 = (self._x2 * self._x2) & _M64
        self._w2 = (self._w2 + self._s2) & _M64
        x2 = (x2 + self._w2) & _M64
        self._x2 = (x2 >> 32) | ((x2 << 32) & _M64)
        return (xx ^ self._x2) & _M64

    generate = roll

    def random(self) -> float:
        """Widynski's float recipe: msws64 value / 2^64."""
        return self.roll() / (1 << 64)

    def getstate(self) -> tuple:
        """Raw state: ``(x1, w1, x2, w2)``."""
        return (self._x1, self._w1, self._x2, self._w2)

    def setstate(self, state: tuple) -> None:
        """Restore ``(x1, w1, x2, w2)``."""
        self._x1, self._w1, self._x2, self._w2 = (int(v) & _M64 for v in state)



def main():
    print("=" * 70)
    print("middle_square - von Neumann + Widynski MSWS self-check battery")
    print("=" * 70)

    # --- 1. the exact middle-slice arithmetic --------------------------------
    assert MSWS_WEYL_S % 2 == 1 and MSWS64_WEYL_S2 % 2 == 1
    assert middle_square_map(1234, 4) == 5227, "1234^2 = 1522756 -> 01522756 -> 5227"
    assert middle_square_map(5227, 4) == 3215 and middle_square_map(3215, 4) == 3362
    assert middle_square_map(3362, 4) == 3030 and middle_square_map(3030, 4) == 1809
    assert middle_square_map(1809, 4) == 2724 and middle_square_map(2724, 4) == 4201
    assert middle_square_map(4201, 4) == 6484
    assert middle_square_map(3792, 4) == 3792, "3792 is a fixed point"
    assert middle_square_map(0, 4) == 0, "the zero mechanism: 0000 -> 0000"
    assert middle_square_map(1, 1) == 0, "1^2 = 01, middle digit 0"
    print("[1] hand-checked slice arithmetic (1234 -> ... -> 6484; traps): OK")

    # --- 2. the traps, live ---------------------------------------------------
    sim = MiddleSquare(1234)
    got = [sim.roll() for _ in range(8)]
    assert got == [5227, 3215, 3362, 3030, 1809, 2724, 4201, 6484], got
    cycle, prelude = MiddleSquare(1234).find_cycle()
    assert prelude[0] == 1234 and cycle, "find_cycle should land on the repeat"
    assert len(prelude) + len(cycle) < 1000, "1234 should not wander far"
    walker = MiddleSquare(1234)
    for _ in range(len(prelude) - 1):
        walker.roll()                        # stand just before the cycle
    assert [walker.roll() for _ in range(len(cycle))] == cycle, \
        "the walk must land on the cycle exactly"
    trap = MiddleSquare(0)
    assert [trap.roll() for _ in range(5)] == [0, 0, 0, 0, 0], "zero trap"
    loop = MiddleSquare(3792)
    assert [loop.roll() for _ in range(3)] == [3792, 3792, 3792], "self-loop"
    print(f"[2] 1234 re-derives von Neumann's orbit; cycle found "
          f"(pre {len(prelude)} + loop {len(cycle)}); 0000/3792 traps live: OK")

    # --- 3. determinism / sensitivity of the classic --------------------------
    a, b = MiddleSquare(2055), MiddleSquare(2055)
    assert [a.roll() for _ in range(500)] == [b.roll() for _ in range(500)]
    assert MiddleSquare(2056).roll() == 2271, "2056^2 = 04227136 -> middle = 2271"
    assert MiddleSquare(2055).roll() != MiddleSquare(2056).roll()
    sim = MiddleSquare(1234)
    for _ in range(100):
        sim.roll()
    snapshot = sim.getstate()
    ahead = [sim.roll() for _ in range(50)]
    sim.setstate(snapshot)
    assert [sim.roll() for _ in range(50)] == ahead, "state round-trip broken"
    try:
        MiddleSquare(10000)
    except ValueError:
        pass
    else:
        raise AssertionError("a 5-digit seed must be refused for width 4")
    print("[3] classic: deterministic, 2056 -> 2271 hand-check, round-trip: OK")

    # --- 4. MSWS: the canonical constants and streams -------------------------
    sim = MSWS()
    got = [sim.roll() for _ in range(6)]
    expected = [3048033998, 3746490460, 411637087, 3336355023, 285663429, 1194354350]
    assert got == expected, f"msws32 stream diverged: {[hex(v) for v in got]}"
    assert all(0 <= v < (1 << 32) for v in got)
    double = MSWS().random()
    assert 0.0 <= double < 1.0
    try:
        MSWS(s=0xB5AD4ECEDA1CE2A8)
    except ValueError:
        pass
    else:
        raise AssertionError("even Weyl constant must be refused")
    print("[4] msws32: s = 0xb5ad4eceda1ce2a9, canonical stream pinned: OK")

    # --- 5. MSWS properties: determinism, 4096 distinct draws ------------------
    a, b = MSWS(), MSWS()
    assert [a.roll() for _ in range(4096)] == [b.roll() for _ in range(4096)]
    distinct = {a.roll() for _ in range(4096)}    # ONE generator, 4096 draws
    assert len(distinct) == 4096, f"collisions in 4096 draws?! {4096 - len(distinct)}"
    sim = MSWS()
    for _ in range(1000):
        sim.roll()
    snapshot = sim.getstate()
    ahead = [sim.roll() for _ in range(100)]
    sim.setstate(snapshot)
    assert [sim.roll() for _ in range(100)] == ahead, "MSWS state round-trip broken"
    assert MSWS(0, 0, 45).roll() != expected[0], "custom s changes the stream"
    print("[5] msws32: 4096 identical under replay, 4096 distinct draws: OK")

    # --- 6. MSWS64: the two-stream XOR ----------------------------------------
    sim = MSWS64()
    got = [sim.roll() for _ in range(4)]
    expected64 = [3581681830636599524, 13621382965901983353,
                  17912333307713246982, 7227778886790185433]
    assert got == expected64, f"msws64 stream diverged: {[hex(v) for v in got]}"
    assert all(0 <= v < (1 << 64) for v in got)
    assert MSWS64().random() != MSWS().random(), "64 xor run differs from 32 run"
    try:
        MSWS64(s2=0x278C5A4D8419FE6A)
    except ValueError:
        pass
    else:
        raise AssertionError("even s2 must be refused")
    sim = MSWS64()
    for _ in range(500):
        sim.roll()
    snapshot = sim.getstate()
    ahead = [sim.roll() for _ in range(100)]
    sim.setstate(snapshot)
    assert [sim.roll() for _ in range(100)] == ahead, "MSWS64 round-trip broken"
    print("[6] msws64 (xx = pre-rotate XOR post-rotate): canonical stream: OK")

    # --- 7. the once-per-process warning, and the global silencer --------------
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
                _middle_square_warning_state["warned"] = False
                MiddleSquare(1)
                MSWS()
                _middle_square_warning_state["warned"] = True
            assert any(_MIDDLE_SQUARE_UNSECURE_WARNING in str(w.message) for w in caught), \
                "unsecure warning went missing"
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                setattr(multirandom, _flag_name.split(".", 1)[1], True)
                _middle_square_warning_state["warned"] = False
                MiddleSquare(1)
                MSWS()
                _middle_square_warning_state["warned"] = True
                assert not caught, "global flag failed to silence the warning"
        finally:
            _middle_square_warning_state["warned"] = True
            setattr(multirandom, _flag_name.split(".", 1)[1], flag)
        print(f"[7] warning fires once, silenced by {_flag_name} = True: OK")

    print("-" * 70)
    print("All middle_square checks passed!")


if __name__ == "__main__":
    main()
