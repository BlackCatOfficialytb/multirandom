"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.prng_unsecure.doom_prng
Description:
Doom's random number generator (Id Software, 1993) -- the table-driven
LUT behind every shotgun spread, muzzle flash and item drop of the most
influential shooter ever made.  The entire "algorithm" is one 256-byte
lookup table (transcribed here from Id's ``m_random.c``) and an index
that walks it::

    prndindex = (prndindex + 1) & 0xff
    return rndtable[prndindex]

increment FIRST, then index -- so from a cleared index the first draw is
``rndtable[1] == 8``.  The period is exactly 256 draws, the table is not
even a permutation of 0..255 (several values repeat, others are missing),
and nobody knows where the numbers came from.  Doom ships TWO separate
indexes through the same table: ``prndindex`` (gameplay: seeded from the
level state, demo-compatible) and ``rndindex`` (cosmetic randomness) --
:class:`DoomRandom` reproduces that with one independent index per
instance, and :meth:`DoomRandom.P_SubRandom` is the source's own
``P_Random() - P_Random()`` symmetric damage spread.

The reversal is peak triviality: ONE observed draw pins the index to at
most a handful of candidates and a second confirms it.
:meth:`DoomRandom.from_outputs` recovers the index and replays the run.

Run this module to execute its assert-based self-checks::

    py -3 -m multirandom.prng_unsecure.doom_prng
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


# The 256-byte lookup table, verbatim from Id Software's m_random.c
# (Doom, 1993; reference transcription checked against chocolate-doom).
RNDTABLE = [
    0,   8, 109, 220, 222, 241, 149, 107,  75, 248, 254, 140,  16,  66,
    74,  21, 211,  47,  80, 242, 154,  27, 205, 128, 161,  89,  77,  36,
    95, 110,  85,  48, 212, 140, 211, 249,  22,  79, 200,  50,  28, 188,
    52, 140, 202, 120,  68, 145,  62,  70, 184, 190,  91, 197, 152, 224,
    149, 104,  25, 178, 252, 182, 202, 182, 141, 197,   4,  81, 181, 242,
    145,  42,  39, 227, 156, 198, 225, 193, 219,  93, 122, 175, 249,   0,
    175, 143,  70, 239,  46, 246, 163,  53, 163, 109, 168, 135,   2, 235,
    25,  92,  20, 145, 138,  77,  69, 166,  78, 176, 173, 212, 166, 113,
    94, 161,  41,  50, 239,  49, 111, 164,  70,  60,   2,  37, 171,  75,
    136, 156,  11,  56,  42, 146, 138, 229,  73, 146,  77,  61,  98, 196,
    135, 106,  63, 197, 195,  86,  96, 203, 113, 101, 170, 247, 181, 113,
    80, 250, 108,   7, 255, 237, 129, 226,  79, 107, 112, 166, 103, 241,
    24, 223, 239, 120, 198,  58,  60,  82, 128,   3, 184,  66, 143, 224,
    145, 224,  81, 206, 163,  45,  63,  90, 168, 114,  59,  33, 159,  95,
    28, 139, 123,  98, 125, 196,  15,  70, 194, 253,  54,  14, 109, 226,
    71,  17, 161,  93, 186,  87, 244, 138,  20,  52, 123, 251,  26,  36,
    17,  46,  52, 231, 232,  76,  31, 221,  84,  37, 216, 165, 212, 106,
    197, 242,  98,  43,  39, 175, 254, 145, 190,  84, 118, 222, 187, 136,
    120, 163, 236, 249,
]

_DOOM_UNSECURE_WARNING = (
    "DoomRandom is a 256-entry lookup table with a period of exactly 256 "
    "draws and a one-byte-recoverable index. For cryptography use csprng.")

_doom_warning_state = {"warned": False}


class DoomRandom:
    """
    Doom's table-driven generator: increment-then-index over ``RNDTABLE``.

    ``P_Random()`` (alias ``roll()``) advances the index first, then reads
    the table -- from a cleared index the first draw is ``rndtable[1] ==
    8``.  ``random()`` maps a draw into [0, 1) at 1/256 resolution.
    ``P_SubRandom()`` is Doom's own symmetric spread: ``P_Random() -
    P_Random()``.  Each instance owns an independent index, mirroring the
    source's separate ``prndindex`` (gameplay) and ``rndindex`` (cosmetic)
    through the one shared table.  Constructing warns once per process
    (governed by the package's global warning flag).
    """

    def __init__(self, index: int = 0):
        index = int(index)
        if not 0 <= index <= 0xFF:
            raise ValueError(f"index must be in [0, 255], got {index}")
        if not _doom_warning_state["warned"]:
            _doom_warning_state["warned"] = True
            _warn_unsecure(_DOOM_UNSECURE_WARNING)
        self.index = index

    def P_Random(self) -> int:
        """One draw, 0..255: increment first, then index (Doom's exact code)."""
        self.index = (self.index + 1) & 0xFF
        return RNDTABLE[self.index]

    roll = P_Random  # the package-common alias for the same operation

    def P_SubRandom(self) -> int:
        """Doom's symmetric spread: ``P_Random() - P_Random()`` in [-255, 255]."""
        return self.P_Random() - self.P_Random()

    def random(self) -> float:
        """One draw as a double in [0, 1) -- 1/256 resolution."""
        return self.P_Random() / 256.0

    def getrandbits(self, k: int) -> int:
        """``k`` bits assembled from successive 8-bit draws."""
        if k < 0:
            raise ValueError("number of bits must be non-negative")
        if k == 0:
            return 0
        words = (k + 7) // 8
        value = 0
        for _ in range(words):
            value = (value << 8) | self.P_Random()
        return value >> (words * 8 - k)

    def getstate(self) -> tuple:
        """Raw state: the table index."""
        return (self.index,)

    def setstate(self, state: tuple) -> None:
        """Restore ``(index,)``; validates the 0..255 range."""
        (index,) = state
        index = int(index)
        if not 0 <= index <= 0xFF:
            raise ValueError("DoomRandom state must be an index in [0, 255]")
        self.index = index

    def clear(self) -> None:
        """``M_ClearRandom``: put the index back to the cleared 0."""
        self.index = 0

    @classmethod
    def from_outputs(cls, outputs) -> "DoomRandom":
        """Rebuild the generator behind a leak -- positioned right after the
        last observed draw.

        ``outputs``: consecutive draws (ints 0..255).  Every table index
        that reproduces the full observed run is a candidate; when more
        than one survives (ambiguous leaks are possible with few draws --
        every byte has 256/256 = 1 expected matches per position), the
        ValueError says so instead of guessing.
        """
        outputs = [int(o) for o in outputs]
        if not outputs:
            raise ValueError("need at least one observed output")
        if any(not 0 <= o <= 0xFF for o in outputs):
            raise ValueError("outputs must be bytes in [0, 255]")
        if not _doom_warning_state["warned"]:
            _doom_warning_state["warned"] = True
            _warn_unsecure(_DOOM_UNSECURE_WARNING)
        n = len(outputs)
        matches = []
        for start in range(256):
            if all(RNDTABLE[(start + 1 + i) & 0xFF] == outputs[i]
                   for i in range(n)):
                matches.append((start + n) & 0xFF)
        if not matches:
            raise ValueError("no table index reproduces the observed stream")
        if len(matches) > 1:
            raise ValueError(
                f"ambiguous leak: {len(matches)} indexes reproduce "
                f"{n} draws -- feed more consecutive outputs")
        gen = cls.__new__(cls)
        gen.index = matches[0]
        return gen



def main():
    print("=" * 70)
    print("doom_prng - the Doom lookup-table generator self-check battery")
    print("=" * 70)

    # --- 1. THE table, verbatim -------------------------------------------------
    assert len(RNDTABLE) == 256
    assert all(isinstance(v, int) and 0 <= v <= 255 for v in RNDTABLE)
    assert RNDTABLE[:16] == [0, 8, 109, 220, 222, 241, 149, 107, 75, 248,
                             254, 140, 16, 66, 74, 21], "head drifted"
    assert RNDTABLE[-16:] == [98, 43, 39, 175, 254, 145, 190, 84, 118,
                              222, 187, 136, 120, 163, 236, 249], "tail drifted"
    assert sum(RNDTABLE) == 32986, \
        f"the documented table sum is 32986, got {sum(RNDTABLE)}"
    # NOT a permutation: values repeat and others are missing
    assert len(set(RNDTABLE)) < 256, "the table unexpectedly IS a permutation"
    assert [i for i, v in enumerate(RNDTABLE) if v == 0] == [0, 83], \
        "the doubled zero moved"
    print("[1] 256-byte table verbatim: head, tail, sum 32986, repeats: OK")

    # --- 2. increment-then-index semantics; period exactly 256 ------------------
    g = DoomRandom()
    assert g.P_Random() == RNDTABLE[1] == 8, "first draw from cleared index"
    assert g.P_Random() == RNDTABLE[2] == 109, "second draw off by one"
    g.clear()
    stream = [g.P_Random() for _ in range(256)]
    assert stream == RNDTABLE[1:] + RNDTABLE[:1], "the cycle is not table[1..0]"
    assert g.index == 0, "period must be exactly 256"
    assert len(set(stream)) == len(set(RNDTABLE)), "the cycle changed the values"
    print("[2] increment-then-index: first draw 8; period exactly 256: OK")

    # --- 3. two indexes through one table (prndindex vs rndindex) ---------------
    prnd, rnd = DoomRandom(), DoomRandom()
    assert prnd.P_Random() == rnd.P_Random(), "cleared indexes must agree"
    prnd.P_Random(); prnd.P_Random(); prnd.P_Random()
    assert prnd.index != rnd.index, "the two indexes must stay independent"
    assert prnd.P_Random() == RNDTABLE[(prnd.index) & 0xFF]
    prnd.clear(); rnd.clear()
    assert prnd.index == rnd.index == 0, "M_ClearRandom semantics broken"
    # determinism + state round-trip
    a, b = DoomRandom(123 & 0xFF), DoomRandom(123 & 0xFF)
    assert [a.P_Random() for _ in range(2560)] == \
           [b.P_Random() for _ in range(2560)], "determinism broke"
    a = DoomRandom(200)
    for _ in range(37):
        a.P_Random()
    snapshot = a.getstate()
    ahead = [a.P_Random() for _ in range(50)]
    a.setstate(snapshot)
    assert [a.P_Random() for _ in range(50)] == ahead, "state round-trip broken"
    for bad in (-1, 256, 999):
        try:
            DoomRandom(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"index {bad} accepted")
    print("[3] two independent indexes; determinism; state round-trip: OK")

    # --- 4. P_SubRandom: Doom's own symmetric spread -----------------------------
    g = DoomRandom(42)
    vals = [g.P_SubRandom() for _ in range(4096)]
    assert all(-255 <= v <= 255 for v in vals), "subrandom out of range"
    # the identity, drawn exactly: P_SubRandom() == t[i+1] - t[i+2]
    g = DoomRandom(7)
    idx = g.index
    assert g.P_SubRandom() == (RNDTABLE[(idx + 1) & 0xFF]
                               - RNDTABLE[(idx + 2) & 0xFF]), \
        "P_SubRandom is not P_Random() - P_Random()"
    # NOT symmetric in practice: each call eats two draws, so the pair-start
    # index only ever visits EVEN positions (gcd(2, 256) = 2).  Over full
    # periods the mean is exactly mean(odd positions) - mean(even positions):
    odd = RNDTABLE[1::2]
    even = RNDTABLE[0::2]
    bias = sum(odd) / len(odd) - sum(even) / len(even)
    assert abs(sum(vals) / len(vals) - bias) < 1e-9, \
        "the pairing-parity bias drifted"
    g_odd = DoomRandom(41)                     # odd start: parity flips
    vals_odd = [g_odd.P_SubRandom() for _ in range(4096)]
    assert abs(sum(vals_odd) / len(vals_odd) + bias) < 1e-9, \
        "an odd start must mirror the bias"
    print(f"[4] P_SubRandom identity exact; parity bias {bias:+.6f} "
          f"(authentic Doom, pairs only visit even indexes): OK")

    # --- 5. THE attack: one-ish draws -> index recovery ---------------------------
    victim = DoomRandom(0xAB)
    leak = [victim.P_Random() for _ in range(6)]
    clone = DoomRandom.from_outputs(leak)
    future = [victim.P_Random() for _ in range(100)]
    assert [clone.P_Random() for _ in range(100)] == future, "clone diverged"
    # ONE draw pins the index only when that byte is unique in the table;
    # 8 occurs exactly once (position 1), 145 occurs five times -> ambiguous
    assert RNDTABLE.count(8) == 1 and RNDTABLE.count(145) == 5, \
        "the uniqueness example drifted"
    try:
        DoomRandom.from_outputs([145])
    except ValueError:
        pass
    else:
        raise AssertionError("a five-way-ambiguous leak must be reported")
    clone1 = DoomRandom.from_outputs([8])      # the single occurrence is unique
    assert clone1.roll() == RNDTABLE[2] == 109, \
        "the unique-draw clone must sit right after the observed position"
    # a full cycle pins it exactly and equivalently
    victim2 = DoomRandom(0xAB)
    full = [victim2.P_Random() for _ in range(256)]
    clone2 = DoomRandom.from_outputs(full)
    assert clone2.index == victim2.index, "a full cycle must pin the index"
    try:
        DoomRandom.from_outputs([])
    except ValueError:
        pass
    else:
        raise AssertionError("an empty leak must be refused")
    print("[5] from_outputs recovers the index; ambiguous leaks refused: OK")

    # --- 6. the once-per-process warning, and the global silencer ---------------
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
                _doom_warning_state["warned"] = False
                DoomRandom(3)
                _doom_warning_state["warned"] = True
            assert any(_DOOM_UNSECURE_WARNING in str(w.message) for w in caught), \
                "unsecure warning went missing"
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                setattr(multirandom, _flag_name.split(".", 1)[1], True)
                _doom_warning_state["warned"] = False
                DoomRandom(3)
                _doom_warning_state["warned"] = True
                assert not caught, "global flag failed to silence the warning"
        finally:
            _doom_warning_state["warned"] = True
            setattr(multirandom, _flag_name.split(".", 1)[1], flag)
        print(f"[6] warning fires once, silenced by {_flag_name} = True: OK")

    print("-" * 70)
    print("All doom_prng checks passed!")


if __name__ == "__main__":
    main()
