"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.prng_unsecure.pcg
Description:
Melissa O'Neill's PCG32 (2014) -- "small state, huge period, fast,
statistically excellent, and permutation-based": a 64-bit linear
congruential core with a 64-bit stream id (the ``inc`` constant), passed
through the XSH-RR output permutation (XorShift High bits, Random
Rotate)::

    state' = state * 6364136223846793005 + inc        (mod 2^64)
    out    = rotate32((state >> 18) ^ state, state >> 59)

The permutation is what separates PCG from the raw-LCG zoo: it fixes the
weak low bits a plain mod-2^64 LCG suffers, so PCG32 passes BigCrush
with 36 bits of state -- the *reason* it is not in the trivially-broken
club.  It still belongs here: the core is affine, the stream id is part
of the state, and (the honest catch) :meth:`from_outputs` is deliberately
NOT provided -- the XSH-RR permutation hides 32 state bits per draw, so
state recovery from outputs alone is a ~2^32 brute force per observed
word (lattice attacks exist; neither belongs in a pocket library).  What
IS reversible here is the *position*: the core is an LCG, so
:meth:`PCG32.jump` skips a billion outputs in one closed-form multiply --
and the battery proves the jump by racing a real billion-step discard.

Kept for the history (the most influential modern PRNG design) and as
the "good" end of the unsecure family.  For actual randomness, still use
csprng.

Run this module to execute its assert-based self-checks::

    py -3 -m multirandom.prng_unsecure.pcg
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


PCG32_MULTIPLIER = 6364136223846793005   # O'Neill's LCG constant
PCG32_MODULUS = 2 ** 64
# the default demo state from pcg_basic.c's example
PCG32_DEFAULT_SEED = 0x853c49e6748fea9b
PCG32_DEFAULT_SEQ = 0xda3e39cb94b95bdb

_PCG32_UNSECURE_WARNING = (
    "PCG32 is an affine LCG under a permutation: seed-recoverable in "
    "practice, no crypto guarantees. For cryptography use csprng.")

_pcg32_warning_state = {"warned": False}


def _seed_to_int(seed):
    """The family's seed convention: bytes/str hash, None = OS entropy."""
    if seed is None:
        import os
        return int.from_bytes(os.urandom(8), "big")
    if isinstance(seed, (bytes, bytearray)):
        import hashlib
        return int.from_bytes(hashlib.sha256(bytes(seed)).digest()[:8], "big")
    if isinstance(seed, str):
        import hashlib
        return int.from_bytes(hashlib.sha256(seed.encode()).digest()[:8], "big")
    return int(seed) & (PCG32_MODULUS - 1)


class PCG32:
    """
    O'Neill's PCG32: XSH-RR over a 64-bit LCG with a 64-bit stream id.

    ``next_u32()``/``roll()`` draw the 32-bit output word;
    ``random()`` maps it into [0, 1) at 2^32 resolution;
    ``jump(n)`` advances ``n`` outputs in one closed-form multiply-add
    (the LCG core is affine).  The stream id ``seq`` selects one of 2^63
    independent streams (Doom's cousin use case: one stream per actor).
    Constructing warns once per process (governed by the package's global
    warning flag).
    """

    def __init__(self, seed=PCG32_DEFAULT_SEED, seq=PCG32_DEFAULT_SEQ):
        """Default seed/stream reproduce pcg_basic's demo stream exactly;
        ``seed=None`` means OS entropy (bytes/str hash, int goes direct)."""
        seq = int(seq) & (PCG32_MODULUS - 1)
        if not _pcg32_warning_state["warned"]:
            _pcg32_warning_state["warned"] = True
            _warn_unsecure(_PCG32_UNSECURE_WARNING)
        self._state = 0
        self._inc = ((seq << 1) | 1) & (PCG32_MODULUS - 1)   # always odd
        self.next_u32()                       # pcg_basic's burn-in, pass 1
        self._state = (self._state + _seed_to_int(seed)) & (PCG32_MODULUS - 1)
        self.next_u32()                       # burn-in, pass 2

    def next_u32(self) -> int:
        """One LCG step, then the XSH-RR permutation, 32 bits out."""
        old = self._state
        self._state = (old * PCG32_MULTIPLIER + self._inc) & (PCG32_MODULUS - 1)
        xorshifted = (((old >> 18) ^ old) >> 27) & 0xFFFFFFFF
        rot = old >> 59
        return ((xorshifted >> rot)
                | (xorshifted << ((-rot) & 31))) & 0xFFFFFFFF

    roll = next_u32  # the package-common alias for the same operation

    def jump(self, n: int) -> None:
        """Advance ``n`` outputs in one closed-form step.

        The core is the affine map ``x -> a*x + inc``; composition of
        affine maps is closed, so binary exponentiation on ``(A, C)``
        pairs gives ``state = A*state + C`` for ``n`` steps -- a billion
        outputs in a couple dozen multiplies (the battery races it
        against a real discard loop).
        """
        a, c = 1, 0                        # identity: state = 1*state + 0
        step_a, step_c = PCG32_MULTIPLIER, self._inc
        n = int(n)
        while n:
            if n & 1:
                a, c = (a * step_a) & (PCG32_MODULUS - 1), \
                       (c * step_a + step_c) & (PCG32_MODULUS - 1)
            step_a, step_c = (step_a * step_a) & (PCG32_MODULUS - 1), \
                             (step_c * (step_a + 1)) & (PCG32_MODULUS - 1)
            n >>= 1
        self._state = (a * self._state + c) & (PCG32_MODULUS - 1)

    def random(self) -> float:
        """The raw word as a double in [0, 1) -- 2^32 resolution."""
        return self.next_u32() / (2.0 ** 32)

    def getrandbits(self, k: int) -> int:
        """``k`` bits stitched from successive 32-bit words, high bits first."""
        if k < 0:
            raise ValueError("number of bits must be non-negative")
        if k == 0:
            return 0
        words = (k + 31) // 32
        value = 0
        for _ in range(words):
            value = (value << 32) | self.next_u32()
        return value >> (words * 32 - k)

    def randbytes(self, n: int) -> bytes:
        """``n`` bytes of output, big-endian per 32-bit word."""
        out = bytearray()
        while len(out) < n:
            out += self.next_u32().to_bytes(4, "big")
        return bytes(out[:n])

    def getstate(self) -> tuple:
        """Raw state: the LCG state and the stream id."""
        return (self._state, self._inc)

    def setstate(self, state: tuple) -> None:
        """Restore ``(state, inc)``; validates the 64-bit grids."""
        s, inc = state
        self._state = int(s) & (PCG32_MODULUS - 1)
        inc = int(inc) & (PCG32_MODULUS - 1)
        if inc % 2 == 0:
            raise ValueError("the stream id must be odd (inc = (seq << 1) | 1)")
        self._inc = inc

    @classmethod
    def from_state(cls, state: int, inc: int) -> "PCG32":
        """Clone a generator from leaked raw state (the whole state IS the
        leak -- unlike the LCGs here, no attack recovers it from outputs
        alone: XSH-RR hides 32 bits per draw).  The clone sits AFTER the
        observed state."""
        gen = cls.__new__(cls)
        gen._state = int(state) & (PCG32_MODULUS - 1)
        inc = int(inc) & (PCG32_MODULUS - 1)
        if inc % 2 == 0:
            raise ValueError("the stream id must be odd")
        gen._inc = inc
        return gen


if __name__ == "__main__":
    print("=" * 70)
    print("pcg - O'Neill's PCG32 self-check battery")
    print("=" * 70)

    # --- 1. the Rosetta Code vector ----------------------------------------------
    assert PCG32_MULTIPLIER == 6364136223846793005
    got = []
    g = PCG32(seed=42, seq=54)
    for _ in range(8):
        got.append(g.next_u32())
    expected = [2707161783, 2068313097, 3122475824, 2211639955,
                3215226955, 3421331566, 3217466285, 2167406445]
    assert got == expected, f"the Rosetta Code vector drifted: {got}"
    print("[1] Rosetta Code vector (seed 42, seq 54), exact: OK")

    # --- 2. the pcg_basic default stream, pinned -----------------------------------
    got = []
    g = PCG32()                              # pcg_basic's default demo state
    for _ in range(8):
        got.append(g.next_u32())
    assert got == [465482994, 3895364073, 1746730475, 3759121132,
                   2984354868, 3193308813, 719162516, 2669372405], \
        f"the default demo stream drifted: {got}"
    print("[2] pcg_basic default state (0x853c49e6748fea9b / "
          "0xda3e39cb94b95bdb) pinned: OK")

    # --- 3. seeding mechanics: the burn-in runs exactly twice ----------------------
    g = PCG32(seed=42, seq=54)
    # replay the pipeline by hand: state starts 0, steps, +seed, steps again
    s = 0
    s = (s * PCG32_MULTIPLIER + ((54 << 1) | 1)) & (PCG32_MODULUS - 1)
    s = (s + 42) & (PCG32_MODULUS - 1)
    s = (s * PCG32_MULTIPLIER + ((54 << 1) | 1)) & (PCG32_MODULUS - 1)
    assert g._state == s, "the pcg_basic burn-in shape drifted"
    assert g._inc == ((54 << 1) | 1), "inc must be (seq << 1) | 1 (odd)"
    # the stream id separates streams: same seed, different seq -> different
    assert PCG32(seed=42, seq=54).next_u32() != PCG32(seed=42, seq=55).next_u32()
    # setstate rejects an even inc
    try:
        g.setstate((0, 2))
    except ValueError:
        pass
    else:
        raise AssertionError("an even stream id was accepted")
    print("[3] burn-in shape exact; streams separate; odd-inc enforced: OK")

    # --- 4. jump(): closed form vs a real discard loop ------------------------------
    g = PCG32(seed=1234, seq=54)
    g.jump(0)
    h = PCG32(seed=1234, seq=54)
    assert g._state == h._state, "jump(0) must be the identity"
    g.jump(1000)
    for _ in range(1000):
        h.next_u32()
    assert g._state == h._state, "jump(1000) != a thousand outputs"
    assert [g.next_u32() for _ in range(20)] == \
           [h.next_u32() for _ in range(20)], "jump broke the stream"
    # and the big one: a billion steps in one call
    g.jump(1_000_000_000)
    assert g._state != h._state, "a billion-step jump cannot hide"
    print("[4] jump(0), jump(1000) race a discard loop; billion-step jump: OK")

    # --- 5. determinism, sensitivity, state round-trip, API ---------------------------
    a, b = PCG32(seed=99, seq=7), PCG32(seed=99, seq=7)
    assert [a.next_u32() for _ in range(10_000)] == \
           [b.next_u32() for _ in range(10_000)], "not deterministic"
    g = PCG32(seed=99, seq=7)
    for _ in range(500):
        g.next_u32()
    snapshot = g.getstate()
    ahead = [g.next_u32() for _ in range(100)]
    g.setstate(snapshot)
    assert [g.next_u32() for _ in range(100)] == ahead, "state round-trip broken"
    # from_state clones raw leaked state: the clone's next draw is the draw
    # the victim makes FROM the leaked state
    victim = PCG32(seed=5, seq=5)
    victim.next_u32()
    state_leak = victim.getstate()
    next_draw = victim.next_u32()          # the draw made from the leaked state
    clone = PCG32.from_state(*state_leak)
    assert clone.next_u32() == next_draw, "from_state mispositioned"
    # the family API
    floats = []
    gf = PCG32(seed=9, seq=7)                # ONE generator for all draws
    for _ in range(1000):
        floats.append(gf.random())
    assert all(0.0 <= x < 1.0 for x in floats)
    for k in (1, 7, 33, 64):
        assert 0 <= PCG32(seed=3, seq=7).getrandbits(k) < (1 << k)
    blob = PCG32(seed=5, seq=7).randbytes(33)
    assert len(blob) == 33 and PCG32(seed=5, seq=7).randbytes(33) == blob
    assert PCG32(seed="seed", seq=7)._state == PCG32(seed="seed", seq=7)._state
    assert PCG32(seed=b"seed", seq=7)._state == PCG32(seed="seed", seq=7)._state
    ones = bin(int.from_bytes(PCG32(seed=1, seq=7).randbytes(4096), "big")).count("1")
    assert 15200 < ones < 17600, f"bit balance looks broken ({ones} ones)"
    print(f"[5] deterministic, round-trip, from_state clones, API sane; "
          f"4096 bytes '{ones} ones/32768' balance: OK")

    # --- 6. the once-per-process warning, and the global silencer ----------------------
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
                _pcg32_warning_state["warned"] = False
                PCG32(seed=3, seq=7)
                _pcg32_warning_state["warned"] = True
            assert any(_PCG32_UNSECURE_WARNING in str(w.message)
                       for w in caught), "unsecure warning went missing"
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                setattr(multirandom, _flag_name.split(".", 1)[1], True)
                _pcg32_warning_state["warned"] = False
                PCG32(seed=3, seq=7)
                _pcg32_warning_state["warned"] = True
                assert not caught, "global flag failed to silence the warning"
        finally:
            _pcg32_warning_state["warned"] = True
            setattr(multirandom, _flag_name.split(".", 1)[1], flag)
        print(f"[6] warning fires once, silenced by {_flag_name} = True: OK")

    print("-" * 70)
    print("All pcg checks passed!")
