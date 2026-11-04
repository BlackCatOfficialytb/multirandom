"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.prng_unsecure.mersenne_twister
Description:
The Mersenne Twister MT19937, rebuilt from Matsumoto & Nishimura's
``mt19937ar.c`` (ACM TOMACS 1998, "Mersenne Twister: A 623-Dimensionally
Equidistributed Uniform Pseudo-Random Generator") -- the very PRNG that has
driven Python's ``random`` module since forever, plus the textbook attack
against it.

:class:`MersenneTwister` implements the 2002 initialization
(:meth:`MersenneTwister.seed`, Knuth's multiplier ``1812433253``) and the
array-based one (:meth:`MersenneTwister.from_key`, ``init_by_array``) -- the
latter byte-for-byte compatible with CPython: ``MersenneTwister.from_key(key)
streams of ``random.Random(n)``. The 32-bit ``roll()`` is ``genrand_int32``:
the twisted state, tempered with the ``(y ^ y >> 11) ^ ...`` chain; and
``random()`` is the 53-bit ``genrand_res53``.

It is in this package because the tempering is the only thing between you and
the full internal state -- and it is NOT a hash: it is an XOR/shift bijection
undone in microseconds by :func:`untemper`. After 624 consecutive outputs the
state is *exactly* recovered (:func:`recover_state_from_outputs`) and the
future of a 2^19937-period stream becomes fully predictable -- for any 624
window, aligned or not. The same fact got several NFS/network services broken
and is why CSPRNGs are one-way. Insecure by design: constructing warns once
per process via the package's global warning flag.

Run this module to execute its assert-based self-checks::

    py -3 -m multirandom.prng_unsecure.mersenne_twister
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


# --- Period parameters from mt19937ar.c --------------------------------------
MT_N = 624                  # degree of recurrence
MT_M = 397                  # middle word offset (1 <= M < N)
MT_MATRIX_A = 0x9908B0DF    # constant vector a ("mag01[y & 1]")
MT_UPPER_MASK = 0x80000000  # most significant w-r bits
MT_LOWER_MASK = 0x7FFFFFFF  # least significant r bits

# Tempering shifts/masks (the only non-linear-looking step, fully invertible).
MT_TEMPER_B = 0x9D2C5680
MT_TEMPER_C = 0xEFC60000

# Seeding constants.
MT_DEFAULT_SEED = 5489      # mt19937ar.c's sgentrand default
MT_KNUTH_INIT = 1812433253  # Knuth TAOCP Vol2 3rd Ed. P.106 multiplier
MT_INIT_BY_ARRAY_A = 1664525
MT_INIT_BY_ARRAY_B = 1566083941
MT_INIT_BY_ARRAY_GLUED = 19650218

_M32 = 0xFFFFFFFF

_MERSENNE_UNSECURE_WARNING = (
    "MersenneTwister is the MT19937 behind Python's random module; it is fast "
    "and equidistributed but 624 observed 32-bit outputs recover the ENTIRE "
    "state (temper() is an invertible bijection, not a hash), after which "
    "every future draw is predictable. For cryptography use csprng.")

_mersenne_warning_state = {"warned": False}


def temper(value: int) -> int:
    """The MT19937 tempering transform applied to a 32-bit word.

    ``y ^= (y >> 11)``; ``y ^= (y << 7) & 0x9d2c5680``;
    ``y ^= (y << 15) & 0xefc60000``; ``y ^= y >> 18`` -- verbatim from
    ``genrand_int32``. A bijection over 32-bit words (:func:`untemper`).
    """
    value &= _M32
    value ^= value >> 11
    value ^= (value << 7) & MT_TEMPER_B
    value ^= (value << 15) & MT_TEMPER_C
    value ^= value >> 18
    return value & _M32


def _unshift_right(value: int, shift: int) -> int:
    """Inverse of ``y ^= y >> shift``: fixed-point iteration from the top."""
    result = value
    while True:
        new = value ^ (result >> shift)
        if new == result:
            return result
        result = new


def _unshift_left(value: int, shift: int, mask: int) -> int:
    """Inverse of ``y ^= (y << shift) & mask``: fixed-point from below."""
    result = value
    while True:
        new = value ^ ((result << shift) & mask)
        if new == result:
            return result
        result = new


def untemper(value: int) -> int:
    """Undo :func:`temper` -- recover the state word behind an output.

    Runs the four tempering steps backwards (right-shift first, then the two
    masked left shifts, then the tail right shift). NOT a hash inversion --
    every step is XOR-linear, so the whole 32-bit state word falls out
    instantly. This single fact is why MT19937 dies after 624 outputs.
    """
    value &= _M32
    value = _unshift_right(value, 18)
    value = _unshift_left(value, 15, MT_TEMPER_C)
    value = _unshift_left(value, 7, MT_TEMPER_B)
    value = _unshift_right(value, 11)
    return value & _M32


class MersenneTwister:
    """
    MT19937 exactly as CPython seeds it, with the reversal attack attached.

    State: a 624-word array plus the rolling index -- the raw ``mt[624]`` and
    ``mti`` of ``mt19937ar.c``. ``roll()`` returns one tempered 32-bit word
    (the full ``genrand_int32``); ``random()`` is the 53-bit
    ``genrand_res53``; ``getstate()``/``setstate()`` round-trip the raw state
    (matching CPython's layout of 624 words + index).

    Constructing warns once per process (governed by the package's global
    warning flag).
    """

    def __init__(self, seed: int = MT_DEFAULT_SEED):
        """Initialize from an arbitrary int (``seed()``'s Knuth path)."""
        if not _mersenne_warning_state["warned"]:
            _mersenne_warning_state["warned"] = True
            _warn_unsecure(_MERSENNE_UNSECURE_WARNING)
        self.seed(seed)

    def seed(self, seed: int = MT_DEFAULT_SEED) -> None:
        """``init_genrand`` -- the Knuth-style 2002 seeding over one word.

        ``mt[0] = seed; mt[i] = 1812433253 * (mt[i-1] ^ (mt[i-1] >> 30)) + i``
        (mod 2^32). The index starts at 624, so the first ``roll()`` twists
        first -- the "index" convention of ``mt19937ar.c`` / CPython (whose
        ``getstate()`` returns index 624 for a freshly seeded generator).
        """
        seed &= _M32
        state = [seed]
        for i in range(1, MT_N):
            state.append((MT_KNUTH_INIT * (state[i - 1] ^ (state[i - 1] >> 30)) + i) & _M32)
        self._mt = state
        self._index = MT_N

    @classmethod
    def from_key(cls, key) -> "MersenneTwister":
        """``init_by_array`` -- CPython-compatible array-based initialization.

        ``key``: any iterable of ints (each masked to 32 bits). Byte-for-byte
        the seeding protocol of CPython's ``_randommodule.c``: glue seed
        ``19650218`` (Knuth-expanded), one ``max(624, len(key))`` pass mixing
        ``1664525``-multiples with ``key[j] + j``, then a ``1566083941`` pass,
        then force MSB of ``mt[0]``. With the little-endian 32-bit-word split
        of an int (see :func:`key_from_int`), a CPython ``random.Random(n)``
        stream is reproduced exactly (the module battery proves it across
        multi-word seeds).
        """
        key = [word & _M32 for word in key]
        gen = cls.__new__(cls)
        mt = [0] * MT_N
        # init_genrand(19650218) first: the glue seed fills the state.
        mt[0] = MT_INIT_BY_ARRAY_GLUED
        for i in range(1, MT_N):
            mt[i] = (MT_KNUTH_INIT * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i) & _M32
        i, j = 1, 0
        for _ in range(max(MT_N, len(key))):
            mt[i] = ((mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >> 30)) * MT_INIT_BY_ARRAY_A)) + key[j] + j) & _M32
            i += 1
            j += 1
            if i >= MT_N:
                mt[0] = mt[MT_N - 1]
                i = 1
            if j >= len(key):
                j = 0
        for _k in range(MT_N - 1, 0, -1):
            mt[i] = ((mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >> 30)) * MT_INIT_BY_ARRAY_B)) - i) & _M32
            i += 1
            if i >= MT_N:
                mt[0] = mt[MT_N - 1]
                i = 1
        mt[0] = 0x80000000
        gen._mt = mt
        gen._index = MT_N
        if not _mersenne_warning_state["warned"]:
            _mersenne_warning_state["warned"] = True
            _warn_unsecure(_MERSENNE_UNSECURE_WARNING)
        return gen

    def _twist(self) -> None:
        """Regenerate all 624 words (the "while index >= 624" twist pass)."""
        mt = self._mt
        for i in range(MT_N):
            y = (mt[i] & MT_UPPER_MASK) | (mt[(i + 1) % MT_N] & MT_LOWER_MASK)
            mt[i] = mt[(i + MT_M) % MT_N] ^ (y >> 1)
            if y & 1:
                mt[i] ^= MT_MATRIX_A
        self._index = 0

    def roll(self) -> int:
        """One tempered 32-bit output -- ``genrand_int32`` of mt19937ar.c.

        The package-conventional "one register step, one output". Twists the
        state first when the index runs out, then tempers the next word.
        """
        if self._index >= MT_N:
            self._twist()
        y = self._mt[self._index]
        self._index += 1
        return temper(y)

    generate = roll  # mt19937ar.c's original name for the same operation

    def random(self) -> float:
        """53-bit double in [0.0, 1.0) -- ``genrand_res53``.

        ``(a * 2^26 + b) / 2^53`` with ``a = word >> 5`` and ``b = word >> 6``
        of two consecutive draws: CPython's ``random.random()`` formula.
        """
        a = self.roll() >> 5
        b = self.roll() >> 6
        return (a * 67108864.0 + b) * (1.0 / 9007199254740992.0)

    def getstate(self) -> tuple:
        """Raw ``(624 word tuple, index)`` state (CPython's layout)."""
        return (tuple(self._mt), self._index)

    def setstate(self, state: tuple) -> None:
        """Restore ``(624 words, index)``; validates shape/ranges."""
        words, index = state
        if len(words) != MT_N:
            raise ValueError(f"state must carry exactly {MT_N} words, got {len(words)}")
        if not 0 <= index <= MT_N:
            raise ValueError(f"index must be in [0, {MT_N}], got {index}")
        self._mt = [word & _M32 for word in words]
        self._index = index

    @classmethod
    def from_outputs(cls, outputs) -> "MersenneTwister":
        """The attack, as an API: build the generator behind the leak.

        ``outputs``: >= 624 consecutive tempered 32-bit draws observed from
        the victim (any window, aligned or not) -- e.g.
        ``[victim.roll() for _ in range(624)]`` scraped from a service
        seeding ``random.Random``. Returns a :class:`MersenneTwister` whose
        every future draw equals the victim's, then and forever. Same engine
        as :func:`clone_rng_from_outputs` (kept for the module-level name).
        """
        return clone_rng_from_outputs(outputs)


# --- THE attack: 624 outputs are the whole state -----------------------------

def recover_state_from_outputs(outputs) -> tuple:
    """Recover the exact internal state from >= 624 consecutive outputs.

    Untempers the *last* 624 observed words -- for MT19937 that block IS the
    state array right after the most recent twist the window covered, plus
    index 624 (the clone must twist before its next draw, exactly when the
    real generator did). Works from ANY consecutive window, aligned at a
    twist boundary or not; the battery proves it for strided starts
    (0, 100, 345, 731, 998). Returns the tuple CPython-style
    ``(624 words, 624)`` ready for :meth:`MersenneTwister.setstate`.
    """
    outputs = list(outputs)
    if len(outputs) < MT_N:
        raise ValueError(f"need >= {MT_N} consecutive tempered outputs, got {len(outputs)}")
    words = tuple(untemper(value & _M32) for value in outputs[-MT_N:])
    return (words, MT_N)


def clone_rng_from_outputs(outputs) -> MersenneTwister:
    """Clone the generator that produced ``outputs`` (>= 624 consecutive).

    Builds a :class:`MersenneTwister` whose every future ``roll()`` /
    ``random()`` equals the real generator's, then and forever.
    """
    gen = MersenneTwister.__new__(MersenneTwister)
    gen.setstate(recover_state_from_outputs(outputs))
    if not _mersenne_warning_state["warned"]:
        _mersenne_warning_state["warned"] = True
        _warn_unsecure(_MERSENNE_UNSECURE_WARNING)
    return gen


def predict_from_outputs(outputs, count: int) -> list[int]:
    """Predict the next ``count`` draws after >= 624 observed ones."""
    gen = clone_rng_from_outputs(outputs)
    return [gen.roll() for _ in range(count)]


def key_from_int(value: int) -> list[int]:
    """Split an int into 32-bit LE words -- CPython's ``random_seed`` key.

    ``random.Random(n)`` passes ``abs(n)`` split from the right into 32-bit
    chunks into ``init_by_array`` (see CPython ``_randommodule.c``). Feeding
    the result to ``MersenneTwister.from_key`` reproduces that stream.
    """
    value = abs(int(value))
    key = []
    while True:
        key.append(value & _M32)
        value >>= 32
        if value == 0:
            return key


if __name__ == "__main__":
    import random

    print("=" * 70)
    print("mersenne_twister - MT19937 self-check battery")
    print("=" * 70)

    # --- 1. structural constants vs mt19937ar.c ----------------------------
    assert MT_N == 624 and MT_M == 397 and MT_M < MT_N
    assert MT_MATRIX_A == 0x9908B0DF and MT_TEMPER_B == 0x9D2C5680 and MT_TEMPER_C == 0xEFC60000
    assert MT_UPPER_MASK == 0x80000000 == (1 << 31) and MT_LOWER_MASK == 0x7FFFFFFF
    assert MT_DEFAULT_SEED == 5489 and MT_INIT_BY_ARRAY_GLUED == 19650218
    print("[1] period/tempering constants match mt19937ar.c: OK")

    # --- 2. official vector for the default Knuth seed ---------------------
    sim = MersenneTwister(5489)
    got = [sim.roll() for _ in range(10)]
    expected = [3499211612, 581869302, 3890346734, 3586334585, 545404204,
                4161255391, 3922919429, 949333985, 2715962298, 1323567403]
    assert got == expected, f"seed 5489 diverged: {[hex(x) for x in got]}"
    print("[2] init_genrand(5489) first 10 outputs (canonical hex vector): OK")

    # --- 3. CPython parity: from_key reproduces random.Random streams ------
    for seed in (0, 1, 2, 5489, 12345, 0xDEADBEEF, 987654321, 2**64 + 123456789, 10**12):
        mine = MersenneTwister.from_key(key_from_int(seed))
        theirs = random.Random(seed)
        assert [mine.roll() for _ in range(40)] == [theirs.getrandbits(32) for _ in range(40)], \
            f"from_key stream != random.Random({seed})"
        assert abs(mine.random() - theirs.random()) == 0.0, f"genrand_res53 != random() for {seed}"
    print("[3] from_key == CPython random.Random for 9 int seeds (rolls + floats): OK")

    # --- 4. display determinism / sensitivity / 32-bit grid ----------------
    a = MersenneTwister(0x12345678)
    b = MersenneTwister(0x12345678)
    stream_a = [a.roll() for _ in range(10_000)]
    stream_b = [b.roll() for _ in range(10_000)]
    assert stream_a == stream_b, "same seed, different stream"
    assert all(0 <= v <= 0xFFFFFFFF for v in stream_a), "output escaped 32 bits"
    c = MersenneTwister(0x12345679)
    assert c.roll() != stream_a[0], "not seed sensitive"
    assert c.roll() != stream_a[1]  # keep rolling: whole streams must differ
    print("[4] 10k draws: deterministic, 32-bit grid, state-sensitive: OK")

    # --- 5. random() stays inside [0, 1) with 53-bit resolution ------------
    sim = MersenneTwister(5489)
    floats = [sim.random() for _ in range(10_000)]
    assert all(0.0 <= x < 1.0 for x in floats), "random() left [0, 1)"
    assert all(x * (1 << 53) == float(int(x * (1 << 53))) for x in floats[:1_000]), \
        "not 53-bit resolution"
    print("[5] 10k genrand_res53 doubles in [0, 1), 53-bit: OK")

    # --- 6. getstate / setstate round-trip ---------------------------------
    sim = MersenneTwister(42)
    for _ in range(1_000):
        sim.roll()
    snapshot = sim.getstate()
    future = [sim.roll() for _ in range(300)]
    sim.setstate(snapshot)
    assert [sim.roll() for _ in range(300)] == future, "state round-trip broken"
    for bad_state in ((tuple(range(60)), 0), ([0] * MT_N, 999)):
        try:
            sim.setstate(bad_state)
        except ValueError:
            pass
        else:
            raise AssertionError(f"invalid state accepted: {bad_state!r}")
    print("[6] getstate/setstate round-trip + rejection of bogus states: OK")

    # --- 7. temper <-> untemper: every step inverts (30k samples) ----------
    import random as _random
    rng = _random.Random(2024)
    for _ in range(30_000):
        x = rng.getrandbits(32)
        assert untemper(temper(x)) == x
        y = rng.getrandbits(32)
        assert temper(untemper(y)) == y
    for edge in (0, 1, _M32, 0x80000000, 0x7FFFFFFF, 0x12345678,
                 MT_TEMPER_B, MT_TEMPER_C, MT_MATRIX_A):
        assert untemper(temper(edge)) == edge and temper(untemper(edge)) == edge
    print("[7] temper/untemper is a full 32-bit bijection (30k samples): OK")

    # --- 8. THE attack: 624 outputs -> the entire state -> the future ------
    sim = MersenneTwister(0x12345678)
    stream = [sim.roll() for _ in range(2_000)]
    for start in (0, 100, 345, 731, 998):     # aligned and unaligned windows
        observed = stream[start:start + MT_N]
        clone = clone_rng_from_outputs(observed)
        predicted = [clone.roll() for _ in range(300)]
        truth = stream[start + MT_N:start + MT_N + 300]
        assert predicted == truth, f"clone failed from window {start}..{start + 623}"
    state = recover_state_from_outputs(stream[:MT_N])
    assert len(state) == 2 and len(state[0]) == MT_N and state[1] == MT_N
    sim.setstate(state)
    assert [sim.roll() for _ in range(624)] == stream[MT_N:2 * MT_N], \
        "state recovery lost the 2^19937 continuation"
    assert predict_from_outputs(stream[:MT_N], 5) == stream[MT_N:MT_N + 5]
    # the .from_outputs() classmethod API (the leak -> clone attack)
    victim = MersenneTwister(0xDEADBEEF)
    first = [victim.roll() for _ in range(650)]       # the leak
    future = [victim.roll() for _ in range(200)]      # the real future
    cloned = MersenneTwister.from_outputs(first)
    assert [cloned.roll() for _ in range(200)] == future, "from_outputs clone diverged"
    print("[8] 624 observed words -> exact state; ANY 624 window (5 tested) "
          "predicts 300 future draws: OK")

    # --- 9. the once-per-process warning, and the global silencer ----------
    try:
        import multirandom
    except ImportError:                              # running as a plain script
        multirandom = None
    _flag_name = ("multirandom."
                  "ignore_unsecure_prng_warning_do_not_set_to_true_unless_you_know_how_risky_it_is")
    if multirandom is None:
        print(f"[9] global-flag test skipped (plain script; run via "
              f"py -3 -m multirandom.prng_unsecure.mersenne_twister to test it)")
    else:
        flag = multirandom.ignore_unsecure_prng_warning_do_not_set_to_true_unless_you_know_how_risky_it_is
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                _mersenne_warning_state["warned"] = False
                MersenneTwister(0xBAD)
                _mersenne_warning_state["warned"] = True
            assert any(_MERSENNE_UNSECURE_WARNING in str(w.message) for w in caught), \
                "unsecure warning went missing"

            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                multirandom.ignore_unsecure_prng_warning_do_not_set_to_true_unless_you_know_how_risky_it_is = True
                _mersenne_warning_state["warned"] = False
                MersenneTwister(0xBAD)
                _mersenne_warning_state["warned"] = True
                assert not caught, "global flag failed to silence the warning"
        finally:
            _mersenne_warning_state["warned"] = True
            multirandom.ignore_unsecure_prng_warning_do_not_set_to_true_unless_you_know_how_risky_it_is = flag
        print(f"[9] warning fires once, silenced by {_flag_name} = True: OK")

    print("-" * 70)
    print("All mersenne_twister checks passed!")
