"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.prng_unsecure.v8_xorshift128plus
Description:
The generator behind JavaScript's ``Math.random()`` in every Chromium and
Node build since 2015: xorshift128+ (Saito & Matsumoto's primitive,
adapted by the V8 team) -- two 64-bit words of state, all shifts and
xors::

    s1 = state0;  s0 = state1          # the V8 XorShift128 step
    state0 = s0
    s1 ^= s1 << 23;  s1 ^= s1 >> 17
    state1 = s1 ^ s0 ^ (s0 >> 26)

V8's ``NextDouble`` then takes the NEW state0 (which is the OLD state1)
and cats its low 52 mantissa bits onto the [1, 2) exponent::

    ToDouble(x) = bit_cast<double>((x & 0xFFFFFFFFFFFFF)
                                   | 0x3FF0000000000000) - 1

so successive floats expose the low 52 bits of successive state1 words
in order.  That is the whole attack: every revealed bit is a linear
function (over GF(2)) of the 128 initial state bits, so five consecutive
``Math.random`` outputs are 260 linear equations -- :meth:`from_outputs`
writes the initial state as 128 symbolic bit-masks, runs the step
symbolically, and Gaussian-eliminates the floats into the exact seed
(no search, no brute force).  The classic integer return
``next_u64()`` is the xorshift128+ sum ``state1 + state0``.

Not broken in the statistical sense -- xorshift128+ passes BigCrush --
but fully reversible from a handful of outputs, which is why V8 later
moved to a cache-based PRNG.  For actual randomness use csprng.

Run this module to execute its assert-based self-checks::

    py -3 -m multirandom.prng_unsecure.v8_xorshift128plus
"""
import struct
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
_MANTISSA_MASK = 0xFFFFFFFFFFFFF          # V8: kMantissaMask, low 52 bits
_EXPONENT_BITS = 0x3FF0000000000000       # V8: kExponentBits, the [1, 2) binade

_V8_UNSECURE_WARNING = (
    "V8XorShift128Plus (Math.random's engine) is fully reversible from "
    "five consecutive outputs by GF(2) elimination -- from_outputs recovers "
    "the exact seed. For cryptography use csprng.")

_v8_warning_state = {"warned": False}


def _seed_to_int(seed):
    """The family's seed convention: bytes/str hash, None = OS entropy."""
    import hashlib
    import os
    if seed is None:
        return int.from_bytes(os.urandom(16), "big")
    if isinstance(seed, (bytes, bytearray)):
        return int.from_bytes(hashlib.sha256(bytes(seed)).digest()[:16], "big")
    if isinstance(seed, str):
        return int.from_bytes(hashlib.sha256(seed.encode()).digest()[:16], "big")
    return int(seed)


def _to_double(word: int) -> float:
    """V8's ToDouble: the word's low 52 bits as the mantissa of [1, 2) - 1."""
    bits = (word & _MANTISSA_MASK) | _EXPONENT_BITS
    return struct.unpack("<d", struct.pack("<Q", bits))[0] - 1.0


def _payload_of(value: float) -> int:
    """The exact inverse of _to_double: float in [0, 1) -> 52-bit payload."""
    if not 0.0 <= value < 1.0:
        raise ValueError(f"Math.random outputs live in [0, 1), got {value!r}")
    return struct.unpack("<Q", struct.pack("<d", value + 1.0))[0] & _MANTISSA_MASK


# --- the symbolic GF(2) machinery ----------------------------------------------
# A word is a list of 64 int masks: mask[i] is the set of initial-state bits
# (0..63 state0, 64..127 state1) that bit i of THIS word is a linear sum of.

def _shl(v: list, n: int) -> list:
    return [0] * n + v[:64 - n]


def _shr(v: list, n: int) -> list:
    return v[n:] + [0] * n


def _xor(a: list, b: list) -> list:
    return [x ^ y for x, y in zip(a, b)]


def _step_sym(s0m: list, s1m: list):
    """The V8 XorShift128 step on symbolic words (returns new s0, s1)."""
    s1 = s0m
    s0 = s1m
    s1 = _xor(s1, _shl(s1, 23))
    s1 = _xor(s1, _shr(s1, 17))
    s1 = _xor(s1, _xor(s0, _shr(s0, 26)))
    return s0, s1


class V8XorShift128Plus:
    """
    V8's Math.random engine: xorshift128+ under V8's exact NextDouble.

    ``random()`` is the faithful NextDouble (XorShift128 step, then
    ToDouble of the new state0); ``next_u64()``/``roll()`` is the classic
    xorshift128+ integer return ``state1 + state0``.  ``from_state``
    clones raw leaked state; ``from_outputs`` recovers the full 128-bit
    seed from five or more consecutive doubles.  An all-zero state is a
    fixed point of the step, so the constructor bumps a zero seed and
    ``setstate``/``from_state`` refuse it.  Constructing warns once per
    process (governed by the package's global warning flag).
    """

    def __init__(self, seed=None):
        if not _v8_warning_state["warned"]:
            _v8_warning_state["warned"] = True
            _warn_unsecure(_V8_UNSECURE_WARNING)
        seed = _seed_to_int(seed)
        self._state0 = seed & _M64
        self._state1 = (seed >> 64) & _M64
        if self._state0 == 0 and self._state1 == 0:
            self._state1 = 1        # zero is the step's unique fixed point

    @classmethod
    def from_state(cls, state0: int, state1: int) -> "V8XorShift128Plus":
        """Clone a generator from leaked raw state; sits AFTER the leak."""
        state0, state1 = int(state0) & _M64, int(state1) & _M64
        if state0 == 0 and state1 == 0:
            raise ValueError("the all-zero state is a fixed point -- refused")
        if not _v8_warning_state["warned"]:
            _v8_warning_state["warned"] = True
            _warn_unsecure(_V8_UNSECURE_WARNING)
        gen = cls.__new__(cls)
        gen._state0, gen._state1 = state0, state1
        return gen

    def _advance(self) -> None:
        """One V8 XorShift128 step, exactly as V8's source writes it."""
        s1 = self._state0
        s0 = self._state1
        self._state0 = s0
        s1 = (s1 ^ ((s1 << 23) & _M64)) & _M64
        s1 ^= s1 >> 17
        s1 = (s1 ^ s0 ^ (s0 >> 26)) & _M64
        self._state1 = s1

    def next_u64(self) -> int:
        """The classic xorshift128+ integer return: new state1 + state0."""
        self._advance()
        return (self._state1 + self._state0) & _M64

    roll = next_u64  # the package-common alias for the same operation

    def random(self) -> float:
        """V8's NextDouble: step, then ToDouble(new state0)."""
        self._advance()
        return _to_double(self._state0)

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
        """Raw state: the two 64-bit words (state0, state1)."""
        return (self._state0, self._state1)

    def setstate(self, state: tuple) -> None:
        """Restore ``(state0, state1)``; the all-zero pair is refused."""
        s0, s1 = (int(x) & _M64 for x in state)
        if s0 == 0 and s1 == 0:
            raise ValueError("the all-zero state is a fixed point -- refused")
        self._state0, self._state1 = s0, s1

    @classmethod
    def from_outputs(cls, outputs) -> "V8XorShift128Plus":
        """Rebuild ``Math.random`` behind a leak -- positioned right after the
        last observed output.

        ``outputs``: five or more CONSECUTIVE NextDouble values in [0, 1).
        Each float's 52 mantissa bits are linear equations over the 128
        initial-state bits; the step is run symbolically and the system is
        Gaussian-eliminated (pivots keyed by the highest unknown bit,
        back-substituted ascending).  Non-consecutive or wrong-shaped
        leaks are caught by an exact replay check before returning.
        """
        outputs = [float(v) for v in outputs]
        if len(outputs) < 5:
            raise ValueError(
                f"five consecutive Math.random outputs are the minimum, "
                f"got {len(outputs)}")
        if not _v8_warning_state["warned"]:
            _v8_warning_state["warned"] = True
            _warn_unsecure(_V8_UNSECURE_WARNING)
        payloads = [_payload_of(v) for v in outputs]

        # run the step symbolically; float k exposes low52(new state0).
        # Gaussian elimination: pivots keyed by the highest unknown bit.
        pivots = {}
        s0m = [1 << i for i in range(64)]
        s1m = [1 << (64 + i) for i in range(64)]
        for payload in payloads:
            s0m, s1m = _step_sym(s0m, s1m)
            for i in range(52):
                mask = s0m[i]
                bit = (payload >> i) & 1
                while mask:
                    h = mask.bit_length() - 1
                    if h in pivots:
                        pmask, pbit = pivots[h]
                        mask ^= pmask
                        bit ^= pbit
                    else:
                        pivots[h] = (mask, bit)
                        break
                if not mask and bit:
                    raise ValueError(
                        "the outputs are inconsistent with xorshift128+")
        if len(pivots) < 128:
            raise ValueError(
                f"rank {len(pivots)}/128 -- feed more consecutive floats")

        # back-substitute ascending: every mask bit below the pivot is known
        known = 0
        for h in sorted(pivots):
            mask, bit = pivots[h]
            parity = bin(mask & known).count("1") & 1
            if bit ^ parity:
                known |= 1 << h

        # replay the observed run from the solved initial state: both a
        # verification and the positioning of the clone after the last float
        gen = cls.__new__(cls)
        gen._state0 = known & _M64
        gen._state1 = (known >> 64) & _M64
        if gen._state0 == 0 and gen._state1 == 0:
            raise ValueError("the outputs decode to the degenerate zero state")
        for payload in payloads:
            gen._advance()
            if (gen._state0 & _MANTISSA_MASK) != payload:
                raise ValueError(
                    "the outputs are not consecutive Math.random doubles")
        return gen


if __name__ == "__main__":
    print("=" * 70)
    print("v8_xorshift128plus - V8's Math.random engine self-check battery")
    print("=" * 70)

    # --- 1. the step, raced against an independent inline transcription ------
    def v8_step_inline(s0, s1):
        # transcribed from V8's XorShift128 (elements/cc source shape)
        s1w = s0
        s0w = s1
        s0 = s0w
        s1w ^= s1w << 23
        s1w &= _M64
        s1w ^= s1w >> 17
        s1w ^= s0w ^ (s0w >> 26)
        return s0, s1w & _M64

    g = V8XorShift128Plus.from_state(0x0123456789ABCDEF, 0xFEDCBA9876543210)
    s0, s1 = 0x0123456789ABCDEF, 0xFEDCBA9876543210
    for _ in range(200):
        s0, s1 = v8_step_inline(s0, s1)
        g._advance()
        assert (g.getstate() == (s0, s1)), "the instance drifted from the spec"
    # the classic integer return, pinned from a live reference run
    g = V8XorShift128Plus.from_state(0x0123456789ABCDEF, 0xFEDCBA9876543210)
    got = [g.next_u64() for _ in range(6)]
    assert got == [0x4b182deded661907, 0x4b182e0a46eba587, 0x1738ed21d98fb1ac,
                   0xd54368ca3c0b083e, 0x4f26ffe82abc47ca, 0x928165d1d312c746], \
        f"the xorshift128+ return stream drifted: {got}"
    print("[1] XorShift128 step raced 200 deep against the V8 shape; "
          "return stream pinned: OK")

    # --- 2. NextDouble: ToDouble(new state0), the V8 specifics ------------------
    g = V8XorShift128Plus.from_state(0x0123456789ABCDEF, 0xFEDCBA9876543210)
    # the first float cats the INITIAL state1's low 52 bits onto [1, 2) - 1:
    # an exact integer identity, no struct needed
    first = g.random()
    assert first == (0xFEDCBA9876543210 & _MANTISSA_MASK) / 2 ** 52, \
        "NextDouble is not ToDouble(new state0)"
    assert first == 0.7955555555555556, "the pinned first float drifted"
    g2 = V8XorShift128Plus.from_state(0x0123456789ABCDEF, 0xFEDCBA9876543210)
    floats = [g2.random() for _ in range(6)]
    mantissas = [int(f * 2 ** 52) for f in floats]
    assert mantissas == [0xcba9876543210, 0xb73557711e6f7, 0xcbab4cfd9be90,
                         0xc326d09b5f31c, 0x7365d32551522, 0xfc98af86732a8], \
        f"the pinned mantissa stream drifted: {mantissas}"
    assert all(0.0 <= f < 1.0 for f in floats)
    print("[2] NextDouble == ToDouble(new state0); mantissa stream pinned: OK")

    # --- 3. THE attack: five-ish floats -> the exact 128-bit seed -----------------
    victim = V8XorShift128Plus.from_state(0xDEADBEEFCAFEBABE, 0x1234567890ABCDEF)
    leak = [victim.random() for _ in range(6)]
    clone = V8XorShift128Plus.from_outputs(leak)
    assert clone.getstate() == victim.getstate(), \
        "the clone is not positioned exactly on the victim's state"
    future = [victim.random() for _ in range(100)]
    assert [clone.random() for _ in range(100)] == future, "clone diverged"
    # exactly five floats suffice
    v2 = V8XorShift128Plus.from_state(1, 2)
    leak5 = [v2.random() for _ in range(5)]
    assert V8XorShift128Plus.from_outputs(leak5).getstate() == v2.getstate(), \
        "five floats must pin the state"
    # refusals
    try:
        V8XorShift128Plus.from_outputs(leak[:4])
    except ValueError:
        pass
    else:
        raise AssertionError("a four-float leak must be refused")
    gapped = leak[:2] + leak[3:5] + leak[5:]          # non-consecutive run
    try:
        V8XorShift128Plus.from_outputs(gapped)
    except ValueError:
        pass
    else:
        raise AssertionError("a gapped leak must be refused")
    for bad in (1.5, -0.1):
        try:
            V8XorShift128Plus.from_outputs(leak + [bad])
        except ValueError:
            pass
        else:
            raise AssertionError(f"out-of-range float {bad} accepted")
    print("[3] from_outputs: five floats pin the seed exactly; "
          "short/gapped leaks refused: OK")

    # --- 4. determinism, zero-state guard, state round-trip, API ------------------
    a, b = V8XorShift128Plus(12345), V8XorShift128Plus(12345)
    assert [a.next_u64() for _ in range(10_000)] == \
           [b.next_u64() for _ in range(10_000)], "not deterministic"
    assert V8XorShift128Plus(54321).next_u64() != V8XorShift128Plus(12345).next_u64(), \
        "not seed sensitive"
    # zero is a fixed point: the constructor bumps, setstate/from_state refuse
    g = V8XorShift128Plus(0)
    assert g.getstate() != (0, 0), "a zero seed must be bumped off the fixed point"
    assert g.next_u64() != 0
    for refuse in (lambda: V8XorShift128Plus.from_state(0, 0),
                   lambda: V8XorShift128Plus(1).setstate((0, 0))):
        try:
            refuse()
        except ValueError:
            pass
        else:
            raise AssertionError("the all-zero state was accepted")
    g = V8XorShift128Plus(12345)
    for _ in range(500):
        g.next_u64()
    snapshot = g.getstate()
    ahead = [g.next_u64() for _ in range(100)]
    g.setstate(snapshot)
    assert [g.next_u64() for _ in range(100)] == ahead, "state round-trip broken"
    # from_state clones raw leaked state, positioned after the observation
    victim = V8XorShift128Plus.from_state(0xAA, 0xBB)
    victim.next_u64()
    leak_state = victim.getstate()
    next_draw = victim.next_u64()
    assert V8XorShift128Plus.from_state(*leak_state).next_u64() == next_draw, \
        "from_state mispositioned"
    # the family API
    floats = []
    gf = V8XorShift128Plus(9)
    for _ in range(1000):
        floats.append(gf.random())
    assert all(0.0 <= f < 1.0 for f in floats)
    for k in (1, 7, 33, 64, 100):
        assert 0 <= V8XorShift128Plus(3).getrandbits(k) < (1 << k)
    blob = V8XorShift128Plus(5).randbytes(33)
    assert len(blob) == 33 and V8XorShift128Plus(5).randbytes(33) == blob
    assert V8XorShift128Plus("seed").getstate() == \
        V8XorShift128Plus("seed").getstate(), "str seed not deterministic"
    assert V8XorShift128Plus(b"seed").getstate() == \
        V8XorShift128Plus("seed").getstate(), "bytes/str seeds disagree"
    assert V8XorShift128Plus(None).getstate() != (0, 0), "None seed dead"
    ones = bin(int.from_bytes(V8XorShift128Plus(1).randbytes(4096), "big")).count("1")
    assert 15200 < ones < 17600, f"bit balance looks broken ({ones} ones)"
    print(f"[4] deterministic, zero-guarded, round-trip, API sane; "
          f"4096 bytes '{ones} ones/32768' balance: OK")

    # --- 5. the once-per-process warning, and the global silencer ------------------
    _flag_name = ("multirandom."
                  "ignore_unsecure_prng_warning_do_not_set_to_true_unless_you_know_how_risky_it_is")
    try:
        import multirandom
    except ImportError:                              # running as a plain script
        multirandom = None
    if multirandom is None:
        print("[5] global-flag test skipped (plain script)")
    else:
        flag = getattr(multirandom, _flag_name.split(".", 1)[1])
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                _v8_warning_state["warned"] = False
                V8XorShift128Plus(3)
                _v8_warning_state["warned"] = True
            assert any(_V8_UNSECURE_WARNING in str(w.message)
                       for w in caught), "unsecure warning went missing"
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                setattr(multirandom, _flag_name.split(".", 1)[1], True)
                _v8_warning_state["warned"] = False
                V8XorShift128Plus(3)
                _v8_warning_state["warned"] = True
                assert not caught, "global flag failed to silence the warning"
        finally:
            _v8_warning_state["warned"] = True
            setattr(multirandom, _flag_name.split(".", 1)[1], flag)
        print(f"[5] warning fires once, silenced by {_flag_name} = True: OK")

    print("-" * 70)
    print("All v8_xorshift128plus checks passed!")
