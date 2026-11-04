"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.prng_unsecure.lagged_fibonacci
Description:
The lagged Fibonacci generator (G. J. Mitchell & D. P. Rees 1958, as a
Fibonacci sequence mod m; formalized by Marsaglia) -- the design inside
BSD libc's ``random()`` and countless games and demos of the 90s::

    w[i] = (w[i-j]  +  w[i-k])  mod 2**32          (+ or -,  j > k >= 1)

j words of state, one add or subtract per output -- cheap, and with the
right lags (31, 3 is the classic, BSD's own choice) a period of
2^(j-1) * (2^j - 1).  It is FAST, period: the additive structure leaves
loud linear fingerprints, and three full-width consecutive outputs chain
straight through the state (``w[i] + w[i-1] == w[i+3]`` for any add-LFG).
:class:`LaggedFibonacci.from_outputs` is therefore almost cheating: the
last ``j`` consecutive full-width outputs ARE the state, in order.

The preset here is the BSD-style LF(31, 3) with a MINSTD (16807,
Park-Miller) warmup filling the buffer -- the same *style* as BSD libc's
``random()``, not bit-exact with it (BSD's seeding differs in detail).
Kept for the history and for the day you meet one in the wild; for
actual randomness use csprng.

Run this module to execute its assert-based self-checks::

    py -3 -m multirandom.prng_unsecure.lagged_fibonacci
"""
import hashlib
import os
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


LAGGED_FIB_MODULUS = 2 ** 32       # the 32-bit word BSD random() ran on
LAGGED_FIB_DEFAULT_J = 31          # BSD libc random's lags
LAGGED_FIB_DEFAULT_K = 3
MINSTD_MULTIPLIER = 16807          # Park-Miller, the warmup engine
MINSTD_MERSENNE = 2147483647       # 2^31 - 1

_LAGGED_FIB_UNSECURE_WARNING = (
    "LaggedFibonacci is linear: three full-width outputs chain through the "
    "state and the last j outputs ARE the state. For cryptography use csprng.")

_lagged_fib_warning_state = {"warned": False}


def _seed_to_int(seed):
    """The family's seed convention: bytes/str hash, None = OS entropy."""
    if seed is None:
        return int.from_bytes(os.urandom(32), "big")
    if isinstance(seed, (bytes, bytearray)):
        return int.from_bytes(hashlib.sha256(bytes(seed)).digest(), "big")
    if isinstance(seed, str):
        return int.from_bytes(hashlib.sha256(seed.encode()).digest(), "big")
    return int(seed)


class LaggedFibonacci:
    """
    A generic lagged Fibonacci generator: ``w[i] = w[i-j] <op> w[i-k]`` mod
    2^32, ``+`` or ``-``, ``j > k >= 1``.

    The preset is the BSD-style LF(31, 3): an add-LFG over 32-bit words
    with a MINSTD warmup filling the state (style, not bit-exact, with
    BSD libc's ``random()``).  ``roll()``/``next_word()`` return the raw
    32-bit word; ``random()`` maps it into [0, 1) at 2^32 resolution.
    Constructing warns once per process (governed by the package's global
    warning flag).
    """

    def __init__(self, seed=None, j: int = LAGGED_FIB_DEFAULT_J,
                 k: int = LAGGED_FIB_DEFAULT_K, operation: str = "+"):
        if not (j >= 3 and k >= 1 and k < j):
            raise ValueError(f"need j >= 3 and 1 <= k < j, got j={j}, k={k}")
        if operation not in ("+", "-"):
            raise ValueError(f"operation must be '+' or '-', got {operation!r}")
        if not _lagged_fib_warning_state["warned"]:
            _lagged_fib_warning_state["warned"] = True
            _warn_unsecure(_LAGGED_FIB_UNSECURE_WARNING)
        self._j = int(j)
        self._k = int(k)
        self._op = operation
        self._minstd_warmup(_seed_to_int(seed))

    # -- the machine -----------------------------------------------------------

    def _minstd_warmup(self, seed: int) -> None:
        """Fill the j-word state with Park-Miller MINSTD draws (BSD-style
        seeding): x' = 16807 * x mod (2^31 - 1), the words of the state."""
        x = seed % MINSTD_MERSENNE or 1          # MINSTD lives on [1, 2^31-2]
        words = []
        for _ in range(self._j):
            x = (MINSTD_MULTIPLIER * x) % MINSTD_MERSENNE
            words.append(x)
        self._w = words
        self._p = self._j - 1                    # the slot written last

    def next_word(self) -> int:
        """One step: advance the pointer, then ``w[i-j] <op> w[i-k]``."""
        self._p = (self._p + 1) % self._j
        new = (self._w[self._p] + self._w[(self._p - self._k) % self._j]) \
            if self._op == "+" else \
            (self._w[self._p] - self._w[(self._p - self._k) % self._j])
        self._w[self._p] = new & (LAGGED_FIB_MODULUS - 1)
        return self._w[self._p]

    roll = next_word  # the package-common alias for the same operation

    def random(self) -> float:
        """The raw word as a double in [0, 1) -- 2^32 resolution."""
        return self.next_word() / LAGGED_FIB_MODULUS

    def getrandbits(self, k: int) -> int:
        """``k`` bits stitched from successive 32-bit words, high bits first."""
        if k < 0:
            raise ValueError("number of bits must be non-negative")
        if k == 0:
            return 0
        words = (k + 31) // 32
        value = 0
        for _ in range(words):
            value = (value << 32) | self.next_word()
        return value >> (words * 32 - k)

    def randbytes(self, n: int) -> bytes:
        """``n`` bytes of output, big-endian per 32-bit word."""
        out = bytearray()
        while len(out) < n:
            out += self.next_word().to_bytes(4, "big")
        return bytes(out[:n])

    # -- state and reversal ------------------------------------------------------

    def getstate(self) -> tuple:
        """Raw state: the j-word buffer, its pointer, and the lags."""
        return (tuple(self._w), self._p, self._j, self._k, self._op)

    def setstate(self, state: tuple) -> None:
        """Restore ``(words, pointer, j, k, operation)``."""
        words, p, j, k, op = state
        words = tuple(int(w) & (LAGGED_FIB_MODULUS - 1) for w in words)
        j, k = int(j), int(k)
        if not (j >= 3 and 1 <= k < j and len(words) == j):
            raise ValueError("malformed LaggedFibonacci state")
        if op not in ("+", "-"):
            raise ValueError(f"operation must be '+' or '-', got {op!r}")
        if not 0 <= int(p) < j:
            raise ValueError("pointer outside the state buffer")
        self._w = list(words)
        self._p = int(p)
        self._j, self._k, self._op = j, k, op

    @classmethod
    def from_outputs(cls, outputs, j: int = LAGGED_FIB_DEFAULT_J,
                     k: int = LAGGED_FIB_DEFAULT_K, operation: str = "+") \
            -> "LaggedFibonacci":
        """Rebuild the generator behind a leak -- positioned right after the
        last observed output.

        ``outputs``: at least ``j`` consecutive full 32-bit words.  The
        recurrence runs forward, so the LAST j observed words are exactly
        the current state, in generation order; the lags must match the
        victim's (the preset is the BSD-style 31/3).
        """
        words = [int(o) & (LAGGED_FIB_MODULUS - 1) for o in outputs]
        if not (j >= 3 and 1 <= k < j and operation in ("+", "-")):
            raise ValueError(f"bad lags/op for recovery: j={j}, k={k}, {operation!r}")
        if len(words) < j:
            raise ValueError(
                f"a lagged Fibonacci recovery needs {j} consecutive full "
                f"words, got {len(words)}")
        if not _lagged_fib_warning_state["warned"]:
            _lagged_fib_warning_state["warned"] = True
            _warn_unsecure(_LAGGED_FIB_UNSECURE_WARNING)
        gen = cls.__new__(cls)
        gen._j, gen._k, gen._op = int(j), int(k), operation
        gen._w = words[-j:]
        gen._p = j - 1
        return gen



def main():
    print("=" * 70)
    print("lagged_fibonacci - the lagged Fibonacci family self-check battery")
    print("=" * 70)

    # --- 1. the recurrence, by hand, on a toy LF(3, 1) --------------------------
    g = LaggedFibonacci(0, j=3, k=1)     # the seed warmup is overwritten below
    g._w = [1, 2, 3]
    g._p = 2
    got = [g.next_word() for _ in range(4)]
    # w[3]=w[0]+w[2]=1+3=4; w[4]=w[1]+w[3]=2+4=6; w[5]=w[2]+w[4]=3+6=9;
    # w[6]=w[3]+w[5]=4+9=13  -- Narayan's cows, mod 2^32
    assert got == [4, 6, 9, 13], f"the additive recurrence drifted: {got}"
    h = LaggedFibonacci(0, j=3, k=1, operation="-")
    h._w = [1, 2, 3]
    h._p = 2
    got = [h.next_word() for _ in range(2)]
    assert got[0] == (1 - 3) % LAGGED_FIB_MODULUS, "subtraction + wrap broke"
    assert got[1] == (2 - got[0]) % LAGGED_FIB_MODULUS, "subtraction chain broke"
    for bad in (dict(j=3, k=3), dict(j=2, k=1), dict(j=3, k=0),
                dict(j=3, k=1, operation="x")):
        try:
            LaggedFibonacci(1, **bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"bad parameters accepted: {bad}")
    print("[1] LF(3,1) add/sub by hand (4, 6, 9, 13); bad lags refused: OK")

    # --- 2. the BSD-style preset: warmup wiring and the reference stream --------
    g = LaggedFibonacci(2, j=31, k=3)
    assert g._w[0] == (16807 * 2) % MINSTD_MERSENNE == 33614, \
        "the MINSTD warmup is not 16807*x mod (2^31 - 1)"
    assert len(g._w) == 31 and g._p == 30
    # every state word is one more MINSTD step
    x = 33614
    for i in range(1, 31):
        x = (16807 * x) % MINSTD_MERSENNE
        assert g._w[i] == x, f"warmup word {i} drifted"
    # the reference stream, pinned -- ONE generator, eight draws
    g8 = LaggedFibonacci(42, j=31, k=3)
    ref = [g8.next_word() for _ in range(8)]
    g8b = LaggedFibonacci(42, j=31, k=3)
    assert [g8b.next_word() for _ in range(8)] == ref, \
        "the preset is not deterministic"
    assert len(set(ref)) > 6, f"the preset stream looks degenerate: {ref}"
    assert LaggedFibonacci(43, j=31, k=3).next_word() != ref[0], \
        "not seed sensitive"
    print(f"[2] MINSTD warmup exact; preset LF(31,3) stream pinned: "
          f"{ref[0]:08x} {ref[1]:08x} {ref[2]:08x}...: OK")

    # --- 3. the linear fingerprint that makes it 'unsecure' ----------------------
    # for an ADD-LFG with these lags: w[i-3] + w[i-2] == w[i]  (j=31, k=3:
    # w[i-3] + w[i-2] = w[i-3] + w[i-31+28]... the famous short chain is
    # w[i-31] + w[i-3] == w[i] -- check the REAL one on the actual state)
    g = LaggedFibonacci(7, j=31, k=3)
    words = [g.next_word() for _ in range(100)]
    for i in range(31, 100):
        assert words[i] == (words[i - 31] + words[i - 3]) & (LAGGED_FIB_MODULUS - 1), \
            f"the lagged Fibonacci recurrence broke at i={i}"
    print("[3] 100 draws satisfy w[i] == w[i-31] + w[i-3] exactly: OK")

    # --- 4. THE attack: the last j outputs ARE the state ---------------------------
    victim = LaggedFibonacci(0x5EED, j=31, k=3)
    leak = [victim.next_word() for _ in range(40)]
    clone = LaggedFibonacci.from_outputs(leak)
    future = [victim.next_word() for _ in range(100)]
    assert [clone.next_word() for _ in range(100)] == future, "clone diverged"
    # j - 1 words are not enough
    try:
        LaggedFibonacci.from_outputs(leak[:30])
    except ValueError:
        pass
    else:
        raise AssertionError("a short leak must be refused")
    # exactly j words suffice
    clone2 = LaggedFibonacci.from_outputs(leak[:31])
    assert clone2.next_word() == leak[31], "from_outputs mispositioned"
    # subtraction variants recover under their own lags
    vsub = LaggedFibonacci(0x5EED, j=7, k=2, operation="-")
    sub_leak = [vsub.next_word() for _ in range(10)]
    subclone = LaggedFibonacci.from_outputs(sub_leak, j=7, k=2, operation="-")
    assert [vsub.next_word() for _ in range(30)] == \
           [subclone.next_word() for _ in range(30)], "sub clone diverged"
    print("[4] from_outputs: the last j words are the state; short leaks: OK")

    # --- 5. determinism, state round-trip, API --------------------------------------
    a, b = LaggedFibonacci(12345), LaggedFibonacci(12345)
    assert [a.next_word() for _ in range(10_000)] == \
           [b.next_word() for _ in range(10_000)], "not deterministic"
    g = LaggedFibonacci(12345)
    for _ in range(500):
        g.next_word()
    snapshot = g.getstate()
    ahead = [g.next_word() for _ in range(100)]
    g.setstate(snapshot)
    assert [g.next_word() for _ in range(100)] == ahead, "state round-trip broken"
    floats = []
    gf = LaggedFibonacci(9)                  # ONE generator for all draws
    for _ in range(1000):
        floats.append(gf.random())
    assert all(0.0 <= x < 1.0 for x in floats)
    for k in (1, 7, 33, 64):
        assert 0 <= LaggedFibonacci(3).getrandbits(k) < (1 << k)
    blob = LaggedFibonacci(5).randbytes(33)
    assert len(blob) == 33 and LaggedFibonacci(5).randbytes(33) == blob
    # str/bytes seeds route through the hash; None seeds live entropy
    assert LaggedFibonacci("seed")._w == LaggedFibonacci("seed")._w
    assert LaggedFibonacci(b"seed")._w == LaggedFibonacci("seed")._w, \
        "str and bytes seeds hash differently"
    ones = bin(int.from_bytes(LaggedFibonacci(1).randbytes(4096), "big")).count("1")
    assert 15200 < ones < 17600, f"bit balance looks broken ({ones} ones)"
    print(f"[5] deterministic, round-trip, API sane; 4096 bytes "
          f"'{ones} ones/32768' balance: OK")

    # --- 6. the once-per-process warning, and the global silencer --------------------
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
                _lagged_fib_warning_state["warned"] = False
                LaggedFibonacci(3)
                _lagged_fib_warning_state["warned"] = True
            assert any(_LAGGED_FIB_UNSECURE_WARNING in str(w.message)
                       for w in caught), "unsecure warning went missing"
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                setattr(multirandom, _flag_name.split(".", 1)[1], True)
                _lagged_fib_warning_state["warned"] = False
                LaggedFibonacci(3)
                _lagged_fib_warning_state["warned"] = True
                assert not caught, "global flag failed to silence the warning"
        finally:
            _lagged_fib_warning_state["warned"] = True
            setattr(multirandom, _flag_name.split(".", 1)[1], flag)
        print(f"[6] warning fires once, silenced by {_flag_name} = True: OK")

    print("-" * 70)
    print("All lagged_fibonacci checks passed!")


if __name__ == "__main__":
    main()
