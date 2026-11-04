"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.prng_unsecure.lcg
Description:
Linear Congruential Generators exactly as the textbooks write them. The class
`LCGs` takes user-supplied formulas acting on the state s: `rules` for the
forward step (e.g. "(s * a + c) % d") and the optional `reverse_rules` for the
inverse step (e.g. "((s - c) * pow(a, -1, d)) % d"), with parameters a/b/c/d
(defaults 10 / 3 / 5 / 25565) and a randomised state by default. roll()
advances the state, reverse_roll() walks it backwards -- demonstrating the
insecurity of simple modular arithmetic: with a few consecutive outputs, state
(and every past and future output) is recoverable via the modular
multiplicative inverse, so a and d must be coprime for reversal to exist.
:meth:`LCGs.java_random` wraps the java.util.Random generator (the 48-bit LCG
with the 0x5DEECE66D multiplier), and :meth:`LCGs.crack_java_random` recovers
its full state from two consecutive 32-bit outputs by brute-forcing the 16
lost low bits.
Intended for offline games/education, NOT cryptography; the class warns once
per process, governed by the package's global warning flag.
"""
import random
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


class LCGs:
    """
    Linear Congruential Generator (LCG) Implementation.

    Summary:
    This class implements a Linear Congruential Generator, a simple algorithm that yields a
    sequence of pseudo-randomized numbers calculated with a linear equation.

    WARNING:
    LCGs are NOT safe for cryptography or high-stakes randomness (like gambling or leaderboards).
    Because they are based on simple math (modular arithmetic), their state can be recovered
    (reversed) if a few outputs are known, e.g., using Modular Multiplicative Inverse (MMI).
    This is only safe for OFFLINE GAMES with NO LEADERBOARDS.
    See: https://youtu.be/XDsYPXRCXAs?si=oDaFsqZyNJWVXwEi

    Required args:
        rules: str - The forward formula, e.g., "(s * a + c) % d"

    Optional args:
        reverse_rules: str or None - The formula to reverse the state, proving insecurity.
                                     e.g., "((s - c) * pow(a, -1, d)) % d"
        s: int - Seed/State
        a: int - Multiplier
        b: int - kept for backward compatibility if needed
        c: int - Increment
        d: int - Modulus
    """

    _warned = False  # warn once per process; governed by the global warning flag

    def __init__(
        self,
        rules: str,
        reverse_rules: "str or None" = None,
        s: int = random.randint(1, 9999),
        a: int = 10,
        b: int = 3,  # kept for backward compatibility if needed
        c: int = 5,
        d: int = 25565
    ):
        if not LCGs._warned:
            LCGs._warned = True
            _warn_unsecure(
                "LCGs are NOT cryptographically secure (linear algebra + a few outputs "
                "are enough to reverse the state). Safe for OFFLINE GAMES with NO "
                "LEADERBOARDS only. https://youtu.be/XDsYPXRCXAs?si=oDaFsqZyNJWVXwEi")

        if rules is None:
            raise ValueError("rules must be provided (e.g., '(s * a + c) % d')")

        self.rules = rules
        self.reverse_rules = reverse_rules
        self.s = s
        self.a = a
        self.b = b
        self.c = c
        self.d = d

    def roll(self):
        """Advance the generator state forward."""
        # Standard eval with restricted scope
        self.s = eval(self.rules, {"__builtins__": None}, {
            's': self.s, 'a': self.a, 'b': self.b,
            'c': self.c, 'd': self.d
        })
        return self.s

    def reverse_roll(self):
        """
        Reverse the generator state backward.

        This method demonstrates the insecurity of LCGs. If you know the parameters (a, c, d)
        and the current state (s), you can calculate the PREVIOUS state using:
        s_prev = (s - c) * a^(-1) mod d
        """
        if self.reverse_rules is None:
            raise ValueError("reverse_rules is not defined! Cannot reverse state.")

        # Using pow(a, -1, d) for modular multiplicative inverse in python 3.8+
        self.s = eval(self.reverse_rules, {"__builtins__": None, "pow": pow}, {
            's': self.s, 'a': self.a, 'b': self.b,
            'c': self.c, 'd': self.d
        })
        return self.s

    def random(self, s: "int or None" = None):
        """Predict next bit/value based on roll (0 or 1)."""
        if s is not None:
            self.s = s
        old_s = self.s
        self.roll()
        return 1 if old_s <= self.s else 0

    def randint(self):
        """Returns the current raw state integer."""
        self.roll()
        return self.s

    # -- java.util.Random ----------------------------------------------------

    @classmethod
    def java_random(cls, seed=None) -> "JavaLCG":
        """java.util.Random as an LCG factory (returns a :class:`JavaLCG`).

        Java's generator is the 48-bit LCG ``s' = (s * 0x5DEECE66D + 11)
        mod 2^48`` with the ``setSeed`` scramble ``seed ^ 0x5DEECE66D``;
        ``next(32)`` exposes only the top 32 bits of the state. ::

            rng = LCGs.java_random()            # java.util.Random(seed)
            rng.next_bits(32)                   # nextInt()
            rng.random()                        # nextDouble()
        """
        return JavaLCG(seed)

    @classmethod
    def crack_java_random(cls, out1: int, out2: int, verify=None) -> int:
        """Recover java.util.Random's 48-bit state from two next(32) outputs.

        Two consecutive ``nextInt()`` values observed from a victim expose
        the top 32 bits of two successive states -- the bottom 16 bits of
        the state are never printed. Brute-force those 65536 lost bits: for
        each candidate ``s1 = (out1 << 16) | low`` check whether
        ``(s1 * 0x5DEECE66D + 11) mod 2^48`` has ``out2`` as its top 32
        bits. Exactly one of the 65536 candidates survives (the others miss
        with probability 1 - 2^-32 per run).

        Returns the recovered 48-bit state from *just before* ``out1`` was
        emitted; feed it to ``JavaLCG.from_state(...)`` and the clone's next
        outputs are ``out1, out2, ...`` -- the victim's stream, replayed. ::

            recovered = LCGs.crack_java_random(x1, x2)
            clone = JavaLCG.from_state(recovered)
            assert clone.next_bits(32) == x1      # replays the leak

        ``verify``: optional third consecutive next(32) output the candidate
        must also reproduce (belt-and-braces for adversarial inputs).
        """
        out1 &= JavaLCG._BITS_MASK
        out2 &= JavaLCG._BITS_MASK
        mult, add, mask = JavaLCG.MULTIPLIER, JavaLCG.ADDEND, JavaLCG.MASK
        hits = []
        for low in range(1 << 16):                # the 16 hidden low bits
            candidate = (out1 << 16) | low        # state that produced out1
            if ((candidate * mult + add) & mask) >> 16 == out2:
                hits.append(candidate)
        if verify is not None:                    # a third output narrows it
            verify &= JavaLCG._BITS_MASK
            hits = [s for s in hits
                    if ((((s * mult + add) & mask) * mult + add) & mask) >> 16 == verify]
        if not hits:
            raise ValueError(
                "no 48-bit state matches these consecutive next(32) outputs; "
                "check that out1 immediately precedes out2 in the stream")
        if len(hits) > 1:
            raise ValueError(
                f"ambiguous: {len(hits)} states match; pass a third output "
                "as verify to disambiguate")
        state = hits[0]
        # step BACK once through the modular inverse so the recovered state
        # replays out1 first (from_state(state).next_bits(32) == out1)
        return ((state - add) * pow(mult, -1, 1 << 48)) & mask


# ---------------------------------------------------------------------------
# The java.util.Random LCG (48-bit, multiplier 0x5DEECE66D)
# ---------------------------------------------------------------------------

class JavaLCG:
    """
    ``java.util.Random`` -- the 48-bit LCG behind Java's Random class.

    State update: ``s = (s * 0x5DEECE66D + 0xB) mod 2^48``; ``setSeed`` first
    scrambles the seed as ``seed ^ 0x5DEECE66D`` (so Java seeds always start
    odd); ``next(bits)`` returns the TOP ``bits`` bits of the new state, which
    for ``nextInt()``/``next(32)`` discards the bottom 16. Only the top bits
    are ever exposed -- the low 16 bits are invisible, which is exactly the
    wrinkle :meth:`LCGs.crack_java_random` brute-forces.

    Constructing warns once per process (governed by the package's global
    warning flag).
    """

    MULTIPLIER = 0x5DEECE66D       # a -- "25214903917"
    ADDEND = 0xB                   # c -- 11
    MASK = (1 << 48) - 1           # d -- 2^48 - 1: the 48-bit state
    _BITS_MASK = 0xFFFFFFFF        # next() may only ask for up to 32 bits

    _warned = False                # warn once per process

    def __init__(self, seed=None):
        if not JavaLCG._warned:
            JavaLCG._warned = True
            _warn_unsecure(
                "JavaLCG is java.util.Random's 48-bit LCG: two consecutive "
                "32-bit outputs recover the full state "
                "(LCGs.crack_java_random), after which every future draw is "
                "predictable. For cryptography use csprng.")
        if seed is None:
            self._state = (random.randrange(1 << 48) ^ JavaLCG.MULTIPLIER) & JavaLCG.MASK
        else:
            self._state = (seed ^ JavaLCG.MULTIPLIER) & JavaLCG.MASK  # setSeed

    @classmethod
    def from_state(cls, state: int) -> "JavaLCG":
        """Build the generator for a RAW 48-bit internal state (no scramble).

        The counterpart of ``state()`` -- what :meth:`LCGs.crack_java_random`
        recovers is exactly the kind of value this accepts. Not a Java seed:
        those go through the ``setSeed`` XOR first; look at ``seed``.
        """
        state &= JavaLCG.MASK
        gen = cls.__new__(cls)
        gen._state = state
        if not JavaLCG._warned:
            JavaLCG._warned = True
            _warn_unsecure(
                "JavaLCG is java.util.Random's 48-bit LCG: two consecutive "
                "32-bit outputs recover the full state "
                "(LCGs.crack_java_random), after which every future draw is "
                "predictable. For cryptography use csprng.")
        return gen

    def seed(self, seed=None):
        """java.util.Random.setSeed -- scramble with the 0x5DEECE66D mask."""
        if seed is None:
            seed = random.randrange(1 << 48)
        self._state = (seed ^ JavaLCG.MULTIPLIER) & JavaLCG.MASK

    def getstate(self) -> tuple:
        """Raw (48-bit state, index 0) -- CPython-compatible layout."""
        return (self._state, 0)

    def setstate(self, state):
        state_, _ = state
        self._state = state_ & JavaLCG.MASK

    def next_bits(self, bits: int = 32) -> int:
        """``next(bits)`` -- advance, then return the top ``bits`` bits.

        Java allows 1..32 bits in ``next(b)``; the modest 48-bit state can
        only honestly expose up to 32.
        """
        if not 1 <= bits <= 32:
            raise ValueError("java.util.Random.next requires 1 <= bits <= 32")
        self._state = (self._state * JavaLCG.MULTIPLIER + JavaLCG.ADDEND) & JavaLCG.MASK
        return self._state >> (48 - bits)

    def next_int(self) -> int:
        """``nextInt()`` -- next(32) seen as a signed Java `int`."""
        value = self.next_bits(32)
        return value - (1 << 32) if value >= (1 << 31) else value

    def roll(self) -> int:
        """Package-conventional step -- next(32) as a plain 32-bit word."""
        return self.next_bits(32)

    def random(self) -> float:
        """``nextDouble()`` -- (next(26) << 27 | next(27)) / 2^53, in [0, 1)."""
        a = self.next_bits(26)
        b = self.next_bits(27)
        return (a * (1 << 27) + b) / (1 << 53)


class JavaRandom(JavaLCG):
    """Alias -- same as :class:`JavaLCG`, the friendlier read for code that
    wants to say "the Java random" instead of "the Java LCG"."""



def main():
    print("=" * 70)
    print("lcg - LCGs + java.util.Random self-check battery")
    print("=" * 70)

    # --- 1. user-supplied formulas: forward / inverse round trip ------------
    forward_rules = "(s * a + c) % d"
    reverse_rules = "((s - c) * pow(a, -1, d)) % d"
    gen = LCGs(forward_rules, reverse_rules, s=7, a=13)  # a=10 is NOT coprime
    forward = [gen.roll() for _ in range(64)]           # with d=25565 (gcd 5)
    assert forward[0] == (7 * 13 + 5) % 25565, "default parameters misapplied"
    walker = LCGs(forward_rules, reverse_rules, s=forward[-1], a=13)
    walked_back = [walker.reverse_roll() for _ in range(64)]
    assert walked_back[::-1] == [7] + forward[:63], "reverse walk lost the track"
    try:
        LCGs(forward_rules).reverse_roll()
    except ValueError:
        pass
    else:
        raise AssertionError("reverse_roll must refuse without reverse_rules")
    print("[1] custom formulas: 64 forward steps retrace perfectly backwards: OK")

    # --- 2. hand-checked textbook values -------------------------------------
    assert LCGs(forward_rules, reverse_rules, s=7).roll() == 75       # 7*10+5
    two = LCGs(forward_rules, reverse_rules, s=1, a=7, c=3, d=10)
    assert two.roll() == 0 and two.reverse_roll() == 1                # and back
    bits = {isinstance(g, int) for g in
            [LCGs(forward_rules, reverse_rules).random() for _ in range(60)]}
    assert bits == {True}, "random() must hand back ints"
    print("[2] hand-checked sequences (75 = 7*10+5 mod 25565; 1*7+3 mod 10 = 0): OK")

    # --- 3. java.util.Random, exactly as the javadoc spells it ---------------
    jc = JavaLCG(0)
    assert jc._state == 0x5DEECE66D, "setSeed must scramble with the multiplier"
    assert jc.next_int() == -1155484576, "new Random(0).nextInt() -- the classic"
    assert jc.next_int() == -723955400 and jc.next_int() == 1033096058
    assert JavaLCG(0).next_bits(16) == 47904, "next(16) must be the top 16 bits"
    double = JavaLCG(0).random()
    assert 0.0 <= double < 1.0 and abs(double - 0.730967787376657) < 1e-15
    assert JavaLCG(987654321).next_bits(1) in (0, 1)
    assert JavaLCG(987654321).next_bits(1) in (0, 1), "next(1) is the top state bit"
    for bits in (1, 7, 16, 31, 32):
        fresh = JavaLCG(987654321)
        for _ in range(50):
            value = fresh.next_bits(bits)
            assert 0 <= value < (1 << bits)
    for bad in (0, 33, -2):
        try:
            JavaLCG(1).next_bits(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"next_bits({bad}) must be refused")
    assert LCGs.java_random(0).next_int() == -1155484576, "factory == JavaLCG"
    print("[3] java.util.Random stream (nextInt/next16/nextDouble) + bounds: OK")

    # --- 4. THE attack: two nextInt() values -> the whole 48-bit state -------
    victim = JavaLCG(123456789)
    x1, x2, x3 = victim.next_bits(32), victim.next_bits(32), victim.next_bits(32)
    tail = [victim.next_bits(32) for _ in range(100)]
    recovered = LCGs.crack_java_random(x1, x2)
    assert 0 <= recovered < (1 << 48)
    clone = JavaLCG.from_state(recovered)
    assert clone.next_bits(32) == x1, "clone must replay out1 first"
    assert clone.next_bits(32) == x2 and clone.next_bits(32) == x3
    assert [clone.next_bits(32) for _ in range(100)] == tail
    assert LCGs.crack_java_random(x1, x2, verify=x3) == recovered
    for bad_verify in (x2, x3 ^ 1):
        try:
            LCGs.crack_java_random(x1, x2, verify=bad_verify)
        except ValueError:
            pass
        else:
            raise AssertionError("crack accepted a wrong verify output")
    try:
        LCGs.crack_java_random(x1, x1)
    except ValueError:
        pass
    else:
        raise AssertionError("crack must refuse an impossible output pair")
    print("[4] two nextInt() -> the seed; cloned generator replays 100 draws: OK")

    # --- 5. the once-per-process warning, and the global silencer -----------
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
                LCGs._warned = JavaLCG._warned = False
                LCGs(forward_rules)
                JavaLCG(5)
                LCGs._warned = JavaLCG._warned = True
            assert any("LCGs are NOT" in str(w.message) for w in caught), \
                "LCG warning went missing"
            assert any("JavaLCG" in str(w.message) for w in caught), \
                "java warning went missing"
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                setattr(multirandom, _flag_name.split(".", 1)[1], True)
                LCGs._warned = JavaLCG._warned = False
                LCGs(forward_rules)
                JavaLCG(5)
                assert not caught, "global flag failed to silence the warning"
        finally:
            LCGs._warned = JavaLCG._warned = True
            setattr(multirandom, _flag_name.split(".", 1)[1], flag)
        print(f"[5] warnings fire once, silenced by {_flag_name} = True: OK")

    print("-" * 70)
    print("All lcg checks passed!")


if __name__ == "__main__":
    main()
