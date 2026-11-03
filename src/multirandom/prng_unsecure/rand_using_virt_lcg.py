"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.prng_unsecure.rand_using_virt_lcg
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
