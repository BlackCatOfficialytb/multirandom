"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.trng.rand_using_real_random
Description:
Ambient-microphone entropy via the optional `real-random` package.
`real-random` (https://pypi.org/project/real-random/) records 1-2 seconds of
microphone audio, hashes it with SHA-256 and turns the hash into random values.
Install the optional dependency with:

    pip install "multirandom[microphone]"

`MicrophoneRandom` captures that entropy once and then runs a local Mersenne
Twister stream; `reseed()` captures again. The higher-level helpers of the
package (`real_random`, `real_random_int`, ...) are re-exported lazily, so each
call captures fresh audio.
"""
import random

_INSTALL_HINT = (
    "Microphone entropy needs the optional 'real-random' package; install it with: "
    'pip install "multirandom[microphone]"'
)

_PASSTHROUGH = {
    "real_random",
    "real_random_int",
    "real_random_float",
    "real_random_choice",
    "real_random_string",
}

def _import_real_random():
    try:
        import real_random
    except ImportError as exc:
        raise ImportError(_INSTALL_HINT) from exc
    return real_random

def microphone_seed():
    """Capture ~1-2 s of ambient audio and return a float in [0, 1)."""
    return _import_real_random().real_random()

class MicrophoneRandom(random.Random):
    """`random.Random` seeded from ambient microphone noise.

    The capture costs 1-2 s; afterwards the stream is a normal local Mersenne
    Twister, so call `reseed()` when you want fresh physical entropy.
    """

    def __init__(self, seed=None):
        if seed is None:
            seed = microphone_seed()
        super().__init__(seed)

    def reseed(self):
        """Replace the state with a fresh microphone capture."""
        super().seed(microphone_seed())
        return self

def __getattr__(name):
    if name in _PASSTHROUGH:
        return getattr(_import_real_random(), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
