"""multirandom - one random-number package, several philosophies of chance.

* ``prng_unsecure/`` - educational PRNGs that must never guard anything (LCGs, xorshift).
* ``csprng/``       - cryptographically strong generators (OS entropy, NIST DRBGs, stream ciphers).
* ``trng/``         - true/hardware entropy sources (microphones, weather, clicks, online APIs).

Everything in ``prng_unsecure/`` and the deliberately broken ``Dual_EC_DRBG`` warns the
first time it is used. Those warnings are controlled by ONE global variable::

    multirandom.ignore_unsecure_prng_warning_do_not_set_to_true_unless_you_know_how_risky_it_is = True

- ``False`` (the default): every unsecure-PRNG warning goes to the console.
- ``True``: the warnings are ignored (not printed) -- risk is all yours.
"""
import warnings

# Global warning switch: False = send unsecure-PRNG warnings to the console, True = ignore them.
ignore_unsecure_prng_warning_do_not_set_to_true_unless_you_know_how_risky_it_is = False


def _warn_unsecure(message, stacklevel=3):
    """Emit *message* as a warning unless the global silencer above is True."""
    if globals()["ignore_unsecure_prng_warning_do_not_set_to_true_unless_you_know_how_risky_it_is"]:
        return
    warnings.warn(message, stacklevel=stacklevel)
