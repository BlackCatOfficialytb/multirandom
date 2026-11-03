"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.prng_unsecure
Description:
Educational pseudo-randomness, deliberately insecure: the XorShift/Xoshiro
family (18 generators, reference vectors included, four equivalent reversal
attacks on Xorshift32), the Mersenne Twister MT19937 rebuilt from
mt19937ar.c with CPython-compatible seeding and the full 624-output state
recovery, Linear Congruential Generators with user-supplied forward/inverse
formulas, and Adobe Flash Player's Math.random() reimplemented
bullet-for-bullet from avmplus together with the CVE-2017-3000 reversal
attack on it. Never use these for cryptography; every constructor warns once
per process via the package's global warning flag.
"""
