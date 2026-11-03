"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.prng_unsecure
Description:
Educational pseudo-randomness, deliberately insecure: the XorShift/Xoshiro
family (18 generators, reference vectors included, four equivalent reversal
attacks on Xorshift32) and classic Linear Congruential Generators with
user-supplied forward/inverse formulas. Never use these for cryptography; every
constructor warns once per process via the package's global warning flag.
"""
