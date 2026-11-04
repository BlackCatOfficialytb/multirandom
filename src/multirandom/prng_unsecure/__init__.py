"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.prng_unsecure
Description:
Educational pseudo-randomness, deliberately insecure -- the iconic and the
historic, every generator with its reference vectors and its reversal:

* ``xor_shift``      - the XorShift/Xoshiro family (18 generators, four
  equivalent reversal attacks on Xorshift32).
* ``mersenne_twister`` - MT19937 rebuilt from mt19937ar.c with
  CPython-compatible seeding and the full 624-output state recovery.
* ``lcg``            - Linear Congruential Generators with user-supplied
  forward/inverse formulas, JavaLCG and ``crack_java_random`` included.
* ``flash_player_prng`` - Adobe Flash Player's Math.random()
  reimplemented bullet-for-bullet from avmplus, with the CVE-2017-3000
  reversal attack on it.
* ``randu``          - IBM's RANDU, the infamous 15-planes generator.
* ``middle_square``  - von Neumann's middle square and MSWS.
* ``doom_prng``      - Doom's 256-entry lookup table, increment-then-index.
* ``splitmix64``     - Steele/Lea/Flood's counter-mixer, inverted exactly.
* ``lagged_fibonacci`` - the BSD-style LF(31, 3) family; the last j
  outputs ARE the state.
* ``pcg``            - O'Neill's PCG32 (the "good" end: closed-form jump,
  no from_outputs -- XSH-RR hides 32 bits per draw).
* ``v8_xorshift128plus`` - JavaScript's Math.random() engine, fully
  recoverable from five consecutive doubles by GF(2) elimination.

Never use these for cryptography; every constructor warns once per process
via the package's global warning flag.
"""
