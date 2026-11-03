"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.csprng
Description:
Cryptographically strong randomness: OS-level CSPRNGs (secrets / os.urandom /
getrandom(2) / BCryptGenRandom / SecRandomCopyBytes), NIST SP 800-90A DRBGs
(CTR, HMAC, Hash, plus the deliberately backdoored Dual_EC_DRBG with a working
reversal demo), ChaCha20/Salsa20 counter-mode DRBGs, Fortuna and Yarrow
accumulators, Jenkins' ISAAC, hash-based counter-mode generators (MD5, SHA-1/2/3,
SHAKE, BLAKE2) and a passthrough wrapper for Python's random module.
"""
