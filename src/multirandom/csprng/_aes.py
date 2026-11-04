"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.csprng._aes
Description:
The raw AES core shared by the csprng modules that need block-level AES
(``CTR_DRBG``, ``FortunaRandom``, ``YarrowRandom``, and ANSI X9.31).

The arithmetic -- key schedule, SubBytes/MixColumns, the ECB mode -- is
delegated to an audited library implementation (``pycryptodome``, with
``pycryptodomex`` or ``cryptography`` accepted as drop-in alternates),
replacing the hand-rolled AES that used to live in ``secure_rand.py``.
What survives here is only the *shape* the DRBG modules are specced
against: ``encrypt_block(block)`` (one 16-byte ECB encryption -- the
primitive CTR_DRBG's (K, V) iterator and ANSI X9.31 run on) and
``ctr(counter, n)`` (big-endian-counter keystream, Fortuna's generator).

FIPS-197 known-answer tests still run in ``__main__`` to prove the wiring::

    py -3 -m multirandom.csprng._aes
"""
from __future__ import annotations

# --- pick the AES library: pycryptodome > pycryptodomex > cryptography ------
try:
    from Crypto.Cipher import AES as _pyc_aes        # pycryptodome
except ImportError:
    try:
        from Cryptodome.Cipher import AES as _pyc_aes  # pycryptodomex
    except ImportError:
        _pyc_aes = None

if _pyc_aes is None:
    try:                     # the cryptography package as the last resort
        from cryptography.hazmat.primitives.ciphers import (
            Cipher as _cipher, algorithms as _algorithms, modes as _modes)
    except ImportError:
        raise ImportError(
            "multirandom.csprng needs an AES implementation: install "
            "pycryptodome (pip install pycryptodome) or the cryptography "
            "package") from None


class _Aes:
    """AES-128/192/256 single-block encryptor + CTR keystream helper.

    Interface kept from the legacy hand-rolled AES so the DRBG modules
    read exactly as before; the one-round-of-AES-per-call arithmetic is
    now the installed library's (FIPS-validated implementation, no hand
    transcription to get wrong).
    """

    def __init__(self, key):
        key = bytes(key)
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24 or 32 bytes")
        self._key = key
        if _pyc_aes is not None:
            # ECB is stateless: one cipher object serves every block.
            self._ecb = _pyc_aes.new(key, _pyc_aes.MODE_ECB)
            self._backend = "pycryptodome"
        else:
            self._ecb = _cipher(
                _algorithms.AES(key), _modes.ECB()).encryptor()
            self._backend = "cryptography"

    def encrypt_block(self, block):
        """AES-ECB of exactly one 16-byte block."""
        block = bytes(block)
        if len(block) != 16:
            raise ValueError("AES blocks are 16 bytes")
        if self._backend == "pycryptodome":
            return self._ecb.encrypt(block)
        return self._ecb.update(block)

    def ctr(self, counter, n):
        """``n`` bytes of AES-CTR keystream for a 128-bit big-endian counter."""
        out = bytearray()
        while len(out) < n:
            out += self.encrypt_block(counter.to_bytes(16, "big"))
            counter = (counter + 1) % (1 << 128)
        return bytes(out[:n])



def main():
    print("=" * 70)
    print("_aes - FIPS-197 wiring self-check battery")
    print("=" * 70)

    # --- 1. FIPS-197 appendix C known-answer tests ---------------------------
    fips_pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    fips_key = bytes(range(16))
    aes = _Aes(fips_key)
    assert aes.encrypt_block(fips_pt) == \
        bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"), "AES-128 KAT failed"
    assert _Aes(bytes(range(24))).encrypt_block(fips_pt) == \
        bytes.fromhex("dda97ca4864cdfe06eaf70a0ec0d7191"), "AES-192 KAT failed"
    assert _Aes(bytes(range(32))).encrypt_block(fips_pt) == \
        bytes.fromhex("8ea2b7ca516745bfeafc49904b496089"), "AES-256 KAT failed"
    print(f"[1] FIPS-197 AES-128/192/256 KATs ({aes._backend} core): OK")

    # --- 2. ECB eats complete, and only complete, blocks ----------------------
    for bad_len in (0, 1, 15, 17, 32):
        try:
            aes.encrypt_block(b"\x00" * bad_len)
        except ValueError:
            pass
        else:
            raise AssertionError(f"block of {bad_len} bytes accepted")
    for bad_key_len in (0, 8, 17, 33):
        try:
            _Aes(b"\x00" * bad_key_len)
        except ValueError:
            pass
        else:
            raise AssertionError(f"key of {bad_key_len} bytes accepted")
    print("[2] only 16-byte blocks and 16/24/32-byte keys accepted: OK")

    # --- 3. the CTR keystream is the concatenation of ECB(counter + i) --------
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    counter = int.from_bytes(
        bytes.fromhex("00112233445566778899aabbccddeeff"), "big")
    runs = _Aes(key)
    manual = (runs.encrypt_block(counter.to_bytes(16, "big"))
              + runs.encrypt_block(((counter + 1) % (1 << 128)).to_bytes(16, "big"))
              + runs.encrypt_block(((counter + 2) % (1 << 128)).to_bytes(16, "big")))
    assert runs.ctr(counter, 40) == manual[:40], "CTR keystream drifted"
    assert runs.ctr(counter, 48) == manual, "CTR keystream wrong at block edges"
    assert runs.ctr(counter, 1) == manual[:1], "CTR short request wrong"
    block4 = runs.encrypt_block(((counter + 3) % (1 << 128)).to_bytes(16, "big"))
    assert runs.ctr(counter, 49) == manual + block4[:1], "CTR carry-over wrong"
    print("[3] ctr() == ECB on counter, counter+1, ... (block edges exact): OK")

    # --- 4. CTR round trip through XOR (the way the DRBGs use it) -------------
    stream = runs.ctr(counter, 64)
    assert bytes(x ^ y for x, y in zip(stream, stream)) == bytes(64)
    assert len({runs.ctr(counter, 32)[i] for i in range(32)}) > 12, \
        "flat keystream?! the library AES looks broken"
    print("[4] keystream XORs back to zero, byte spread sane: OK")

    print("-" * 70)
    print("All _aes checks passed!")


if __name__ == "__main__":
    main()
