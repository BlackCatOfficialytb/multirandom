_sha1 = None
_sha224 = None
_sha256 = None
_sha384 = None
_sha512 = None

def _get_sha1():
    global _sha1
    if _sha1 is None:
        try:
            from _sha1 import sha1 as _sha1
        except ImportError:
            from hashlib import sha1 as _sha1
    return _sha1

def _get_sha224():
    global _sha224
    if _sha224 is None:
        try:
            from _sha2 import sha224 as _sha224
        except ImportError:
            from hashlib import sha224 as _sha224
    return _sha224

def _get_sha256():
    global _sha256
    if _sha256 is None:
        try:
            from _sha2 import sha256 as _sha256
        except ImportError:
            from hashlib import sha256 as _sha256
    return _sha256

def _get_sha384():
    global _sha384
    if _sha384 is None:
        try:
            from _sha2 import sha384 as _sha384
        except ImportError:
            from hashlib import sha384 as _sha384
    return _sha384

def _get_sha512():
    global _sha512
    if _sha512 is None:
        try:
            # hashlib is pretty heavy to load, try lean internal module first
            from _sha2 import sha512 as _sha512
        except ImportError:
            # fallback to official implementation
            from hashlib import sha512 as _sha512
    return _sha512
class _SHARandom:
    def __init__(self, seed=None):
        self.seed = seed
        self.counter = 0

    def _get_hash(self):
        raise NotImplementedError

    def getrandbytes(self, n):
        res = b""
        hf = self._get_hash()
        seed_bytes = str(self.seed).encode()
        while len(res) < n:
            h = hf()
            h.update(seed_bytes + self.counter.to_bytes(8, 'big'))
            res += h.digest()
            self.counter += 1
        return res[:n]

class SHA1Random(_SHARandom):
    def _get_hash(self):
        return _get_sha1()

class SHA256Random(_SHARandom):
    def _get_hash(self):
        return _get_sha256()

class SHA384Random(_SHARandom):
    def _get_hash(self):
        return _get_sha384()

class SHA512Random(_SHARandom):
    def _get_hash(self):
        return _get_sha512()