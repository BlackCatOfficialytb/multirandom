import functools
import inspect
import random
import warnings

# Safety Warnings -- routed through the package's global warning flag
# multirandom.ignore_unsecure_prng_warning_do_not_set_to_true_unless_you_know_how_risky_it_is
try:
    from .. import _warn_unsecure
except ImportError:  # running as a plain script
    def _warn_unsecure(message, stacklevel=3):
        warnings.warn(message, stacklevel=stacklevel)

def reverse_xor_lshift(x, s, bits=32):
    """Reverses x ^= x << s (iterative feedback)."""
    res = x
    mask = (1 << bits) - 1
    for _ in range(bits // s):
        res = x ^ ((res << s) & mask)
    return res & mask

def reverse_xor_rshift(x, s, bits=32):
    """Reverses x ^= x >> s (iterative feedback)."""
    res = x
    mask = (1 << bits) - 1
    for _ in range(bits // s):
        res = x ^ (res >> s)
    return res & mask

def doubling_xor_lshift(x, s, bits=32):
    """Reverses x ^= x << s by doubling the shift: XOR with s, 2s, 4s, ..."""
    mask = (1 << bits) - 1
    shift = s
    while shift < bits:
        x ^= (x << shift) & mask
        shift *= 2
    return x & mask

def doubling_xor_rshift(x, s, bits=32):
    """Reverses x ^= x >> s by doubling the shift: XOR with s, 2s, 4s, ..."""
    mask = (1 << bits) - 1
    shift = s
    while shift < bits:
        x ^= x >> shift
        shift *= 2
    return x & mask

def increments_xor_lshift(x, s, bits=32):
    """Reverses x ^= x << s by XOR-ing the final value at s, 2s, 3s, ..."""
    mask = (1 << bits) - 1
    res = x
    shift = s
    while shift < bits:
        res ^= (x << shift) & mask
        shift += s
    return res & mask

def increments_xor_rshift(x, s, bits=32):
    """Reverses x ^= x >> s by XOR-ing the final value at s, 2s, 3s, ..."""
    mask = (1 << bits) - 1
    res = x
    shift = s
    while shift < bits:
        res ^= x >> shift
        shift += s
    return res & mask

def gf2_inverse_matrix(apply, bits):
    """Inverse of the linear map `apply` over GF(2), returned as `bits` row words.

    Row i is the mask for output bit i: the original input bit i is the parity of
    (output & row). Rows are the images of the basis vectors transposed, so that
    `x_i = parity(y & Inv[i])`. Using the plain row images would decode A^-1.y
    instead of (A^-1)^T.y and recover nothing.
    """
    A = [sum(((apply(1 << j) >> i) & 1) << j for j in range(bits)) for i in range(bits)]
    Inv = [1 << i for i in range(bits)]
    for col in range(bits):
        pivot = next((r for r in range(col, bits) if (A[r] >> col) & 1), None)
        if pivot is None:
            raise ValueError("matrix is not invertible over GF(2)")
        A[col], A[pivot] = A[pivot], A[col]
        Inv[col], Inv[pivot] = Inv[pivot], Inv[col]
        for row in range(bits):
            if row != col and ((A[row] >> col) & 1):
                A[row] ^= A[col]
                Inv[row] ^= Inv[col]
    return Inv

class Xorshift32:
    """
    Marsaglia's original 32-bit Xorshift.
    Passes some tests but too linear for modern standards.

    Because every step is linear, the output can be undone three different ways:
    `reverse_roll_increments()` (XOR the final value at s, 2s, 3s, ...),
    `reverse_roll_doubling()` (XOR the intermediate value at s, 2s, 4s, ...),
    and `reverse_roll_matrix()` (GF(2) matrix inversion). `reverse_roll()` is the
    classic fixed-shift feedback loop and returns the same result.
    """
    MASK = 0xFFFFFFFF

    def __init__(self, seed: int = None, a: int = 13, b: int = 17, c: int = 5):
        if seed is None:
            seed = random.randint(1, self.MASK)
        self.state = seed & self.MASK
        if self.state == 0: self.state = 1
        self.a = a
        self.b = b
        self.c = c
        self._inv_matrix = None

    def forward(self, x):
        """One Xorshift32 step; `roll` and the GF(2) matrix both use this."""
        mask = self.MASK
        x = (x ^ ((x << self.a) & mask)) & mask
        x = (x ^ (x >> self.b)) & mask
        x = (x ^ ((x << self.c) & mask)) & mask
        return x

    def roll(self):
        self.state = self.forward(self.state)
        return self.state

    # Method 2: iterative feedback -- x = y ^ (x << s) until the bits settle.
    def reverse_roll(self):
        """Demonstrates the reversibility of pure Xorshift."""
        x = self.state
        # Reverse x ^= x << c
        x = reverse_xor_lshift(x, self.c, 32)
        # Reverse x ^= x >> b
        x = reverse_xor_rshift(x, self.b, 32)
        # Reverse x ^= x << a
        x = reverse_xor_lshift(x, self.a, 32)
        self.state = x
        return self.state

    # Method 1: XOR the final value with copies shifted by s, 2s, 3s, ...
    def reverse_roll_increments(self):
        """Undo one step by XOR-ing copies of the output at s, 2s, 3s, ..."""
        x = self.state
        x = increments_xor_lshift(x, self.c, 32)
        x = increments_xor_rshift(x, self.b, 32)
        x = increments_xor_lshift(x, self.a, 32)
        self.state = x
        return self.state

    # Method 2: shift doubling -- XOR with the shift, 2x, 4x, ... until >= 32.
    def reverse_roll_doubling(self):
        """Undo one step by doubling the shift amount each round."""
        x = self.state
        x = doubling_xor_lshift(x, self.c, 32)
        x = doubling_xor_rshift(x, self.b, 32)
        x = doubling_xor_lshift(x, self.a, 32)
        self.state = x
        return self.state

    # Method 3: multiply the output by the inverse GF(2) matrix.
    def reverse_roll_matrix(self):
        """Undo one step with a precomputed GF(2) inverse matrix (cached)."""
        if self._inv_matrix is None:
            self._inv_matrix = gf2_inverse_matrix(self.forward, 32)
        y = self.state
        x = 0
        for i, row in enumerate(self._inv_matrix):
            if bin(y & row).count("1") & 1:   # parity on GF(2)
                x |= 1 << i
        self.state = x
        return self.state

    def random(self):
        # Normalize to [0, 1)
        return self.roll() / 0x100000000

class Xorshift64:
    """
    Marsaglia's 64-bit Xorshift.
    Same three-shift structure as Xorshift32, one register wider.
    """
    def __init__(self, seed: int = None, a: int = 13, b: int = 7, c: int = 17):
        if seed is None:
            seed = random.randint(1, 0xFFFFFFFFFFFFFFFF)
        self.state = seed & 0xFFFFFFFFFFFFFFFF
        if self.state == 0: self.state = 1
        self.a = a
        self.b = b
        self.c = c

    def roll(self):
        x = self.state
        x ^= (x << self.a) & 0xFFFFFFFFFFFFFFFF
        x ^= (x >> self.b) & 0xFFFFFFFFFFFFFFFF
        x ^= (x << self.c) & 0xFFFFFFFFFFFFFFFF
        self.state = x
        return self.state

    def reverse_roll(self):
        """Demonstrates the reversibility of pure Xorshift."""
        x = self.state
        x = reverse_xor_lshift(x, self.c, 64)
        x = reverse_xor_rshift(x, self.b, 64)
        x = reverse_xor_lshift(x, self.a, 64)
        self.state = x
        return self.state

    def random(self):
        # Normalize to [0, 1)
        return self.roll() / 0x10000000000000000

class Xorshift128:
    """
    Marsaglia's original 128-bit Xorshift.
    Uses a 4-word state.
    """
    def __init__(self, seeds: list = None, a: int = 11, b: int = 8, c: int = 19):
        if seeds is None or len(seeds) < 4:
            seeds = [random.randint(1, 0xFFFFFFFF) for _ in range(4)]
        self.state = [s & 0xFFFFFFFF for s in seeds]
        if all(s == 0 for s in self.state): self.state[0] = 1
        self.a = a
        self.b = b
        self.c = c

    def roll(self):
        t = self.state[3]
        s = self.state[0]
        self.state[3] = self.state[2]
        self.state[2] = self.state[1]
        self.state[1] = s

        t ^= (t << self.a) & 0xFFFFFFFF
        t ^= (t >> self.b) & 0xFFFFFFFF
        self.state[0] = (t ^ s ^ (s >> self.c)) & 0xFFFFFFFF
        return self.state[0]

    def reverse_roll(self):
        """Demonstrates reversibility of 128-bit version."""
        s_prev = self.state[1]
        res_xor_s = (self.state[0] ^ s_prev ^ (s_prev >> self.c)) & 0xFFFFFFFF
        # Undo in reverse order: the forward pass applies (<< a) then (>> b).
        t_original = reverse_xor_lshift(reverse_xor_rshift(res_xor_s, self.b, 32), self.a, 32)

        # Shift back
        self.state[0] = self.state[1]
        self.state[1] = self.state[2]
        self.state[2] = self.state[3]
        self.state[3] = t_original
        return self.state[0]

class Xorwow:
    """Xorwow adds a Weyl sequence to fix linearity issues."""
    def __init__(self, seeds: list = None):
        if seeds is None or len(seeds) < 5:
            seeds = [random.randint(1, 0xFFFFFFFF) for _ in range(5)]
        self.state = [s & 0xFFFFFFFF for s in seeds]
        self.counter = 0

    def roll(self):
        t = self.state[4]
        s = self.state[0]
        self.state[4] = self.state[3]
        self.state[3] = self.state[2]
        self.state[2] = self.state[1]
        self.state[1] = s

        t ^= (t >> 2) & 0xFFFFFFFF
        t ^= (t << 1) & 0xFFFFFFFF
        t ^= (s ^ (s << 4)) & 0xFFFFFFFF
        self.state[0] = t
        self.counter = (self.counter + 362437) & 0xFFFFFFFF
        return (t + self.counter) & 0xFFFFFFFF

class XorshiftStar:
    """Xorshift* multiplies outputs by a constant."""
    def __init__(self, seed: int = None, a: int = 12, b: int = 25, c: int = 27):
        self.state = seed or random.randint(1, 0xFFFFFFFFFFFFFFFF)
        self.a = a
        self.b = b
        self.c = c

    def roll(self):
        x = self.state
        x ^= (x >> self.a) & 0xFFFFFFFFFFFFFFFF
        x ^= (x << self.b) & 0xFFFFFFFFFFFFFFFF
        x ^= (x >> self.c) & 0xFFFFFFFFFFFFFFFF
        self.state = x
        return (x * 0x2545F4914F6CDD1D) & 0xFFFFFFFFFFFFFFFF

class Xorshift1024Star:
    """Vigna's xorshift1024*: a pool of 16 x 64-bit words."""
    def __init__(self, seeds: list = None):
        if seeds is None or len(seeds) < 16:
            seeds = [random.randint(1, 0xFFFFFFFFFFFFFFFF) for _ in range(16)]
        self.s = [x & 0xFFFFFFFFFFFFFFFF for x in seeds]
        if all(x == 0 for x in self.s): self.s[0] = 1
        self.p = 0

    def roll(self):
        t = self.s[self.p]
        self.p = (self.p + 1) & 15
        t ^= (t << 13) & 0xFFFFFFFFFFFFFFFF
        t ^= t >> 7
        t ^= (t << 17) & 0xFFFFFFFFFFFFFFFF
        self.s[self.p] ^= t
        return self.s[self.p]

class XorshiftPlus:
    """Xorshift128+ used in V8 and Safari."""
    def __init__(self, s0: int = None, s1: int = None, a: int = 23, b: int = 17, c: int = 26):
        self.s0 = s0 or random.randint(1, 0xFFFFFFFFFFFFFFFF)
        self.s1 = s1 or random.randint(1, 0xFFFFFFFFFFFFFFFF)
        self.a = a
        self.b = b
        self.c = c

    def roll(self):
        x = self.s0
        y = self.s1
        self.s0 = y
        x ^= (x << self.a) & 0xFFFFFFFFFFFFFFFF
        self.s1 = (x ^ y ^ (x >> self.b) ^ (y >> self.c)) & 0xFFFFFFFFFFFFFFFF
        return (self.s1 + y) & 0xFFFFFFFFFFFFFFFF

def rotl(x, k, bits=64):
    mask = (1 << bits) - 1
    return ((x << k) & mask) | (x >> (bits - k))

def _seed_words(seeds, count, bits):
    """Take `count` non-zero `bits`-wide words, falling back to random seeds."""
    mask = (1 << bits) - 1
    if seeds is None or len(seeds) < count:
        seeds = [random.randint(1, mask) for _ in range(count)]
    words = [s & mask for s in seeds]
    if all(s == 0 for s in words): words[0] = 1
    return words

def _xoshiro_step(s, bits, lshift, rot):
    """Shared 4-word xoshiro state transition (in place; call after reading the output)."""
    mask = (1 << bits) - 1
    t = (s[1] << lshift) & mask
    s[2] ^= s[0]
    s[3] ^= s[1]
    s[1] ^= s[2]
    s[0] ^= s[3]
    s[2] ^= t
    s[3] = rotl(s[3], rot, bits)

def _xoroshiro_step(s, bits, rot0, lshift, rot1):
    """Shared 2-word xoroshiro state transition (in place; call after reading the output).

    64-bit `+`/`**` use (24, 16, 37), 64-bit `++` uses (49, 21, 28),
    and the 32-bit xoroshiro64 family uses (26, 9, 13).
    """
    mask = (1 << bits) - 1
    s0 = s[0]
    s1 = s[1] ^ s0
    s[0] = (rotl(s0, rot0, bits) ^ s1 ^ ((s1 << lshift) & mask)) & mask
    s[1] = rotl(s1, rot1, bits)

M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF

class Xoshiro256Plus:
    """xoshiro256+: fastest of the 64-bit family, slightly weaker low bits."""
    def __init__(self, seeds: list = None):
        self.s = _seed_words(seeds, 4, 64)

    def roll(self):
        res = (self.s[0] + self.s[3]) & M64
        _xoshiro_step(self.s, 64, 17, 45)
        return res

class Xoshiro256PlusPlus:
    """xoshiro256++: passes BigCrush, best general purpose of the family."""
    def __init__(self, seeds: list = None):
        self.s = _seed_words(seeds, 4, 64)

    def roll(self):
        res = (rotl((self.s[0] + self.s[3]) & M64, 23) + self.s[0]) & M64
        _xoshiro_step(self.s, 64, 17, 45)
        return res

class Xoshiro256StarStar:
    """Modern robust 64-bit generator (xoshiro256**)."""
    def __init__(self, seeds: list = None):
        self.s = _seed_words(seeds, 4, 64)

    def roll(self):
        res = (rotl((self.s[1] * 5) & M64, 7) * 9) & M64
        _xoshiro_step(self.s, 64, 17, 45)
        return res

class Xoshiro128Plus:
    """xoshiro128+: 32-bit optimized modern generator."""
    def __init__(self, seeds: list = None):
        self.s = _seed_words(seeds, 4, 32)

    def roll(self):
        res = (self.s[0] + self.s[3]) & M32
        _xoshiro_step(self.s, 32, 9, 11)
        return res

class Xoshiro128PlusPlus:
    """xoshiro128++: 32-bit variant with better equidistribution."""
    def __init__(self, seeds: list = None):
        self.s = _seed_words(seeds, 4, 32)

    def roll(self):
        res = (rotl((self.s[0] + self.s[3]) & M32, 7, 32) + self.s[0]) & M32
        _xoshiro_step(self.s, 32, 9, 11)
        return res

class Xoshiro128StarStar:
    """xoshiro128**: 32-bit scrambler variant, passes PractRand up to TB."""
    def __init__(self, seeds: list = None):
        self.s = _seed_words(seeds, 4, 32)

    def roll(self):
        res = (rotl((self.s[1] * 5) & M32, 7, 32) * 9) & M32
        _xoshiro_step(self.s, 32, 9, 11)
        return res

class Xoroshiro64Star:
    """xoroshiro64*: two 32-bit words, the smallest useful xoroshiro."""
    def __init__(self, seeds: list = None):
        self.s = _seed_words(seeds, 2, 32)

    def roll(self):
        res = (self.s[0] * 0x9E3779BB) & M32
        _xoroshiro_step(self.s, 32, 26, 9, 13)
        return res

class Xoroshiro64StarStar:
    """xoroshiro64**: the 32-bit scrambler variant of xoroshiro64*."""
    def __init__(self, seeds: list = None):
        self.s = _seed_words(seeds, 2, 32)

    def roll(self):
        res = (rotl((self.s[0] * 0x9E3779BB) & M32, 5, 32) * 5) & M32
        _xoroshiro_step(self.s, 32, 26, 9, 13)
        return res

class Xoroshiro128Plus:
    """xoroshiro128+: minimal 2-word state, faster than xoshiro128+."""
    def __init__(self, seeds: list = None):
        self.s = _seed_words(seeds, 2, 64)

    def roll(self):
        res = (self.s[0] + self.s[1]) & M64
        _xoroshiro_step(self.s, 64, 24, 16, 37)
        return res

class Xoroshiro128PlusPlus:
    """
    Xoroshiro128++ generator.
    Used in modern Minecraft (Java 1.18+) for world generation and other random tasks.
    """
    def __init__(self, seeds: list = None):
        self.s = _seed_words(seeds, 2, 64)

    def roll(self):
        res = (rotl((self.s[0] + self.s[1]) & M64, 17) + self.s[0]) & M64
        _xoroshiro_step(self.s, 64, 49, 21, 28)
        return res

class Xoroshiro128StarStar:
    """xoroshiro128**: smallest state that passes BigCrush at 64 bits."""
    def __init__(self, seeds: list = None):
        self.s = _seed_words(seeds, 2, 64)

    def roll(self):
        res = (rotl((self.s[0] * 5) & M64, 7) * 9) & M64
        _xoroshiro_step(self.s, 64, 24, 16, 37)
        return res


ALL_GENERATORS = [
    Xorshift32, Xorshift64, Xorshift128, Xorwow, XorshiftStar, Xorshift1024Star,
    XorshiftPlus, Xoshiro256Plus, Xoshiro256PlusPlus, Xoshiro256StarStar,
    Xoshiro128Plus, Xoshiro128PlusPlus, Xoshiro128StarStar,
    Xoroshiro64Star, Xoroshiro64StarStar,
    Xoroshiro128Plus, Xoroshiro128PlusPlus, Xoroshiro128StarStar,
]

# One-time construction warning for every generator above, governed by the
# package's global warning flag.
_XOR_UNSECURE_WARNING = (
    "XorShift/Xoshiro generators are SAFER than LCGs but still INSECURE for "
    "cryptography: they are linear pseudo-randomness (an LFSR), not true "
    "randomness. https://youtu.be/XDsYPXRCXAs?si=oDaFsqZyNJWVXwEi")

_xor_warning_state = {"warned": False}


def _make_warned_init(original_init):
    @functools.wraps(original_init)          # keeps __wrapped__, name, docstring
    def __init__(self, *args, **kwargs):
        if not _xor_warning_state["warned"]:
            _xor_warning_state["warned"] = True
            _warn_unsecure(_XOR_UNSECURE_WARNING)
        return original_init(self, *args, **kwargs)
    return __init__


for _cls in ALL_GENERATORS:
    _cls.__init__ = _make_warned_init(_cls.__init__)

# Output of the official C reference implementations for fixed seeds, as mirrored by
# rand_xoshiro's test suite (https://github.com/rust-random/rngs).
REFERENCE_VECTORS = [
    (Xoroshiro64Star, [1, 2],
     [2654435771, 327208753, 4063491769, 4259754937, 261922412,
      168123673, 552743735, 1672597395, 1031040050, 2755315674]),
    (Xoroshiro64StarStar, [1, 2],
     [3802928447, 813792938, 1618621494, 2955957307, 3252880261,
      1129983909, 2539651700, 1327610908, 1757650787, 2763843748]),
    (Xoshiro128Plus, [1, 2, 3, 4],
     [5, 12295, 25178119, 27286542, 39879690, 1140358681,
      3276312097, 4110231701, 399823256, 2144435200]),
    (Xoshiro128StarStar, [1, 2, 3, 4],
     [11520, 0, 5927040, 70819200, 2031721883, 1637235492,
      1287239034, 3734860849, 3729100597, 4258142804]),
    (Xoshiro128PlusPlus, [1, 2, 3, 4],
     [641, 1573767, 3222811527, 3517856514, 836907274,
      4247214768, 3867114732, 1355841295, 495546011, 621204420]),
    (Xoshiro256Plus, [1, 2, 3, 4],
     [5, 211106232532999, 211106635186183, 9223759065350669058, 9250833439874351877,
      13862484359527728515, 2346507365006083650, 1168864526675804870,
      34095955243042024, 3466914240207415127]),
    (Xoshiro256PlusPlus, [1, 2, 3, 4],
     [41943041, 58720359, 3588806011781223, 3591011842654386, 9228616714210784205,
      9973669472204895162, 14011001112246962877, 12406186145184390807,
      15849039046786891736, 10450023813501588000]),
    (Xoshiro256StarStar, [1, 2, 3, 4],
     [11520, 0, 1509978240, 1215971899390074240, 1216172134540287360,
      607988272756665600, 16172922978634559625, 8476171486693032832,
      10595114339597558777, 2904607092377533576]),
    (Xoroshiro128Plus, [1, 2],
     [3, 412333834243, 2360170716294286339, 9295852285959843169, 2797080929874688578,
      6019711933173041966, 3076529664176959358, 3521761819100106140,
      7493067640054542992, 920801338098114767]),
    (Xoroshiro128PlusPlus, [1, 2],
     [393217, 669327710093319, 1732421326133921491, 11394790081659126983,
      9555452776773192676, 3586421180005889563, 1691397964866707553,
      10735626796753111697, 15216282715349408991, 14247243556711267923]),
    (Xoroshiro128StarStar, [1, 2],
     [5760, 97769243520, 9706862127477703552, 9223447511460779954, 8358291023205304566,
      15695619998649302768, 8517900938696309774, 16586480348202605369,
      6959129367028440372, 16822147227405758281]),
]

if __name__ == "__main__":
    for cls, seeds, expected in REFERENCE_VECTORS:
        gen = cls(seeds)
        got = [gen.roll() for _ in expected]
        assert got == expected, f"{cls.__name__} deviates from the reference implementation"
        print(f"{cls.__name__} reference vector: OK")

    # Reversibility of the plain xorshift registers.
    for gen in (Xorshift32(42), Xorshift64(42), Xorshift128([42, 43, 44, 45])):
        original = list(gen.state) if isinstance(gen.state, list) else gen.state
        gen.roll()
        gen.reverse_roll()
        assert gen.state == original, f"{type(gen).__name__} reverse_roll is broken"
        print(f"{type(gen).__name__} reverse: OK")

    # Both equivalent write-up forms plus the feedback loop and GF(2) matrix must
    # undo a step for every seed.
    methods = (
        "reverse_roll", "reverse_roll_increments", "reverse_roll_doubling",
        "reverse_roll_matrix",
    )
    for seed in range(1, 65):
        for method in methods:
            gen = Xorshift32(seed)
            gen.roll()
            getattr(gen, method)()
            assert gen.state == seed, f"Xorshift32.{method} failed for seed {seed}"
    print("Xorshift32 feedback / increments / doubling / GF(2) matrix reverse: OK")

    # The two write-up forms must agree with the feedback loop for every shift
    # and width: Method 1 XORs the final value at s, 2s, 3s, ...; Method 2 XORs
    # the intermediate value at s, 2s, 4s, ... .
    for bits in (16, 32, 64):
        mask = (1 << bits) - 1
        for s in range(1, bits):
            for x in (0, 1, 2, mask, mask - 1, 0xDEADBEEF & mask, random.getrandbits(bits)):
                assert increments_xor_lshift(x, s, bits) == doubling_xor_lshift(x, s, bits) \
                    == reverse_xor_lshift(x, s, bits), f"lshift mismatch bits={bits} s={s}"
                assert increments_xor_rshift(x, s, bits) == doubling_xor_rshift(x, s, bits) \
                    == reverse_xor_rshift(x, s, bits), f"rshift mismatch bits={bits} s={s}"
    print("Increments / doubling / feedback helpers agree for all shifts and widths: OK")

    # Every generator must produce distinct output and survive an all-zero seed.
    for cls in ALL_GENERATORS:
        # inspect.signature follows functools.wraps' __wrapped__, so it still
        # sees the real (pre-warning-wrapper) constructor parameters.
        takes_seeds = "seeds" in inspect.signature(cls.__init__).parameters
        gen = cls(seeds=[0, 0, 0, 0]) if takes_seeds else cls(0)
        out = [gen.roll() for _ in range(64)]
        # An all-zero state (or one left degenerate by the seed) repeats instantly.
        assert len(set(out)) >= 32, f"{cls.__name__} output repeats within 64 rolls"
        print(f"{cls.__name__}: OK")

    print("All xorshift/xoshiro checks passed!")
