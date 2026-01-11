import random
import warnings

# Safety Warnings
warnings.warn("WARNING: XorShift/Xoshiro generators are SAFER than LCGs but still INSECURE for cryptography. They are pseudo-random and not true randomness.")
warnings.warn("It uses a linear feedback shift register (LFSR) to generate pseudo-random numbers.")
warnings.warn("See: https://youtu.be/XDsYPXRCXAs?si=oDaFsqZyNJWVXwEi")

def reverse_xor_lshift(x, s, bits=32):
    """Reverses x ^= x << s."""
    res = x
    mask = (1 << bits) - 1
    for _ in range(bits // s):
        res = x ^ ((res << s) & mask)
    return res & mask

def reverse_xor_rshift(x, s, bits=32):
    """Reverses x ^= x >> s."""
    res = x
    mask = (1 << bits) - 1
    for _ in range(bits // s):
        res = x ^ (res >> s)
    return res & mask

class Xorshift32:
    """
    Marsaglia's original 32-bit Xorshift.
    Passes some tests but too linear for modern standards.
    """
    def __init__(self, seed: int = None, a: int = 13, b: int = 17, c: int = 5):
        if seed is None:
            seed = random.randint(1, 0xFFFFFFFF)
        self.state = seed & 0xFFFFFFFF
        if self.state == 0: self.state = 1
        self.a = a
        self.b = b
        self.c = c

    def roll(self):
        x = self.state
        x ^= (x << self.a) & 0xFFFFFFFF
        x ^= (x >> self.b) & 0xFFFFFFFF
        x ^= (x << self.c) & 0xFFFFFFFF
        self.state = x
        return self.state

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

    def random(self):
        # Normalize to [0, 1)
        return self.roll() / 0x100000000

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
        t_original = reverse_xor_rshift(reverse_xor_lshift(res_xor_s, self.a, 32), self.b, 32)
        
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

class Xoshiro256StarStar:
    """Modern robust 64-bit generator."""
    def __init__(self, seeds: list = None):
        if seeds is None or len(seeds) < 4:
            seeds = [random.randint(1, 0xFFFFFFFFFFFFFFFF) for _ in range(4)]
        self.s = [s & 0xFFFFFFFFFFFFFFFF for s in seeds]

    def roll(self):
        res = (rotl((self.s[1] * 5) & 0xFFFFFFFFFFFFFFFF, 7) * 9) & 0xFFFFFFFFFFFFFFFF
        t = (self.s[1] << 17) & 0xFFFFFFFFFFFFFFFF
        
        self.s[2] ^= self.s[0]
        self.s[3] ^= self.s[1]
        self.s[1] ^= self.s[2]
        self.s[0] ^= self.s[3]
        self.s[2] ^= t
        self.s[3] = rotl(self.s[3], 45)
        
        return res

class Xoshiro128Plus:
    """32-bit optimized modern generator."""
    def __init__(self, seeds: list = None):
        if seeds is None or len(seeds) < 4:
            seeds = [random.randint(1, 0xFFFFFFFF) for _ in range(4)]
        self.s = [s & 0xFFFFFFFF for s in seeds]

    def roll(self):
        res = (self.s[0] + self.s[3]) & 0xFFFFFFFF
        t = (self.s[1] << 9) & 0xFFFFFFFF
        
        self.s[2] ^= self.s[0]
        self.s[3] ^= self.s[1]
        self.s[1] ^= self.s[2]
        self.s[0] ^= self.s[3]
        self.s[2] ^= t
        self.s[3] = rotl(self.s[3], 11, bits=32)
        
        return res

class Xoroshiro128PlusPlus:
    """
    Xoroshiro128++ generator.
    Used in modern Minecraft (Java 1.18+) for world generation and other random tasks.
    """
    def __init__(self, seeds: list = None):
        if seeds is None or len(seeds) < 2:
            seeds = [random.randint(1, 0xFFFFFFFFFFFFFFFF) for _ in range(2)]
        self.s = [s & 0xFFFFFFFFFFFFFFFF for s in seeds]
        if all(s == 0 for s in self.s):
            self.s[0] = 1

    def roll(self):
        s0 = self.s[0]
        s1 = self.s[1]
        res = (rotl((s0 + s1) & 0xFFFFFFFFFFFFFFFF, 17) + s0) & 0xFFFFFFFFFFFFFFFF
        
        s1 ^= s0
        self.s[0] = (rotl(s0, 49) ^ s1 ^ ((s1 << 21) & 0xFFFFFFFFFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF
        self.s[1] = rotl(s1, 28)
        
        return res


if __name__ == "__main__":
    print("Testing Xorshift32 Reverse...")
    gen = Xorshift32(42)
    original = gen.state
    gen.roll()
    print(f"Post Roll: {gen.state}")
    gen.reverse_roll()
    print(f"Post Reverse: {gen.state}")
    assert gen.state == original
    print("Success!")
