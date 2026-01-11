import random
import warnings

# Safety Warnings
warnings.warn("WARNING: LCGs are NOT cryptographically secure. They use linear algebra and can be reversed.")
warnings.warn("This is only safe for OFFLINE GAMES with NO LEADERBOARDS.")
warnings.warn("See: https://youtu.be/XDsYPXRCXAs?si=oDaFsqZyNJWVXwEi")

class LCGs: 
	"""
	Linear Congruential Generator (LCG) Implementation.
	
	Summary:
	This class implements a Linear Congruential Generator, a simple algorithm that yields a
	sequence of pseudo-randomized numbers calculated with a linear equation.
	
	WARNING:
	LCGs are NOT safe for cryptography or high-stakes randomness (like gambling or leaderboards).
	Because they are based on simple math (modular arithmetic), their state can be recovered 
	(reversed) if a few outputs are known, e.g., using Modular Multiplicative Inverse (MMI).
	
	Required args:
		rules: str - The forward formula, e.g., "(s * a + c) % d"
	
	Optional args:
		reverse_rules: str or None - The formula to reverse the state, proving insecurity.
									 e.g., "((s - c) * pow(a, -1, d)) % d"
		s: int - Seed/State
		a: int - Multiplier
		c: int - Increment
		d: int - Modulus
	"""
	def __init__(
		self,
		rules: str,
		reverse_rules: str or None = None,
		s: int = random.randint(1, 9999),
		a: int = 10,
		b: int = 3, # kept for backward compatibility if needed
		c: int = 5,
		d: int = 25565
	):
		if rules is None:
			raise ValueError("rules must be provided (e.g., '(s * a + c) % d')")
			
		self.rules = rules
		self.reverse_rules = reverse_rules
		self.s = s
		self.a = a
		self.b = b
		self.c = c
		self.d = d

	def roll(self):
		"""Advance the generator state forward."""
		# Standard eval with restricted scope
		self.s = eval(self.rules, {"__builtins__": None}, {
			's': self.s, 'a': self.a, 'b': self.b, 
			'c': self.c, 'd': self.d
		})
		return self.s

	def reverse_roll(self):
		"""
		Reverse the generator state backward.
		
		This method demonstrates the insecurity of LCGs. If you know the parameters (a, c, d)
		and the current state (s), you can calculate the PREVIOUS state using:
		s_prev = (s - c) * a^(-1) mod d
		"""
		if self.reverse_rules is None:
			raise ValueError("reverse_rules is not defined! Cannot reverse state.")
			
		# Using pow(a, -1, d) for modular multiplicative inverse in python 3.8+
		self.s = eval(self.reverse_rules, {"__builtins__": None, "pow": pow}, {
			's': self.s, 'a': self.a, 'b': self.b, 
			'c': self.c, 'd': self.d
		})
		return self.s

	def random(self, s: int or None = None):
		"""Predict next bit/value based on roll (0 or 1)."""
		if s is not None:
			self.s = s
		old_s = self.s
		self.roll()
		return 1 if old_s <= self.s else 0
	
	def randint(self):
		"""Returns the current raw state integer."""
		self.roll()
		return self.s
	