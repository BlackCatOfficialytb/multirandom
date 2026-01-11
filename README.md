# MultiRandom 🎲

A comprehensive library for exploring and generating randomness across the spectrum—from true physical entropy to mathematical pseudo-randomness and everything in between.

## 🌟 Overview

MultiRandom is designed for developers, researchers, and hobbyists who want to understand high-quality randomness. It provides tools to fetch random data from quantum sources, physical human interaction, and modern mathematical algorithms.

> [!WARNING]
> **Security Note**: This library contains both "True" and "Pseudo" random sources. While some sources (like QRNG) are highly secure, others (like LCGs) are provided for educational purposes and include **reverse logic** to demonstrate their insecurity. Always use the appropriate generator for your use case.

---

## 🏗 Project Structure

```text
MultiRandom/
├── true_rand/          # Physical & Hardware Entropy
│   ├── rand_via_clicks.py       # Human-in-the-loop entropy (Left/Right/Middle/Mixed)
│   └── rand_using_online_api.py # Quantum & Hardware APIs (random.org, ANU QRNG, Roll-API)
├── virt_rand/          # Mathematical Randomness (PRNGs)
│   ├── xor_shift.py             # XorShift & Xoshiro Family (Original, Scrambled, modern)
│   └── rand_using_virt_lng.py   # Linear Congruential Generators (LCGs)
├── hash_rand/          # Hash-based Generators
│   └── sha_rand.py              # SHA-1, SHA-256, SHA-512 based PRNGs
└── requirements.txt    # Project dependencies
```

---

## 🛠 Features & Usage

### 1. Human-in-the-loop Entropy (`true_rand`)
Uses `pyautogui` and Windows API to capture sub-microsecond timing jitter and spatial coordinates from physical mouse clicks.

```python
from true_rand.rand_via_clicks import MultiRandomUsingBetweenMixedClicks

# Requires a sequence of Left -> Right -> Middle clicks to seed
gen = MultiRandomUsingBetweenMixedClicks()
print(gen.random())
```

### 2. Quantum & Hardware APIs (`true_rand`)
Fetch "True" randomness from remote physical processes.

- **Australian National University (ANU)**: Quantum vacuum noise.
- **Random.org**: Atmospheric noise.
- **Roll-API**: Physical dice rolling hardware.

### 3. Bit-Shift Generators (`virt_rand`)
Implementations of the most popular mathematical generators used in modern systems.

- **Original XorShift**: Includes `reverse_roll()` to demonstrate mathematical reversibility.
- **Scrambled Variants**: Xorwow (CUDA), Xorshift+ (V8/Webkit).
- **Modern Xoshiro**: Xoshiro256**, Xoroshiro128++ (Minecraft Java 1.18+).

### 4. Mathematical LCGs (`virt_rand`)
Classic Linear Congruential Generators with customizable shift parameters. Ideal for understanding how modular arithmetic creates pseudo-random patterns.

---

## 🚀 Getting Started

### Installation
1. Clone the repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Running Tests
Most modules include a built-in test suite in their `if __name__ == "__main__":` block.
```bash
python virt_rand/xor_shift.py
```

---

## 📺 Educational Resources
This project was built with a focus on understanding the limits of computer-generated randomness. For more context, check out:
- [Why computers can't generate truly random numbers](https://youtu.be/XDsYPXRCXAs?si=oDaFsqZyNJWVXwEi)

---

## 📜 License
Provided for educational and research purposes.
