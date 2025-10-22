# GEUR-QKD Toy Simulator

A small educational simulation of a **Quantum Key Distribution (QKD)** protocol based on a *Generalized Entropy Uncertainty Relation (GEUR)* model.

This Python script allows you to explore how parameters such as error rate, basis bias, and privacy amplification security affect the strength of the generated key.

---

## Overview

This simulator models the major stages of a QKD system:

1. **Quantum Transmission** — Alice and Bob send and measure qubits using random bases (Z, X, Y).
2. **Sifting** — They keep only the bits measured in matching bases.
3. **Error Estimation** — Computes the Quantum Bit Error Rate (QBER).
4. **Adaptive Advantage Distillation (AD)** — Optional post-processing step to reduce Eve’s knowledge.
5. **Error Correction (EC)** — Simulated Shannon-limited leak.
6. **Privacy Amplification (PA)** — Reduces Eve’s knowledge using finite-key bounds.
7. **Authentication (optional)** — Uses Wegman–Carter MAC for secure classical channel authentication.
8. **Security Accounting** — Displays a full ε-budget for composable security.

---

## Requirements

- Python 3.10 or newer
- Standard library only (no extra dependencies required)

Modules used: `math`, `argparse`, `json`, `os`, `random`, `statistics`, `time`, `secrets`, `pathlib`, and `dataclasses`.

---

## Basic Usage

Run a single simulation using a profile:

```bash
python geur_qkd_sim.py --profile target10

```Run with message authentication:
python geur_qkd_sim.py --profile target10 --auth mac


```Run with tighter security parameters:
python geur_qkd_sim.py --profile target10 --auth mac --auth-eps 1e-20 --eps-pa 1e-15


```Tune system parameters to find the best configuration:
python geur_qkd_sim.py --profile target10 --tune --tune-rounds 10000 --tune-max-qber 0.18 --export-best


```Perform a quick sweep over candidate parameters:
python geur_qkd_sim.py --profile target10 --sweep mini


Output Description
Each run prints:

QBER (Quantum Bit Error Rate)

Eve’s Knowledge (p_eve_used)

Leakage (EC + AD)

Final Key Length (after PA and authentication)

Composable Security Budget (ε_total)

If authentication is enabled:
Authentication: Wegman–Carter MAC (ε_auth=1.00e-20, tag=67 bits)
If tuning or sweep mode is used, results are exported to CSV files under the runs/ directory.

Security Parameters
This toy model approximates the following composable security guarantees:

Component	Symbol	Typical ε
Parameter Estimation	ε_PE	2×10⁻¹⁰
Error Correction	ε_EC	2×10⁻¹⁰
Privacy Amplification	ε_PA	10⁻¹⁵
Authentication (MAC)	ε_AUTH	10⁻²⁰
Abort Probability	ε_ABORT	2×10⁻¹⁰

Total ε_total ≈ 6×10⁻¹⁰, which would be considered information-theoretically secure under the composable security definition.

Advanced Features
Tuner: Searches for near-optimal configurations for given QBER and Eve limits.

Wegman–Carter MAC: Automatically computes tag size from ε_auth.

Finite-Key Bound: Uses Hoeffding inequality correction for finite sample sizes.

CSV Output: Automatically logs candidate and sweep results for analysis.

Project Structure
graphql
Copy code
geur_qkd_sim.py   # Main simulation file
runs/              # Auto-generated output CSVs from tuner/sweeps
README.md          # Project documentation


Example Output
ε-budget: PE=2.00e-10 + EC=2.00e-10 + PA=1.00e-15 + Auth=1.00e-20 + Abort=2.00e-10 -> ε_total=6.00e-10
Authentication: Wegman–Carter MAC (ε_auth=1.00e-20, tag=67 bits)
===== GEUR-QKD TOY SIMULATION =====
Total rounds sent: 20000
Sifted key length (pre-AD): 6632
Raw error rate (pre-AD): 10.87%
Eve knowledge used for PA: 25.44%
Final key length after PA: 37 bits
===================================

Notes
This project is not production-grade cryptography.
It is intended for learning and demonstration purposes.

You can adjust ε values to explore security versus key-rate trade-offs.

The results vary between runs due to random quantum sampling.

Extending the Simulator: Toeplitz Privacy Amplification
The Toeplitz Hash method is a 2-universal hashing scheme used in real QKD systems to perform privacy amplification.
It compresses the reconciled raw key using a random binary Toeplitz matrix to generate a secure final key.

Concept
Given:

A raw key k_raw of length n

A random seed defining a binary Toeplitz matrix T of size m×n

The desired final key length m (based on the privacy bound)

The final key is computed as:
k_final = (T × k_raw) mod 2
This ensures Eve’s probability of guessing the final key is bounded by the chosen ε_PA.

Implementation Outline
To extend your simulator:

Import NumPy (optional but recommended):
import numpy as np

Add a helper function:
def toeplitz_hash(raw_bits: list[int], final_len: int, seed: int = None) -> list[int]:
    if seed is None:
        seed = secrets.randbits(len(raw_bits) + final_len - 1)
    # Convert seed into Toeplitz matrix diagonals
    seed_bits = [(seed >> i) & 1 for i in range(len(raw_bits) + final_len - 1)]
    result = []
    for i in range(final_len):
        s = sum(seed_bits[i + j] * raw_bits[j] for j in range(len(raw_bits))) % 2
        result.append(s)
    return result
Call this inside your privacy amplification step:
Replace your current final_key generation logic with:
final_bits = toeplitz_hash(alice_bits, final_len)
Optionally output a hex digest:
final_key_hex = hex(int(''.join(map(str, final_bits)), 2))[2:]
This addition makes the PA stage cryptographically meaningful, ensuring a secure compression step consistent with modern QKD implementations.

Author
Developed as a Quantum Cryptography Learning Simulator, inspired by the BB84, B92, and GEUR-based QKD frameworks.
