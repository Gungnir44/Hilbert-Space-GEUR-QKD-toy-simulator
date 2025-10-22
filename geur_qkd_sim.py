import argparse
import json
import math
import os
import random
import statistics
import time
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

# ======================================================
# Simple GEUR-QKD Toy Simulator (Patched) Using : 
# Hilbert Spaces
#  - Single-run tuner flow
#  - Robust tuner returns
#  - EC leakage computed from POST-AD error
#  - No hidden second simulate() call
# ======================================================

# ------------------------------------------------------
# Globals / Defaults
# ------------------------------------------------------
N_ROUNDS = 10000
P_BASIS = [1/3, 1/3, 1/3]  # [Z, X, Y]
BASIS_LABELS = ['Z','X','Y']

USE_AD = True
USE_AD_WEIGHTED = True
AD_BLOCK_SIZE = 4
AD_BIT_RULE = 'majority'  # majority or parity
AD_SCORE_THRESH = 3.0
BASIS_WEIGHT = {'Z':1.0,'X':1.3,'Y':1.3}
AD_PARITY_LEAK = False   # count parity bits as leakage

CHANNEL_ERROR = 0.01
EVE_MODE = 'intercept'    # intercept or weak
EVE_STRENGTH = 0.2        # 0..1 (interpretation depends on mode)
EVE_PARTIAL_EQUIV = 0.5

EC_EFFICIENCY = 1.05      # f in leakEC = f * n * h(Q)
FINITE_SIZE = True
CONFIDENCE_DELTA = 1e-6   # Hoeffding
SECURITY_EPS = 1e-9

RNG = random.Random(1337)

# === Composable security epsilons (defaults) ===
EPS_PE    = 2e-10   # parameter estimation
EPS_EC    = 2e-10   # error correction
EPS_PA    = 2e-10   # privacy amplification
EPS_AUTH  = 1e-20   # authentication (Wegman–Carter)
EPS_ABORT = 2e-10   # probability we abort incorrectly

# === Auth & PA modes (defaults) ===
AUTH_MODE    = "none"       # "none" | "mac"
AUTH_EPS     = EPS_AUTH     # can be overridden by CLI
PA_MODE      = "toeplitz"   # "toeplitz" | "none"
PA_SEED_HEX  = None         # CLI can set; otherwise random
OUT_PSK_PATH = None         # optional file to dump final key

# ------------------------------------------------------
# Small helpers
# ------------------------------------------------------


def epsilon_total(eps_pe, eps_ec, eps_pa, eps_auth, eps_abort):
    return eps_pe + eps_ec + eps_pa + eps_auth + eps_abort

def _ceil_log2_inv_eps(eps: float) -> int:
    # returns ceil(log2(1/eps))
    return int(math.ceil(-math.log2(max(float(eps), 1e-300))))

def wc_mac_tag_bits(eps_auth: float) -> int:
    # Wegman–Carter tag length needed for failure prob eps_auth
    return _ceil_log2_inv_eps(eps_auth)

def _bytes_to_bits(b: bytes) -> list[int]:
    return [(byte >> k) & 1 for byte in b for k in range(7, -1, -1)]

def _bits_to_bytes(bits: list[int]) -> bytes:
    if not bits:
        return b""
    out = bytearray((len(bits) + 7) // 8)
    for i, bit in enumerate(bits):
        if bit:
            out[i // 8] |= (1 << (7 - (i % 8)))
    return bytes(out)

def toeplitz_hash(seed_bits: list[int], in_bits: list[int], L: int) -> list[int]:
    """
    2-universal Toeplitz extractor.
    seed_bits must have length L + len(in_bits) - 1.
    Returns L output bits (list of 0/1).
    """
    n = len(in_bits)
    assert len(seed_bits) == L + n - 1, "toeplitz seed length mismatch"
    out = [0] * L
    # y[i] = XOR_j( in_bits[j] AND seed_bits[i+j] )
    for i in range(L):
        acc = 0
        sb = seed_bits[i:i+n]
        # small XOR dot-product mod 2
        for a, b in zip(in_bits, sb):
            acc ^= (a & b)
        out[i] = acc
    return out

def leftover_hash_output_len(n_bits_raw: int, qber: float, eve_frac: float, leak_ec_bits: float, eps_pa: float) -> int:
    """
    A toy min-entropy bound:
      H_min ≈ n * (1 - h2(qber)) * (1 - eve_frac)
    Then leftover hash lemma suggests:
      l ≤ H_min - leak_ec - 2*log2(1/ε_pa)
    We clamp to [0, n_bits_raw].
    """
    hmin = n_bits_raw * max(0.0, (1.0 - h2(qber))) * max(0.0, (1.0 - eve_frac))
    sec_term = 2.0 * math.log2(1.0/eps_pa)
    l = int(max(0.0, math.floor(hmin - leak_ec_bits - sec_term)))
    return min(l, n_bits_raw)

def compose_epsilon(eps_pe: float, eps_ec: float, eps_pa: float, eps_auth: float) -> float:
    # Simple sum (union bound); more sophisticated compositions exist.
    return eps_pe + eps_ec + eps_pa + eps_auth


def toeplitz_hash_bits(in_bits, out_len, seed_bits):
    """
    Toeplitz matrix hashing over GF(2). Seed length must be len(in_bits) + out_len - 1.
    Returns list[int] of length out_len (bits).
    """
    n = len(in_bits)
    needed = n + out_len - 1
    if len(seed_bits) < needed:
        raise ValueError(f"Toeplitz seed too short: have {len(seed_bits)} need {needed}")
    out = [0]*out_len
    # Row i uses seed slice [i : i+n]
    # out[i] = sum_j in_bits[j] & seed_bits[i+j] mod 2
    for i in range(out_len):
        s = 0
        sb = seed_bits[i:i+n]
        # XOR over ANDs: s ^= (in_bits[j] & sb[j])
        # A branchless-ish loop:
        for j, b in enumerate(in_bits):
            s ^= (b & sb[j])
        out[i] = s & 1
    return out

def random_bitstring(L: int):
    # returns list[int] of bits
    b = secrets.token_bytes((L+7)//8)
    bits = bits_from_bytes(b)
    return bits[:L]


def h2(p: float) -> float:
    # Binary entropy in bits
    if p <= 0.0 or p >= 1.0:
        return 0.0
    return -p*math.log2(p) - (1.0 - p)*math.log2(1.0 - p)

def bits_from_bytes(b: bytes):
    return [(byte >> i) & 1 for byte in b for i in range(8)]

def bytes_from_bits(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        v = 0
        for j in range(8):
            if i + j < len(bits) and bits[i + j]:
                v |= (1 << j)
        out.append(v)
    return bytes(out)

def auth_failure_epsilon(num_msgs: int, tag_bits: int, override_eps: float | None) -> float:
    if override_eps is not None:
        return override_eps
    # Wegman–Carter: forging probability per message ≤ 2^-t; union bound over M messages.
    return num_msgs * (2.0 ** (-tag_bits))


def choose_basis():
    r = random.random(); c = 0
    for i,w in enumerate(P_BASIS):
        c += w
        if r < c:
            return BASIS_LABELS[i]
    return 'Y'

# Eve interaction (very toy)

def eve_interaction(basis: str, bit: int):
    if EVE_MODE == 'intercept':
        p_int = EVE_STRENGTH
        intercepted = (random.random() < p_int)
        disturbed = intercepted and (random.random() < 0.5)
        eve_correct = intercepted and (random.random() < 0.7)
        k_eve = 1.0 if eve_correct else (EVE_PARTIAL_EQUIV if intercepted else 0.0)
        fwd_bit = bit ^ (1 if disturbed else 0)
        return fwd_bit, intercepted, eve_correct, k_eve, disturbed
    else:  # weak measurement style
        strength = EVE_STRENGTH
        delta = (random.random()-0.5)*0.2*strength
        p_flip = max(0.0, min(1.0, CHANNEL_ERROR + delta))
        disturbed = (random.random() < p_flip)
        fwd_bit = bit ^ (1 if disturbed else 0)
        k_eve = 0.5*strength
        eve_correct = (random.random() < (0.5 + 0.2*strength))
        return fwd_bit, True, eve_correct, k_eve, disturbed


def bob_measure(tx_basis: str, fwd_bit: int, intercepted: bool, disturbed: bool):
    # Bob picks same distribution of bases
    bob_basis = choose_basis()
    bit = fwd_bit
    # channel noise
    if random.random() < CHANNEL_ERROR:
        bit ^= 1
    return bob_basis, bit

# ------------------------------------------------------------
# Advantage distillation (toy)
# ------------------------------------------------------------

def _block_iter(bits: List[int], size: int):
    for i in range(0, len(bits), size):
        if i+size <= len(bits):
            yield i, bits[i:i+size]


def majority(bits: List[int]) -> int:
    ones = sum(bits)
    return 1 if ones*2 >= len(bits) else 0


def advantage_distill(a_bits: List[int], b_bits: List[int], block_size=4, rule='majority', count_leak=False):
    kept_a, kept_b = [], []
    blocks_kept = []
    leak = 0
    for idx, a_blk in _block_iter(a_bits, block_size):
        b_blk = b_bits[idx:idx+block_size]
        if rule == 'majority':
            if sum(x^y for x,y in zip(a_blk,b_blk)) <= 1:
                kept_a.append(majority(a_blk))
                kept_b.append(majority(b_blk))
                blocks_kept.append(idx//block_size)
                leak += 1 if count_leak else 0
        else:  # parity
            pa = sum(a_blk) % 2; pb = sum(b_blk) % 2
            if pa == pb:
                kept_a.append(pa); kept_b.append(pb)
                blocks_kept.append(idx//block_size)
                leak += 1 if count_leak else 0
    return kept_a, kept_b, blocks_kept, leak


def advantage_distill_weighted(a_bits: List[int], b_bits: List[int], bases: List[str], eve_know: List[float],
                               block_size=4, rule='majority', score_thresh=3.0, weights=None, count_leak=False):
    if weights is None:
        weights = {'Z':1.0,'X':1.0,'Y':1.0}
    kept_a, kept_b = [], []
    blocks_kept = []
    leak = 0
    kept_blocks_idx = []
    for idx, a_blk in _block_iter(a_bits, block_size):
        b_blk = b_bits[idx:idx+block_size]
        base_blk = bases[idx:idx+block_size]
        score = sum(weights.get(b,1.0) for b in base_blk)
        if score >= score_thresh:
            if rule == 'majority':
                if sum(x^y for x,y in zip(a_blk,b_blk)) <= 1:
                    kept_a.append(majority(a_blk))
                    kept_b.append(majority(b_blk))
                    blocks_kept.append(idx//block_size)
                    kept_blocks_idx.append(idx//block_size)
                    leak += 1 if count_leak else 0
            else:
                pa = sum(a_blk) % 2; pb = sum(b_blk) % 2
                if pa == pb:
                    kept_a.append(pa); kept_b.append(pb)
                    blocks_kept.append(idx//block_size)
                    kept_blocks_idx.append(idx//block_size)
                    leak += 1 if count_leak else 0
    return kept_a, kept_b, blocks_kept, leak, kept_blocks_idx


def estimate_eve_post_ad(eve_know_round: List[float], kept_blocks_idx: List[int], rule='majority', partial_equiv=0.5):
    # crude: average Eve knowledge for kept blocks
    if not kept_blocks_idx:
        return 1.0
    # each block contributes one distilled bit
    vals = []
    for _ in kept_blocks_idx:
        # assume average of per-round knowledge
        vals.append(statistics.mean(eve_know_round))
    return max(0.0, min(1.0, statistics.mean(vals)))

# ------------------------------------------------------------
# EC & finite-size
# ------------------------------------------------------------

def hoeffding_upper_bound(p_hat: float, n: int, delta: float) -> float:
    if n <= 0:
        return 1.0
    eps = math.sqrt(math.log(1/delta)/(2*max(1,n)))
    return min(1.0, max(0.0, p_hat + eps))

def compute_ec_leakage(n: int, q: float) -> float:
    return EC_EFFICIENCY * n * h2(q)

# ------------------------------------------------------------
# One-shot simulate for tuner (PATCHED)
# ------------------------------------------------------------

def simulate_once_return_metrics(rounds=1000):
    alice_bits, bob_bits = [], []
    sift_bases, eve_knows, eve_know_round = [], [], []

    for _ in range(rounds):
        basis = choose_basis()
        bit = random.randint(0,1)
        fwd_bit, intercepted, eve_correct, k_eve, disturbed = eve_interaction(basis, bit)
        bob_basis, bob_bit = bob_measure(basis, fwd_bit, intercepted, disturbed)
        if bob_basis == basis:
            alice_bits.append(bit); bob_bits.append(bob_bit)
            sift_bases.append(basis); eve_knows.append(k_eve); eve_know_round.append(k_eve)

    n0 = len(alice_bits)
    if n0 == 0:
        return dict(sift_len=0, p_error=0, p_eve_used=1.0, final_len=0, success_rate=0.0, ad_leak=0, total_leak=0)

    # Pre-AD error (for reporting and gating)
    p_error_pre = sum(a != b for a, b in zip(alice_bits, bob_bits)) / n0

    # Advantage distillation
    ad_leak = 0
    kept_blocks_idx = []
    if USE_AD:
        if USE_AD_WEIGHTED:
            dist_a, dist_b, blocks_kept, ad_leak, kept_blocks_idx = advantage_distill_weighted(
                alice_bits, bob_bits, sift_bases, eve_know_round,
                block_size=AD_BLOCK_SIZE, rule=AD_BIT_RULE,
                score_thresh=AD_SCORE_THRESH, weights=BASIS_WEIGHT,
                count_leak=AD_PARITY_LEAK
            )
        else:
            dist_a, dist_b, blocks_kept, ad_leak = advantage_distill(
                alice_bits, bob_bits, block_size=AD_BLOCK_SIZE,
                rule=AD_BIT_RULE, count_leak=AD_PARITY_LEAK
            )
        alice_bits, bob_bits = dist_a, dist_b

    # Eve estimator (post-AD when weighted and we know which blocks survived)
    if USE_AD and USE_AD_WEIGHTED and kept_blocks_idx:
        p_eve_used = estimate_eve_post_ad(
            eve_know_round, kept_blocks_idx, rule=AD_BIT_RULE, partial_equiv=EVE_PARTIAL_EQUIV
        )
        n_for_bound = len(kept_blocks_idx)
    else:
        p_eve_used = sum(eve_knows) / n0
        n_for_bound = n0

    if FINITE_SIZE:
        p_eve_used = hoeffding_upper_bound(p_eve_used, n_for_bound, CONFIDENCE_DELTA)

    # Post-AD error drives EC leakage
    # --- Privacy amplification inputs (Toeplitz extractor) ---
    n = len(alice_bits)

    # Post-AD error drives EC leakage
    p_error_post = (sum(a != b for a, b in zip(alice_bits, bob_bits)) / n) if n else 0.0

    # Leakage: EC from post-AD + (optional) AD parity leakage
    leak_ec   = compute_ec_leakage(n, p_error_post)
    total_leak = leak_ec + (ad_leak if AD_PARITY_LEAK else 0)

    # Finite-key secrecy term (leftover hash lemma, 2-universal extractor)
    # You can split SECURITY_EPS into PA and smoothing if you like; keeping it simple here.
    eps_pa  = SECURITY_EPS         # e.g. 1e-10
    sec_term = 2 * math.log2(1/eps_pa)

    # Min-entropy bound against Eve (toy: p_eve_used is the Eve-knowledge fraction)
    H_min = max(0.0, n * (1.0 - p_eve_used) - total_leak)

    # Output key length after PA
    final_len = max(int(H_min - sec_term), 0)

    # If/when you actually output bits, a Toeplitz extractor needs this seed length:
    # seed_len = n + final_len - 1
    pa_seed_len = max(0, n + final_len - 1)

    # (optional) compose an epsilon budget for the summary
    # If you add MAC auth later, include AUTH_EPS when AUTH_MODE == 'mac'
    epsilon_total = eps_pa + (AUTH_EPS if 'AUTH_MODE' in globals() and AUTH_MODE == 'mac' else 0.0)
    
    # ---- Account for authentication tag if MAC is enabled ----
    auth_tag_bits = 0
    if AUTH_MODE == "mac":
        # Wegman–Carter one-time MAC: tag length ≈ ceil(log2(1/eps_auth))
        auth_tag_bits = int(math.ceil(math.log2(1.0 / AUTH_EPS)))
        # We "spend" tag bits from the final key we’re about to output
        spend = min(final_len, auth_tag_bits)
        final_len -= spend

    # (optional) keep this in your printed metrics dict if you have one:
    # metrics["auth_tag_bits"] = auth_tag_bits


    return dict(
        sift_len=n0,
        p_error=p_error_pre,
        p_eve_used=p_eve_used,
        final_len=final_len,
        success_rate=(n / rounds if rounds > 0 else 0.0),
        ad_leak=ad_leak,
        total_leak=total_leak,
        pa_seed_len=pa_seed_len,
        epsilon_total=epsilon_total,

    )

# ------------------------------------------------------------
# Tuner (sweeps EVE_STRENGTH and applies optional Eve cap)
# ------------------------------------------------------------

def tune_for_target_eve(
    target_eve     =  0.10, rounds=8000,
    basis_profiles = ([0.88,0.06,0.06],[0.85,0.075,0.075],[0.80,0.10,0.10]),
    chan_errors    = (0.0025, 0.003, 0.004, 0.005),
    ad_modes       = ("weighted",),            # we keep weighted in this tuner
    block_sizes    = (4,),                     # your best runs were with 4
    score_thresh   = (2.6, 2.8, 3.0, 3.2, 3.4),
    ec_eff         = (1.05,),                  # keep simple; widen later if needed
    max_qber       =  0.18,
    eve_cap        =  None,                    # hard cap on Eve knowledge
    eve_strengths  = (0.08, 0.10, 0.12, 0.15, 0.20),  # <-- NEW: sweep Eve
):  # Tune for target Eve knowledge
    from pathlib import Path
    import statistics, time

    candidates = []

    for pb in basis_profiles:
        for ce in chan_errors:
            for bs in block_sizes:
                for thr in score_thresh:
                    for es in eve_strengths:
                        # apply temp config
                        global P_BASIS, CHANNEL_ERROR, AD_BLOCK_SIZE, AD_SCORE_THRESH
                        global USE_AD, USE_AD_WEIGHTED, EC_EFFICIENCY, AD_PARITY_LEAK, EVE_STRENGTH

                        P_BASIS = list(pb)
                        CHANNEL_ERROR = ce
                        AD_BLOCK_SIZE = bs
                        AD_SCORE_THRESH = thr
                        USE_AD = True
                        USE_AD_WEIGHTED = True
                        EC_EFFICIENCY = 1.05
                        AD_PARITY_LEAK = False
                        EVE_STRENGTH = es          # <-- NEW: actually sweep Eve

                        m = simulate_once_return_metrics(rounds=rounds)

                        # Keep only those that don’t blow the QBER budget
                        if m['p_error'] > max_qber:
                            continue

                        candidates.append(dict(
                            cfg={
                                'P_BASIS': list(pb),
                                'CHANNEL_ERROR': ce,
                                'USE_AD': True,
                                'USE_AD_WEIGHTED': True,
                                'AD_BLOCK_SIZE': bs,
                                'EC_EFFICIENCY': EC_EFFICIENCY,
                                'AD_PARITY_LEAK': AD_PARITY_LEAK,
                                'AD_SCORE_THRESH': thr,
                                'EVE_STRENGTH': es,    # <-- keep for replay/export
                            },
                            eve   = m['p_eve_used'],
                            final = m['final_len'],
                            sift  = m['sift_len'],
                            qber  = m['p_error'],
                            leak  = m['total_leak'],
                        ))

    print(f"[tune] candidates kept: {len(candidates)}")

    # Optional hard Eve cap filtering
    kept = candidates
    if eve_cap is not None:
        kept = [c for c in kept if c['eve'] <= eve_cap]
        if not kept:
            print(f"[tune] No candidates within Eve cap {eve_cap:.3f}")
            return (None, None)

    if kept:
        qs = [c['qber'] for c in kept]
        print(f"[tune] QBER kept range: {min(qs):.3f} – {max(qs):.3f} (median {statistics.median(qs):.3f})")
        # Write CSV for inspection
        Path('runs').mkdir(exist_ok=True)
        out = Path('runs')/f"tuner_candidates_{time.strftime('%Y%m%d-%H%M%S')}.csv"
        with out.open('w', encoding='utf-8') as f:
            f.write('P_BASIS,CHANNEL_ERROR,AD_BLOCK_SIZE,AD_SCORE_THRESH,EC_EFFICIENCY,USE_AD_WEIGHTED,EVE_STRENGTH,EVE,FINAL,SIFT,QBER,LEAK\n')
            for c in kept:
                pb = c['cfg']['P_BASIS']
                f.write(f"{pb[0]}|{pb[1]}|{pb[2]},{c['cfg']['CHANNEL_ERROR']},{c['cfg']['AD_BLOCK_SIZE']},"
                        f"{c['cfg']['AD_SCORE_THRESH']},{c['cfg']['EC_EFFICIENCY']},True,{c['cfg']['EVE_STRENGTH']},"
                        f"{c['eve']:.6f},{c['final']},{c['sift']},{c['qber']:.6f},{c['leak']:.1f}\n")

    if not kept:
        print("[tune] No candidates met constraints. Try increasing --tune-max-qber, --tune-rounds, or widening the grid.")
        return (None, None)

    # Prefer configs within (target_eve + 0.02), then maximize final; otherwise pick closest Eve then max final
    feasible = [c for c in kept if c['final'] > 0 and c['eve'] <= (target_eve + 0.02)]
    if feasible:
        feasible.sort(key=lambda c: (-c['final'], c['eve']))
        best = feasible[0]
    else:
        kept.sort(key=lambda c: (abs(c['eve'] - target_eve), -c['final']))
        best = kept[0]

    best_cfg = dict(best['cfg'])  # already includes EVE_STRENGTH now
    best_metrics = {
        'eve': best['eve'], 
        'final_len': best['final'],
        'sift_len': best['sift'],
        'qber': best['qber'],
        'leak': best['leak'],
    }
    return best_cfg, best_metrics

# ------------------------------------------------------------
# Profiles and applying
# ------------------------------------------------------------

PROFILES = {
    'baseline': {},
    'target10': {
        'N_ROUNDS': 20000,
        'P_BASIS': [1/3,1/3,1/3],
        'CHANNEL_ERROR': 0.01,
        'USE_AD': True,
        'USE_AD_WEIGHTED': True,
        'AD_BLOCK_SIZE': 6,
        'AD_SCORE_THRESH': 3.0,
        'EC_EFFICIENCY': 1.05,
        'AD_PARITY_LEAK': False,
        'EVE_MODE': 'intercept',
        'EVE_STRENGTH': 0.2,
        'FINITE_SIZE': True,
        'CONFIDENCE_DELTA': 1e-6
    }
}


def apply_profile(name: str, overrides=None):
    cfg = dict(PROFILES.get(name, {}))
    if overrides:
        cfg.update(overrides)
    globals_dict = globals()
    for k,v in cfg.items():
        globals_dict[k] = v
    print(f"[profile] Applied '{name}' with overrides={overrides}")

# ------------------------------------------------------------
# CLI and top-level simulate/plots (minimal stubs)
# ------------------------------------------------------------

def simulate():
    # minimal top-level report using simulate_once_return_metrics
    m = simulate_once_return_metrics(rounds=N_ROUNDS)
    print("===== GEUR-QKD TOY SIMULATION =====")
    print(f"Total rounds sent: {N_ROUNDS}")
    print(f"Sifted key length (pre-AD): {m['sift_len']}")
    print(f"Raw error rate (pre-AD): {m['p_error']*100:.2f}%")
    print(f"AD mode: {'Weighted' if USE_AD_WEIGHTED else 'Classic'}  |  Block size={AD_BLOCK_SIZE}, rule={AD_BIT_RULE}")
    if USE_AD_WEIGHTED:
        print(f"AD score threshold: {AD_SCORE_THRESH}  |  BASIS_WEIGHT={BASIS_WEIGHT}")
    print(f"AD parity leakage: {int(AD_PARITY_LEAK)} bits")
    # Post-AD length not shown explicitly in this stub
    print(f"Eve knowledge used for PA: {m['p_eve_used']*100:.2f}%  (finite-size={'on' if FINITE_SIZE else 'off'})")
    print(f"Leakage (EC): {m['total_leak']- (m['ad_leak'] if AD_PARITY_LEAK else 0):.1f}  |  Total leakage (EC+AD): {m['total_leak']:.1f}")
    print(f"Final key length after PA: {m['final_len']} bits")
    if m['final_len']>0:
        print(f"Final key (hex, truncated): {'%064x'%RNG.randrange(1<<256)}")
    # ε-budget (composable security summary)
    if 'epsilon_total' in locals():
        auth_note = f", Auth={AUTH_EPS:.2e}" if 'AUTH_MODE' in globals() and AUTH_MODE == 'mac' else ""
        print(f"ε_total ≈ {epsilon_total:.2e}  (PA={SECURITY_EPS:.2e}{auth_note})")
    print("===================================")


def plot_tradeoff_vs_strength():
    import matplotlib.pyplot as plt
    import numpy as np
    # placeholder chart of Eve vs strength at current CE
    xs = np.linspace(0,1,9)
    ys = np.clip(0.2 + 0.8*xs**2, 0, 1) * 100
    plt.figure(figsize=(8,4.5))
    plt.plot(xs, ys, marker='o')
    plt.title('Eve Knowledge vs Attack Strength')
    plt.xlabel('EVE_STRENGTH'); plt.ylabel('Eve Knowledge (%)')
    Path('plots').mkdir(exist_ok=True)
    plt.savefig('plots/tradeoff_eve_vs_strength.png', bbox_inches='tight')
    plt.close()


def plot_tradeoff_vs_strength_with_band():
    import matplotlib.pyplot as plt
    import numpy as np
    xs = np.linspace(0,1,9)
    base = np.maximum(0, 80*(1-xs**2))
    lo, hi = np.maximum(0, base-50), np.maximum(0, base+50)
    plt.figure(figsize=(8,4.5))
    plt.fill_between(xs, lo, hi, alpha=0.15)
    plt.plot(xs, base, marker='s')
    plt.title('Final Key vs Strength (finite-key band)')
    plt.xlabel('EVE_STRENGTH'); plt.ylabel('Final Key Length (bits)')
    Path('plots').mkdir(exist_ok=True)
    plt.savefig('plots/tradeoff_vs_strength_with_band.png', bbox_inches='tight')
    plt.close()


def heatmap_tradeoff():
    import matplotlib.pyplot as plt
    import numpy as np
    strengths = np.linspace(0.2,1.0,9)
    cherrs = np.linspace(0.0,0.05,6)
    # fake heatmap placeholder
    Z = np.zeros((len(cherrs), len(strengths)))
    for i,ce in enumerate(cherrs):
        for j,s in enumerate(strengths):
            Z[i,j] = max(0, 100*(1.0 - 1.3*s - 0.3*ce/0.05))
    plt.figure(figsize=(9,5))
    plt.imshow(Z, aspect='auto', origin='lower',
               extent=[strengths.min(), strengths.max(), cherrs.min(), cherrs.max()])
    plt.colorbar(label='Eve Knowledge (%)')
    plt.xlabel('EVE_STRENGTH'); plt.ylabel('CHANNEL_ERROR')
    plt.title('Eve Knowledge vs Strength & Channel Error')
    Path('plots').mkdir(exist_ok=True)
    plt.savefig('plots/heatmap_eve_knowledge.png', bbox_inches='tight')
    plt.close()

def run_quick_sweep(mode: str = "mini"):
    """
    Minimal sweep runner. Produces a small CSV in ./runs and prints summary stats.
    mode: "mini" or "full"
    """
    from pathlib import Path
    import time, csv, statistics

    # Define a very small grid (expand later if you like)
    grids = {
        "mini": dict(
            P_BASIS=[[0.88,0.06,0.06], [0.85,0.075,0.075]],
            CHANNEL_ERROR=[0.003, 0.004],
            AD_BLOCK_SIZE=[4],
            AD_SCORE_THRESH=[3.0, 3.2],
            USE_AD_WEIGHTED=[True],
            EC_EFFICIENCY=[1.05, 1.06],
        ),
        "full": dict(
            P_BASIS=[[0.88,0.06,0.06], [0.85,0.075,0.075], [0.80,0.10,0.10]],
            CHANNEL_ERROR=[0.0025, 0.003, 0.004, 0.005],
            AD_BLOCK_SIZE=[4, 6],
            AD_SCORE_THRESH=[2.8, 3.0, 3.2],
            USE_AD_WEIGHTED=[True, False],
            EC_EFFICIENCY=[1.05, 1.06, 1.08],
        ),
    }
    G = grids.get(mode, grids["mini"])

    # Ensure output dir
    Path("runs").mkdir(exist_ok=True)
    out_csv = Path("runs")/f"sweep_{mode}_{time.strftime('%Y%m%d-%H%M%S')}.csv"

    # Save current globals so we can restore after each run
    save = dict(
        P_BASIS=P_BASIS, CHANNEL_ERROR=CHANNEL_ERROR,
        AD_BLOCK_SIZE=AD_BLOCK_SIZE, AD_SCORE_THRESH=AD_SCORE_THRESH,
        USE_AD_WEIGHTED=USE_AD_WEIGHTED, EC_EFFICIENCY=EC_EFFICIENCY,
        AD_PARITY_LEAK=AD_PARITY_LEAK
    )

    rows = []
    try:
        # Cartesian sweep
        for pb in G["P_BASIS"]:
            for ce in G["CHANNEL_ERROR"]:
                for bs in G["AD_BLOCK_SIZE"]:
                    for thr in G["AD_SCORE_THRESH"]:
                        for w in G["USE_AD_WEIGHTED"]:
                            for ecc in G["EC_EFFICIENCY"]:
                                # apply config
                                globals().update(dict(
                                    P_BASIS=pb, CHANNEL_ERROR=ce,
                                    AD_BLOCK_SIZE=bs, AD_SCORE_THRESH=thr,
                                    USE_AD=True, USE_AD_WEIGHTED=w,
                                    EC_EFFICIENCY=ecc, AD_PARITY_LEAK=False,
                                ))
                                m = simulate_once_return_metrics(rounds=8000)
                                rows.append(dict(
                                    P_BASIS="|".join(map(str,pb)),
                                    CHANNEL_ERROR=ce,
                                    AD_BLOCK_SIZE=bs,
                                    AD_SCORE_THRESH=thr,
                                    USE_AD_WEIGHTED=w,
                                    EC_EFFICIENCY=ecc,
                                    sift_len=m.get("sift_len", 0),
                                    qber=m.get("p_error", 0.0),
                                    eve=m.get("p_eve_used", 0.0),
                                    leak=m.get("total_leak", 0.0),
                                    final_len=m.get("final_len", 0),
                                ))
    finally:
        # restore globals
        globals().update(save)

    # write CSV
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else
            ["P_BASIS","CHANNEL_ERROR","AD_BLOCK_SIZE","AD_SCORE_THRESH","USE_AD_WEIGHTED","EC_EFFICIENCY",
             "sift_len","qber","eve","leak","final_len"])
        w.writeheader()
        for r in rows:
            w.writerow(r)

    # print quick summary
    if rows:
        with out_csv.open("w", newline="", encoding="utf-8") as f:
            import csv
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            for r in rows: w.writerow(r)

        import statistics
        finals = [r["final_len"] for r in rows]
        eves   = [r["eve"] for r in rows]
        qb     = [r["qber"] for r in rows]
        print(f"[sweep:{mode}] wrote {out_csv}")
        print(f"[sweep:{mode}] final_len median={statistics.median(finals)}, max={max(finals)}")
        print(f"[sweep:{mode}] eve median={statistics.median(eves):.3f}, min={min(eves):.3f}")
        print(f"[sweep:{mode}] qber median={statistics.median(qb):.3f}, min={min(qb):.3f}, max={max(qb):.3f}")
    else:
        print(f"[sweep:{mode}] no rows collected")
        


# ------------------------------------------------------------
# CLI
# ------------------------------------------------------------

def load_json_arg(s):
    if not s:
        return None
    s = s.strip()
    if s.startswith('@'):
        path = s[1:]
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return json.loads(s)

def parse_cli():
    import argparse, json, os, sys
    parser = argparse.ArgumentParser()

    parser.add_argument("--profile", default="baseline")
    parser.add_argument("--override", default=None,
                        help="JSON string or @path.json with overrides")
    parser.add_argument("--plots", action="store_true")
    parser.add_argument("--band",  action="store_true")

    # (Optional) tuner flags
    parser.add_argument("--tune", action="store_true")
    parser.add_argument("--tune-target", type=float, default=0.10)
    parser.add_argument("--tune-max-qber", type=float, default=0.13)
    parser.add_argument("--tune-max-eve", type=float, default=None)
    parser.add_argument("--tune-rounds", type=int, default=8000)
    parser.add_argument("--export-best", action="store_true")
    parser.add_argument("--export-best-path", dest="export_best", default="runs/best_config.json")
    parser.add_argument("--sweep", choices=["mini", "full"], default=None,
                    help="Run a parameter sweep and write a CSV/HTML report")

    # NEW: authentication switch
    parser.add_argument(
        "--auth",
        choices=["none", "mac"],
        default="none",
        help="Authentication mode: 'none' (no MAC) or 'mac' (Wegman–Carter MAC with ε_auth=1e-12)"
    )

    parser.add_argument("--auth-eps", type=float, default=1e-20,
                        help="Authentication failure probability (sets MAC tag bits).")

    parser.add_argument("--eps-pe", type=float, default=2e-10)
    parser.add_argument("--eps-ec", type=float, default=2e-10)
    parser.add_argument("--eps-pa", type=float, default=2e-10)
    parser.add_argument("--eps-abort", type=float, default=2e-10)

    parser.add_argument("--pa", choices=["toeplitz", "none"], default="toeplitz",
                        help="Privacy amplification extractor.")
    parser.add_argument("--pa-seed-hex", default=None,
                        help="Optional hex seed for Toeplitz extractor (test/repro).")

    parser.add_argument("--out-psk", default=None,
                        help="If set, write final key bytes to this file.")

    return parser.parse_args()

# ------------------------------------------------------------
# Main (PATCHED single-flow)
# ------------------------------------------------------------

if __name__ == "__main__":
    args = parse_cli()
    
    # --- Authentication globals ---
    # Apply security/PA/auth options from CLI to globals
    AUTH_MODE    = args.auth
    AUTH_EPS     = args.auth_eps
    EPS_PE       = args.eps_pe
    EPS_EC       = args.eps_ec
    EPS_PA       = args.eps_pa
    EPS_ABORT    = args.eps_abort
    PA_MODE      = args.pa
    PA_SEED_HEX  = args.pa_seed_hex
    OUT_PSK_PATH = args.out_psk


    # 1) Apply profile/overrides first
    if args.profile:
        overrides = load_json_arg(args.override)
        apply_profile(args.profile, overrides)

    # 2) Optionally run tuner once, then (if successful) apply best config
    best_cfg = None
    best_metrics = None
    # ---- Print composable security budget line ----
    eps_tot = epsilon_total(EPS_PE, EPS_EC, EPS_PA, AUTH_EPS, EPS_ABORT)
    print(
        "ε-budget: "
        f"PE={EPS_PE:.2e} + EC={EPS_EC:.2e} + PA={EPS_PA:.2e} + "
        f"Auth={AUTH_EPS:.2e} + Abort={EPS_ABORT:.2e}  ->  ε_total={eps_tot:.2e}"
    )

    if args.tune:
        best_cfg, best_metrics = tune_for_target_eve(
            target_eve=args.tune_target,
            rounds=args.tune_rounds,
            max_qber=args.tune_max_qber,
            eve_cap=args.tune_max_eve,
        )
        if not best_cfg:
            print("[tune] No candidates met constraints. Try increasing --tune-max-qber, --tune-rounds, or widening the grid.")
        else:
            print("Best config:", best_cfg)
            print("Metrics:", best_metrics)
            # Optional export of best config
            if args.export_best:
                export_path = args.export_best
                os.makedirs(os.path.dirname(export_path), exist_ok=True)
                with open(export_path, 'w', encoding='utf-8') as f:
                    json.dump(best_cfg, f, indent=2)
                print(f"[tune] Exported best config to {export_path}")
                print(f"[tip] Re-run with: --override @{export_path}")
                print(f"[auth] Mode={AUTH_MODE.upper()}  (ε_auth={AUTH_EPS:.2e})")
    auth_tag_bits = 0        
    if AUTH_MODE == "mac":
        print(f"Authentication: Wegman–Carter MAC (ε_auth={AUTH_EPS:.2e}, tag={auth_tag_bits} bits)")
    else:
        print("Authentication: none")

    # 3) Single simulate() call
    simulate()

    # 4) Optional plots
    if args.plots:
        try:
            plot_tradeoff_vs_strength()
        except Exception as e:
            print("[plots] tradeoff:", e)
        if args.band:
            try:
                plot_tradeoff_vs_strength_with_band()
            except Exception as e:
                print("[plots] band:", e)
        try:
            heatmap_tradeoff()
        except Exception as e:
            print("[plots] heatmap:", e)

    # 5) Optional sweep
    if getattr(args, "sweep", None):
        fn = globals().get("run_quick_sweep")
        if callable(fn):
            run_quick_sweep(args.sweep)
        else:
            print("[sweep] Requested, but run_quick_sweep() is not defined. Skipping.")
