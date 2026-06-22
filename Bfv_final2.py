"""
Post-Quantum Batch Authentication using BFV (Paper-Perfect Version)

Implements the base paper model:

σ_i = F(ID_i, t_i, sk_EAG)
C_i = Enc_BFV(pk, σ_i)
C_batch = Σ (α_i · C_i)
Dec_BFV(sk, C_batch) = Σ (α_i · σ_i)

Key properties:
- Randomized Linear Combination (RLC)
- Verifier-side batch aggregation
- Correctness verification
- Full metric coverage
"""

import time
import hashlib
import numpy as np
from Pyfhel import Pyfhel


# =====================================================
# BFV SYSTEM SETUP
# =====================================================

def setup_bfv(poly_degree=8192, plaintext_modulus=65537):
    """
    Initializes BFV context and generates keys.
    """
    HE = Pyfhel()
    HE.contextGen(
        scheme='BFV',
        n=poly_degree,
        t=plaintext_modulus
    )
    HE.keyGen()
    return HE


# =====================================================
# AUTHENTICATION TOKEN GENERATION
# σ_i = F(ID_i, t_i, sk_EAG)
# =====================================================

def generate_sigma(device_id, timestamp, sk_eag, vector_size=8):
    """
    Generates authentication token σ_i using SHA-256 as PRF.
    Vectorized for BFV batching (SIMD packing).
    """
    data = f"{device_id}|{timestamp}|{sk_eag}".encode()
    digest = hashlib.sha256(data).digest()
    sigma = np.frombuffer(digest, dtype=np.uint8)[:vector_size]
    return sigma.astype(np.int64)


# =====================================================
# ENCRYPTION
# =====================================================

def encrypt_sigma(HE, sigma_vector):
    """
    Encrypts σ_i using BFV.
    """
    plaintext = HE.encodeInt(sigma_vector)
    return HE.encryptPtxt(plaintext)


# =====================================================
# RANDOMIZED LINEAR COMBINATION (RLC)
# =====================================================

def randomized_batch_aggregate(ciphertexts, coefficients):
    """
    Computes C_batch = Σ (α_i · C_i)
    """
    C_batch = ciphertexts[0] * coefficients[0]
    for ct, alpha in zip(ciphertexts[1:], coefficients[1:]):
        C_batch += ct * alpha
    return C_batch


# =====================================================
# DECRYPTION
# =====================================================

def decrypt_batch(HE, C_batch):
    """
    Decrypts aggregated ciphertext.
    """
    return HE.decryptInt(C_batch)


# =====================================================
# STORAGE SIZE MEASUREMENT
# =====================================================

def get_serialized_size(HE):
    """
    Measures total storage cost (context + keys).
    """
    size = 0
    size += len(HE.to_bytes_context())
    size += len(HE.to_bytes_public_key())
    size += len(HE.to_bytes_secret_key())
    return size


# =====================================================
# MAIN EXPERIMENT
# =====================================================

def main():

    NUM_RUNS = 10
    DEVICE_COUNTS = [20, 40, 60, 80, 100]
    VECTOR_SIZE = 8
    SK_EAG = "SECRET_EAG_KEY"

    print("\n=== PQ Batch Authentication (BFV) — Base Paper Accurate ===\n")

    HE = setup_bfv()
    storage_bytes = get_serialized_size(HE)

    print(
        f"{'Devices':<10} | "
        f"{'Auth Latency (ms)':<18} | "
        f"{'Comp. Cost (ms)':<16} | "
        f"{'Comm. Cost (KB)':<16} | "
        f"{'Storage (KB)':<16} | "
        f"{'Throughput (Dev/s)':<18}"
    )
    print("-" * 115)

    for num_devices in DEVICE_COUNTS:

        auth_latencies = []
        agg_delays = []
        comp_costs = []
        throughputs = []

        ciphertext_size = None

        for _ in range(NUM_RUNS):
            sigmas = []
            ciphertexts = []
            coefficients = []

            start_wall = time.time()

            # -------------------------------
            # TOKEN GENERATION + ENCRYPTION
            # -------------------------------
            for i in range(num_devices):
                device_id = f"device_{i}"
                timestamp = int(time.time())

                sigma = generate_sigma(
                    device_id, timestamp, SK_EAG, VECTOR_SIZE
                )
                sigmas.append(sigma)

                ct = encrypt_sigma(HE, sigma)
                ciphertexts.append(ct)

                if ciphertext_size is None:
                    ciphertext_size = len(ct.to_bytes())

                alpha = np.random.randint(1, 10)
                coefficients.append(alpha)

            # -------------------------------
            # BATCH AGGREGATION (RLC)
            # -------------------------------
            t_agg_start = time.time()
            C_batch = randomized_batch_aggregate(ciphertexts, coefficients)
            agg_delay = time.time() - t_agg_start

            # -------------------------------
            # BATCH DECRYPTION
            # -------------------------------
            t_dec_start = time.time()
            decrypted = decrypt_batch(HE, C_batch)
            decrypt_time = time.time() - t_dec_start

            end_wall = time.time()

            # -------------------------------
            # CORRECTNESS VERIFICATION
            # -------------------------------
            expected = np.zeros(VECTOR_SIZE, dtype=np.int64)
            for sigma, alpha in zip(sigmas, coefficients):
                expected += sigma * alpha

            t = HE.t                      # BFV plaintext modulus
            expected_mod = expected % t
            decrypted_mod = decrypted[:VECTOR_SIZE] % t

            assert np.allclose(
                decrypted_mod,
                expected_mod
            ), f"❌ Batch authentication verification failed"

            # -------------------------------
            # METRICS
            # -------------------------------
            server_latency = agg_delay + decrypt_time
            total_time = end_wall - start_wall
            throughput = num_devices / total_time

            auth_latencies.append(server_latency)
            agg_delays.append(agg_delay + decrypt_time)
            comp_costs.append(total_time)
            throughputs.append(throughput)

        avg_auth_latency = np.mean(auth_latencies)
        avg_agg_delay = np.mean(agg_delays)
        avg_comp_cost = np.mean(comp_costs)
        avg_throughput = np.mean(throughputs)

        comm_cost_kb = (ciphertext_size * num_devices) / 1024

        storage_kb = storage_bytes / 1024
        print(
            f"{num_devices:<10} | "
            f"{avg_auth_latency * 1000:<18.2f} | "
            f"{avg_comp_cost * 1000:<16.2f} | "
            f"{comm_cost_kb:<16.2f} | "
            f"{storage_kb:<16.2f} | "
            f"{avg_throughput:<18.2f}"
        )

    print("-" * 120)
    print("\n✔ Correctness verified for all batches")
    print("✔ Randomized Linear Combination enabled")
    print("✔ Metrics aligned with base paper\n")


if __name__ == "__main__":
    main()
