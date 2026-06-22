"""
Post-Quantum Batch Authentication using BFV (Optimized)

Steps to run:
1. open cmd -> wsl --install
2. reboot
3. open Ubuntu
4. sudo apt update && apt upgrade -y
5. sudo apt install -y python3 python3-pip python3-venv build-essential cmake
6. python3 -m venv venv
        source venv/bin/activate
7. pip install numpy
8. pip install pyfhel
9. cd path-to-file
10. python3 filename.py

Implements:
σ_i = F(ID_i, t_i, sk_EAG)
C_i = Enc_BFV(pk, σ_i)
C_batch = Σ C_i
Dec_BFV(sk, C_batch) = Σ σ_i

Includes:
- Authentication latency
- Authentication throughput
- Batch throughput
- Direct comparison with existing PQ schemes
"""

import time
import hashlib
import numpy as np
from Pyfhel import Pyfhel

# ---------------------------------------------------
# SYSTEM SETUP (BFV)
# ---------------------------------------------------

def setup_bfv(n=8192, t=65537):
    HE = Pyfhel()
    HE.contextGen(scheme='BFV', n=n, t=t)
    HE.keyGen()
    return HE


# ---------------------------------------------------
# AUTHENTICATION TOKEN GENERATION
# σ_i = H(ID_i || t_i || sk_EAG)
# ---------------------------------------------------

def generate_sigma(device_id, timestamp, sk, vec_size=8):
    data = f"{device_id}|{timestamp}|{sk}".encode()
    digest = hashlib.sha256(data).digest()
    sigma = np.frombuffer(digest, dtype=np.uint8)[:vec_size]
    return sigma.astype(np.int64)


# ---------------------------------------------------
# ENCRYPTION
# ---------------------------------------------------

def encrypt_sigma(HE, sigma):
    ptxt = HE.encodeInt(sigma)
    return HE.encryptPtxt(ptxt)


# ---------------------------------------------------
# RANDOMIZED BATCH AGGREGATION (RLC)
# ---------------------------------------------------

def randomized_batch_aggregate(ciphertexts, coefficients):
    """
    Computes C_batch = Σ (α_i · C_i)
    """
    C_batch = ciphertexts[0] * coefficients[0]
    for ct, alpha in zip(ciphertexts[1:], coefficients[1:]):
        C_batch += ct * alpha
    return C_batch


# ---------------------------------------------------
# DECRYPTION
# ---------------------------------------------------

def decrypt_batch(HE, C_batch):
    return HE.decryptInt(C_batch)


def get_serialized_size(HE):
    size = 0
    size += len(HE.to_bytes_context())
    size += len(HE.to_bytes_public_key())
    size += len(HE.to_bytes_secret_key())
    return size

def main():
    NUM_RUNS = 10
    DEVICE_COUNTS = [20, 40, 60, 80, 100]
    VECTOR_SIZE = 8
    SK_EAG = "SECRET_EAG_KEY"

    print("\n=== PQ Batch Authentication (BFV) — Detailed Scalability Test ===\n")

    HE = setup_bfv()
    print("[+] BFV context initialized\n")

    storage_bytes = get_serialized_size(HE)
    storage_kb = storage_bytes / 1024

    final_comparison_data = []

    for num_devices in DEVICE_COUNTS:
        print(f"[*] Testing with {num_devices} devices...")

        # Arrays to store metrics across all runs
        all_avg_token_times = []
        all_avg_encrypt_times = []
        all_batch_formation_times = []
        all_decrypt_times = []
        all_latencies = []
        all_auth_throughputs = []

        for run in range(1, NUM_RUNS + 1):
            sigmas = []
            ciphertexts = []
            coefficients = [np.random.randint(1, 10) for _ in range(num_devices)]
            
            # Start E2E timer
            start_e2e = time.time()

            token_times = []
            encrypt_times = []

            # -------------------------------
            # TOKEN GENERATION + ENCRYPTION
            # -------------------------------
            for i in range(num_devices):
                device_id = f"device_{run}_{i}"
                timestamp = int(time.time())

                # Token Gen (σ_i)
                t0 = time.time()
                sigma = generate_sigma(device_id, timestamp, SK_EAG, VECTOR_SIZE)
                token_times.append(time.time() - t0)
                sigmas.append(sigma)

                # Encryption (C_i)
                t0 = time.time()
                ct = encrypt_sigma(HE, sigma)
                encrypt_times.append(time.time() - t0)
                ciphertexts.append(ct)

            # -------------------------------
            # SERVER-SIDE: BATCH AGGREGATION (RLC)
            # -------------------------------
            t_batch_start = time.time()
            C_batch = randomized_batch_aggregate(ciphertexts, coefficients)
            batch_formation_time = time.time() - t_batch_start

            # -------------------------------
            # SERVER-SIDE: BATCH DECRYPTION
            # -------------------------------
            t_dec_start = time.time()
            decrypted_sum = decrypt_batch(HE, C_batch)
            decrypt_time = time.time() - t_dec_start

            end_e2e = time.time()

            # -------------------------------
            # CORRECTNESS VERIFICATION
            # -------------------------------
            expected_mod_sum = np.zeros(VECTOR_SIZE, dtype=np.int64)
            for sigma, alpha in zip(sigmas, coefficients):
                expected_mod_sum += (sigma * alpha)
            
            # Verify against BFV plaintext modulus
            t_mod = HE.t
            expected_final = expected_mod_sum % t_mod
            decrypted_final = decrypted_sum[:VECTOR_SIZE] % t_mod

            assert np.allclose(expected_final, decrypted_final), "❌ Verification Failed!"

            # -------------------------------
            # METRICS CALCULATION (PER RUN)
            # -------------------------------
            avg_token_time = sum(token_times) / num_devices
            avg_encrypt_time = sum(encrypt_times) / num_devices
            
            # Auth Latency = Server-side operations (RLC + Decryption)
            server_latency = batch_formation_time + decrypt_time
            
            # Total E2E time for throughput
            total_e2e_time = end_e2e - start_e2e
            throughput = num_devices / total_e2e_time

            all_avg_token_times.append(avg_token_time)
            all_avg_encrypt_times.append(avg_encrypt_time)
            all_batch_formation_times.append(batch_formation_time)
            all_decrypt_times.append(decrypt_time)
            all_latencies.append(server_latency)
            all_auth_throughputs.append(throughput)

        # -----------------------------
        # FINAL AVERAGE RESULTS FOR THIS COUNT
        # -----------------------------
        avg_final_token = np.mean(all_avg_token_times)
        avg_final_encrypt = np.mean(all_avg_encrypt_times)
        avg_final_batch = np.mean(all_batch_formation_times)
        avg_final_decrypt = np.mean(all_decrypt_times)
        avg_final_latency = np.mean(all_latencies)
        avg_final_auth_tp = np.mean(all_auth_throughputs)

        print("-" * 50)
        print(f"AVERAGE RESULTS FOR {num_devices} DEVICES")
        print("-" * 50)
        print(f"Token Generation Time (avg): {avg_final_token * 1000:.6f} ms")
        print(f"Token Encryption Time (avg): {avg_final_encrypt * 1000:.6f} ms")
        print(f"Batch Formation Time (RLC):  {avg_final_batch * 1000:.6f} ms")
        print(f"Batch Decryption Time:       {avg_final_decrypt * 1000:.6f} ms")
        print(f"Authentication Latency (Server-side): {avg_final_latency * 1000:.6f} ms")
        print(f"Storage Overhead (Keys/Context):      {storage_kb:.2f} KB")
        print(f"Authentication Throughput (E2E):      {avg_final_auth_tp:.2f} devices/sec\n")

        final_comparison_data = [avg_final_latency, avg_final_auth_tp]

    # -----------------------------
    # COMPARISON WITH EXISTING SCHEMES (Using results from 100 devices)
    # -----------------------------
    compare_with_existing_schemes(
        final_comparison_data[0],
        final_comparison_data[1],
        0 # Not using batch throughput for comparison anymore
    )


# ---------------------------------------------------
# COMPARATIVE RESULTS (FROM PAPERS)
# ---------------------------------------------------

def compare_with_existing_schemes(our_latency, our_auth_tp, our_batch_tp):
    print("\n=== Comparative Performance (at 100 Devices) ===\n")

    comparison = {
        "Base Paper (Lattice Group Auth)": {
            "Latency_ms": 29.25,
            "Auth_TP": round(1 / 0.02925, 2)
        },
        "PQCAIE (IoT E-Health)": {
            "Latency_ms": 43.00,
            "Auth_TP": round(1 / 0.043, 2)
        },
        "PQ Identity-Based Signature": {
            "Latency_ms": 20.00,
            "Auth_TP": round(1 / 0.020, 2)
        },
        "Lightweight PQ Lattice Auth": {
            "Latency_ms": 35.00,
            "Auth_TP": round(1 / 0.035, 2)
        },
        "Ours (BFV Batch Authentication)": {
            "Latency_ms": round(our_latency * 1000, 2),
            "Auth_TP": round(our_auth_tp, 2)
        }
    }

    for scheme, values in comparison.items():
        print(f"{scheme}:")
        print(f"  Auth Latency (Server): {values['Latency_ms']} ms")
        print(f"  Auth Throughput (E2E): {values['Auth_TP']} dev/s\n")


# ---------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------

if __name__ == "__main__":
    main()
