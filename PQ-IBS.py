import pqcrypto.sign.falcon_512 as falcon512
import time
import numpy as np

def run(devices):
    start_total = time.perf_counter()

    sigs = []
    # Key extraction and signing
    for i in range(devices):
        pk, sk = falcon512.generate_keypair()
        sig = falcon512.sign(sk, b"identity-auth")
        sigs.append((sig, pk))

    # Verification (Server-side)
    start_server = time.perf_counter()
    for sig, pk in sigs:
        falcon512.verify(pk, sig, b"identity-auth")
    end_server = time.perf_counter()

    end_total = time.perf_counter()

    latency_ms = (end_server - start_server) * 1000
    comp_cost_ms = (end_total - start_total) * 1000
    throughput = devices / (comp_cost_ms / 1000)

    return latency_ms, throughput, comp_cost_ms

if __name__ == "__main__":
    NUM_RUNS = 10
    DEVICE_COUNTS = [20,40,60,80, 100]
    
    # Falcon-512 sizes (approximate): PK=897B, Sig=666B -> Total=1563B
    FALCON_OVERHEAD_BYTES = 897 + 666
    # Storage Overhead (Keys): PK=897B, SK=1281B
    FALCON_STORAGE_BYTES = 897 + 1281

    print("\n=== PQ Identity-Based Signature (Falcon) Simulation ===\n")
    print(
        f"{'Devices':<10} | "
        f"{'Auth Latency (ms)':<18} | "
        f"{'Comp. Cost (ms)':<16} | "
        f"{'Comm. Cost (KB)':<16} | "
        f"{'Storage (KB)':<16} | "
        f"{'Throughput (Dev/s)':<18}"
    )
    print("-" * 115)
    
    for k in DEVICE_COUNTS:
        latencies = []
        throughputs = []
        comp_costs = []
        for _ in range(NUM_RUNS):
            lat, thr, comp = run(k)
            latencies.append(lat)
            throughputs.append(thr)
            comp_costs.append(comp)
            
        avg_lat = np.mean(latencies)
        avg_thr = np.mean(throughputs)
        avg_comp = np.mean(comp_costs)
        comm_cost_kb = (FALCON_OVERHEAD_BYTES * k) / 1024

        storage_kb = FALCON_STORAGE_BYTES / 1024
        print(
            f"{k:<10} | "
            f"{avg_lat:<18.2f} | "
            f"{avg_comp:<16.2f} | "
            f"{comm_cost_kb:<16.2f} | "
            f"{storage_kb:<16.2f} | "
            f"{avg_thr:<18.2f}"
        )
    print("-" * 115)
