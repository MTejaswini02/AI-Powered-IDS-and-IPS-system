import pandas as pd
import numpy as np

np.random.seed(42)

features = [f"f{i}" for i in range(1, 42)]

def generate_csv(filename, rows, pattern):
    data = np.random.rand(rows, 41) * 100

    if pattern == "DoS":
        data[:, :10] += 150   # heavy burst → DoS
    elif pattern == "Probe":
        data[:, 10:20] += 200  # scanning → Probe
    elif pattern == "Clean":
        data = np.random.rand(rows, 41) * 10  # low traffic
    elif pattern == "Mixed":
        data[:, :5] += 100
        data[:, 20:30] += 50  # mix of DoS + intrusion
    elif pattern == "Unseen":
        data *= 250  # anomaly-like distribution

    df = pd.DataFrame(data, columns=features)
    df.to_csv(filename, index=False)
    print(f"✅ Saved: {filename}")

# Generate all 5 files
generate_csv("test_dos_high.csv", 50, "DoS")
generate_csv("test_probe_medium.csv", 50, "Probe")
generate_csv("test_clean_low.csv", 50, "Clean")
generate_csv("test_random_mixed.csv", 50, "Mixed")
generate_csv("test_unseen_attack.csv", 50, "Unseen")

print("\n🎯 All testing files successfully generated!")
