import pandas as pd
import numpy as np
import time

from backend.predictor import predict_attack
from backend.ips_engine import process_attack


def stream_csv(file_path, delay=0.2):
    """
    Generator that streams CSV row-by-row like live traffic.
    delay: seconds between rows (controls speed)
    """

    df = pd.read_csv(file_path)

    # Ensure only feature columns (no Label)
    if "Label" in df.columns:
        df = df.drop(columns=["Label"])

    for _, row in df.iterrows():

        # Convert row → numpy shape (1, 41)
        features = np.array(row.values, dtype=float).reshape(1, -1)

        # Predict attack
        attack_label = predict_attack(features)[0]

        # IPS decision
        action = process_attack(attack_label)

        # Return result
        yield {
            "attack": attack_label,
            "action": action
        }

        time.sleep(delay)
