import numpy as np
from backend.model_loader import load_model_and_scaler


# Attack label mapping (same as your dashboard)
LABEL_MAP = {
    0: "DoS",
    1: "Probe",
    2: "R2L",
    3: "U2R"
}


def predict_attack(features_array):
    """
    features_array: numpy array shape (n_samples, 41)
    Returns: list of attack labels (string)
    """

    # Load model + scaler from backend
    model, scaler = load_model_and_scaler()

    
    
    import pandas as pd

    # Convert numpy → DataFrame with feature names
    feature_names = [f"f{i}" for i in range(1, 42)]
    features_df = pd.DataFrame(features_array, columns=feature_names)

    scaled = scaler.transform(features_df)


    # Predict numeric classes
    preds = model.predict(scaled)

    # Convert numeric → attack name
    attack_labels = [LABEL_MAP.get(int(p), "Unknown") for p in preds]

    return attack_labels
