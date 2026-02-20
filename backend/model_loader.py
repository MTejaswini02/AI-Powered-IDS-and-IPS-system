import joblib
import os

# Paths to model and scaler (relative to main project folder)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODEL_PATH = os.path.join(BASE_DIR, "ids_model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "scaler.pkl")

_model = None
_scaler = None


def load_model_and_scaler():
    """
    Loads ML model and scaler only once.
    Returns (model, scaler)
    """
    global _model, _scaler

    if _model is None or _scaler is None:
        _model = joblib.load(MODEL_PATH)
        _scaler = joblib.load(SCALER_PATH)

    return _model, _scaler
