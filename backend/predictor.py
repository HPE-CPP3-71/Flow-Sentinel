import numpy as np
import pandas as pd

def run_prediction(model, le, feature_cols, row_dict):
    """
    Align the row dict to the saved feature column list, then predict.
    fill_value=0 handles any column in feature_cols that is absent from the
    dict (e.g. near-zero-variance features that ended up in training data).
    """
    X = pd.DataFrame([row_dict]).reindex(columns=feature_cols, fill_value=0)
    X.replace([np.inf, -np.inf], 0, inplace=True)
    X.fillna(0, inplace=True)
    proba   = model.predict_proba(X)[0]
    pred_idx = int(np.argmax(proba))
    label   = le.inverse_transform([pred_idx])[0]
    return label, float(proba[pred_idx])