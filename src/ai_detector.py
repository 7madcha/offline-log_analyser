"""Offline Isolation Forest anomaly detector."""

from __future__ import annotations

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

from src.ai_explanation import explain_anomalies
from src.ai_features import MODEL_FEATURES


def detect_ai_anomalies(features: pd.DataFrame, config: dict | None = None) -> pd.DataFrame:
    """Fit Isolation Forest and return windows ranked by a normalized 0-100 score."""
    cfg = config or {}
    output = features.copy(deep=True)
    output["ai_anomaly_score"] = pd.Series(dtype=float)
    output["raw_anomaly_score"] = pd.Series(dtype=float)
    output["isolation_forest_prediction"] = pd.Series(dtype=int)
    output["is_ai_anomaly"] = pd.Series(dtype=bool)
    output["ai_explanation"] = pd.Series(dtype=str)
    if len(features) < 5 or not set(MODEL_FEATURES).issubset(features.columns):
        output.attrs["warning"] = "At least five complete behavioral windows are needed for AI detection."
        return output
    matrix = features[MODEL_FEATURES].apply(pd.to_numeric, errors="coerce").fillna(0)
    scaled = RobustScaler().fit_transform(matrix)
    model = IsolationForest(
        n_estimators=int(cfg.get("n_estimators", 200)),
        contamination=float(cfg.get("contamination", 0.02)),
        random_state=int(cfg.get("random_state", 42)),
    )
    normal_mask = features.get("has_reliable_normal_label", pd.Series(False, index=features.index)).fillna(False).astype(bool)
    training_matrix = scaled[normal_mask.to_numpy()] if int(normal_mask.sum()) >= 5 else scaled
    model.fit(training_matrix)
    raw = -model.score_samples(scaled)
    predictions = model.predict(scaled)
    low, high = float(raw.min()), float(raw.max())
    scores = ((raw - low) / (high - low) * 100) if high > low else raw * 0
    output["ai_anomaly_score"] = pd.Series(scores, index=output.index).round(2).clip(0, 100)
    output["raw_anomaly_score"] = pd.Series(raw, index=output.index)
    output["isolation_forest_prediction"] = pd.Series(predictions, index=output.index).astype(int)
    threshold = float(cfg.get("anomaly_threshold", 60))
    output["is_ai_anomaly"] = output["isolation_forest_prediction"].eq(-1) & output["ai_anomaly_score"].ge(threshold)
    output["ai_explanation"] = explain_anomalies(features)
    if int(normal_mask.sum()) >= 5:
        output.attrs["warning"] = f"The model baseline used {int(normal_mask.sum())} windows labelled as normal; human validation is still required."
        output.attrs["training_strategy"] = "labelled_normal_windows"
    else:
        output.attrs["warning"] = "No sufficiently large reliable normal-labelled baseline was available. The model learned from the currently loaded dataset; human validation is required."
        output.attrs["training_strategy"] = "all_loaded_windows"
    return output.sort_values("ai_anomaly_score", ascending=False).reset_index(drop=True)
