import pandas as pd

from src.ai_detector import detect_ai_anomalies
from src.ai_features import MODEL_FEATURES


def _features():
    rows = []
    for index in range(20):
        row = {name: 1.0 for name in MODEL_FEATURES}
        row.update(src_ip=f"10.0.0.{index}", window_start=pd.Timestamp("2026-01-01") + pd.Timedelta(minutes=5 * index))
        rows.append(row)
    rows[-1].update(connection_count=1000, unique_dst_ips=500, unique_dst_ports=500, bytes_sent_total=10_000_000)
    return pd.DataFrame(rows)


def test_detector_is_deterministic_ranked_and_bounded():
    config = {"random_state": 42, "n_estimators": 100, "contamination": 0.05, "anomaly_threshold": 60}
    first = detect_ai_anomalies(_features(), config)
    second = detect_ai_anomalies(_features(), config)
    assert {"ai_anomaly_score", "is_ai_anomaly", "ai_explanation"}.issubset(first.columns)
    assert {"raw_anomaly_score", "isolation_forest_prediction"}.issubset(first.columns)
    assert first["ai_anomaly_score"].between(0, 100).all()
    assert first["ai_anomaly_score"].tolist() == second["ai_anomaly_score"].tolist()
    assert first.iloc[0]["src_ip"] == "10.0.0.19"
    assert first.iloc[0]["isolation_forest_prediction"] == -1


def test_detector_handles_too_few_rows():
    result = detect_ai_anomalies(_features().head(2))
    assert result["ai_anomaly_score"].isna().all()
    assert "warning" in result.attrs


def test_detector_uses_reliable_normal_windows_for_training():
    features = _features()
    features["has_reliable_normal_label"] = [True] * 10 + [False] * 10
    result = detect_ai_anomalies(features, {"random_state": 42, "contamination": 0.1})
    assert result.attrs["training_strategy"] == "labelled_normal_windows"
