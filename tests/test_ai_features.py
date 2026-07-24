import pandas as pd

from src.ai_features import build_behavioral_features


def test_five_minute_feature_aggregation_and_empty_handling():
    logs = pd.DataFrame({
        "timestamp": pd.to_datetime(["2026-01-01 10:01:00", "2026-01-01 10:04:00", "2026-01-01 10:06:00"]),
        "src_ip": ["10.0.0.1"] * 3, "dst_ip": ["1.1.1.1", "2.2.2.2", "3.3.3.3"],
        "dst_port": [80, 443, 53], "action": ["ALLOW", "BLOCK", "ALLOW"],
        "protocol": ["TCP", None, "UDP"], "bytes_sent": [10, 20, 30], "bytes_received": [1, 2, 3],
    })
    result = build_behavioral_features(logs)
    assert len(result) == 2
    assert result.iloc[0]["connection_count"] == 2
    assert result.iloc[0]["unique_dst_ports"] == 2
    assert result.iloc[0]["unique_dst_ips"] == 2
    assert result.iloc[0]["blocked_ratio"] == 0.5
    assert result.iloc[0]["bytes_sent_total"] == 30
    assert build_behavioral_features(pd.DataFrame()).empty


def test_missing_optional_values_do_not_divide_by_zero():
    result = build_behavioral_features(pd.DataFrame({"timestamp": ["2026-01-01 10:00:00"], "src_ip": ["x"]}))
    assert result.iloc[0]["blocked_ratio"] == 0
    assert result.iloc[0]["tcp_ratio"] == 0


def test_reliable_normal_labels_are_kept_as_training_metadata_not_features():
    logs = pd.DataFrame({"timestamp": ["2026-01-01 10:00:00"], "src_ip": ["x"], "label": ["normal"]})
    result = build_behavioral_features(logs)
    assert bool(result.iloc[0]["has_reliable_normal_label"])
    assert result.iloc[0]["normal_label_ratio"] == 1
    from src.ai_features import MODEL_FEATURES
    assert "normal_label_ratio" not in MODEL_FEATURES
