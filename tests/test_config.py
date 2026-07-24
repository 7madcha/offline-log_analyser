from pathlib import Path

from src.utils import load_config


def test_invalid_ai_and_analytics_config_uses_safe_defaults(tmp_path):
    path = tmp_path / "invalid.yaml"
    path.write_text("ai_detection:\n  window_minutes: bad\n  n_estimators: -1\n  contamination: 0.9\n  random_state: no\n  anomaly_threshold: 200\nanalytics:\n  top_n: 0\nworking_hours:\n  start_hour: 99\n  end_hour: bad\n", encoding="utf-8")
    config = load_config(path)
    assert config["ai_detection"]["window_minutes"] == 5
    assert config["ai_detection"]["n_estimators"] == 200
    assert config["ai_detection"]["contamination"] == 0.02
    assert config["ai_detection"]["random_state"] == 42
    assert config["ai_detection"]["anomaly_threshold"] == 60
    assert config["analytics"]["top_n"] == 10
    assert config["working_hours"] == {"start_hour": 5, "end_hour": 24}
