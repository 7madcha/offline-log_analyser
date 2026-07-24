from pathlib import Path

from main import run_pipeline
from src.generate_logs import generate_firewall_logs
import yaml
import pandas as pd


def test_cli_creates_new_exports(tmp_path):
    input_path = tmp_path / "logs.csv"
    generate_firewall_logs(rows=100, seed=7).to_csv(input_path, index=False)
    result = run_pipeline(str(input_path), output_root=str(tmp_path / "outputs"))
    assert Path(result["anomalies_path"]).exists()
    assert Path(result["sources_path"]).exists()
    assert Path(result["ports_path"]).exists()


def test_cli_disabled_ai_exports_empty_anomaly_table(tmp_path):
    input_path = tmp_path / "logs.csv"
    generate_firewall_logs(rows=25, seed=8).to_csv(input_path, index=False)
    config = yaml.safe_load(Path("config.yaml").read_text(encoding="utf-8"))
    config["ai_detection"]["enabled"] = False
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    result = run_pipeline(str(input_path), str(config_path), str(tmp_path / "outputs"))
    exported = pd.read_csv(result["anomalies_path"])
    assert exported.empty
    assert result["ai_anomalies"] == 0
