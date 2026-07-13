"""Command-line analysis pipeline for Offline Log Forensic Analyzer."""

from __future__ import annotations

import argparse
from pathlib import Path

from src.cleaner import clean_logs
from src.correlator import correlate_alerts
from src.detectors import run_all_detectors
from src.exporter import export_alerts, export_cleaned_data, export_incidents
from src.loader import load_logs
from src.utils import load_config
from src.validator import validate_columns, validate_dataset


def run_pipeline(input_path: str, config_path: str = "config.yaml", output_root: str = "outputs") -> dict[str, object]:
    """Execute the complete offline analysis pipeline."""
    config = load_config(config_path)
    raw_df = load_logs(input_path)
    validate_dataset(raw_df)
    validate_columns(raw_df, config["required_columns"])

    cleaned_df, cleaning_summary = clean_logs(raw_df)
    validate_dataset(cleaned_df)

    alerts = run_all_detectors(cleaned_df, config)
    incidents = correlate_alerts(alerts, config)

    cleaned_path = export_cleaned_data(cleaned_df, "data/processed/cleaned_logs.csv")
    alerts_path = export_alerts(alerts, output_root)
    incidents_path = export_incidents(incidents, output_root)

    return {
        "input_rows": len(raw_df),
        "cleaned_rows": len(cleaned_df),
        "alerts_detected": len(alerts),
        "incidents_created": len(incidents),
        "cleaning_summary": cleaning_summary,
        "cleaned_path": cleaned_path,
        "alerts_path": alerts_path,
        "incidents_path": incidents_path,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze offline firewall logs.")
    parser.add_argument("--input", required=True, help="Input firewall log CSV path.")
    parser.add_argument("--config", default="config.yaml", help="Configuration YAML path.")
    parser.add_argument("--output", default="outputs", help="Output root directory.")
    args = parser.parse_args()

    result = run_pipeline(args.input, args.config, args.output)
    print("Analysis completed")
    print()
    print(f"Input rows: {result['input_rows']:,}")
    print(f"Cleaned rows: {result['cleaned_rows']:,}")
    print(f"Alerts detected: {result['alerts_detected']:,}")
    print(f"Incidents created: {result['incidents_created']:,}")
    print()
    print("Alerts file:")
    print(result["alerts_path"])
    print()
    print("Incidents file:")
    print(result["incidents_path"])


if __name__ == "__main__":
    main()
