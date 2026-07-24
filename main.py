"""Command-line analysis pipeline for Offline Log Forensic Analyzer."""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from src.cleaner import clean_logs
from src.ai_detector import detect_ai_anomalies
from src.ai_features import build_behavioral_features
from src.correlator import correlate_alerts
from src.detectors import run_all_detectors
from src.exporter import export_alerts, export_cleaned_data, export_dataframe, export_incidents
from src.traffic_analytics import top_destination_ports, top_source_ips
from src.loader import load_logs
from src.reporting import export_pdf_report
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
    ai_cfg = config["ai_detection"]
    hours = config["working_hours"]
    features = build_behavioral_features(cleaned_df, ai_cfg["window_minutes"], hours["start_hour"], hours["end_hour"])
    if ai_cfg["enabled"]:
        ai_results = detect_ai_anomalies(features, ai_cfg)
        anomalies = ai_results[ai_results["is_ai_anomaly"]].copy() if "is_ai_anomaly" in ai_results else pd.DataFrame()
    else:
        ai_results = pd.DataFrame()
        anomalies = pd.DataFrame(columns=["src_ip", "window_start", "ai_anomaly_score", "is_ai_anomaly", "ai_explanation"])
    top_n = config["analytics"]["top_n"]
    sources = top_source_ips(cleaned_df, alerts, incidents, top_n)
    ports = top_destination_ports(cleaned_df, top_n)

    cleaned_path = export_cleaned_data(cleaned_df, "data/processed/cleaned_logs.csv")
    alerts_path = export_alerts(alerts, output_root)
    incidents_path = export_incidents(incidents, output_root)
    anomalies_path = export_dataframe(anomalies, Path(output_root) / "ai" / "anomalies.csv")
    sources_path = export_dataframe(sources, Path(output_root) / "analytics" / "top_source_ips.csv")
    ports_path = export_dataframe(ports, Path(output_root) / "analytics" / "top_destination_ports.csv")
    report_path = export_pdf_report(
        cleaned_df,
        alerts,
        incidents,
        Path(output_root) / "reports" / "incident_report.pdf",
        cleaning_summary,
    )

    return {
        "input_rows": len(raw_df),
        "cleaned_rows": len(cleaned_df),
        "alerts_detected": len(alerts),
        "incidents_created": len(incidents),
        "ai_anomalies": len(anomalies),
        "highest_ai_score": float(ai_results["ai_anomaly_score"].max()) if "ai_anomaly_score" in ai_results and not ai_results.empty else 0.0,
        "most_active_source_ip": str(sources.iloc[0]["src_ip"]) if not sources.empty else "None",
        "most_frequent_destination_port": str(ports.iloc[0]["dst_port"]) if not ports.empty else "None",
        "cleaning_summary": cleaning_summary,
        "cleaned_path": cleaned_path,
        "alerts_path": alerts_path,
        "incidents_path": incidents_path,
        "report_path": report_path,
        "anomalies_path": anomalies_path,
        "sources_path": sources_path,
        "ports_path": ports_path,
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
    print(f"AI anomalies: {result['ai_anomalies']:,}")
    print(f"Highest AI anomaly score: {result['highest_ai_score']:.2f}")
    print(f"Most active source IP: {result['most_active_source_ip']}")
    print(f"Most frequently contacted destination port: {result['most_frequent_destination_port']}")
    print()
    print("Alerts file:")
    print(result["alerts_path"])
    print()
    print("Incidents file:")
    print(result["incidents_path"])
    print()
    print("PDF report:")
    print(result["report_path"])


if __name__ == "__main__":
    main()
