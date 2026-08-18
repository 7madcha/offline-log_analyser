"""Standalone command for comparing two local firewall-log files."""

from __future__ import annotations

import argparse
from pathlib import Path

from src.comparison import compare_files
from src.comparison_reporting import write_comparison_report


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare two firewall-log files using the existing offline analyzer.")
    parser.add_argument("file_a", help="First CSV, JSON, JSONL, or NDJSON log file.")
    parser.add_argument("file_b", help="Second file of the same supported type.")
    parser.add_argument("--config", default="config.yaml", help="Existing analyzer configuration file.")
    parser.add_argument("--baseline", action="store_true", help="Use the existing per-asset baseline mode for both files.")
    parser.add_argument("--output", default="outputs/comparison/comparison_report.html", help="Local comparison report path.")
    args = parser.parse_args()

    try:
        result = compare_files(args.file_a, args.file_b, config_path=args.config, baseline_enabled=args.baseline)
        report_path = write_comparison_report(result, args.output)
    except (FileNotFoundError, ValueError) as exc:
        parser.error(str(exc))
    print(f"Comparison completed: {Path(args.file_a).name} vs {Path(args.file_b).name}")
    print(f"Baseline: {'ON' if result['baseline_enabled'] else 'OFF'} (same setting for both files)")
    print(result["overview"].to_string(index=False))
    print()
    print("What became more suspicious?")
    for finding in result["interpretation"]:
        print(f"- {finding}")
    print()
    print(f"Local HTML report: {report_path}")


if __name__ == "__main__":
    main()
