"""Standalone, read-only comparison around the existing analysis pipeline."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import pandas as pd

from src.ai_detector import detect_ai_anomalies
from src.ai_features import build_behavioral_features
from src.loader import load_logs
from src.utils import load_config

SUPPORTED_SUFFIXES = {".csv", ".json", ".jsonl", ".ndjson"}
SEVERITY_ORDER = ("Low", "Medium", "High", "Critical")


@dataclass
class DatasetAnalysis:
    """One file analyzed independently by the existing analyzer."""

    path: Path
    raw_event_count: int
    logs: pd.DataFrame
    alerts: pd.DataFrame
    incidents: pd.DataFrame
    anomalies: pd.DataFrame
    cleaning_summary: dict[str, int]
    period_start: pd.Timestamp | None
    period_end: pd.Timestamp | None

    @property
    def label(self) -> str:
        return self.path.name

    @property
    def cleaned_event_count(self) -> int:
        return len(self.logs)


def _validate_paths(file_a: str | Path, file_b: str | Path) -> tuple[Path, Path]:
    paths = (Path(file_a), Path(file_b))
    for index, path in enumerate(paths, start=1):
        if not path.exists():
            raise FileNotFoundError(f"File {index} does not exist: {path}")
        if not path.is_file():
            raise ValueError(f"File {index} is not a file: {path}")
        if path.suffix.lower() not in SUPPORTED_SUFFIXES:
            raise ValueError(f"File {index} has an unsupported format: {path.suffix or '(none)'}. Use CSV, JSON, JSONL, or NDJSON.")
    if paths[0].suffix.lower() != paths[1].suffix.lower():
        raise ValueError("Both comparison inputs must use the same supported file type.")
    return paths


def _validate_input_names(label_a: str, label_b: str) -> None:
    """Apply the standalone comparator's file-type rules to uploaded names."""
    suffixes = (Path(label_a).suffix.lower(), Path(label_b).suffix.lower())
    for index, suffix in enumerate(suffixes, start=1):
        if suffix not in SUPPORTED_SUFFIXES:
            raise ValueError(f"File {index} has an unsupported format: {suffix or '(none)'}. Use CSV, JSON, JSONL, or NDJSON.")
    if suffixes[0] != suffixes[1]:
        raise ValueError("Both comparison inputs must use the same supported file type.")


def _detect_anomalies(logs: pd.DataFrame, config_path: str | Path) -> pd.DataFrame:
    config = load_config(config_path)
    ai = config["ai_detection"]
    if not ai.get("enabled", True):
        return pd.DataFrame()
    hours = config["working_hours"]
    features = build_behavioral_features(logs, ai["window_minutes"], hours["start_hour"], hours["end_hour"])
    results = detect_ai_anomalies(features, ai)
    if results.empty or "is_ai_anomaly" not in results:
        return pd.DataFrame(columns=results.columns)
    return results[results["is_ai_anomaly"].fillna(False).astype(bool)].copy()


def analyze_comparison_file(
    path: str | Path,
    *,
    config_path: str | Path = "config.yaml",
    baseline_enabled: bool = False,
) -> DatasetAnalysis:
    """Analyze one input without changing or exporting existing application state."""
    input_path = Path(path)
    raw = load_logs(input_path)
    return analyze_comparison_dataframe(
        raw,
        input_path.name,
        config_path=config_path,
        baseline_enabled=baseline_enabled,
    )


def analyze_comparison_dataframe(
    raw: pd.DataFrame,
    label: str,
    *,
    config_path: str | Path = "config.yaml",
    baseline_enabled: bool = False,
    analyzer: Callable[..., tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, dict[str, int]]] | None = None,
) -> DatasetAnalysis:
    """Analyze one already-loaded dashboard input without writing a temp file."""
    if analyzer is None:
        # Lazy import keeps the standalone CLI behavior while allowing the
        # running dashboard to pass its already-loaded pipeline directly.
        from app import analyze_dataframe as analyzer
    logs, alerts, incidents, cleaning = analyzer(raw, str(config_path), baseline_enabled)
    timestamps = pd.to_datetime(logs["timestamp"], errors="coerce") if "timestamp" in logs else pd.Series(dtype="datetime64[ns]")
    return DatasetAnalysis(
        path=Path(label),
        raw_event_count=len(raw),
        logs=logs,
        alerts=alerts,
        incidents=incidents,
        anomalies=_detect_anomalies(logs, config_path),
        cleaning_summary=cleaning,
        period_start=timestamps.min() if not timestamps.empty else None,
        period_end=timestamps.max() if not timestamps.empty else None,
    )


def _metric_row(name: str, value_a: float, value_b: float) -> dict[str, float | str | None]:
    difference = value_b - value_a
    percentage = (difference / value_a * 100) if value_a else None
    return {"metric": name, "file_a": value_a, "file_b": value_b, "difference": difference, "percentage_change": percentage}


def _overview(a: DatasetAnalysis, b: DatasetAnalysis) -> pd.DataFrame:
    return pd.DataFrame([
        _metric_row("Raw events", a.raw_event_count, b.raw_event_count),
        _metric_row("Cleaned events", a.cleaned_event_count, b.cleaned_event_count),
        _metric_row("Alerts", len(a.alerts), len(b.alerts)),
        _metric_row("Incidents", len(a.incidents), len(b.incidents)),
        _metric_row("AI anomalies", len(a.anomalies), len(b.anomalies)),
    ])


def alerts_per_1000(alert_count: int, event_count: int) -> float:
    """Return a size-normalized alert rate without dividing by zero."""
    return (alert_count / event_count * 1000) if event_count else 0.0


def _alert_type_comparison(a: DatasetAnalysis, b: DatasetAnalysis) -> pd.DataFrame:
    def counts(alerts: pd.DataFrame, column: str) -> pd.DataFrame:
        if alerts.empty or "alert_type" not in alerts:
            return pd.DataFrame(columns=["alert_type", column])
        return alerts.groupby("alert_type").size().reset_index(name=column)

    result = counts(a.alerts, "file_a").merge(counts(b.alerts, "file_b"), on="alert_type", how="outer").fillna(0)
    result[["file_a", "file_b"]] = result[["file_a", "file_b"]].astype(int)
    result["difference"] = result["file_b"] - result["file_a"]
    result["status"] = result.apply(
        lambda row: "newly appearing" if row["file_a"] == 0 and row["file_b"] > 0 else
        "disappeared" if row["file_a"] > 0 and row["file_b"] == 0 else
        "increased" if row["difference"] > 0 else "decreased" if row["difference"] < 0 else "unchanged",
        axis=1,
    )
    return result.sort_values(["difference", "alert_type"], ascending=[False, True]).reset_index(drop=True)


def _severity_comparison(a: DatasetAnalysis, b: DatasetAnalysis) -> pd.DataFrame:
    rows = []
    for severity in SEVERITY_ORDER:
        count_a = int((a.incidents.get("severity", pd.Series(dtype=str)) == severity).sum())
        count_b = int((b.incidents.get("severity", pd.Series(dtype=str)) == severity).sum())
        rows.append({"severity": severity, "file_a": count_a, "file_b": count_b, "difference": count_b - count_a})
    return pd.DataFrame(rows)


def _incident_metrics(a: DatasetAnalysis, b: DatasetAnalysis) -> pd.DataFrame:
    def score(incidents: pd.DataFrame, aggregate: str) -> float:
        if incidents.empty or "risk_score" not in incidents:
            return 0.0
        values = pd.to_numeric(incidents["risk_score"], errors="coerce").fillna(0)
        return float(values.max() if aggregate == "max" else values.mean())

    return pd.DataFrame([
        _metric_row("Incident count", len(a.incidents), len(b.incidents)),
        _metric_row("Highest incident risk", score(a.incidents, "max"), score(b.incidents, "max")),
        _metric_row("Average incident risk", score(a.incidents, "mean"), score(b.incidents, "mean")),
    ])


def _incident_categories(incidents: pd.DataFrame) -> set[str]:
    categories: set[str] = set()
    if incidents.empty or "alert_types" not in incidents:
        return categories
    for value in incidents["alert_types"].dropna().astype(str):
        categories.update(item.strip() for item in value.split(",") if item.strip())
    return categories


def _string_values(frame: pd.DataFrame, column: str) -> set[str]:
    if frame.empty or column not in frame:
        return set()
    return set(frame[column].dropna().astype(str))


def _related_alert_count(analysis: DatasetAnalysis, category: str, value: str) -> int:
    alerts = analysis.alerts
    if alerts.empty:
        return 0
    if category == "source_ip" and "src_ip" in alerts:
        return int(alerts["src_ip"].astype(str).eq(value).sum())
    column = "affected_destinations" if category == "destination_ip" else "affected_ports"
    if column not in alerts:
        return 0
    return int(alerts[column].fillna("").astype(str).apply(lambda text: value in {part.strip() for part in text.split(",")}).sum())


def _observable_rows(analysis: DatasetAnalysis, category: str, column: str, values: set[str], status: str) -> list[dict[str, Any]]:
    rows = []
    for value in values:
        event_count = int(analysis.logs[column].dropna().astype(str).eq(value).sum()) if column in analysis.logs else 0
        alert_count = _related_alert_count(analysis, category, value)
        highest_risk = 0
        if category == "source_ip" and not analysis.incidents.empty and {"src_ip", "risk_score"}.issubset(analysis.incidents):
            matches = analysis.incidents[analysis.incidents["src_ip"].astype(str) == value]
            highest_risk = int(pd.to_numeric(matches["risk_score"], errors="coerce").max()) if not matches.empty else 0
        rows.append({"category": category, "value": value, "status": status, "event_count": event_count, "related_alerts": alert_count, "highest_incident_risk": highest_risk, "priority": highest_risk + alert_count * 20 + min(event_count, 100)})
    return rows


def _observable_comparison(a: DatasetAnalysis, b: DatasetAnalysis) -> tuple[pd.DataFrame, pd.DataFrame]:
    new_rows: list[dict[str, Any]] = []
    removed_rows: list[dict[str, Any]] = []
    for category, column in (("source_ip", "src_ip"), ("destination_ip", "dst_ip"), ("destination_port", "dst_port")):
        values_a, values_b = _string_values(a.logs, column), _string_values(b.logs, column)
        new_rows.extend(_observable_rows(b, category, column, values_b - values_a, "newly observed"))
        removed_rows.extend(_observable_rows(a, category, column, values_a - values_b, "disappeared"))
    columns = ["category", "value", "status", "event_count", "related_alerts", "highest_incident_risk", "priority"]
    new = pd.DataFrame(new_rows, columns=columns).sort_values(["priority", "category", "value"], ascending=[False, True, True]).reset_index(drop=True)
    removed = pd.DataFrame(removed_rows, columns=columns).sort_values(["priority", "category", "value"], ascending=[False, True, True]).reset_index(drop=True)
    return new, removed


def _traffic_metrics(a: DatasetAnalysis, b: DatasetAnalysis) -> pd.DataFrame:
    def total(frame: pd.DataFrame, column: str) -> float:
        return float(pd.to_numeric(frame[column], errors="coerce").fillna(0).sum()) if column in frame else 0.0

    def action_count(frame: pd.DataFrame, action: str) -> int:
        return int(frame["action"].astype(str).str.upper().eq(action).sum()) if "action" in frame else 0

    blocked_a, blocked_b = action_count(a.logs, "BLOCK"), action_count(b.logs, "BLOCK")
    rows = [
        _metric_row("Blocked events", blocked_a, blocked_b),
        _metric_row("Allowed events", action_count(a.logs, "ALLOW"), action_count(b.logs, "ALLOW")),
        _metric_row("Block ratio", blocked_a / a.cleaned_event_count if a.cleaned_event_count else 0, blocked_b / b.cleaned_event_count if b.cleaned_event_count else 0),
        _metric_row("Bytes sent", total(a.logs, "bytes_sent"), total(b.logs, "bytes_sent")),
        _metric_row("Bytes received", total(a.logs, "bytes_received"), total(b.logs, "bytes_received")),
    ]
    return pd.DataFrame(rows)


def _activity_changes(a: DatasetAnalysis, b: DatasetAnalysis) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for category, column in (("source_ip", "src_ip"), ("destination_ip", "dst_ip"), ("destination_port", "dst_port"), ("protocol", "protocol"), ("action", "action")):
        counts_a = a.logs[column].dropna().astype(str).value_counts() if column in a.logs else pd.Series(dtype=int)
        counts_b = b.logs[column].dropna().astype(str).value_counts() if column in b.logs else pd.Series(dtype=int)
        for value in sorted(set(counts_a.index) | set(counts_b.index)):
            value_a, value_b = int(counts_a.get(value, 0)), int(counts_b.get(value, 0))
            rows.append({"category": category, "value": value, "file_a": value_a, "file_b": value_b, "difference": value_b - value_a})
    columns = ["category", "value", "file_a", "file_b", "difference"]
    return pd.DataFrame(rows, columns=columns).sort_values("difference", key=lambda values: values.abs(), ascending=False).reset_index(drop=True)


def _max_anomaly_score(analysis: DatasetAnalysis) -> float:
    if analysis.anomalies.empty or "ai_anomaly_score" not in analysis.anomalies:
        return 0.0
    return float(pd.to_numeric(analysis.anomalies["ai_anomaly_score"], errors="coerce").fillna(0).max())


def _interpretation(result: dict[str, Any]) -> list[str]:
    a, b = result["file_a"], result["file_b"]
    findings: list[str] = []
    rate = result["alert_rate"]
    if rate["difference"] > 0:
        findings.append(f"Alert rate increased from {rate['file_a']:.2f} to {rate['file_b']:.2f} per 1,000 cleaned events.")
    elif rate["difference"] < 0:
        findings.append(f"Alert rate decreased from {rate['file_a']:.2f} to {rate['file_b']:.2f} per 1,000 cleaned events.")
    severity = result["incident_severities"].set_index("severity")
    for level in ("Critical", "High"):
        if int(severity.loc[level, "file_b"]) > int(severity.loc[level, "file_a"]):
            findings.append(f"{level}-severity incidents increased from {int(severity.loc[level, 'file_a'])} to {int(severity.loc[level, 'file_b'])}.")
    changed_alerts = result["alert_types"]
    for row in changed_alerts[changed_alerts["status"].isin(["newly appearing", "increased"])].head(3).itertuples():
        findings.append(f"{row.alert_type} alerts {row.status}: {row.file_a} in {a.label} and {row.file_b} in {b.label}.")
    suspicious_new = result["new_observables"].query("related_alerts > 0 or highest_incident_risk > 0").head(3)
    for row in suspicious_new.itertuples():
        findings.append(f"Newly observed {row.category.replace('_', ' ')} {row.value} is linked to {row.related_alerts} alert(s) and highest incident risk {row.highest_incident_risk}.")
    if len(b.anomalies) > len(a.anomalies) or _max_anomaly_score(b) > _max_anomaly_score(a):
        findings.append(f"AI anomaly findings changed from {len(a.anomalies)} to {len(b.anomalies)}; highest score changed from {_max_anomaly_score(a):.2f} to {_max_anomaly_score(b):.2f}. Human validation is required.")
    blocked = result["traffic_metrics"].set_index("metric").loc["Block ratio"]
    if blocked["file_b"] > blocked["file_a"]:
        findings.append(f"Blocked traffic ratio increased from {blocked['file_a']:.2%} to {blocked['file_b']:.2%}.")
    return findings or ["No material increase in the calculated suspicious indicators was identified; review the detailed differences for context."]


def compare_files(
    file_a: str | Path,
    file_b: str | Path,
    *,
    config_path: str | Path = "config.yaml",
    baseline_enabled: bool = False,
) -> dict[str, Any]:
    """Analyze exactly two same-type files independently, then compare results."""
    path_a, path_b = _validate_paths(file_a, file_b)
    analysis_a = analyze_comparison_file(path_a, config_path=config_path, baseline_enabled=baseline_enabled)
    analysis_b = analyze_comparison_file(path_b, config_path=config_path, baseline_enabled=baseline_enabled)
    return compare_analyses(analysis_a, analysis_b, baseline_enabled=baseline_enabled)


def compare_dataframes(
    raw_a: pd.DataFrame,
    raw_b: pd.DataFrame,
    label_a: str,
    label_b: str,
    *,
    config_path: str | Path = "config.yaml",
    baseline_enabled: bool = False,
    analyzer: Callable[..., tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, dict[str, int]]] | None = None,
) -> dict[str, Any]:
    """Compare two dashboard uploads in memory using the same analyzer settings."""
    _validate_input_names(label_a, label_b)
    analysis_a = analyze_comparison_dataframe(raw_a, label_a, config_path=config_path, baseline_enabled=baseline_enabled, analyzer=analyzer)
    analysis_b = analyze_comparison_dataframe(raw_b, label_b, config_path=config_path, baseline_enabled=baseline_enabled, analyzer=analyzer)
    return compare_analyses(analysis_a, analysis_b, baseline_enabled=baseline_enabled)


def compare_analyses(
    analysis_a: DatasetAnalysis,
    analysis_b: DatasetAnalysis,
    *,
    baseline_enabled: bool = False,
) -> dict[str, Any]:
    """Build all comparison metrics from two independently analyzed inputs."""
    rate_a = alerts_per_1000(len(analysis_a.alerts), analysis_a.cleaned_event_count)
    rate_b = alerts_per_1000(len(analysis_b.alerts), analysis_b.cleaned_event_count)
    new_observables, removed_observables = _observable_comparison(analysis_a, analysis_b)
    result = {
        "file_a": analysis_a,
        "file_b": analysis_b,
        "baseline_enabled": bool(baseline_enabled),
        "overview": _overview(analysis_a, analysis_b),
        "alert_rate": _metric_row("Alerts per 1,000 cleaned events", rate_a, rate_b),
        "alert_types": _alert_type_comparison(analysis_a, analysis_b),
        "incident_metrics": _incident_metrics(analysis_a, analysis_b),
        "incident_severities": _severity_comparison(analysis_a, analysis_b),
        "new_incident_categories": sorted(_incident_categories(analysis_b.incidents) - _incident_categories(analysis_a.incidents)),
        "new_observables": new_observables,
        "removed_observables": removed_observables,
        "traffic_metrics": _traffic_metrics(analysis_a, analysis_b),
        "activity_changes": _activity_changes(analysis_a, analysis_b),
    }
    result["interpretation"] = _interpretation(result)
    return result
