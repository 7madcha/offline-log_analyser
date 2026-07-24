"""Reusable source-IP and destination-port traffic summaries."""

from __future__ import annotations

import pandas as pd

COMMON_PORTS = {20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP alternative"}


def _prepared(logs: pd.DataFrame) -> pd.DataFrame:
    data = logs.copy(deep=True) if logs is not None else pd.DataFrame()
    for name in ("bytes_sent", "bytes_received"):
        data[name] = pd.to_numeric(data[name], errors="coerce").fillna(0) if name in data else 0
    data["action"] = data["action"].astype(str).str.upper() if "action" in data else ""
    data["allowed"] = data["action"].eq("ALLOW").astype(int)
    data["blocked"] = data["action"].eq("BLOCK").astype(int)
    return data


def top_source_ips(logs: pd.DataFrame, alerts: pd.DataFrame | None = None, incidents: pd.DataFrame | None = None, top_n: int = 10) -> pd.DataFrame:
    """Rank source IPs by event count without changing the inputs."""
    data = _prepared(logs)
    if data.empty or "src_ip" not in data:
        return pd.DataFrame(columns=["src_ip", "total_events", "allowed_events", "blocked_events", "blocked_ratio", "unique_dst_ips", "unique_dst_ports", "bytes_sent_total", "bytes_received_total", "alert_count", "highest_incident_risk_score"])
    for col in ("dst_ip", "dst_port"):
        if col not in data: data[col] = pd.NA
    result = data.groupby("src_ip").agg(total_events=("src_ip", "size"), allowed_events=("allowed", "sum"), blocked_events=("blocked", "sum"), unique_dst_ips=("dst_ip", "nunique"), unique_dst_ports=("dst_port", "nunique"), bytes_sent_total=("bytes_sent", "sum"), bytes_received_total=("bytes_received", "sum")).reset_index()
    result["blocked_ratio"] = result["blocked_events"] / result["total_events"].replace(0, 1)
    alert_counts = alerts.groupby("src_ip").size() if alerts is not None and not alerts.empty and "src_ip" in alerts else pd.Series(dtype=int)
    risks = incidents.groupby("src_ip")["risk_score"].max() if incidents is not None and not incidents.empty and {"src_ip", "risk_score"}.issubset(incidents.columns) else pd.Series(dtype=float)
    result["alert_count"] = result["src_ip"].map(alert_counts).fillna(0).astype(int)
    result["highest_incident_risk_score"] = result["src_ip"].map(risks).fillna(0)
    return result.sort_values(["total_events", "src_ip"], ascending=[False, True]).head(max(1, int(top_n))).reset_index(drop=True)


def top_destination_ports(logs: pd.DataFrame, top_n: int = 10) -> pd.DataFrame:
    """Rank destination ports and attach a safe common-service label."""
    data = _prepared(logs)
    if data.empty or "dst_port" not in data:
        return pd.DataFrame(columns=["dst_port", "service_name", "total_events", "unique_source_ips", "unique_destination_ips", "allowed_events", "blocked_events", "blocked_ratio", "bytes_sent_total", "bytes_received_total"])
    for col in ("src_ip", "dst_ip"):
        if col not in data: data[col] = pd.NA
    result = data.groupby("dst_port").agg(total_events=("dst_port", "size"), unique_source_ips=("src_ip", "nunique"), unique_destination_ips=("dst_ip", "nunique"), allowed_events=("allowed", "sum"), blocked_events=("blocked", "sum"), bytes_sent_total=("bytes_sent", "sum"), bytes_received_total=("bytes_received", "sum")).reset_index()
    result["blocked_ratio"] = result["blocked_events"] / result["total_events"].replace(0, 1)
    result["service_name"] = pd.to_numeric(result["dst_port"], errors="coerce").map(COMMON_PORTS).fillna("Unknown")
    columns = ["dst_port", "service_name", "total_events", "unique_source_ips", "unique_destination_ips", "allowed_events", "blocked_events", "blocked_ratio", "bytes_sent_total", "bytes_received_total"]
    return result.sort_values(["total_events", "dst_port"], ascending=[False, True]).head(max(1, int(top_n)))[columns].reset_index(drop=True)
