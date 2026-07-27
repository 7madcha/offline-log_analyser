"""Cleaning and normalization for firewall logs."""

from __future__ import annotations

import ipaddress
from typing import Any

import pandas as pd

ACTION_MAP = {
    "ALLOW": "ALLOW",
    "ALLOWED": "ALLOW",
    "ACCEPT": "ALLOW",
    "ACCEPTED": "ALLOW",
    "PERMIT": "ALLOW",
    "PASS": "ALLOW",
    "BLOCK": "BLOCK",
    "BLOCKED": "BLOCK",
    "DENY": "BLOCK",
    "DENIED": "BLOCK",
    "DROP": "BLOCK",
    "DROPPED": "BLOCK",
    "REJECT": "BLOCK",
    "REJECTED": "BLOCK",
}


def _valid_ipv4(value: Any) -> bool:
    try:
        ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return True


def _valid_port(series: pd.Series) -> pd.Series:
    return series.between(0, 65535, inclusive="both")


def clean_logs(df: pd.DataFrame, available_columns: set[str] | None = None) -> tuple[pd.DataFrame, dict[str, int]]:
    """Return a cleaned copy of firewall logs and a cleaning summary."""
    working = df.copy(deep=True)
    available = set(available_columns or working.attrs.get("available_columns", working.columns))
    original_count = len(working)
    duplicate_count = int(working.duplicated().sum())
    missing_values = int(working.isna().sum().sum())

    working = working.drop_duplicates().copy()
    try:
        working["timestamp"] = pd.to_datetime(working["timestamp"], format="mixed", errors="coerce")
    except TypeError:
        working["timestamp"] = pd.to_datetime(working["timestamp"], errors="coerce")
    invalid_timestamps = int(working["timestamp"].isna().sum())

    for column in ("src_ip", "dst_ip", "protocol", "action"):
        working[column] = working[column].astype(str).str.strip()

    working["protocol"] = working["protocol"].str.upper()
    working["action"] = working["action"].str.upper().map(lambda value: ACTION_MAP.get(value, value))

    for column in ("src_port", "dst_port", "bytes_sent", "bytes_received"):
        working[column] = pd.to_numeric(working[column], errors="coerce")

    invalid_src_ports = ~_valid_port(working["src_port"]) | working["src_port"].isna()
    invalid_dst_ports = ~_valid_port(working["dst_port"]) | working["dst_port"].isna()
    invalid_ports_mask = (invalid_src_ports if "src_port" in available else False) | (invalid_dst_ports if "dst_port" in available else False)
    invalid_ports = int(pd.Series(invalid_ports_mask, index=working.index).sum())
    invalid_src_ips = ~working["src_ip"].map(_valid_ipv4)
    invalid_dst_ips = ~working["dst_ip"].map(_valid_ipv4)
    invalid_ips_mask = invalid_src_ips | (invalid_dst_ips if "dst_ip" in available else False)
    invalid_ips = int(pd.Series(invalid_ips_mask, index=working.index).sum())

    valid_dst_ips = ~invalid_dst_ips if "dst_ip" in available else pd.Series(True, index=working.index)
    valid_src_ports = ~invalid_src_ports if "src_port" in available else pd.Series(True, index=working.index)
    valid_dst_ports = ~invalid_dst_ports if "dst_port" in available else pd.Series(True, index=working.index)
    valid_bytes_sent = ~(working["bytes_sent"].isna() | (working["bytes_sent"] < 0)) if "bytes_sent" in available else pd.Series(True, index=working.index)
    valid_bytes_received = ~(working["bytes_received"].isna() | (working["bytes_received"] < 0)) if "bytes_received" in available else pd.Series(True, index=working.index)
    valid_mask = (
        working["timestamp"].notna()
        & ~invalid_src_ips
        & valid_dst_ips
        & valid_src_ports
        & valid_dst_ports
        & valid_bytes_sent
        & valid_bytes_received
    )
    cleaned = working.loc[valid_mask].copy()
    if "src_port" in available:
        cleaned["src_port"] = cleaned["src_port"].astype(int)
    if "dst_port" in available:
        cleaned["dst_port"] = cleaned["dst_port"].astype(int)
    cleaned["bytes_sent"] = cleaned["bytes_sent"].astype(int)
    cleaned["bytes_received"] = cleaned["bytes_received"].astype(int)
    cleaned = cleaned.sort_values("timestamp").reset_index(drop=True)
    cleaned.attrs["available_columns"] = list(available)

    summary = {
        "original_row_count": int(original_count),
        "final_row_count": int(len(cleaned)),
        "duplicate_rows_removed": duplicate_count,
        "invalid_timestamps": invalid_timestamps,
        "invalid_ip_addresses": invalid_ips,
        "invalid_ports": invalid_ports,
        "missing_values": missing_values,
    }
    return cleaned, summary
