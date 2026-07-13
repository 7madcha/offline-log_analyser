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


def clean_logs(df: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, int]]:
    """Return a cleaned copy of firewall logs and a cleaning summary."""
    working = df.copy(deep=True)
    original_count = len(working)
    duplicate_count = int(working.duplicated().sum())
    missing_values = int(working.isna().sum().sum())

    working = working.drop_duplicates().copy()
    working["timestamp"] = pd.to_datetime(working["timestamp"], format="%Y-%m-%d %H:%M:%S", errors="coerce")
    invalid_timestamps = int(working["timestamp"].isna().sum())

    for column in ("src_ip", "dst_ip", "protocol", "action"):
        working[column] = working[column].astype(str).str.strip()

    working["protocol"] = working["protocol"].str.upper()
    working["action"] = working["action"].str.upper().map(lambda value: ACTION_MAP.get(value, value))

    for column in ("src_port", "dst_port", "bytes_sent", "bytes_received"):
        working[column] = pd.to_numeric(working[column], errors="coerce")

    invalid_ports = int((~_valid_port(working["src_port"]) | ~_valid_port(working["dst_port"]) | working["src_port"].isna() | working["dst_port"].isna()).sum())
    invalid_ips = int((~working["src_ip"].map(_valid_ipv4) | ~working["dst_ip"].map(_valid_ipv4)).sum())

    invalid_bytes = working["bytes_sent"].isna() | working["bytes_received"].isna() | (working["bytes_sent"] < 0) | (working["bytes_received"] < 0)
    valid_mask = (
        working["timestamp"].notna()
        & working["src_ip"].map(_valid_ipv4)
        & working["dst_ip"].map(_valid_ipv4)
        & _valid_port(working["src_port"])
        & _valid_port(working["dst_port"])
        & ~invalid_bytes
    )
    cleaned = working.loc[valid_mask].copy()
    cleaned["src_port"] = cleaned["src_port"].astype(int)
    cleaned["dst_port"] = cleaned["dst_port"].astype(int)
    cleaned["bytes_sent"] = cleaned["bytes_sent"].astype(int)
    cleaned["bytes_received"] = cleaned["bytes_received"].astype(int)
    cleaned = cleaned.sort_values("timestamp").reset_index(drop=True)

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
