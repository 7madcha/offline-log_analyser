"""Map supported log schemas into the analyzer's canonical columns."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import pandas as pd


CANONICAL_COLUMNS = (
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "action", "bytes_sent", "bytes_received",
)
REQUIRED_COLUMNS = ("timestamp", "src_ip")
DEFAULT_ALIASES = {
    "timestamp": ("timestamp", "event_time", "time", "date", "datetime", "log_time", "generated time", "receive time", "high resolution timestamp"),
    "src_ip": ("src_ip", "source_ip", "source_address", "source address", "client_ip", "src"),
    "dst_ip": ("dst_ip", "destination_ip", "destination_address", "destination address", "server_ip", "dst"),
    "src_port": ("src_port", "source_port", "source port", "client_port", "sport"),
    "dst_port": ("dst_port", "destination_port", "destination port", "server_port", "dport", "port"),
    "protocol": ("protocol", "transport_protocol", "transport", "proto"),
    "action": ("action", "verdict", "decision", "disposition", "result", "status"),
    "bytes_sent": ("bytes_sent", "bytes sent", "bytes_out", "outbound_bytes", "sent_bytes", "out_bytes"),
    "bytes_received": ("bytes_received", "bytes received", "bytes_in", "inbound_bytes", "received_bytes", "in_bytes"),
}
DEFAULT_VALUES = {
    "dst_ip": pd.NA,
    "src_port": pd.NA,
    "dst_port": pd.NA,
    "protocol": "UNKNOWN",
    "action": "UNKNOWN",
    "bytes_sent": 0,
    "bytes_received": 0,
}


@dataclass(frozen=True)
class SchemaMappingResult:
    """Canonical data plus information about columns supplied by the source."""

    logs: pd.DataFrame
    mapped_columns: dict[str, str]
    unavailable_columns: list[str]


def _aliases_for(column: str, config: dict | None) -> list[str]:
    configured = (config or {}).get("schema_mapping", {}).get("aliases", {}).get(column, [])
    aliases: Iterable[str] = [column, *configured, *DEFAULT_ALIASES.get(column, ())]
    return list(dict.fromkeys(str(alias).strip() for alias in aliases if str(alias).strip()))


def map_log_schema(logs: pd.DataFrame, config: dict | None = None) -> SchemaMappingResult:
    """Rename recognized source columns and add safe placeholders for unavailable fields."""
    if logs is None:
        raise ValueError("Dataset is missing.")
    source_columns = {str(column).strip().lower(): str(column) for column in logs.columns}
    mapped: dict[str, str] = {}
    for canonical in CANONICAL_COLUMNS:
        for alias in _aliases_for(canonical, config):
            source_column = source_columns.get(alias.lower())
            if source_column is not None:
                mapped[canonical] = source_column
                break

    missing_required = [column for column in REQUIRED_COLUMNS if column not in mapped]
    if missing_required:
        raise ValueError(f"Unable to map required log fields: {', '.join(missing_required)}")

    result = logs.copy(deep=True)
    for canonical, source_column in mapped.items():
        if canonical != source_column:
            result[canonical] = result[source_column]
    for column, default in DEFAULT_VALUES.items():
        if column not in result:
            result[column] = default

    unavailable = [column for column in CANONICAL_COLUMNS if column not in mapped]
    result.attrs["available_columns"] = list(mapped)
    result.attrs["schema_mapping"] = mapped
    result.attrs["unavailable_columns"] = unavailable
    return SchemaMappingResult(result, mapped, unavailable)
