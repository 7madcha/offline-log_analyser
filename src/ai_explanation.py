"""Evidence-based plain-language explanations for AI anomalies."""

from __future__ import annotations

import pandas as pd

LABELS = {
    "unique_dst_ports": "Number of destination ports",
    "bytes_sent_total": "Outgoing data volume",
    "unique_dst_ips": "Number of destination machines",
    "connection_count": "Connection count",
    "blocked_ratio": "Blocked-connection ratio",
    "bytes_received_total": "Incoming data volume",
}


def explain_anomalies(features: pd.DataFrame) -> pd.Series:
    """Return up to three statements supported by feature-to-median comparisons."""
    if features.empty:
        return pd.Series(dtype=str)
    medians = features[list(LABELS)].median(numeric_only=True)

    def explain(row: pd.Series) -> str:
        evidence: list[tuple[float, str]] = []
        for column, label in LABELS.items():
            value = float(row.get(column, 0) or 0)
            median = float(medians.get(column, 0) or 0)
            ratio = value / median if median > 0 else (value + 1 if value > 0 else 1)
            if ratio >= 1.5:
                evidence.append((ratio, f"{label} is {ratio:.1f} times higher than the dataset median ({value:g} vs {median:g})."))
        if int(row.get("off_hours_indicator", 0)) == 1:
            evidence.append((2.0, "Activity occurred outside the configured working hours."))
        evidence.sort(key=lambda item: item[0], reverse=True)
        return " ".join(text for _, text in evidence[:3]) or "The combined behavior differs from the dataset baseline; no single feature exceeded 1.5 times its median."

    return features.apply(explain, axis=1)
