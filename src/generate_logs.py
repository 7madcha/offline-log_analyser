"""Synthetic firewall log generator for offline analysis."""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from src.utils import ensure_directory

NORMAL_LABEL = "normal"
SEED = 42
PROFILE_CHOICES = ("normal", "noisy", "attack-heavy")


def _ip_from(prefix: str, rng: np.random.Generator) -> str:
    if prefix == "10":
        return f"10.{rng.integers(0, 256)}.{rng.integers(0, 256)}.{rng.integers(1, 255)}"
    if prefix == "172":
        return f"172.{rng.integers(16, 32)}.{rng.integers(0, 256)}.{rng.integers(1, 255)}"
    if prefix == "192168":
        return f"192.168.{rng.integers(0, 256)}.{rng.integers(1, 255)}"
    if prefix == "19202":
        return f"192.0.2.{rng.integers(1, 255)}"
    if prefix == "19851100":
        return f"198.51.100.{rng.integers(1, 255)}"
    if prefix == "2030113":
        return f"203.0.113.{rng.integers(1, 255)}"
    raise ValueError(f"Unsupported prefix: {prefix}")


def _internal_ip(rng: np.random.Generator) -> str:
    return _ip_from(rng.choice(["10", "172", "192168"]), rng)


def _external_doc_ip(rng: np.random.Generator) -> str:
    return _ip_from(rng.choice(["19202", "19851100", "2030113"]), rng)


def _event(
    timestamp: pd.Timestamp,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: str,
    action: str,
    bytes_sent: int,
    bytes_received: int,
    label: str,
) -> dict[str, object]:
    return {
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": int(src_port),
        "dst_port": int(dst_port),
        "protocol": protocol,
        "action": action,
        "bytes_sent": int(bytes_sent),
        "bytes_received": int(bytes_received),
        "label": label,
    }


def _normal_event(rng: np.random.Generator, start: pd.Timestamp) -> dict[str, object]:
    day_offset = int(rng.integers(0, 7))
    business_hour = int(
        rng.choice(
            np.arange(8, 19),
            p=np.array([0.05, 0.08, 0.1, 0.11, 0.11, 0.11, 0.11, 0.1, 0.09, 0.08, 0.06]),
        )
    )
    timestamp = start + pd.Timedelta(
        days=day_offset,
        hours=business_hour,
        minutes=int(rng.integers(0, 60)),
        seconds=int(rng.integers(0, 60)),
    )
    src_ip = _internal_ip(rng)
    dst_ip = _external_doc_ip(rng)
    protocol = "TCP"
    traffic_type = rng.choice(["https", "http", "dns", "ssh", "random", "blocked"], p=[0.42, 0.16, 0.16, 0.07, 0.14, 0.05])
    action = "ALLOW"

    if traffic_type == "https":
        dst_port = 443
        bytes_sent = rng.integers(400, 6000)
        bytes_received = rng.integers(1000, 50000)
    elif traffic_type == "http":
        dst_port = 80
        bytes_sent = rng.integers(300, 4000)
        bytes_received = rng.integers(800, 30000)
    elif traffic_type == "dns":
        protocol = "UDP"
        dst_port = 53
        bytes_sent = rng.integers(50, 300)
        bytes_received = rng.integers(80, 700)
    elif traffic_type == "ssh":
        dst_port = 22
        bytes_sent = rng.integers(300, 3000)
        bytes_received = rng.integers(300, 10000)
    elif traffic_type == "blocked":
        dst_port = int(rng.choice([22, 23, 3389, 445, 8080]))
        action = "BLOCK"
        bytes_sent = rng.integers(40, 200)
        bytes_received = 0
    else:
        dst_port = int(rng.choice([25, 110, 123, 143, 389, 445, 587, 8080, 8443]))
        bytes_sent = rng.integers(100, 10000)
        bytes_received = rng.integers(100, 20000)

    return _event(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=int(rng.integers(1024, 65535)),
        dst_port=dst_port,
        protocol=protocol,
        action=action,
        bytes_sent=int(bytes_sent),
        bytes_received=int(bytes_received),
        label=NORMAL_LABEL,
    )


def _inject_noisy_scenarios(events: list[dict[str, object]], start: pd.Timestamp) -> None:
    """Add suspicious-looking but smaller local-only samples."""
    base = start + pd.Timedelta(days=1, hours=1, minutes=20)
    for i in range(18):
        events.append(_event(base + pd.Timedelta(seconds=i * 3), "10.0.0.45", "192.0.2.45", 43000 + i, 3389, "TCP", "BLOCK", 70, 0, "noisy_off_hours"))

    scan_base = start + pd.Timedelta(days=2, hours=10, minutes=5)
    for i, port in enumerate(range(8000, 8014)):
        events.append(_event(scan_base + pd.Timedelta(seconds=i * 10), "10.0.0.46", "198.51.100.46", 44000 + i, port, "TCP", "BLOCK", 85, 0, "noisy_port_probe"))

    events.append(_event(start + pd.Timedelta(days=3, hours=15, minutes=10), "192.168.20.20", "203.0.113.50", 45000, 443, "TCP", "ALLOW", 25_000_000, 9000, "noisy_large_transfer"))


def _inject_scenarios(events: list[dict[str, object]], start: pd.Timestamp) -> None:
    brute_src = "10.0.0.99"
    base = start + pd.Timedelta(days=1, hours=2, minutes=13)
    for i in range(60):
        events.append(_event(base + pd.Timedelta(seconds=i), brute_src, "192.0.2.10", 42000 + i, 22, "TCP", "BLOCK", 60, 0, "brute_force"))

    scan_src = "10.0.0.88"
    scan_base = start + pd.Timedelta(days=2, hours=10, minutes=5)
    for i, port in enumerate(range(1, 35)):
        events.append(_event(scan_base + pd.Timedelta(seconds=i * 7), scan_src, "198.51.100.20", 50000 + i, port, "TCP", "BLOCK", 80, 0, "port_scan"))

    host_src = "172.16.5.44"
    host_base = start + pd.Timedelta(days=3, hours=11, minutes=20)
    for i in range(45):
        events.append(_event(host_base + pd.Timedelta(seconds=i * 6), host_src, f"203.0.113.{i + 1}", 51000 + i, 445, "TCP", "BLOCK", 90, 0, "host_scan"))

    transfer_src = "192.168.10.15"
    events.append(_event(start + pd.Timedelta(days=4, hours=14, minutes=35), transfer_src, "198.51.100.77", 53000, 443, "TCP", "ALLOW", 75_000_000, 12_000, "large_transfer"))

    off_src = "10.0.0.66"
    off_base = start + pd.Timedelta(days=5, hours=1, minutes=30)
    for i in range(8):
        events.append(_event(off_base + pd.Timedelta(seconds=i * 20), off_src, "192.0.2.66", 54000 + i, 3389, "TCP", "BLOCK", 75, 0, "off_hours"))

    combined_src = "10.0.0.123"
    combined_base = start + pd.Timedelta(days=6, hours=3, minutes=10)
    for i in range(55):
        events.append(_event(combined_base + pd.Timedelta(seconds=i), combined_src, "192.0.2.200", 55000 + i, 22, "TCP", "BLOCK", 70, 0, "combined_incident"))
    for i, port in enumerate(range(1000, 1032)):
        events.append(_event(combined_base + pd.Timedelta(minutes=2, seconds=i * 5), combined_src, "198.51.100.150", 56000 + i, port, "TCP", "BLOCK", 85, 0, "combined_incident"))
    for i in range(42):
        events.append(_event(combined_base + pd.Timedelta(minutes=4, seconds=i * 4), combined_src, f"203.0.113.{100 + i}", 57000 + i, 445, "TCP", "BLOCK", 95, 0, "combined_incident"))
    events.append(_event(combined_base + pd.Timedelta(minutes=6), combined_src, "198.51.100.201", 58000, 443, "TCP", "ALLOW", 95_000_000, 9000, "combined_incident"))


def generate_firewall_logs(rows: int = 50_000, seed: int = SEED, profile: str = "attack-heavy") -> pd.DataFrame:
    """Generate synthetic firewall logs with a selectable local-only sample profile."""
    if profile not in PROFILE_CHOICES:
        raise ValueError(f"Unsupported profile: {profile}")
    rng = np.random.default_rng(seed)
    start = pd.Timestamp("2026-07-01 00:00:00")
    events = [_normal_event(rng, start) for _ in range(max(rows, 0))]
    if profile == "noisy":
        _inject_noisy_scenarios(events, start)
    elif profile == "attack-heavy":
        _inject_scenarios(events, start)
    df = pd.DataFrame(events).sort_values("timestamp").reset_index(drop=True)
    return df


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic firewall logs.")
    parser.add_argument("--rows", type=int, default=50_000, help="Number of normal baseline rows to generate.")
    parser.add_argument("--output", default="data/synthetic/firewall_logs.csv", help="Output CSV path.")
    parser.add_argument("--seed", type=int, default=SEED, help="Random seed for reproducibility.")
    parser.add_argument("--profile", choices=PROFILE_CHOICES, default="attack-heavy", help="Synthetic sample profile.")
    args = parser.parse_args()

    output_path = Path(args.output)
    ensure_directory(output_path.parent)
    df = generate_firewall_logs(rows=args.rows, seed=args.seed, profile=args.profile)
    df.to_csv(output_path, index=False, encoding="utf-8")
    print(f"Generated {len(df):,} rows at {output_path} using profile '{args.profile}'")


if __name__ == "__main__":
    main()
