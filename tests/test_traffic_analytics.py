import pandas as pd

from src.traffic_analytics import top_destination_ports, top_source_ips


def _logs():
    return pd.DataFrame({"src_ip": ["a", "a", "b"], "dst_ip": ["x", "y", "x"], "dst_port": [443, 443, 9999], "action": ["ALLOW", "BLOCK", "BLOCK"], "bytes_sent": [1, 2, 10], "bytes_received": [3, 4, 20]})


def test_source_ranking_counts_totals_and_limit_without_mutation():
    logs = _logs(); original = logs.copy(deep=True)
    result = top_source_ips(logs, top_n=1)
    assert result.iloc[0]["src_ip"] == "a"
    assert result.iloc[0]["allowed_events"] == 1
    assert result.iloc[0]["blocked_events"] == 1
    assert result.iloc[0]["bytes_sent_total"] == 3
    assert len(result) == 1
    pd.testing.assert_frame_equal(logs, original)


def test_port_ranking_mapping_unknown_ratio_and_limit():
    result = top_destination_ports(_logs(), top_n=2)
    assert result.iloc[0]["dst_port"] == 443
    assert result.iloc[0]["service_name"] == "HTTPS"
    assert result.iloc[0]["blocked_ratio"] == 0.5
    assert result.iloc[1]["service_name"] == "Unknown"
