"""Streamlit dashboard for Offline Log Forensic Analyzer."""

from __future__ import annotations

from html import escape
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.cleaner import clean_logs
from src.correlator import correlate_alerts
from src.detectors import run_all_detectors
from src.loader import load_logs
from src.utils import load_config
from src.validator import validate_columns, validate_dataset

DEFAULT_FILE = Path("data/synthetic/firewall_logs.csv")
SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]
SEVERITY_COLORS = {
    "Low": "#0f766e",
    "Medium": "#d97706",
    "High": "#dc2626",
    "Critical": "#7f1d1d",
}
CHART_COLORS = ["#0f766e", "#2563eb", "#d97706", "#dc2626", "#64748b", "#9333ea"]


@st.cache_data(show_spinner=False)
def analyze_default_file(path: str) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, dict[str, int]]:
    """Load and analyze the default CSV file."""
    config = load_config("config.yaml")
    raw = load_logs(path)
    validate_dataset(raw)
    validate_columns(raw, config["required_columns"])
    cleaned, summary = clean_logs(raw)
    alerts = run_all_detectors(cleaned, config)
    incidents = correlate_alerts(alerts, config)
    return cleaned, alerts, incidents, summary


def analyze_uploaded_file(uploaded_file) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, dict[str, int]]:
    """Analyze an uploaded CSV file without saving it."""
    config = load_config("config.yaml")
    raw = pd.read_csv(uploaded_file, dtype=str)
    validate_dataset(raw)
    validate_columns(raw, config["required_columns"])
    cleaned, summary = clean_logs(raw)
    alerts = run_all_detectors(cleaned, config)
    incidents = correlate_alerts(alerts, config)
    return cleaned, alerts, incidents, summary


def inject_styles() -> None:
    """Apply dashboard-specific styling."""
    st.markdown(
        """
        <style>
        :root {
            --bg: #f6f7fb;
            --panel: #ffffff;
            --panel-soft: #f9fafb;
            --ink: #111827;
            --muted: #64748b;
            --line: #e5e7eb;
            --teal: #0f766e;
            --blue: #2563eb;
            --amber: #d97706;
            --red: #dc2626;
        }
        .stApp {
            background: var(--bg);
            color: var(--ink);
        }
        .block-container {
            max-width: 1440px;
            padding-top: 1.25rem;
            padding-bottom: 2rem;
        }
        [data-testid="stSidebar"] {
            background: #ffffff;
            border-right: 1px solid var(--line);
        }
        [data-testid="stSidebar"] h1,
        [data-testid="stSidebar"] h2,
        [data-testid="stSidebar"] h3 {
            color: var(--ink);
        }
        div[data-testid="stMetric"] {
            background: transparent;
        }
        .hero {
            background: linear-gradient(135deg, #ffffff 0%, #f8fafc 58%, #eef6f3 100%);
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: 1.15rem 1.25rem;
            margin-bottom: 1rem;
            box-shadow: 0 10px 25px rgba(15, 23, 42, 0.06);
        }
        .hero-kicker {
            color: var(--teal);
            font-size: 0.76rem;
            font-weight: 800;
            letter-spacing: 0;
            text-transform: uppercase;
            margin-bottom: 0.35rem;
        }
        .hero-title {
            color: var(--ink);
            font-size: 2rem;
            line-height: 1.15;
            font-weight: 800;
            margin: 0;
        }
        .hero-copy {
            color: var(--muted);
            font-size: 0.98rem;
            max-width: 860px;
            margin-top: 0.45rem;
            margin-bottom: 0;
        }
        .status-row {
            display: flex;
            flex-wrap: wrap;
            gap: 0.55rem;
            margin-top: 0.9rem;
        }
        .status-pill {
            background: #ffffff;
            border: 1px solid var(--line);
            border-radius: 999px;
            color: #334155;
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
            font-size: 0.8rem;
            font-weight: 700;
            padding: 0.35rem 0.65rem;
        }
        .status-dot {
            width: 0.55rem;
            height: 0.55rem;
            border-radius: 999px;
            background: var(--teal);
        }
        .metric-card {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 8px;
            min-height: 112px;
            padding: 0.9rem 1rem;
            box-shadow: 0 8px 18px rgba(15, 23, 42, 0.045);
        }
        .metric-label {
            color: var(--muted);
            font-size: 0.78rem;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0;
        }
        .metric-value {
            color: var(--ink);
            font-size: 1.75rem;
            line-height: 1.15;
            font-weight: 800;
            margin-top: 0.35rem;
        }
        .metric-note {
            color: var(--muted);
            font-size: 0.82rem;
            margin-top: 0.35rem;
        }
        .metric-accent-teal { border-top: 4px solid var(--teal); }
        .metric-accent-blue { border-top: 4px solid var(--blue); }
        .metric-accent-amber { border-top: 4px solid var(--amber); }
        .metric-accent-red { border-top: 4px solid var(--red); }
        .section-title {
            margin: 1rem 0 0.45rem 0;
            color: var(--ink);
            font-size: 1.1rem;
            line-height: 1.25;
            font-weight: 800;
        }
        .section-subtitle {
            color: var(--muted);
            font-size: 0.9rem;
            margin-top: -0.25rem;
            margin-bottom: 0.75rem;
        }
        .panel-note {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 8px;
            padding: 0.85rem 1rem;
            color: #334155;
        }
        .badge {
            border-radius: 999px;
            color: #ffffff;
            display: inline-block;
            font-size: 0.78rem;
            font-weight: 800;
            padding: 0.22rem 0.55rem;
        }
        .badge-low { background: #0f766e; }
        .badge-medium { background: #d97706; }
        .badge-high { background: #dc2626; }
        .badge-critical { background: #7f1d1d; }
        .recommendation-list {
            margin: 0;
            padding-left: 1.1rem;
            color: #334155;
        }
        .recommendation-list li {
            margin-bottom: 0.35rem;
        }
        .stTabs [data-baseweb="tab-list"] {
            gap: 0.25rem;
            border-bottom: 1px solid var(--line);
        }
        .stTabs [data-baseweb="tab"] {
            background: #ffffff;
            border: 1px solid var(--line);
            border-bottom: 0;
            border-radius: 8px 8px 0 0;
            color: #475569;
            font-weight: 700;
            padding: 0.45rem 0.75rem;
        }
        .stTabs [aria-selected="true"] {
            color: var(--teal);
        }
        div[data-testid="stDataFrame"] {
            border: 1px solid var(--line);
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 8px 18px rgba(15, 23, 42, 0.04);
        }
        .stDownloadButton button,
        .stButton button {
            border-radius: 8px;
            border: 1px solid #cbd5e1;
            font-weight: 800;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _csv_download(df: pd.DataFrame) -> bytes:
    return df.to_csv(index=False).encode("utf-8")


def _format_number(value: int | float) -> str:
    if isinstance(value, float) and not value.is_integer():
        return f"{value:,.1f}"
    return f"{int(value):,}"


def _truncate(value: object, limit: int = 140) -> str:
    text = "" if pd.isna(value) else str(value)
    return text if len(text) <= limit else f"{text[:limit - 3]}..."


def _metric_card(label: str, value: int | float | str, note: str = "", accent: str = "teal") -> None:
    value_text = _format_number(value) if isinstance(value, (int, float)) else escape(str(value))
    note_html = f'<div class="metric-note">{escape(note)}</div>' if note else ""
    st.markdown(
        f"""
        <div class="metric-card metric-accent-{accent}">
            <div class="metric-label">{escape(label)}</div>
            <div class="metric-value">{value_text}</div>
            {note_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


def _section(title: str, subtitle: str | None = None) -> None:
    st.markdown(f'<div class="section-title">{escape(title)}</div>', unsafe_allow_html=True)
    if subtitle:
        st.markdown(f'<div class="section-subtitle">{escape(subtitle)}</div>', unsafe_allow_html=True)


def _severity_badge(severity: str) -> str:
    css_name = severity.lower() if severity in SEVERITY_ORDER else "low"
    return f'<span class="badge badge-{css_name}">{escape(severity)}</span>'


def _multiselect(label: str, values: pd.Series) -> list[str]:
    options = sorted(values.dropna().astype(str).unique().tolist())
    return st.sidebar.multiselect(label, options)


def _contains_any(series: pd.Series, values: list[str]) -> pd.Series:
    if not values:
        return pd.Series(True, index=series.index)
    return series.fillna("").astype(str).apply(lambda value: any(item in value for item in values))


def _style_figure(fig: go.Figure, height: int = 360) -> go.Figure:
    fig.update_layout(
        height=height,
        template="plotly_white",
        paper_bgcolor="rgba(255,255,255,0)",
        plot_bgcolor="#ffffff",
        font={"color": "#334155", "family": "Arial"},
        margin={"l": 10, "r": 10, "t": 48, "b": 10},
        legend={"orientation": "h", "yanchor": "bottom", "y": 1.02, "xanchor": "right", "x": 1},
    )
    fig.update_xaxes(gridcolor="#edf2f7", zerolinecolor="#e5e7eb")
    fig.update_yaxes(gridcolor="#edf2f7", zerolinecolor="#e5e7eb")
    return fig


def _empty_alert(message: str) -> None:
    st.markdown(f'<div class="panel-note">{escape(message)}</div>', unsafe_allow_html=True)


def apply_filters(
    logs: pd.DataFrame,
    alerts: pd.DataFrame,
    incidents: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Apply sidebar filters to logs, alerts, and incidents."""
    filtered_logs = logs.copy()
    filtered_alerts = alerts.copy()
    filtered_incidents = incidents.copy()

    min_date = filtered_logs["timestamp"].dt.date.min()
    max_date = filtered_logs["timestamp"].dt.date.max()
    date_range = st.sidebar.date_input("Date range", value=(min_date, max_date), min_value=min_date, max_value=max_date)
    src_filter = _multiselect("Source IP", filtered_logs["src_ip"])
    dst_filter = _multiselect("Destination IP", filtered_logs["dst_ip"])
    protocol_filter = _multiselect("Protocol", filtered_logs["protocol"])
    action_filter = _multiselect("Action", filtered_logs["action"])
    severity_filter = st.sidebar.multiselect("Severity", SEVERITY_ORDER)
    alert_type_values = filtered_alerts["alert_type"] if "alert_type" in filtered_alerts else pd.Series(dtype=str)
    alert_type_filter = _multiselect("Alert type", alert_type_values)

    if isinstance(date_range, tuple) and len(date_range) == 2:
        start_date, end_date = date_range
        filtered_logs = filtered_logs[
            (filtered_logs["timestamp"].dt.date >= start_date)
            & (filtered_logs["timestamp"].dt.date <= end_date)
        ]
        if not filtered_alerts.empty:
            alert_dates = pd.to_datetime(filtered_alerts["timestamp"], errors="coerce").dt.date
            filtered_alerts = filtered_alerts[(alert_dates >= start_date) & (alert_dates <= end_date)]
        if not filtered_incidents.empty:
            starts = pd.to_datetime(filtered_incidents["start_time"], errors="coerce").dt.date
            ends = pd.to_datetime(filtered_incidents["end_time"], errors="coerce").dt.date
            filtered_incidents = filtered_incidents[(starts <= end_date) & (ends >= start_date)]

    if src_filter:
        filtered_logs = filtered_logs[filtered_logs["src_ip"].astype(str).isin(src_filter)]
        if not filtered_alerts.empty:
            filtered_alerts = filtered_alerts[filtered_alerts["src_ip"].astype(str).isin(src_filter)]
        if not filtered_incidents.empty:
            filtered_incidents = filtered_incidents[filtered_incidents["src_ip"].astype(str).isin(src_filter)]
    if dst_filter:
        filtered_logs = filtered_logs[filtered_logs["dst_ip"].astype(str).isin(dst_filter)]
        if "affected_destinations" in filtered_alerts:
            filtered_alerts = filtered_alerts[_contains_any(filtered_alerts["affected_destinations"], dst_filter)]
        if "affected_destinations" in filtered_incidents:
            filtered_incidents = filtered_incidents[_contains_any(filtered_incidents["affected_destinations"], dst_filter)]
    if protocol_filter:
        filtered_logs = filtered_logs[filtered_logs["protocol"].astype(str).isin(protocol_filter)]
    if action_filter:
        filtered_logs = filtered_logs[filtered_logs["action"].astype(str).isin(action_filter)]
    if severity_filter:
        if not filtered_alerts.empty:
            filtered_alerts = filtered_alerts[filtered_alerts["severity"].astype(str).isin(severity_filter)]
        if not filtered_incidents.empty:
            filtered_incidents = filtered_incidents[filtered_incidents["severity"].astype(str).isin(severity_filter)]
    if alert_type_filter:
        if not filtered_alerts.empty:
            filtered_alerts = filtered_alerts[filtered_alerts["alert_type"].astype(str).isin(alert_type_filter)]
        if "alert_types" in filtered_incidents:
            filtered_incidents = filtered_incidents[_contains_any(filtered_incidents["alert_types"], alert_type_filter)]
    return filtered_logs, filtered_alerts, filtered_incidents


def render_header(logs: pd.DataFrame, alerts: pd.DataFrame, incidents: pd.DataFrame) -> None:
    """Render the top dashboard header."""
    latest = logs["timestamp"].max() if not logs.empty else "No events"
    critical_count = int((incidents["severity"] == "Critical").sum()) if not incidents.empty else 0
    st.markdown(
        f"""
        <div class="hero">
            <div class="hero-kicker">Local forensic dashboard</div>
            <h1 class="hero-title">Offline Log Forensic Analyzer</h1>
            <p class="hero-copy">
                Review synthetic firewall activity, correlated incidents, explainable risk scores,
                and investigation evidence from one local Streamlit workspace.
            </p>
            <div class="status-row">
                <span class="status-pill"><span class="status-dot"></span>{_format_number(len(logs))} events loaded</span>
                <span class="status-pill"><span class="status-dot"></span>{_format_number(len(alerts))} alerts</span>
                <span class="status-pill"><span class="status-dot"></span>{_format_number(len(incidents))} incidents</span>
                <span class="status-pill"><span class="status-dot"></span>{critical_count} critical</span>
                <span class="status-pill"><span class="status-dot"></span>Latest: {escape(str(latest))}</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_overview(logs: pd.DataFrame, alerts: pd.DataFrame, incidents: pd.DataFrame) -> None:
    """Render overview KPIs and charts."""
    allowed = int((logs["action"] == "ALLOW").sum()) if not logs.empty else 0
    blocked = int((logs["action"] == "BLOCK").sum()) if not logs.empty else 0
    max_risk = int(incidents["risk_score"].max()) if not incidents.empty else 0
    critical = int((incidents["severity"] == "Critical").sum()) if not incidents.empty else 0

    columns = st.columns(4)
    with columns[0]:
        _metric_card("Total log events", len(logs), "Filtered events in scope", "teal")
    with columns[1]:
        _metric_card("Blocked connections", blocked, f"Allowed: {_format_number(allowed)}", "amber")
    with columns[2]:
        _metric_card("Open incidents", len(incidents), f"Critical: {critical}", "red" if critical else "blue")
    with columns[3]:
        _metric_card("Highest risk", max_risk, "Maximum incident score", "red" if max_risk >= 80 else "teal")

    _section("Traffic Overview", "Event volume and connection outcomes across the selected window.")
    if logs.empty:
        _empty_alert("No log events match the selected filters.")
        return

    hourly = logs.set_index("timestamp").resample("h").size().reset_index(name="events")
    fig = px.area(hourly, x="timestamp", y="events", title="Events Over Time", color_discrete_sequence=["#0f766e"])
    fig.update_traces(line={"width": 2}, fillcolor="rgba(15, 118, 110, 0.16)")
    st.plotly_chart(_style_figure(fig, 330), width="stretch")

    left, right = st.columns(2)
    with left:
        action_counts = logs["action"].value_counts().rename_axis("action").reset_index(name="count")
        fig = px.bar(
            action_counts,
            x="action",
            y="count",
            title="Allowed Versus Blocked Events",
            color="action",
            color_discrete_map={"ALLOW": "#0f766e", "BLOCK": "#dc2626", "OTHER": "#64748b"},
        )
        st.plotly_chart(_style_figure(fig, 330), width="stretch")
    with right:
        top_ports = logs["dst_port"].value_counts().head(10).rename_axis("dst_port").reset_index(name="count")
        fig = px.bar(
            top_ports,
            x="count",
            y="dst_port",
            orientation="h",
            title="Top Destination Ports",
            color_discrete_sequence=["#2563eb"],
        )
        fig.update_yaxes(type="category", autorange="reversed")
        st.plotly_chart(_style_figure(fig, 330), width="stretch")

    _section("Security Signals", "Alert distribution, severity mix, and the most suspicious source IPs.")
    left, right = st.columns(2)
    with left:
        if alerts.empty:
            _empty_alert("No alerts match the selected filters.")
        else:
            type_counts = alerts["alert_type"].value_counts().rename_axis("alert_type").reset_index(name="count")
            fig = px.bar(
                type_counts,
                x="count",
                y="alert_type",
                orientation="h",
                title="Alerts By Type",
                color="alert_type",
                color_discrete_sequence=CHART_COLORS,
            )
            fig.update_yaxes(autorange="reversed")
            st.plotly_chart(_style_figure(fig, 360), width="stretch")
    with right:
        if incidents.empty:
            _empty_alert("No incidents match the selected filters.")
        else:
            severity_counts = incidents["severity"].value_counts().reindex(SEVERITY_ORDER, fill_value=0).reset_index()
            severity_counts.columns = ["severity", "count"]
            fig = px.bar(
                severity_counts,
                x="severity",
                y="count",
                title="Incidents By Severity",
                color="severity",
                color_discrete_map=SEVERITY_COLORS,
            )
            st.plotly_chart(_style_figure(fig, 360), width="stretch")

    if not alerts.empty:
        top_sources = alerts["src_ip"].value_counts().head(10).rename_axis("src_ip").reset_index(name="alerts")
        fig = px.bar(
            top_sources,
            x="alerts",
            y="src_ip",
            orientation="h",
            title="Top Suspicious Source IPs",
            color_discrete_sequence=["#d97706"],
        )
        fig.update_yaxes(autorange="reversed")
        st.plotly_chart(_style_figure(fig, 340), width="stretch")


def render_alerts(alerts: pd.DataFrame) -> None:
    """Render alert table and download."""
    _section("Alerts", "Detected suspicious behaviors with evidence and score contribution.")
    search = st.text_input("Search alerts", placeholder="Search by source IP, alert type, severity, or evidence")
    visible = alerts.copy()
    if search:
        visible = visible[visible.astype(str).apply(lambda row: row.str.contains(search, case=False, na=False).any(), axis=1)]

    if visible.empty:
        _empty_alert("No alerts match the current search and filters.")
        return

    display = visible.copy()
    display["evidence"] = display["evidence"].apply(lambda value: _truncate(value, 180))
    columns = ["alert_id", "timestamp", "src_ip", "alert_type", "severity", "event_count", "score_contribution", "evidence"]
    st.dataframe(
        display[columns],
        width="stretch",
        hide_index=True,
        column_config={
            "score_contribution": st.column_config.NumberColumn("Score", format="%d"),
            "event_count": st.column_config.NumberColumn("Events", format="%d"),
        },
    )
    st.download_button("Download alerts CSV", _csv_download(visible), "alerts.csv", "text/csv")


def render_incidents(incidents: pd.DataFrame) -> None:
    """Render incident table and download."""
    _section("Incidents", "Correlated alerts grouped by source IP and investigation window.")
    if incidents.empty:
        _empty_alert("No incidents match the selected filters.")
        return

    visible = incidents.sort_values("risk_score", ascending=False).copy()
    visible["alert_types"] = visible["alert_types"].apply(lambda value: _truncate(value, 120))
    columns = ["incident_id", "src_ip", "start_time", "end_time", "risk_score", "severity", "alert_types", "alert_count"]
    st.dataframe(
        visible[columns],
        width="stretch",
        hide_index=True,
        column_config={
            "risk_score": st.column_config.ProgressColumn("Risk score", min_value=0, max_value=100, format="%d"),
            "alert_count": st.column_config.NumberColumn("Alerts", format="%d"),
        },
    )
    st.download_button("Download incidents CSV", _csv_download(visible), "incidents.csv", "text/csv")


def _risk_gauge(score: int) -> go.Figure:
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            number={"font": {"size": 34, "color": "#111827"}},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": "#94a3b8"},
                "bar": {"color": "#dc2626" if score >= 80 else "#d97706" if score >= 60 else "#0f766e"},
                "bgcolor": "#ffffff",
                "borderwidth": 1,
                "bordercolor": "#e5e7eb",
                "steps": [
                    {"range": [0, 30], "color": "#ecfdf5"},
                    {"range": [30, 60], "color": "#fffbeb"},
                    {"range": [60, 80], "color": "#fef2f2"},
                    {"range": [80, 100], "color": "#fee2e2"},
                ],
            },
        )
    )
    return _style_figure(fig, 260)


def _split_pipe_values(value: object) -> list[str]:
    if pd.isna(value):
        return []
    return [item.strip() for item in str(value).split(" | ") if item.strip()]


def _build_timeline(related_alerts: pd.DataFrame, related_events: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, object]] = []
    if not related_events.empty:
        first_event = related_events.iloc[0]
        rows.append(
            {
                "time": first_event["timestamp"],
                "activity": "First related raw event",
                "evidence": f"{first_event['action']} {first_event['protocol']} to {first_event['dst_ip']}:{first_event['dst_port']}",
            }
        )
    for _, alert in related_alerts.iterrows():
        rows.append(
            {
                "time": pd.to_datetime(alert["timestamp"], errors="coerce"),
                "activity": alert["alert_type"],
                "evidence": _truncate(alert["evidence"], 220),
            }
        )
    if not related_events.empty:
        last_event = related_events.iloc[-1]
        rows.append(
            {
                "time": last_event["timestamp"],
                "activity": "Last related raw event",
                "evidence": f"{last_event['action']} {last_event['protocol']} to {last_event['dst_ip']}:{last_event['dst_port']}",
            }
        )
    return pd.DataFrame(rows).sort_values("time") if rows else pd.DataFrame(columns=["time", "activity", "evidence"])


def render_investigation(logs: pd.DataFrame, alerts: pd.DataFrame, incidents: pd.DataFrame) -> None:
    """Render investigation detail for one selected incident."""
    _section("Investigation", "Incident-level explanation, score breakdown, recommendations, and timeline.")
    if incidents.empty:
        _empty_alert("No incidents available for investigation.")
        return

    ordered = incidents.sort_values("risk_score", ascending=False)
    labels = [f"{row.incident_id} | {row.severity} | risk {int(row.risk_score)} | {row.src_ip}" for row in ordered.itertuples()]
    selected_label = st.selectbox("Incident", labels)
    selected_id = selected_label.split(" | ", 1)[0]
    incident = ordered[ordered["incident_id"] == selected_id].iloc[0]

    start_time = pd.to_datetime(incident["start_time"])
    end_time = pd.to_datetime(incident["end_time"])
    related_alerts = alerts[
        (alerts["src_ip"] == incident["src_ip"])
        & (pd.to_datetime(alerts["timestamp"]) >= start_time)
        & (pd.to_datetime(alerts["timestamp"]) <= end_time)
    ].sort_values("timestamp")
    related_events = logs[
        (logs["src_ip"] == incident["src_ip"])
        & (logs["timestamp"] >= start_time)
        & (logs["timestamp"] <= end_time)
    ].sort_values("timestamp")

    score = int(incident["risk_score"])
    left, right = st.columns([1, 2])
    with left:
        st.plotly_chart(_risk_gauge(score), width="stretch")
        st.markdown(_severity_badge(str(incident["severity"])), unsafe_allow_html=True)
    with right:
        c1, c2, c3 = st.columns(3)
        with c1:
            _metric_card("Incident", incident["incident_id"], "Selected case", "teal")
        with c2:
            _metric_card("Source IP", incident["src_ip"], "Primary source", "blue")
        with c3:
            _metric_card("Events", int(incident["event_count"]), f"Alerts: {int(incident['alert_count'])}", "amber")
        st.markdown(
            f"""
            <div class="panel-note">
                <strong>First event:</strong> {escape(str(start_time))}<br>
                <strong>Last event:</strong> {escape(str(end_time))}<br>
                <strong>Alert types:</strong> {escape(str(incident['alert_types']))}<br>
                <strong>Affected destinations:</strong> {escape(_truncate(incident['affected_destinations'], 260))}<br>
                <strong>Affected ports:</strong> {escape(_truncate(incident['affected_ports'], 260))}
            </div>
            """,
            unsafe_allow_html=True,
        )

    _section("Explanation")
    st.markdown(f'<div class="panel-note">{escape(str(incident["explanation"]))}</div>', unsafe_allow_html=True)

    left, right = st.columns(2)
    with left:
        _section("Risk Score Breakdown")
        st.code(str(incident["score_breakdown"]).replace(" | ", "\n"))
    with right:
        _section("Recommendations")
        items = _split_pipe_values(incident["recommendations"])
        html_items = "".join(f"<li>{escape(item)}</li>" for item in items)
        st.markdown(f'<ul class="recommendation-list">{html_items}</ul>', unsafe_allow_html=True)

    _section("Chronological Timeline")
    timeline = _build_timeline(related_alerts, related_events)
    st.dataframe(timeline, width="stretch", hide_index=True)

    _section("Related Raw Events")
    event_columns = ["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "action", "bytes_sent", "bytes_received"]
    st.dataframe(related_events[event_columns], width="stretch", hide_index=True)


def render_sidebar() -> tuple[object, bool]:
    """Render data source controls."""
    st.sidebar.title("Controls")
    st.sidebar.caption("Offline analysis workspace")
    st.sidebar.header("Data source")
    uploaded = st.sidebar.file_uploader("CSV file", type=["csv"])
    use_default = st.sidebar.button("Load default synthetic file", width="stretch")
    return uploaded, use_default


def main() -> None:
    st.set_page_config(page_title="Offline Log Forensic Analyzer", layout="wide")
    inject_styles()

    uploaded, use_default = render_sidebar()

    try:
        if uploaded is not None:
            logs, alerts, incidents, summary = analyze_uploaded_file(uploaded)
        elif use_default or DEFAULT_FILE.exists():
            logs, alerts, incidents, summary = analyze_default_file(str(DEFAULT_FILE))
        else:
            st.info("Generate synthetic logs first or upload a CSV file.")
            return
    except Exception as exc:
        st.error(str(exc))
        return

    st.sidebar.header("Filters")
    filtered_logs, filtered_alerts, filtered_incidents = apply_filters(logs, alerts, incidents)

    render_header(filtered_logs, filtered_alerts, filtered_incidents)
    page = st.tabs(["Overview", "Alerts", "Incidents", "Investigation"])

    with page[0]:
        render_overview(filtered_logs, filtered_alerts, filtered_incidents)
        st.caption(f"Cleaning summary: {summary}")
    with page[1]:
        render_alerts(filtered_alerts)
    with page[2]:
        render_incidents(filtered_incidents)
    with page[3]:
        render_investigation(filtered_logs, filtered_alerts, filtered_incidents)


if __name__ == "__main__":
    main()

