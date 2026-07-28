"""Streamlit dashboard for Offline Log Forensic Analyzer."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.cleaner import clean_logs
from src.ai_detector import detect_ai_anomalies
from src.ai_features import build_behavioral_features
from src.correlator import correlate_alerts
from src.detectors import run_all_detectors
from src.generate_logs import generate_firewall_logs
from src.loader import load_logs, load_uploaded_logs
from src.reporting import build_pdf_report, build_visual_pdf_report, csv_schema_template
from src.schema_mapper import map_log_schema
from src.utils import ensure_directory, load_config
from src.validator import validate_columns, validate_dataset
from src.traffic_analytics import top_destination_ips, top_destination_ports, top_source_ips

DEFAULT_FILE = Path("data/synthetic/firewall_logs.csv")
SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]
SEVERITY_COLORS = {"Low": "#0f766e", "Medium": "#d97706", "High": "#dc2626", "Critical": "#7f1d1d"}
SAMPLE_PROFILES = {
    "Normal": {"profile": "normal", "rows": 8_000, "seed": 101},
    "Noisy": {"profile": "noisy", "rows": 12_000, "seed": 202},
    "Attack-heavy": {"profile": "attack-heavy", "rows": 50_000, "seed": 42},
}


def inject_styles() -> None:
    """Keep the interface simple and readable."""
    st.markdown(
        """
        <style>
        .block-container { max-width: 1180px; padding-top: 1rem; }
        .stApp { background: #f8fafc; color: #111827; }
        [data-testid="stSidebar"] { background: #ffffff; border-right: 1px solid #e5e7eb; }
        [data-testid="stSidebar"] * { color: #111827; }
        [data-testid="stSidebar"] .stCaptionContainer,
        [data-testid="stSidebar"] .stCaptionContainer * { color: #64748b; }
        .simple-header {
            background: #ffffff;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1rem;
        }
        .simple-header h1 { color: #111827; font-size: 1.6rem; margin: 0 0 .25rem 0; }
        .simple-header p { color: #475569; margin: 0; }
        div[data-testid="stMetric"] {
            background: #ffffff;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: .75rem;
        }
        div[data-testid="stDataFrame"] { border: 1px solid #e5e7eb; border-radius: 8px; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def analyze_dataframe(raw: pd.DataFrame, config_path: str = "config.yaml") -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, dict[str, int]]:
    """Analyze a dataframe without contacting any external service."""
    config = load_config(config_path)
    validate_dataset(raw)
    mapping = map_log_schema(raw, config)
    validate_columns(mapping.logs, ["timestamp", "src_ip"])
    cleaned, summary = clean_logs(mapping.logs, set(mapping.mapped_columns))
    validate_dataset(cleaned)
    alerts = run_all_detectors(cleaned, config, set(mapping.mapped_columns))
    cleaned.attrs["mapped_columns"] = mapping.mapped_columns
    cleaned.attrs["unavailable_columns"] = mapping.unavailable_columns
    cleaned.attrs["skipped_detectors"] = alerts.attrs.get("skipped_detectors", [])
    incidents = correlate_alerts(alerts, config)
    return cleaned, alerts, incidents, summary


@st.cache_data(show_spinner=False)
def analyze_default_file(path: str) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, dict[str, int]]:
    """Load and analyze the default local CSV file."""
    return analyze_dataframe(load_logs(path))


def analyze_generated_profile(name: str, rows: int) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, dict[str, int]]:
    """Generate fake logs locally, save them, and analyze them."""
    options = SAMPLE_PROFILES[name]
    raw = generate_firewall_logs(rows=rows, seed=options["seed"], profile=options["profile"])
    ensure_directory(DEFAULT_FILE.parent)
    raw.to_csv(DEFAULT_FILE, index=False, encoding="utf-8")
    return analyze_dataframe(raw)


def analyze_uploaded_file(uploaded_file) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, dict[str, int]]:
    """Analyze an uploaded local CSV or JSON log without saving it."""
    return analyze_dataframe(load_uploaded_logs(uploaded_file))


def render_sidebar() -> tuple[str, str, int, object, bool]:
    """Render simple data controls."""
    st.sidebar.title("Offline Analyzer")
    st.sidebar.caption("Local files and synthetic data only.")
    source = st.sidebar.radio("Choose input", ["Generate fake logs", "Upload log file", "Use existing log file"])

    profile = "Attack-heavy"
    rows = int(SAMPLE_PROFILES[profile]["rows"])
    uploaded = None

    if source == "Generate fake logs":
        profile = st.sidebar.selectbox("Fake log type", list(SAMPLE_PROFILES), index=2)
        rows = st.sidebar.number_input(
            "Rows",
            min_value=100,
            max_value=200_000,
            value=int(SAMPLE_PROFILES[profile]["rows"]),
            step=1_000,
        )
    elif source == "Upload log file":
        uploaded = st.sidebar.file_uploader("Select CSV or JSON", type=["csv", "json", "jsonl", "ndjson"])
    else:
        st.sidebar.caption(f"Uses `{DEFAULT_FILE}`")

    run_clicked = st.sidebar.button("Run analysis", type="primary", width="stretch")
    st.sidebar.download_button(
        "CSV template",
        csv_schema_template(),
        file_name="firewall_log_template.csv",
        mime="text/csv",
        width="stretch",
    )
    st.sidebar.caption("Local only: no scanning, APIs, VPN, or company system access.")
    return source, profile, int(rows), uploaded, run_clicked


def get_analysis(source: str, profile: str, rows: int, uploaded, run_clicked: bool):
    """Run analysis from the selected dashboard source."""
    if not run_clicked:
        if "analysis" in st.session_state:
            return st.session_state["analysis"]
        st.info("Choose a data source in the sidebar, then click Run analysis.")
        return None
    if source == "Upload log file":
        if uploaded is None:
            st.info("Upload a CSV or JSON log file, then click Run analysis.")
            return None
        result = analyze_uploaded_file(uploaded)
        label = f"Uploaded file: {uploaded.name}"
    elif source == "Generate fake logs":
        result = analyze_generated_profile(profile, rows)
        label = f"Generated fake logs: {profile} ({rows:,} rows)"
    else:
        if not DEFAULT_FILE.exists():
            st.info("No existing CSV found. Choose Generate fake logs, then click Run analysis.")
            return None
        result = analyze_default_file(str(DEFAULT_FILE))
        label = f"Existing local file: {DEFAULT_FILE}"
    st.session_state["analysis"] = (*result, label)
    return st.session_state["analysis"]


def apply_filters(logs: pd.DataFrame, alerts: pd.DataFrame, incidents: pd.DataFrame):
    """Apply sidebar filters."""
    if logs.empty:
        return logs, alerts, incidents
    st.sidebar.header("Filters")
    min_date = logs["timestamp"].dt.date.min()
    max_date = logs["timestamp"].dt.date.max()
    date_range = st.sidebar.date_input("Date range", value=(min_date, max_date), min_value=min_date, max_value=max_date)
    src_filter = st.sidebar.multiselect("Source IP", sorted(logs["src_ip"].dropna().astype(str).unique()))
    severity_filter = st.sidebar.multiselect("Severity", SEVERITY_ORDER)
    alert_type_options = sorted(alerts["alert_type"].dropna().astype(str).unique()) if not alerts.empty else []
    alert_type_filter = st.sidebar.multiselect("Alert type", alert_type_options)

    filtered_logs = logs.copy()
    filtered_alerts = alerts.copy()
    filtered_incidents = incidents.copy()
    if isinstance(date_range, tuple) and len(date_range) == 2:
        start, end = date_range
        filtered_logs = filtered_logs[(filtered_logs["timestamp"].dt.date >= start) & (filtered_logs["timestamp"].dt.date <= end)]
        if not filtered_alerts.empty:
            alert_dates = pd.to_datetime(filtered_alerts["timestamp"], errors="coerce").dt.date
            filtered_alerts = filtered_alerts[(alert_dates >= start) & (alert_dates <= end)]
        if not filtered_incidents.empty:
            starts = pd.to_datetime(filtered_incidents["start_time"], errors="coerce").dt.date
            ends = pd.to_datetime(filtered_incidents["end_time"], errors="coerce").dt.date
            filtered_incidents = filtered_incidents[(starts <= end) & (ends >= start)]
    if src_filter:
        filtered_logs = filtered_logs[filtered_logs["src_ip"].astype(str).isin(src_filter)]
        if not filtered_alerts.empty:
            filtered_alerts = filtered_alerts[filtered_alerts["src_ip"].astype(str).isin(src_filter)]
        if not filtered_incidents.empty:
            filtered_incidents = filtered_incidents[filtered_incidents["src_ip"].astype(str).isin(src_filter)]
    if severity_filter:
        if not filtered_alerts.empty:
            filtered_alerts = filtered_alerts[filtered_alerts["severity"].isin(severity_filter)]
        if not filtered_incidents.empty:
            filtered_incidents = filtered_incidents[filtered_incidents["severity"].isin(severity_filter)]
    if alert_type_filter:
        if not filtered_alerts.empty:
            filtered_alerts = filtered_alerts[filtered_alerts["alert_type"].isin(alert_type_filter)]
        if not filtered_incidents.empty:
            filtered_incidents = filtered_incidents[
                filtered_incidents["alert_types"].fillna("").apply(lambda value: any(item in value for item in alert_type_filter))
            ]
    return filtered_logs, filtered_alerts, filtered_incidents


def chart_layout(fig: go.Figure, height: int = 320) -> go.Figure:
    """Apply a consistent simple chart style."""
    fig.update_layout(
        height=height,
        template="plotly_white",
        margin={"l": 10, "r": 10, "t": 45, "b": 10},
        paper_bgcolor="rgba(255,255,255,0)",
        font={"color": "#334155"},
    )
    fig.update_xaxes(gridcolor="#eef2f7")
    fig.update_yaxes(gridcolor="#eef2f7")
    return fig


def render_header(label: str) -> None:
    st.markdown(
        f"""
        <div class="simple-header">
            <h1>Offline Log Forensic Analyzer</h1>
            <p>{label}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_downloads(
    logs: pd.DataFrame,
    alerts: pd.DataFrame,
    incidents: pd.DataFrame,
    summary: dict[str, int],
    source_label: str,
    top_sources: pd.DataFrame | None = None,
    top_ports: pd.DataFrame | None = None,
    top_dst_ips: pd.DataFrame | None = None,
) -> None:
    """Render report download controls."""
    try:
        pdf = build_visual_pdf_report(logs, alerts, incidents, summary, source_label, top_sources, top_ports, top_dst_ips)
        st.download_button("Download PDF report", pdf, "incident_report.pdf", "application/pdf")
    except Exception:
        st.warning("Visual PDF layout is unavailable (Playwright/Chromium not installed). Downloading standard text-only PDF.")
        pdf = build_pdf_report(logs, alerts, incidents, summary, top_sources, top_ports, top_dst_ips)
        st.download_button("Download PDF report", pdf, "incident_report.pdf", "application/pdf")


def render_overview(
    logs: pd.DataFrame,
    alerts: pd.DataFrame,
    incidents: pd.DataFrame,
    summary: dict[str, int],
    source_label: str,
    top_sources: pd.DataFrame | None = None,
    top_ports: pd.DataFrame | None = None,
    top_dst_ips: pd.DataFrame | None = None,
) -> None:
    """Render compact overview metrics and charts."""
    blocked = int((logs["action"] == "BLOCK").sum()) if not logs.empty else 0
    allowed = int((logs["action"] == "ALLOW").sum()) if not logs.empty else 0
    max_risk = int(incidents["risk_score"].max()) if not incidents.empty else 0
    critical = int((incidents["severity"] == "Critical").sum()) if not incidents.empty else 0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Events", f"{len(logs):,}")
    c2.metric("Alerts", f"{len(alerts):,}")
    c3.metric("Incidents", f"{len(incidents):,}", f"Critical: {critical}")
    c4.metric("Highest risk", max_risk)

    render_downloads(logs, alerts, incidents, summary, source_label, top_sources, top_ports, top_dst_ips)

    unavailable = logs.attrs.get("unavailable_columns", [])
    skipped = logs.attrs.get("skipped_detectors", [])
    if unavailable:
        st.info(f"Mapped the available fields. Missing source fields: {', '.join(unavailable)}.")
    if skipped:
        st.warning(f"Skipped detectors because their required fields are unavailable: {', '.join(skipped)}.")

    if logs.empty:
        st.info("No log events match the current filters.")
        return

    hourly = logs.set_index("timestamp").resample("h").size().reset_index(name="events")
    st.plotly_chart(chart_layout(px.line(hourly, x="timestamp", y="events", title="Events over time")), width="stretch")

    left, right = st.columns(2)
    with left:
        action_counts = pd.DataFrame({"action": ["ALLOW", "BLOCK"], "count": [allowed, blocked]})
        fig = px.bar(action_counts, x="action", y="count", title="Allowed vs blocked", color="action", color_discrete_map={"ALLOW": "#0f766e", "BLOCK": "#dc2626"})
        st.plotly_chart(chart_layout(fig), width="stretch")
    with right:
        if incidents.empty:
            st.info("No incidents detected.")
        else:
            severity_counts = incidents["severity"].value_counts().reindex(SEVERITY_ORDER, fill_value=0).reset_index()
            severity_counts.columns = ["severity", "count"]
            fig = px.bar(severity_counts, x="severity", y="count", title="Incidents by severity", color="severity", color_discrete_map=SEVERITY_COLORS)
            st.plotly_chart(chart_layout(fig), width="stretch")

    with st.expander("Cleaning summary"):
        st.json(summary)


def render_alerts(alerts: pd.DataFrame) -> None:
    """Render alert table."""
    search = st.text_input("Search alerts")
    visible = alerts.copy()
    if search and not visible.empty:
        visible = visible[visible.astype(str).apply(lambda row: row.str.contains(search, case=False, na=False).any(), axis=1)]
    if visible.empty:
        st.info("No alerts to show.")
        return
    columns = ["timestamp", "src_ip", "alert_type", "severity", "event_count", "score_contribution"]
    st.dataframe(
        visible[columns],
        width="stretch",
        hide_index=True,
        column_config={
            "event_count": st.column_config.NumberColumn("Events", format="%d"),
            "score_contribution": st.column_config.NumberColumn("Score", format="%d"),
        },
    )
    with st.expander("Show alert evidence"):
        st.dataframe(visible[["alert_id", "evidence"]], width="stretch", hide_index=True)
    st.download_button("Download alerts CSV", visible.to_csv(index=False).encode("utf-8"), "alerts.csv", "text/csv")


def render_incidents(incidents: pd.DataFrame) -> None:
    """Render incidents table."""
    if incidents.empty:
        st.info("No incidents to show.")
        return
    visible = incidents.sort_values("risk_score", ascending=False)
    columns = ["incident_id", "src_ip", "start_time", "end_time", "risk_score", "severity", "alert_types", "alert_count"]
    st.dataframe(
        visible[columns],
        width="stretch",
        hide_index=True,
        column_config={"risk_score": st.column_config.ProgressColumn("Risk", min_value=0, max_value=100, format="%d")},
    )
    st.download_button("Download incidents CSV", visible.to_csv(index=False).encode("utf-8"), "incidents.csv", "text/csv")


@st.cache_data(show_spinner=False)
def cached_ai_analysis(logs: pd.DataFrame, model_config: dict, working_hours: dict) -> pd.DataFrame:
    """Cache model fitting independently from the display-only score threshold."""
    features = build_behavioral_features(logs, model_config["window_minutes"], working_hours["start_hour"], working_hours["end_hour"])
    detector_config = dict(model_config)
    detector_config["anomaly_threshold"] = 0
    return detect_ai_anomalies(features, detector_config)


def render_ai_analytics(logs: pd.DataFrame, alerts: pd.DataFrame, incidents: pd.DataFrame) -> None:
    """Render local AI findings and filtered traffic summaries."""
    config = load_config("config.yaml")
    ai_config = dict(config["ai_detection"])
    enabled = st.checkbox("Enable AI anomaly detection", value=bool(ai_config["enabled"]), help="Runs Isolation Forest locally. No log data leaves this computer.")
    left, right = st.columns(2)
    with left:
        ai_config["anomaly_threshold"] = st.slider("AI score threshold", 0, 100, int(ai_config["anomaly_threshold"]))
    with right:
        ai_config["contamination"] = st.slider("Expected anomaly fraction", 0.001, 0.5, float(ai_config["contamination"]), 0.001)
    sources = top_source_ips(logs, alerts, incidents, config["analytics"]["top_n"])
    ports = top_destination_ports(logs, config["analytics"]["top_n"])
    model_config = {key: value for key, value in ai_config.items() if key != "anomaly_threshold"}
    ai_results = cached_ai_analysis(logs, model_config, config["working_hours"]) if enabled else pd.DataFrame()
    if not ai_results.empty:
        ai_results = ai_results.copy()
        ai_results["is_ai_anomaly"] = ai_results["isolation_forest_prediction"].eq(-1) & ai_results["ai_anomaly_score"].ge(ai_config["anomaly_threshold"])
    anomalies = ai_results[ai_results["is_ai_anomaly"]] if not ai_results.empty and "is_ai_anomaly" in ai_results else pd.DataFrame()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("AI anomalies", len(anomalies))
    c2.metric("Highest AI score", f"{ai_results['ai_anomaly_score'].max():.2f}" if not ai_results.empty else "0.00")
    c3.metric("Source IPs analyzed", logs["src_ip"].nunique() if "src_ip" in logs else 0)
    c4.metric("Destination ports observed", logs["dst_port"].nunique() if "dst_port" in logs else 0)

    st.subheader("AI anomaly analysis")
    if not enabled:
        st.info("AI detection is disabled. Traffic summaries are still available below.")
    elif ai_results.empty:
        st.warning(ai_results.attrs.get("warning", "AI detection could not be performed for this dataset."))
    else:
        st.warning(ai_results.attrs.get("warning", "AI anomalies require human validation."))
        chart_data = ai_results.head(30).copy()
        chart_data["window_label"] = chart_data["src_ip"].astype(str) + " | " + chart_data["window_start"].astype(str)
        fig = px.bar(chart_data.sort_values("ai_anomaly_score"), x="ai_anomaly_score", y="window_label", orientation="h", title="Highest AI anomaly scores")
        st.plotly_chart(chart_layout(fig, 520), width="stretch")
        shown = anomalies if not anomalies.empty else ai_results.head(20)
        columns = ["src_ip", "window_start", "connection_count", "unique_dst_ips", "unique_dst_ports", "blocked_ratio", "bytes_sent_total", "ai_anomaly_score", "is_ai_anomaly", "ai_explanation"]
        st.dataframe(shown[columns], width="stretch", hide_index=True)
        choices = [f"{row.src_ip} | {row.window_start} | score {row.ai_anomaly_score:.2f}" for row in shown.itertuples()]
        if choices:
            selected = st.selectbox("Explain a selected window", choices)
            st.info(shown.iloc[choices.index(selected)]["ai_explanation"])
        st.download_button("Download AI anomalies CSV", anomalies.to_csv(index=False).encode("utf-8"), "anomalies.csv", "text/csv")

    st.subheader("Most active source IPs")
    if sources.empty:
        st.warning("Source-IP analytics are unavailable because no source IP data is present.")
    else:
        fig = px.bar(sources.sort_values("total_events"), x="total_events", y="src_ip", orientation="h", title="Top active source IPs")
        st.plotly_chart(chart_layout(fig), width="stretch")
        st.dataframe(sources, width="stretch", hide_index=True)
        st.download_button("Download source IP analytics CSV", sources.to_csv(index=False).encode("utf-8"), "top_source_ips.csv", "text/csv")

    st.subheader("Most frequently used destination ports")
    if ports.empty:
        st.warning("Port analytics are unavailable because no destination-port data is present.")
    else:
        port_chart = ports.copy()
        port_chart["port_label"] = port_chart["dst_port"].astype(str) + " - " + port_chart["service_name"]
        fig = px.bar(port_chart.sort_values("total_events"), x="total_events", y="port_label", orientation="h", title="Top destination ports")
        st.plotly_chart(chart_layout(fig), width="stretch")
        st.dataframe(ports, width="stretch", hide_index=True)
        st.download_button("Download destination-port analytics CSV", ports.to_csv(index=False).encode("utf-8"), "top_destination_ports.csv", "text/csv")


def build_timeline(related_alerts: pd.DataFrame, related_events: pd.DataFrame) -> pd.DataFrame:
    """Build a clearer incident timeline from actual timestamps."""
    rows: list[dict[str, object]] = []
    if not related_events.empty:
        first = related_events.iloc[0]
        rows.append({"time": first["timestamp"], "activity": "First related event", "details": f"{first['action']} {first['protocol']} to {first['dst_ip']}:{first['dst_port']}"})
    for _, alert in related_alerts.iterrows():
        rows.append(
            {
                "time": pd.to_datetime(alert["timestamp"], errors="coerce"),
                "activity": f"{alert['alert_type']} threshold reached",
                "details": f"{int(alert['event_count'])} event(s), score +{int(alert['score_contribution'])}",
            }
        )
    if not related_events.empty:
        last = related_events.iloc[-1]
        rows.append({"time": last["timestamp"], "activity": "Last related event", "details": f"{last['action']} {last['protocol']} to {last['dst_ip']}:{last['dst_port']}"})
    return pd.DataFrame(rows).sort_values("time") if rows else pd.DataFrame(columns=["time", "activity", "details"])


def render_investigation(logs: pd.DataFrame, alerts: pd.DataFrame, incidents: pd.DataFrame) -> None:
    """Render one incident investigation."""
    if incidents.empty:
        st.info("No incidents available for investigation.")
        return
    ordered = incidents.sort_values("risk_score", ascending=False)
    labels = [f"{row.incident_id} | {row.severity} | risk {int(row.risk_score)} | {row.src_ip}" for row in ordered.itertuples()]
    selected = st.selectbox("Incident", labels)
    incident_id = selected.split(" | ", 1)[0]
    incident = ordered[ordered["incident_id"] == incident_id].iloc[0]

    start = pd.to_datetime(incident["start_time"])
    end = pd.to_datetime(incident["end_time"])
    related_alerts = alerts[(alerts["src_ip"] == incident["src_ip"]) & (pd.to_datetime(alerts["timestamp"]) >= start) & (pd.to_datetime(alerts["timestamp"]) <= end)].sort_values("timestamp")
    related_events = logs[(logs["src_ip"] == incident["src_ip"]) & (logs["timestamp"] >= start) & (logs["timestamp"] <= end)].sort_values("timestamp")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Incident", incident["incident_id"])
    c2.metric("Risk", int(incident["risk_score"]))
    c3.metric("Severity", incident["severity"])
    c4.metric("Source", incident["src_ip"])

    st.write(incident["explanation"])
    left, right = st.columns(2)
    with left:
        st.subheader("Score breakdown")
        st.code(str(incident["score_breakdown"]).replace(" | ", "\n"))
    with right:
        st.subheader("Recommendations")
        for item in str(incident["recommendations"]).split(" | "):
            if item:
                st.write(f"- {item}")

    st.subheader("Timeline")
    st.dataframe(build_timeline(related_alerts, related_events), width="stretch", hide_index=True)

    st.subheader("Related raw events")
    columns = ["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "action", "bytes_sent", "bytes_received"]
    st.dataframe(related_events[columns], width="stretch", hide_index=True)


def main() -> None:
    st.set_page_config(page_title="Offline Log Forensic Analyzer", layout="wide")
    inject_styles()
    source, profile, rows, uploaded, run_clicked = render_sidebar()

    try:
        analysis = get_analysis(source, profile, rows, uploaded, run_clicked)
    except Exception as exc:
        st.error(str(exc))
        return
    if analysis is None:
        return

    logs, alerts, incidents, summary, label = analysis
    filtered_logs, filtered_alerts, filtered_incidents = apply_filters(logs, alerts, incidents)
    render_header(label)

    # Pre-compute traffic analytics for both the Overview tab and the PDF report
    config = load_config("config.yaml")
    top_n = config["analytics"]["top_n"]
    rpt_top_sources = top_source_ips(filtered_logs, filtered_alerts, filtered_incidents, top_n)
    rpt_top_ports = top_destination_ports(filtered_logs, top_n)
    rpt_top_dst_ips = top_destination_ips(filtered_logs, top_n)

    overview, alerts_tab, incidents_tab, investigation, analytics_tab = st.tabs(["Overview", "Alerts", "Incidents", "Investigation", "AI & Traffic Analytics"])
    with overview:
        render_overview(filtered_logs, filtered_alerts, filtered_incidents, summary, label, rpt_top_sources, rpt_top_ports, rpt_top_dst_ips)
    with alerts_tab:
        render_alerts(filtered_alerts)
    with incidents_tab:
        render_incidents(filtered_incidents)
    with investigation:
        render_investigation(filtered_logs, filtered_alerts, filtered_incidents)
    with analytics_tab:
        render_ai_analytics(filtered_logs, filtered_alerts, filtered_incidents)


if __name__ == "__main__":
    main()
