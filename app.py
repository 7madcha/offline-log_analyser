"""Plotly Dash dashboard for the Offline Log Forensic Analyzer.

100% local / air-gapped: no CDN stylesheets, no external fonts, no network
calls. All styling lives in ./assets/theme.css, which Dash serves locally.

Every analysis, detection, scoring, and reporting behavior comes directly
from the src/ package.
"""

from __future__ import annotations

import base64
import io
import json
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from dash import Dash, Input, Output, State, dash_table, dcc, html, no_update

from src.analysis_settings import AnalysisMode, AnalysisSettings, SettingsValidationError, effective_analysis_mode
from src.ai_detector import detect_ai_anomalies
from src.ai_features import build_behavioral_features
from src.cleaner import clean_logs
from src.correlator import correlate_alerts
from src.custom_analysis import analyze_dataframe_with_custom_settings
from src.detectors import run_all_detectors
from src.generate_logs import generate_firewall_logs
from src.loader import load_logs, load_uploaded_logs
from src.reporting import build_pdf_report, build_visual_pdf_report, csv_schema_template
from src.schema_mapper import map_log_schema
from src.traffic_analytics import top_destination_ips, top_destination_ports, top_source_ips
from src.utils import ensure_directory, load_config
from src.validator import validate_columns, validate_dataset

DEFAULT_FILE = Path("data/synthetic/firewall_logs.csv")
SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]
SEVERITY_COLORS = {"Low": "#2563EB", "Medium": "#B45309", "High": "#C2410C", "Critical": "#B91C1C"}
SAMPLE_PROFILES = {
    "Normal": {"profile": "normal", "rows": 8_000, "seed": 101},
    "Noisy": {"profile": "noisy", "rows": 12_000, "seed": 202},
    "Attack-heavy": {"profile": "attack-heavy", "rows": 50_000, "seed": 42},
}

# ---------------------------------------------------------------------------
# Server-side state. Single-user, local, offline in-memory state dictionary
# to avoid round-tripping full DataFrames through JSON on every callback.
# ---------------------------------------------------------------------------
def _empty_analysis_state() -> dict[str, object]:
    """Return a fresh dashboard state for a new browser page load."""
    return {
        "logs": pd.DataFrame(),
        "alerts": pd.DataFrame(),
        "incidents": pd.DataFrame(),
        "summary": {},
        "label": "",
        "baselining_enabled": False,
        "analysis_mode": AnalysisMode.STANDARD.value,
        "custom_settings": None,
        "filtered_logs": pd.DataFrame(),
        "filtered_alerts": pd.DataFrame(),
        "filtered_incidents": pd.DataFrame(),
        "top_sources": pd.DataFrame(),
        "top_ports": pd.DataFrame(),
        "top_dst_ips": pd.DataFrame(),
        "ai_fit_cache": {},
        "ai_anomalies": pd.DataFrame(),
        "comparison_result": None,
    }


_STATE: dict[str, object] = _empty_analysis_state()


def _reset_analysis_state() -> None:
    """Discard results retained by a previous analysis in this process."""
    _STATE.clear()
    _STATE.update(_empty_analysis_state())


class _UploadedFile(io.BytesIO):
    """Adapts a Dash dcc.Upload payload to the `.name` + file-like API that
    src.loader.load_uploaded_logs expects."""

    def __init__(self, data: bytes, name: str) -> None:
        super().__init__(data)
        self.name = name


def _decode_upload(contents: str, filename: str) -> _UploadedFile:
    _header, b64data = contents.split(",", 1)
    return _UploadedFile(base64.b64decode(b64data), filename)


# ---------------------------------------------------------------------------
# Analysis pipeline (pure functions over src/, no UI framework calls in here)
# ---------------------------------------------------------------------------


def analyze_dataframe(raw: pd.DataFrame, config_path: str = "config.yaml", baselining_enabled: bool | None = None):
    config = load_config(config_path)
    if baselining_enabled is not None:
        config.setdefault("baselining", {})["enabled"] = baselining_enabled
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


def analyze_default_file(path: str, baselining_enabled: bool | None = None):
    return analyze_dataframe(load_logs(path), baselining_enabled=baselining_enabled)


def analyze_generated_profile(name: str, rows: int, baselining_enabled: bool | None = None):
    options = SAMPLE_PROFILES[name]
    raw = generate_firewall_logs(rows=rows, seed=options["seed"], profile=options["profile"])
    ensure_directory(DEFAULT_FILE.parent)
    raw.to_csv(DEFAULT_FILE, index=False, encoding="utf-8")
    return analyze_dataframe(raw, baselining_enabled=baselining_enabled)


def analyze_uploaded_file(uploaded_file, baselining_enabled: bool | None = None):
    return analyze_dataframe(load_uploaded_logs(uploaded_file), baselining_enabled=baselining_enabled)


def apply_filters(logs, alerts, incidents, start_date, end_date, src_filter, severity_filter, alert_type_filter):
    if logs.empty:
        return logs, alerts, incidents
    filtered_logs, filtered_alerts, filtered_incidents = logs.copy(), alerts.copy(), incidents.copy()
    if start_date and end_date:
        start = pd.to_datetime(start_date).date()
        end = pd.to_datetime(end_date).date()
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


def build_timeline(related_alerts: pd.DataFrame, related_events: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, object]] = []
    if not related_events.empty:
        first = related_events.iloc[0]
        rows.append({"time": first["timestamp"], "activity": "First related event", "details": f"{first['action']} {first['protocol']} to {first['dst_ip']}:{first['dst_port']}"})
    for _, alert in related_alerts.iterrows():
        rows.append({
            "time": pd.to_datetime(alert["timestamp"], errors="coerce"),
            "activity": f"{alert['alert_type']} threshold reached",
            "details": f"{int(alert['event_count'])} event(s), score +{int(alert['score_contribution'])}",
        })
    if not related_events.empty:
        last = related_events.iloc[-1]
        rows.append({"time": last["timestamp"], "activity": "Last related event", "details": f"{last['action']} {last['protocol']} to {last['dst_ip']}:{last['dst_port']}"})
    return pd.DataFrame(rows).sort_values("time") if rows else pd.DataFrame(columns=["time", "activity", "details"])


# ---------------------------------------------------------------------------
# Dark SOC chart / table styling helpers
# ---------------------------------------------------------------------------


def chart_layout(fig: go.Figure, height: int = 320) -> go.Figure:
    fig.update_layout(
        height=height,
        template="plotly_white",
        margin={"l": 10, "r": 10, "t": 45, "b": 10},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#6B675F", "family": "-apple-system, Segoe UI, system-ui, sans-serif"},
        title_font={"color": "#23211D", "size": 14},
        legend={"bgcolor": "rgba(0,0,0,0)"},
    )
    fig.update_xaxes(gridcolor="#E5E2D9", zerolinecolor="#D8D4C7")
    fig.update_yaxes(gridcolor="#E5E2D9", zerolinecolor="#D8D4C7")
    return fig


TABLE_STYLE = dict(
    style_table={"overflowX": "auto", "borderRadius": "8px", "border": "1px solid #E5E2D9"},
    style_header={
        "backgroundColor": "#FAF9F5",
        "color": "#6B675F",
        "fontWeight": "700",
        "fontSize": "0.74rem",
        "textTransform": "uppercase",
        "letterSpacing": "0.04em",
        "border": "none",
        "borderBottom": "1px solid #E5E2D9",
    },
    style_cell={
        "backgroundColor": "#FFFFFF",
        "color": "#23211D",
        "border": "none",
        "borderBottom": "1px solid #F0EEE6",
        "fontSize": "0.82rem",
        "padding": "8px 10px",
        "fontFamily": "-apple-system, Segoe UI, system-ui, sans-serif",
        "textAlign": "left",
        "maxWidth": "320px",
        "overflow": "hidden",
        "textOverflow": "ellipsis",
    },
    style_data={"backgroundColor": "#FFFFFF"},
    style_as_list_view=True,
    page_size=12,
    sort_action="native",
    filter_action="native",
    style_filter={"backgroundColor": "#FAF9F5"},
)

SEVERITY_CONDITIONAL = [
    {
        "if": {"filter_query": f'{{severity}} = "{sev}"', "column_id": "severity"},
        "color": color,
        "fontWeight": "700",
    }
    for sev, color in SEVERITY_COLORS.items()
]


def data_table(df: pd.DataFrame, columns: list[str] | None = None, id: str | None = None, extra_conditional=None, **kwargs):
    cols = columns or list(df.columns)
    view = df[cols] if not df.empty else pd.DataFrame(columns=cols)
    style_conditional = list(SEVERITY_CONDITIONAL)
    if extra_conditional:
        style_conditional.extend(extra_conditional)
    props = dict(TABLE_STYLE)
    props.update(kwargs)
    return dash_table.DataTable(
        id=id or {"type": "generic-table", "index": cols[0] if cols else "t"},
        data=view.to_dict("records"),
        columns=[{"name": c.replace("_", " ").title(), "id": c} for c in cols],
        style_data_conditional=style_conditional,
        **props,
    )


def kpi_card(label: str, value: str, delta: str | None = None, accent: str | None = None) -> html.Div:
    value_class = "kpi-value" + (f" accent-{accent}" if accent else "")
    children = [html.Div(label, className="kpi-label"), html.Div(value, className=value_class)]
    if delta:
        children.append(html.Div(delta, className="kpi-delta"))
    return html.Div(children, className="kpi-card")


def panel(title: str | None, children, extra_class: str = "") -> html.Div:
    body = ([html.Div(title, className="panel-title")] if title else []) + (children if isinstance(children, list) else [children])
    return html.Div(body, className=f"panel {extra_class}".strip())


def callout(kind: str, text: str) -> html.Div:
    return html.Div(text, className=f"callout callout-{kind}")


def row(children, className: str = "") -> html.Div:
    return html.Div(children, className=f"row {className}".strip())


def col(children, width: int | None = None, className: str = "") -> html.Div:
    cls = f"col-{width}" if width else "col"
    return html.Div(children, className=f"{cls} {className}".strip())


def download_button(label: str, btn_id: str, dl_id: str) -> html.Div:
    return html.Div(
        [html.Button(label, id=btn_id, n_clicks=0, className="btn-secondary"), dcc.Download(id=dl_id)],
        style={"marginTop": "0.6rem"},
    )


def _csv_bytes(df: pd.DataFrame) -> str:
    return df.to_csv(index=False)


# ---------------------------------------------------------------------------
# App + static layout
# ---------------------------------------------------------------------------

app = Dash(__name__, suppress_callback_exceptions=True, title="Offline Log Forensic Analyzer")
server = app.server

_base_config = load_config("config.yaml")
_default_custom_settings = AnalysisSettings.from_config(_base_config)


def build_sidebar() -> html.Div:
    return html.Div(
        [
            html.Div(
                [html.Span(className="brand-dot"), html.Span("OFFLINE ANALYZER", className="brand-title")],
                className="brand",
            ),
            html.P("Local files and synthetic data only. No network access.", className="brand-caption"),
            html.Div(
                [
                    html.Div("Data source", className="sidebar-section-title"),
                    dcc.RadioItems(
                        id="input-source",
                        options=[
                            {"label": "Generate", "value": "generate"},
                            {"label": "Upload", "value": "upload"},
                            {"label": "Existing", "value": "existing"},
                        ],
                        value="generate",
                        className="radio-group segmented",
                        labelStyle={"display": "flex"},
                    ),
                    html.Div(
                        [
                            html.Label("Fake log type", className="control-label"),
                            dcc.Dropdown(
                                id="gen-profile",
                                options=[{"label": k, "value": k} for k in SAMPLE_PROFILES],
                                value="Attack-heavy",
                                clearable=False,
                            ),
                            html.Label("Rows", className="control-label"),
                            dcc.Input(id="gen-rows", type="number", min=100, max=200_000, step=1000, value=SAMPLE_PROFILES["Attack-heavy"]["rows"], className="dash-input"),
                        ],
                        id="gen-controls",
                        style={"marginTop": "0.7rem"},
                    ),
                    html.Div(
                        [
                            html.Label("Select CSV, JSON, JSONL, or NDJSON", className="control-label"),
                            dcc.Upload(
                                id="upload-data",
                                children=html.Div(["Drag & drop or ", html.A("browse a file")]),
                                style={
                                    "border": "1px dashed var(--border-strong)", "borderRadius": "8px", "padding": "1rem",
                                    "textAlign": "center", "color": "var(--text-muted)", "fontSize": "0.82rem", "cursor": "pointer",
                                },
                                multiple=False,
                            ),
                            html.Div(id="upload-filename", className="small-muted", style={"marginTop": "0.4rem"}),
                        ],
                        id="upload-controls",
                        style={"display": "none", "marginTop": "0.7rem"},
                    ),
                    html.Div(
                        f"Uses {DEFAULT_FILE}",
                        id="existing-controls",
                        className="small-muted",
                        style={"display": "none", "marginTop": "0.7rem"},
                    ),
                    html.Div(
                        dcc.Checklist(
                            id="comparison-toggle",
                            options=[{"label": " Compare with a second file", "value": "on"}],
                            value=[],
                            labelStyle={"display": "flex", "alignItems": "center", "gap": "0.5rem"},
                        ),
                        className="toggle-group",
                        style={"marginTop": "0.85rem"},
                    ),
                    html.Div(
                        [
                            html.Label("Second file (File B)", className="control-label"),
                            dcc.Upload(
                                id="comparison-upload-data",
                                children=html.Div(["Drag & drop or ", html.A("browse the second file")]),
                                style={
                                    "border": "1px dashed var(--border-strong)", "borderRadius": "8px", "padding": "1rem",
                                    "textAlign": "center", "color": "var(--text-muted)", "fontSize": "0.82rem", "cursor": "pointer",
                                },
                                multiple=False,
                            ),
                            html.Div(id="comparison-upload-filename", className="small-muted", style={"marginTop": "0.4rem"}),
                            html.P("File A is the data source selected above. Both files must use the same format.", className="small-muted", style={"margin": "0.45rem 0 0"}),
                        ],
                        id="comparison-upload-controls",
                        style={"display": "none", "marginTop": "0.7rem"},
                    ),
                    html.Button("Run analysis", id="run-button", n_clicks=0, className="btn-primary", style={"marginTop": "0.85rem"}),
                    html.Div(
                        [html.Button("Download CSV template", id="btn-csv-template", n_clicks=0, className="btn-link"), dcc.Download(id="dl-csv-template")],
                        style={"marginTop": "0.5rem", "textAlign": "center"},
                    ),
                ],
                className="sidebar-card",
            ),
            html.Div(
                [
                    html.Div("Detection settings", className="sidebar-section-title"),
                    html.Div(
                        dcc.Checklist(
                            id="baseline-toggle",
                            options=[{"label": " Per-asset baselining", "value": "on"}],
                            value=[],
                            labelStyle={"display": "flex", "alignItems": "center", "gap": "0.5rem"},
                        ),
                        className="toggle-group",
                    ),
                    html.P(
                        "Adapts thresholds to each host's own history instead of one global value.",
                        className="small-muted",
                        style={"margin": "0.35rem 0 0 0"},
                    ),
                    html.Hr(className="side-divider"),
                    html.Div(
                        dcc.Checklist(
                            id="custom-settings-toggle",
                            options=[{"label": " Use custom analysis settings", "value": "on"}],
                            value=[],
                            labelStyle={"display": "flex", "alignItems": "center", "gap": "0.5rem"},
                        ),
                        className="toggle-group",
                    ),
                    html.P(
                        "Custom mode takes precedence over per-asset baselining for this analysis.",
                        className="small-muted",
                        style={"margin": "0.35rem 0 0 0"},
                    ),
                    html.Div(
                        [
                            html.Label("Blocked attempts", className="control-label"),
                            dcc.Input(id="custom-brute-attempts", type="number", min=1, step=1, value=_default_custom_settings.brute_force_blocked_attempts, className="dash-input"),
                            html.Label("Blocked-attempt window (minutes)", className="control-label"),
                            dcc.Input(id="custom-brute-window", type="number", min=1, step=1, value=_default_custom_settings.brute_force_window_minutes, className="dash-input"),
                            html.Label("Monitored destination ports", className="control-label"),
                            dcc.Input(id="custom-brute-ports", type="text", value=", ".join(map(str, _default_custom_settings.brute_force_destination_ports)), placeholder="22, 23, 3389", className="dash-input"),
                            html.Label("Port-scan unique ports", className="control-label"),
                            dcc.Input(id="custom-port-threshold", type="number", min=1, step=1, value=_default_custom_settings.port_scan_unique_ports, className="dash-input"),
                            html.Label("Port-scan window (minutes)", className="control-label"),
                            dcc.Input(id="custom-port-window", type="number", min=1, step=1, value=_default_custom_settings.port_scan_window_minutes, className="dash-input"),
                            html.Label("Host-scan unique destinations", className="control-label"),
                            dcc.Input(id="custom-host-threshold", type="number", min=1, step=1, value=_default_custom_settings.host_scan_unique_destinations, className="dash-input"),
                            html.Label("Host-scan window (minutes)", className="control-label"),
                            dcc.Input(id="custom-host-window", type="number", min=1, step=1, value=_default_custom_settings.host_scan_window_minutes, className="dash-input"),
                            html.Label("Large-transfer percentile", className="control-label"),
                            dcc.Input(id="custom-transfer-percentile", type="number", min=0.001, max=1, step=0.001, value=float(_default_custom_settings.large_transfer_percentile), className="dash-input"),
                            html.Label("Minimum outbound bytes", className="control-label"),
                            dcc.Input(id="custom-transfer-bytes", type="number", min=1, step=1, value=_default_custom_settings.large_transfer_minimum_bytes, className="dash-input"),
                            html.Label("Off-hours start (0-23)", className="control-label"),
                            dcc.Input(id="custom-offhours-start", type="number", min=0, max=23, step=1, value=_default_custom_settings.off_hours_start_hour, className="dash-input"),
                            html.Label("Off-hours end (0-24)", className="control-label"),
                            dcc.Input(id="custom-offhours-end", type="number", min=0, max=24, step=1, value=_default_custom_settings.off_hours_end_hour, className="dash-input"),
                        ],
                        id="custom-settings-controls",
                        style={"display": "none", "marginTop": "0.7rem"},
                    ),
                ],
                className="sidebar-card",
            ),
            html.Details(
                [
                    html.Summary("Filters", className="sidebar-section-title", style={"cursor": "pointer", "display": "inline-block"}),
                    html.Label("Date range", className="control-label"),
                    dcc.DatePickerRange(id="filter-daterange", display_format="YYYY-MM-DD", style={"width": "100%"}),
                    html.Label("Source IP", className="control-label"),
                    dcc.Dropdown(id="filter-srcip", options=[], value=[], multi=True),
                    html.Label("Severity", className="control-label"),
                    dcc.Dropdown(id="filter-severity", options=[{"label": s, "value": s} for s in SEVERITY_ORDER], value=[], multi=True),
                    html.Label("Alert type", className="control-label"),
                    dcc.Dropdown(id="filter-alerttype", options=[], value=[], multi=True),
                ],
                className="sidebar-card",
                open=True,
            ),
            html.P("Local only: no scanning, APIs, VPN, or company system access.", className="small-muted", style={"marginTop": "1rem", "padding": "0 0.1rem"}),
            dcc.Store(id="store-data-version", data=0),
            dcc.Store(id="store-filter-version", data=0),
        ],
        className="sidebar",
    )


def build_overview_tab() -> html.Div:
    return html.Div(id="overview-content", className="loading-wrap")


def build_alerts_tab() -> html.Div:
    return html.Div(
        [
            dcc.Input(id="alerts-search", type="text", placeholder="Search alerts…", className="dash-input", style={"maxWidth": "320px", "marginBottom": "0.8rem"}),
            html.Div(id="alerts-content", className="loading-wrap"),
        ]
    )


def build_incidents_tab() -> html.Div:
    return html.Div(id="incidents-content", className="loading-wrap")


def build_investigation_tab() -> html.Div:
    return html.Div(
        [
            html.Label("Incident", className="control-label"),
            dcc.Dropdown(id="incident-dropdown", options=[], value=None, clearable=False),
            html.Div(id="investigation-content", className="loading-wrap", style={"marginTop": "0.8rem"}),
        ]
    )


def build_analytics_tab() -> html.Div:
    ai_cfg = _base_config.get("ai_detection", {})
    ai_settings = panel(
        "AI settings",
        row([
            col(dcc.Checklist(
                id="ai-enable",
                options=[{"label": " Enable AI anomaly detection", "value": "on"}],
                value=["on"] if ai_cfg.get("enabled", True) else [],
            ), width=4, className="toggle-group"),
            col([
                html.Label("AI score threshold", className="control-label"),
                dcc.Slider(id="ai-threshold", min=0, max=100, step=1, value=int(ai_cfg.get("anomaly_threshold", 60)), marks=None, tooltip={"placement": "bottom", "always_visible": False}),
            ], width=4),
            col([
                html.Label("Expected anomaly fraction", className="control-label"),
                dcc.Slider(id="ai-contamination", min=0.001, max=0.5, step=0.001, value=float(ai_cfg.get("contamination", 0.02)), marks=None, tooltip={"placement": "bottom", "always_visible": False}),
            ], width=4),
        ]),
    )
    return html.Div(
        [
            ai_settings,
            html.Div(id="analytics-ai-content", className="loading-wrap"),
            html.Div(id="analytics-traffic-content", className="loading-wrap"),
        ]
    )


def build_comparison_tab() -> html.Div:
    return html.Div(
        [
            html.Div(id="comparison-content", className="loading-wrap"),
            html.Div(
                [
                    html.Button("Download comparison HTML report", id="btn-comparison-report", n_clicks=0, className="btn-secondary"),
                    dcc.Download(id="dl-comparison-report"),
                ],
                id="comparison-download-wrap",
                style={"display": "none", "marginTop": "0.8rem"},
            ),
        ]
    )


def render_header(label: str, status: str | None = None, show_download: bool = False) -> html.Div:
    right_children = []
    if status:
        right_children.append(html.Span(status, className="status-pill"))
    if show_download:
        right_children += [
            html.Button("Download PDF report", id="btn-pdf-report", n_clicks=0, className="btn-secondary", style={"width": "auto"}),
            dcc.Download(id="dl-pdf-report"),
        ]
    else:
        # Keep the button/Download component present (with a stable id) even
        # before the first analysis run, so the download callback has
        # something registered to bind to as soon as it does exist.
        right_children += [html.Button("Download PDF report", id="btn-pdf-report", n_clicks=0, className="btn-secondary", disabled=True, style={"width": "auto"}), dcc.Download(id="dl-pdf-report")]
    return html.Div(
        [
            html.Div([html.H1("Offline Log Forensic Analyzer"), html.P(label)]),
            html.Div(right_children, style={"display": "flex", "alignItems": "center", "gap": "0.7rem"}),
        ],
        className="page-header",
    )


def build_layout() -> html.Div:
    # Dash calls the layout factory when a browser loads/reloads the app. Clear
    # the single-user in-memory results so an old analysis is never rendered
    # as if it belonged to the new page session.
    _reset_analysis_state()
    return html.Div(
        [
            build_sidebar(),
            html.Div(
                [
                    html.Div(render_header("Choose a data source in the sidebar, then click Run analysis."), id="page-header"),
                    html.Div(id="error-banner"),
                    dcc.Tabs(
                        id="tabs",
                        value="overview",
                        className="custom-tabs",
                        children=[
                            dcc.Tab(label="Overview", value="overview", className="custom-tab", selected_className="custom-tab--selected", children=[build_overview_tab()]),
                            dcc.Tab(label="Alerts", value="alerts", className="custom-tab", selected_className="custom-tab--selected", children=[build_alerts_tab()]),
                            dcc.Tab(label="Incidents", value="incidents", className="custom-tab", selected_className="custom-tab--selected", children=[build_incidents_tab()]),
                            dcc.Tab(label="Investigation", value="investigation", className="custom-tab", selected_className="custom-tab--selected", children=[build_investigation_tab()]),
                            dcc.Tab(label="AI & Traffic Analytics", value="analytics", className="custom-tab", selected_className="custom-tab--selected", children=[build_analytics_tab()]),
                            dcc.Tab(label="Comparison", value="comparison", className="custom-tab", selected_className="custom-tab--selected", children=[build_comparison_tab()]),
                        ],
                    ),
                ],
                className="main-area",
            ),
        ],
        className="app-shell",
    )


app.layout = build_layout


# ---------------------------------------------------------------------------
# Callbacks — sidebar reactivity
# ---------------------------------------------------------------------------


@app.callback(Output("gen-rows", "value"), Input("gen-profile", "value"))
def sync_rows_with_profile(profile: str):
    return SAMPLE_PROFILES[profile]["rows"]


@app.callback(
    Output("gen-controls", "style"),
    Output("upload-controls", "style"),
    Output("existing-controls", "style"),
    Input("input-source", "value"),
)
def toggle_source_controls(source: str):
    hidden, shown = {"display": "none"}, {"display": "block"}
    return (
        shown if source == "generate" else hidden,
        shown if source == "upload" else hidden,
        shown if source == "existing" else hidden,
    )


@app.callback(Output("upload-filename", "children"), Input("upload-data", "filename"))
def show_upload_filename(filename):
    return f"Selected: {filename}" if filename else ""


@app.callback(Output("comparison-upload-controls", "style"), Input("comparison-toggle", "value"))
def toggle_comparison_controls(comparison_value):
    return {"display": "block", "marginTop": "0.7rem"} if "on" in (comparison_value or []) else {"display": "none", "marginTop": "0.7rem"}


@app.callback(Output("custom-settings-controls", "style"), Input("custom-settings-toggle", "value"))
def toggle_custom_settings_controls(custom_value):
    return {"display": "block", "marginTop": "0.7rem"} if "on" in (custom_value or []) else {"display": "none", "marginTop": "0.7rem"}


def _integer_custom_control(name: str, value) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not float(value).is_integer():
        raise SettingsValidationError(f"{name} must be a whole number.")
    return int(value)


def custom_settings_from_dashboard(
    brute_attempts,
    brute_window,
    brute_ports,
    port_threshold,
    port_window,
    host_threshold,
    host_window,
    transfer_percentile,
    transfer_bytes,
    offhours_start,
    offhours_end,
) -> AnalysisSettings:
    """Validate Dash control values and return one immutable settings object."""
    if not isinstance(brute_ports, str) or not brute_ports.strip():
        raise SettingsValidationError("Monitored destination ports must be a comma-separated list.")
    try:
        destination_ports = tuple(int(value.strip()) for value in brute_ports.split(",") if value.strip())
    except ValueError as exc:
        raise SettingsValidationError("Monitored destination ports must contain only whole numbers separated by commas.") from exc
    if isinstance(transfer_percentile, bool) or not isinstance(transfer_percentile, (int, float)):
        raise SettingsValidationError("Large-transfer percentile must be numeric.")

    return AnalysisSettings(
        brute_force_blocked_attempts=_integer_custom_control("Blocked attempts", brute_attempts),
        brute_force_window_minutes=_integer_custom_control("Blocked-attempt window", brute_window),
        brute_force_destination_ports=destination_ports,
        port_scan_unique_ports=_integer_custom_control("Port-scan unique ports", port_threshold),
        port_scan_window_minutes=_integer_custom_control("Port-scan window", port_window),
        host_scan_unique_destinations=_integer_custom_control("Host-scan unique destinations", host_threshold),
        host_scan_window_minutes=_integer_custom_control("Host-scan window", host_window),
        large_transfer_percentile=float(transfer_percentile),
        large_transfer_minimum_bytes=_integer_custom_control("Minimum outbound bytes", transfer_bytes),
        off_hours_start_hour=_integer_custom_control("Off-hours start", offhours_start),
        off_hours_end_hour=_integer_custom_control("Off-hours end", offhours_end),
    )


@app.callback(Output("comparison-upload-filename", "children"), Input("comparison-upload-data", "filename"))
def show_comparison_upload_filename(filename):
    return f"Selected File B: {filename}" if filename else ""


@app.callback(Output("dl-csv-template", "data"), Input("btn-csv-template", "n_clicks"), prevent_initial_call=True)
def download_csv_template(_n):
    return dict(content=csv_schema_template(), filename="firewall_log_template.csv")


# ---------------------------------------------------------------------------
# Callback: run the analysis pipeline
# ---------------------------------------------------------------------------


@app.callback(
    Output("store-data-version", "data"),
    Output("error-banner", "children"),
    Output("filter-srcip", "options"),
    Output("filter-alerttype", "options"),
    Output("filter-daterange", "min_date_allowed"),
    Output("filter-daterange", "max_date_allowed"),
    Output("filter-daterange", "start_date"),
    Output("filter-daterange", "end_date"),
    Input("run-button", "n_clicks"),
    State("input-source", "value"),
    State("gen-profile", "value"),
    State("gen-rows", "value"),
    State("upload-data", "contents"),
    State("upload-data", "filename"),
    State("comparison-toggle", "value"),
    State("comparison-upload-data", "contents"),
    State("comparison-upload-data", "filename"),
    State("baseline-toggle", "value"),
    State("store-data-version", "data"),
    State("custom-settings-toggle", "value"),
    State("custom-brute-attempts", "value"),
    State("custom-brute-window", "value"),
    State("custom-brute-ports", "value"),
    State("custom-port-threshold", "value"),
    State("custom-port-window", "value"),
    State("custom-host-threshold", "value"),
    State("custom-host-window", "value"),
    State("custom-transfer-percentile", "value"),
    State("custom-transfer-bytes", "value"),
    State("custom-offhours-start", "value"),
    State("custom-offhours-end", "value"),
    prevent_initial_call=True,
)
def run_analysis(
    _n_clicks,
    source,
    profile,
    rows,
    upload_contents,
    upload_filename,
    comparison_value,
    comparison_contents,
    comparison_filename,
    baseline_value,
    version,
    custom_value=None,
    custom_brute_attempts=None,
    custom_brute_window=None,
    custom_brute_ports=None,
    custom_port_threshold=None,
    custom_port_window=None,
    custom_host_threshold=None,
    custom_host_window=None,
    custom_transfer_percentile=None,
    custom_transfer_bytes=None,
    custom_offhours_start=None,
    custom_offhours_end=None,
):
    baselining_on = "on" in (baseline_value or [])
    comparison_on = "on" in (comparison_value or [])
    custom_on = "on" in (custom_value or [])
    comparison_result = None
    active_custom_settings = None
    try:
        if custom_on and comparison_on:
            raise ValueError("Custom settings currently support single-file analysis only. Disable comparison mode and run again.")

        if custom_on:
            active_custom_settings = custom_settings_from_dashboard(
                custom_brute_attempts,
                custom_brute_window,
                custom_brute_ports,
                custom_port_threshold,
                custom_port_window,
                custom_host_threshold,
                custom_host_window,
                custom_transfer_percentile,
                custom_transfer_bytes,
                custom_offhours_start,
                custom_offhours_end,
            )
            if source == "upload":
                if not upload_contents or not upload_filename:
                    return no_update, callout("warn", "Upload a CSV or JSON log file, then click Run analysis."), no_update, no_update, no_update, no_update, no_update, no_update
                raw = load_uploaded_logs(_decode_upload(upload_contents, upload_filename))
                label = f"Custom analysis: {upload_filename}"
            elif source == "generate":
                row_count = int(rows or SAMPLE_PROFILES[profile]["rows"])
                options = SAMPLE_PROFILES[profile]
                raw = generate_firewall_logs(rows=row_count, seed=options["seed"], profile=options["profile"])
                ensure_directory(DEFAULT_FILE.parent)
                raw.to_csv(DEFAULT_FILE, index=False, encoding="utf-8")
                label = f"Custom analysis: generated {profile} ({row_count:,} rows)"
            else:
                if not DEFAULT_FILE.exists():
                    return no_update, callout("warn", "No existing CSV found. Choose Generate fake logs, then click Run analysis."), no_update, no_update, no_update, no_update, no_update, no_update
                raw = load_logs(DEFAULT_FILE)
                label = f"Custom analysis: {DEFAULT_FILE}"
            logs, alerts, incidents, summary = analyze_dataframe_with_custom_settings(raw, active_custom_settings)
        elif comparison_on:
            if not comparison_contents or not comparison_filename:
                return no_update, callout("warn", "Upload the second comparison file (File B), then click Run analysis."), no_update, no_update, no_update, no_update, no_update, no_update

            if source == "upload":
                if not upload_contents or not upload_filename:
                    return no_update, callout("warn", "Upload the first log file (File A), then click Run analysis."), no_update, no_update, no_update, no_update, no_update, no_update
                raw_a = load_uploaded_logs(_decode_upload(upload_contents, upload_filename))
                label_a = upload_filename
            elif source == "generate":
                row_count = int(rows or SAMPLE_PROFILES[profile]["rows"])
                options = SAMPLE_PROFILES[profile]
                raw_a = generate_firewall_logs(rows=row_count, seed=options["seed"], profile=options["profile"])
                ensure_directory(DEFAULT_FILE.parent)
                raw_a.to_csv(DEFAULT_FILE, index=False, encoding="utf-8")
                label_a = f"generated-{profile.lower()}.csv"
            else:
                if not DEFAULT_FILE.exists():
                    return no_update, callout("warn", "No existing CSV found. Choose Generate fake logs, then click Run analysis."), no_update, no_update, no_update, no_update, no_update, no_update
                raw_a = load_logs(DEFAULT_FILE)
                label_a = DEFAULT_FILE.name

            raw_b = load_uploaded_logs(_decode_upload(comparison_contents, comparison_filename))
            from src.comparison import compare_dataframes

            comparison_result = compare_dataframes(
                raw_a,
                raw_b,
                label_a,
                comparison_filename,
                baseline_enabled=baselining_on,
                analyzer=analyze_dataframe,
            )
            first = comparison_result["file_a"]
            logs, alerts, incidents, summary = first.logs, first.alerts, first.incidents, first.cleaning_summary
            label = f"Comparison: {label_a} vs {comparison_filename}"
        elif source == "upload":
            if not upload_contents:
                return no_update, callout("warn", "Upload a CSV or JSON log file, then click Run analysis."), no_update, no_update, no_update, no_update, no_update, no_update
            uploaded = _decode_upload(upload_contents, upload_filename)
            logs, alerts, incidents, summary = analyze_uploaded_file(uploaded, baselining_enabled=baselining_on)
            label = f"Uploaded file: {upload_filename}"
        elif source == "generate":
            row_count = int(rows or SAMPLE_PROFILES[profile]["rows"])
            logs, alerts, incidents, summary = analyze_generated_profile(profile, row_count, baselining_enabled=baselining_on)
            label = f"Generated fake logs: {profile} ({row_count:,} rows)"
        else:
            if not DEFAULT_FILE.exists():
                return no_update, callout("warn", "No existing CSV found. Choose Generate fake logs, then click Run analysis."), no_update, no_update, no_update, no_update, no_update, no_update
            logs, alerts, incidents, summary = analyze_default_file(str(DEFAULT_FILE), baselining_enabled=baselining_on)
            label = f"Existing local file: {DEFAULT_FILE}"
    except Exception as exc:  # noqa: BLE001 — surface any pipeline error to the banner
        return no_update, callout("error", str(exc)), no_update, no_update, no_update, no_update, no_update, no_update

    _STATE["logs"] = logs
    _STATE["alerts"] = alerts
    _STATE["incidents"] = incidents
    _STATE["summary"] = summary
    _STATE["label"] = label
    _STATE["analysis_mode"] = effective_analysis_mode(custom_settings_enabled=custom_on, baseline_enabled=baselining_on).value
    _STATE["baselining_enabled"] = baselining_on and not custom_on
    _STATE["custom_settings"] = active_custom_settings.to_dict() if active_custom_settings else None
    _STATE["ai_fit_cache"] = {}
    _STATE["comparison_result"] = comparison_result

    src_options = [{"label": ip, "value": ip} for ip in sorted(logs["src_ip"].dropna().astype(str).unique())] if not logs.empty else []
    alert_type_options = [{"label": a, "value": a} for a in sorted(alerts["alert_type"].dropna().astype(str).unique())] if not alerts.empty else []
    if not logs.empty:
        min_date = logs["timestamp"].dt.date.min()
        max_date = logs["timestamp"].dt.date.max()
    else:
        min_date = max_date = None

    return (int(version or 0) + 1, "", src_options, alert_type_options, min_date, max_date, min_date, max_date)


# ---------------------------------------------------------------------------
# Callback: recompute filtered data + traffic analytics
# ---------------------------------------------------------------------------


@app.callback(
    Output("store-filter-version", "data"),
    Output("page-header", "children"),
    Input("store-data-version", "data"),
    Input("filter-daterange", "start_date"),
    Input("filter-daterange", "end_date"),
    Input("filter-srcip", "value"),
    Input("filter-severity", "value"),
    Input("filter-alerttype", "value"),
    State("store-filter-version", "data"),
    prevent_initial_call=True,
)
def refresh_filters(_data_version, start_date, end_date, src_filter, severity_filter, alert_type_filter, filter_version):
    logs, alerts, incidents = _STATE["logs"], _STATE["alerts"], _STATE["incidents"]
    if logs is None or logs.empty:
        return no_update, no_update

    f_logs, f_alerts, f_incidents = apply_filters(logs, alerts, incidents, start_date, end_date, src_filter, severity_filter, alert_type_filter)
    _STATE["filtered_logs"] = f_logs
    _STATE["filtered_alerts"] = f_alerts
    _STATE["filtered_incidents"] = f_incidents

    config = load_config("config.yaml")
    top_n = config["analytics"]["top_n"]
    _STATE["top_sources"] = top_source_ips(f_logs, f_alerts, f_incidents, top_n)
    _STATE["top_ports"] = top_destination_ports(f_logs, top_n)
    _STATE["top_dst_ips"] = top_destination_ips(f_logs, top_n)

    mode = _STATE.get("analysis_mode", AnalysisMode.STANDARD.value)
    if mode == AnalysisMode.CUSTOM.value:
        status = "Custom thresholds"
    elif _STATE["baselining_enabled"]:
        status = "⚡ Per-asset baselining ON"
    else:
        status = "Global thresholds"
    return int(filter_version or 0) + 1, render_header(_STATE["label"], status, show_download=True)


# ---------------------------------------------------------------------------
# Comparison tab
# ---------------------------------------------------------------------------


@app.callback(Output("tabs", "value"), Input("store-data-version", "data"), State("comparison-toggle", "value"), prevent_initial_call=True)
def open_result_tab(_data_version, comparison_value):
    return "comparison" if "on" in (comparison_value or []) else "overview"


def _comparison_table(frame: pd.DataFrame, table_id: str, limit: int | None = None):
    shown = frame.head(limit).copy() if limit else frame.copy()
    shown = shown.astype(object).where(pd.notna(shown), None)
    return data_table(shown, id=table_id)


@app.callback(
    Output("comparison-content", "children"),
    Output("comparison-download-wrap", "style"),
    Input("store-data-version", "data"),
)
def render_comparison(_data_version):
    result = _STATE.get("comparison_result")
    hidden = {"display": "none", "marginTop": "0.8rem"}
    shown = {"display": "block", "marginTop": "0.8rem"}
    if not result:
        return callout("info", "Enable 'Compare with a second file', select File B, and run the analysis."), hidden

    first, second = result["file_a"], result["file_b"]
    rate = result["alert_rate"]
    kpis = row([
        col(kpi_card(f"Events — {first.label}", f"{first.cleaned_event_count:,}"), width=3),
        col(kpi_card(f"Events — {second.label}", f"{second.cleaned_event_count:,}"), width=3),
        col(kpi_card(f"Alert rate — {first.label}", f"{rate['file_a']:.2f} / 1K", accent="blue"), width=3),
        col(kpi_card(f"Alert rate — {second.label}", f"{rate['file_b']:.2f} / 1K", accent="amber" if rate["difference"] > 0 else "blue"), width=3),
    ])

    interpretation = panel(
        "What became more suspicious?",
        html.Ul([html.Li(item) for item in result["interpretation"]], style={"margin": "0", "paddingLeft": "1.25rem"}),
    )

    alert_types = result["alert_types"]
    if alert_types.empty:
        alert_chart = callout("info", "No detector alerts appeared in either file.")
    else:
        alert_plot = alert_types.melt(id_vars="alert_type", value_vars=["file_a", "file_b"], var_name="file", value_name="alerts")
        alert_plot["file"] = alert_plot["file"].map({"file_a": first.label, "file_b": second.label})
        alert_chart = dcc.Graph(
            figure=chart_layout(px.bar(alert_plot, x="alert_type", y="alerts", color="file", barmode="group", title="Alerts by detector"), 360),
            config={"displayModeBar": False},
        )

    severity = result["incident_severities"]
    severity_plot = severity.melt(id_vars="severity", value_vars=["file_a", "file_b"], var_name="file", value_name="incidents")
    severity_plot["file"] = severity_plot["file"].map({"file_a": first.label, "file_b": second.label})
    severity_chart = dcc.Graph(
        figure=chart_layout(px.bar(severity_plot, x="severity", y="incidents", color="file", barmode="group", category_orders={"severity": SEVERITY_ORDER}, title="Incidents by severity"), 340),
        config={"displayModeBar": False},
    )

    content = [
        callout("info", f"File A: {first.label}  |  File B: {second.label}  |  Per-asset baseline: {'ON' if result['baseline_enabled'] else 'OFF'} for both files"),
        kpis,
        interpretation,
        panel("Dataset overview", _comparison_table(result["overview"], "comparison-overview-table")),
        panel("Alert and detection differences", [alert_chart, _comparison_table(alert_types, "comparison-alert-types-table")]),
        row([
            col(panel("Incident risk differences", _comparison_table(result["incident_metrics"], "comparison-incident-metrics-table")), width=6),
            col(panel("Incident severity differences", severity_chart), width=6),
        ]),
        panel("Newly observed in File B", _comparison_table(result["new_observables"], "comparison-new-observables-table", 100) if not result["new_observables"].empty else callout("info", "No new source IPs, destination IPs, or destination ports.")),
        panel("Disappeared observables", _comparison_table(result["removed_observables"], "comparison-removed-observables-table", 100) if not result["removed_observables"].empty else callout("info", "No observables disappeared.")),
        panel("Traffic-volume changes", _comparison_table(result["traffic_metrics"], "comparison-traffic-table")),
        panel("Top activity changes", _comparison_table(result["activity_changes"], "comparison-activity-table", 100)),
    ]
    return html.Div(content), shown


@app.callback(Output("dl-comparison-report", "data"), Input("btn-comparison-report", "n_clicks"), prevent_initial_call=True)
def download_comparison_report(_n_clicks):
    result = _STATE.get("comparison_result")
    if not result:
        return no_update
    from src.comparison_reporting import build_comparison_html

    return dict(content=build_comparison_html(result), filename="comparison_report.html", type="text/html")


# ---------------------------------------------------------------------------
# Overview tab
# ---------------------------------------------------------------------------


@app.callback(Output("overview-content", "children"), Input("store-filter-version", "data"))
def render_overview(_version):
    logs, alerts, incidents, summary = _STATE["filtered_logs"], _STATE["filtered_alerts"], _STATE["filtered_incidents"], _STATE["summary"]
    if logs is None or logs.empty:
        return callout("info", "Choose a data source in the sidebar, then click Run analysis.")

    blocked = int((logs["action"] == "BLOCK").sum())
    allowed = int((logs["action"] == "ALLOW").sum())
    max_risk = int(incidents["risk_score"].max()) if not incidents.empty else 0
    critical = int((incidents["severity"] == "Critical").sum()) if not incidents.empty else 0

    kpis = row([
        col(kpi_card("Events", f"{len(logs):,}"), width=3),
        col(kpi_card("Alerts", f"{len(alerts):,}", accent="blue"), width=3),
        col(kpi_card("Incidents", f"{len(incidents):,}", f"Critical: {critical}", accent="amber" if critical else None), width=3),
        col(kpi_card("Highest risk", str(max_risk), accent="red" if max_risk >= 80 else None), width=3),
    ])

    notices = []
    unavailable = logs.attrs.get("unavailable_columns", [])
    skipped = logs.attrs.get("skipped_detectors", [])
    if unavailable:
        notices.append(callout("info", f"Mapped the available fields. Missing source fields: {', '.join(unavailable)}."))
    if skipped:
        notices.append(callout("warn", f"Skipped detectors because their required fields are unavailable: {', '.join(skipped)}."))

    time_range = logs["timestamp"].max() - logs["timestamp"].min()
    if time_range <= pd.Timedelta(minutes=10):
        freq, freq_label = "s", "second"
    elif time_range <= pd.Timedelta(hours=2):
        freq, freq_label = "min", "minute"
    elif time_range <= pd.Timedelta(days=2):
        freq, freq_label = "h", "hour"
    else:
        freq, freq_label = "D", "day"
    binned = logs.set_index("timestamp").resample(freq).size().reset_index(name="events")
    events_fig = chart_layout(px.line(binned, x="timestamp", y="events", title=f"Events over time (per {freq_label})", color_discrete_sequence=["#CC7A57"]))

    action_counts = pd.DataFrame({"action": ["ALLOW", "BLOCK"], "count": [allowed, blocked]})
    action_fig = chart_layout(px.bar(action_counts, x="action", y="count", title="Allowed vs blocked", color="action", color_discrete_map={"ALLOW": "#22c55e", "BLOCK": "#ef4444"}))

    if incidents.empty:
        severity_fig_block = callout("info", "No incidents detected.")
    else:
        severity_counts = incidents["severity"].value_counts().reindex(SEVERITY_ORDER, fill_value=0).reset_index()
        severity_counts.columns = ["severity", "count"]
        severity_fig_block = dcc.Graph(figure=chart_layout(px.bar(severity_counts, x="severity", y="count", title="Incidents by severity", color="severity", color_discrete_map=SEVERITY_COLORS)), config={"displayModeBar": False})

    cleaning_accordion = html.Details(
        [html.Summary("Cleaning summary"), html.Pre(json.dumps(summary, indent=2, default=str))],
        className="accordion-item",
        style={"padding": "0.7rem 0.9rem"},
    )

    return html.Div(
        notices
        + [
            kpis,
            panel(None, dcc.Graph(figure=events_fig, config={"displayModeBar": False})),
            row([
                col(panel(None, dcc.Graph(figure=action_fig, config={"displayModeBar": False})), width=6),
                col(panel(None, severity_fig_block), width=6),
            ]),
            cleaning_accordion,
        ]
    )


@app.callback(Output("dl-pdf-report", "data"), Input("btn-pdf-report", "n_clicks"), prevent_initial_call=True)
def download_pdf(_n):
    logs, alerts, incidents, summary = _STATE["filtered_logs"], _STATE["filtered_alerts"], _STATE["filtered_incidents"], _STATE["summary"]
    label = _STATE["label"]
    top_sources, top_ports, top_dst_ips = _STATE["top_sources"], _STATE["top_ports"], _STATE["top_dst_ips"]
    try:
        pdf_bytes = build_visual_pdf_report(logs, alerts, incidents, summary, label, top_sources, top_ports, top_dst_ips)
    except Exception:
        pdf_bytes = build_pdf_report(logs, alerts, incidents, summary, top_sources, top_ports, top_dst_ips)
    return dcc.send_bytes(pdf_bytes, "incident_report.pdf")


# ---------------------------------------------------------------------------
# Alerts tab
# ---------------------------------------------------------------------------


@app.callback(Output("alerts-content", "children"), Input("store-filter-version", "data"), Input("alerts-search", "value"))
def render_alerts(_version, search):
    alerts = _STATE["filtered_alerts"]
    if alerts is None or alerts.empty:
        return callout("info", "No alerts to show.")

    visible = alerts.copy()
    if search:
        visible = visible[visible.astype(str).apply(lambda r: r.str.contains(search, case=False, na=False).any(), axis=1)]
    if visible.empty:
        return callout("info", "No alerts match your search.")

    def _ev(raw):
        try:
            return json.loads(raw) if isinstance(raw, str) else {}
        except Exception:
            return {}

    ev_parsed = visible["evidence"].apply(_ev)
    visible = visible.copy()
    visible["threshold_mode"] = ev_parsed.apply(
        lambda evidence: "Custom" if evidence.get("threshold_source") == "custom_settings"
        else "⚡ per-asset" if evidence.get("threshold_source") == "per_asset_baseline"
        else "— global"
    )
    visible["eff_threshold"] = ev_parsed.apply(lambda e: e.get("effective_threshold", ""))
    visible["observed"] = ev_parsed.apply(lambda e: e.get("observed_value", ""))

    n_baseline = int((visible["threshold_mode"] == "⚡ per-asset").sum())
    n_custom = int((visible["threshold_mode"] == "Custom").sum())
    if n_custom > 0:
        banner = callout("success", f"Custom analysis active — {n_custom} of {len(visible)} alerts used the dashboard thresholds.")
    elif n_baseline > 0:
        banner = callout("success", f"⚡ Per-asset baselining active — {n_baseline} of {len(visible)} alerts used host-specific thresholds.")
    else:
        banner = callout("info", "Per-asset baselining is off — all alerts used global thresholds.")

    columns = ["timestamp", "src_ip", "alert_type", "severity", "threshold_mode", "eff_threshold", "observed", "event_count", "score_contribution"]
    table = data_table(visible, columns, id="alerts-table")

    evidence_accordion = html.Details(
        [
            html.Summary("Show alert evidence"),
            data_table(visible, ["alert_id", "evidence"], id="alerts-evidence-table"),
        ],
        className="accordion-item",
        style={"padding": "0.7rem 0.9rem", "marginTop": "0.8rem"},
    )

    return html.Div([banner, table, evidence_accordion, download_button("Download alerts CSV", "btn-alerts-csv", "dl-alerts-csv")])


@app.callback(Output("dl-alerts-csv", "data"), Input("btn-alerts-csv", "n_clicks"), prevent_initial_call=True)
def download_alerts_csv(_n):
    return dict(content=_csv_bytes(_STATE["filtered_alerts"]), filename="alerts.csv")


# ---------------------------------------------------------------------------
# Incidents tab
# ---------------------------------------------------------------------------


@app.callback(Output("incidents-content", "children"), Input("store-filter-version", "data"))
def render_incidents(_version):
    incidents = _STATE["filtered_incidents"]
    if incidents is None or incidents.empty:
        return callout("info", "No incidents to show.")
    visible = incidents.sort_values("risk_score", ascending=False)
    columns = ["incident_id", "src_ip", "start_time", "end_time", "risk_score", "severity", "alert_types", "alert_count"]
    table = data_table(visible, columns, id="incidents-table")
    return html.Div([table, download_button("Download incidents CSV", "btn-incidents-csv", "dl-incidents-csv")])


@app.callback(Output("dl-incidents-csv", "data"), Input("btn-incidents-csv", "n_clicks"), prevent_initial_call=True)
def download_incidents_csv(_n):
    return dict(content=_csv_bytes(_STATE["filtered_incidents"]), filename="incidents.csv")


# ---------------------------------------------------------------------------
# Investigation tab
# ---------------------------------------------------------------------------


@app.callback(
    Output("incident-dropdown", "options"),
    Output("incident-dropdown", "value"),
    Input("store-filter-version", "data"),
)
def refresh_incident_options(_version):
    incidents = _STATE["filtered_incidents"]
    if incidents is None or incidents.empty:
        return [], None
    ordered = incidents.sort_values("risk_score", ascending=False)
    options = [
        {"label": f"{row.incident_id} | {row.severity} | risk {int(row.risk_score)} | {row.src_ip}", "value": row.incident_id}
        for row in ordered.itertuples()
    ]
    return options, options[0]["value"] if options else None


@app.callback(Output("investigation-content", "children"), Input("incident-dropdown", "value"), Input("store-filter-version", "data"))
def render_investigation(incident_id, _version):
    incidents, alerts, logs = _STATE["filtered_incidents"], _STATE["filtered_alerts"], _STATE["filtered_logs"]
    if incidents is None or incidents.empty or not incident_id:
        return callout("info", "No incidents available for investigation.")
    matches = incidents[incidents["incident_id"] == incident_id]
    if matches.empty:
        return callout("info", "Selected incident is no longer in the filtered results.")
    incident = matches.iloc[0]

    start = pd.to_datetime(incident["start_time"])
    end = pd.to_datetime(incident["end_time"])
    related_alerts = alerts[(alerts["src_ip"] == incident["src_ip"]) & (pd.to_datetime(alerts["timestamp"]) >= start) & (pd.to_datetime(alerts["timestamp"]) <= end)].sort_values("timestamp")
    related_events = logs[(logs["src_ip"] == incident["src_ip"]) & (logs["timestamp"] >= start) & (logs["timestamp"] <= end)].sort_values("timestamp")

    kpis = row([
        col(kpi_card("Incident", str(incident["incident_id"])), width=3),
        col(kpi_card("Risk", str(int(incident["risk_score"])), accent="red" if incident["risk_score"] >= 80 else "amber"), width=3),
        col(kpi_card("Severity", str(incident["severity"])), width=3),
        col(kpi_card("Source", str(incident["src_ip"])), width=3),
    ])

    recommendations = [html.Li(item) for item in str(incident["recommendations"]).split(" | ") if item]

    evidence_items = []
    for _, alert_row in related_alerts.iterrows():
        try:
            ev = json.loads(alert_row["evidence"]) if isinstance(alert_row["evidence"], str) else {}
        except Exception:
            ev = {}
        threshold_source = ev.get("threshold_source", "global_config")
        if threshold_source == "per_asset_baseline":
            note = callout("info", f"Per-asset baseline used — asset median: {ev.get('asset_baseline_value', 'n/a')}, effective threshold: {ev.get('effective_threshold', 'n/a')}, observed: {ev.get('observed_value', 'n/a')}")
        elif threshold_source == "custom_settings":
            note = callout("success", f"Custom dashboard threshold: {ev.get('effective_threshold', 'n/a')} | Observed: {ev.get('observed_value', 'n/a')}")
        else:
            note = html.P(f"Global config threshold: {ev.get('effective_threshold', 'n/a')} | Observed: {ev.get('observed_value', 'n/a')}", className="small-muted")
        evidence_items.append(
            html.Details(
                [html.Summary(f"{alert_row['alert_type']} — {alert_row['alert_id']}"), note, html.Pre(json.dumps(ev, indent=2, default=str))],
                className="accordion-item",
                style={"padding": "0.6rem 0.85rem", "marginBottom": "0.4rem"},
            )
        )

    return html.Div(
        [
            kpis,
            panel("Explanation", html.P(incident["explanation"])),
            row([
                col(panel("Score breakdown", html.Pre(str(incident["score_breakdown"]).replace(" | ", "\n"))), width=6),
                col(panel("Recommendations", html.Ul(recommendations)), width=6),
            ]),
            panel("Timeline", data_table(build_timeline(related_alerts, related_events), id="timeline-table")),
            panel(
                "Related raw events",
                data_table(related_events, ["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "action", "bytes_sent", "bytes_received"], id="related-events-table"),
            ),
            panel("Alert evidence", html.Div(evidence_items)) if evidence_items else html.Div(),
        ]
    )


# ---------------------------------------------------------------------------
# AI & Traffic Analytics tab
# ---------------------------------------------------------------------------


def _cached_ai_analysis(logs: pd.DataFrame, model_config: dict, working_hours: dict) -> pd.DataFrame:
    cache: dict = _STATE["ai_fit_cache"]  # type: ignore[assignment]
    key = (len(logs), tuple(sorted(model_config.items())), tuple(sorted(working_hours.items())))
    if key in cache:
        return cache[key]
    features = build_behavioral_features(logs, model_config["window_minutes"], working_hours["start_hour"], working_hours["end_hour"])
    detector_config = dict(model_config)
    detector_config["anomaly_threshold"] = 0
    result = detect_ai_anomalies(features, detector_config)
    cache[key] = result
    return result


@app.callback(
    Output("analytics-ai-content", "children"),
    Input("store-filter-version", "data"),
    Input("ai-enable", "value"),
    Input("ai-threshold", "value"),
    Input("ai-contamination", "value"),
)
def render_analytics_ai(_version, enable_value, threshold, contamination):
    logs = _STATE["filtered_logs"]
    if logs is None or logs.empty:
        return callout("info", "Run an analysis to see AI anomaly detection.")

    config = load_config("config.yaml")
    ai_config = dict(config["ai_detection"])
    enabled = "on" in (enable_value or [])
    ai_config["anomaly_threshold"] = threshold if threshold is not None else ai_config["anomaly_threshold"]
    ai_config["contamination"] = contamination if contamination is not None else ai_config["contamination"]
    model_config = {k: v for k, v in ai_config.items() if k != "anomaly_threshold"}

    ai_results = _cached_ai_analysis(logs, model_config, config["working_hours"]) if enabled else pd.DataFrame()
    if not ai_results.empty:
        ai_results = ai_results.copy()
        ai_results["is_ai_anomaly"] = ai_results["isolation_forest_prediction"].eq(-1) & ai_results["ai_anomaly_score"].ge(ai_config["anomaly_threshold"])
    anomalies = ai_results[ai_results["is_ai_anomaly"]] if not ai_results.empty and "is_ai_anomaly" in ai_results else pd.DataFrame()
    _STATE["ai_anomalies"] = anomalies

    kpis = row([
        col(kpi_card("AI anomalies", str(len(anomalies))), width=3),
        col(kpi_card("Highest AI score", f"{ai_results['ai_anomaly_score'].max():.2f}" if not ai_results.empty else "0.00"), width=3),
        col(kpi_card("Source IPs analyzed", str(logs["src_ip"].nunique()) if "src_ip" in logs else "0"), width=3),
        col(kpi_card("Destination ports observed", str(logs["dst_port"].nunique()) if "dst_port" in logs else "0"), width=3),
    ])

    if not enabled:
        body = callout("info", "AI detection is disabled. Traffic summaries are still available below.")
    elif ai_results.empty:
        body = callout("warn", ai_results.attrs.get("warning", "AI detection could not be performed for this dataset."))
    else:
        chart_data = ai_results.head(30).copy()
        chart_data["window_label"] = chart_data["src_ip"].astype(str) + " | " + chart_data["window_start"].astype(str)
        fig = chart_layout(px.bar(chart_data.sort_values("ai_anomaly_score"), x="ai_anomaly_score", y="window_label", orientation="h", title="Highest AI anomaly scores", color_discrete_sequence=["#CC7A57"]), height=520)
        shown = anomalies if not anomalies.empty else ai_results.head(20)
        columns = ["src_ip", "window_start", "connection_count", "unique_dst_ips", "unique_dst_ports", "blocked_ratio", "bytes_sent_total", "ai_anomaly_score", "is_ai_anomaly", "ai_explanation"]
        body = html.Div(
            [
                callout("warn", ai_results.attrs.get("warning", "AI anomalies require human validation.")),
                dcc.Graph(figure=fig, config={"displayModeBar": False}),
                data_table(shown, columns, id="ai-results-table"),
                download_button("Download AI anomalies CSV", "btn-ai-csv", "dl-ai-csv"),
            ]
        )

    return html.Div([kpis, panel("AI anomaly analysis", body)])


@app.callback(Output("dl-ai-csv", "data"), Input("btn-ai-csv", "n_clicks"), prevent_initial_call=True)
def download_ai_csv(_n):
    anomalies = _STATE.get("ai_anomalies", pd.DataFrame())
    return dict(content=_csv_bytes(anomalies), filename="anomalies.csv")


@app.callback(Output("analytics-traffic-content", "children"), Input("store-filter-version", "data"))
def render_analytics_traffic(_version):
    sources, ports, dst_ips = _STATE["top_sources"], _STATE["top_ports"], _STATE["top_dst_ips"]

    if sources.empty:
        sources_body = callout("warn", "Source-IP analytics are unavailable because no source IP data is present.")
    else:
        fig = chart_layout(px.bar(sources.sort_values("total_events"), x="total_events", y="src_ip", orientation="h", title="Top active source IPs", color_discrete_sequence=["#CC7A57"]))
        sources_body = html.Div([
            dcc.Graph(figure=fig, config={"displayModeBar": False}),
            data_table(sources, id="sources-table"),
            download_button("Download source IP analytics CSV", "btn-sources-csv", "dl-sources-csv"),
        ])

    if ports.empty:
        ports_body = callout("warn", "Port analytics are unavailable because no destination-port data is present.")
    else:
        port_chart = ports.copy()
        port_chart["port_label"] = port_chart["dst_port"].astype(str) + " - " + port_chart["service_name"]
        fig = chart_layout(px.bar(port_chart.sort_values("total_events"), x="total_events", y="port_label", orientation="h", title="Top destination ports", color_discrete_sequence=["#f59e0b"]))
        ports_body = html.Div([
            dcc.Graph(figure=fig, config={"displayModeBar": False}),
            data_table(ports, id="ports-table"),
            download_button("Download destination-port analytics CSV", "btn-ports-csv", "dl-ports-csv"),
        ])

    if dst_ips.empty:
        dst_ips_body = callout("warn", "Destination-IP analytics are unavailable because no destination IP data is present.")
    else:
        fig = chart_layout(px.bar(dst_ips.sort_values("total_events"), x="total_events", y="dst_ip", orientation="h", title="Top destination IPs", color_discrete_sequence=["#ef4444"]))
        dst_ips_body = html.Div([
            dcc.Graph(figure=fig, config={"displayModeBar": False}),
            data_table(dst_ips, id="dstips-table"),
            download_button("Download destination-IP analytics CSV", "btn-dstips-csv", "dl-dstips-csv"),
        ])

    return html.Div([
        panel("Most active source IPs", sources_body),
        panel("Most frequently used destination ports", ports_body),
        panel("Most contacted destination IPs", dst_ips_body),
    ])


@app.callback(Output("dl-sources-csv", "data"), Input("btn-sources-csv", "n_clicks"), prevent_initial_call=True)
def download_sources_csv(_n):
    return dict(content=_csv_bytes(_STATE["top_sources"]), filename="top_source_ips.csv")


@app.callback(Output("dl-ports-csv", "data"), Input("btn-ports-csv", "n_clicks"), prevent_initial_call=True)
def download_ports_csv(_n):
    return dict(content=_csv_bytes(_STATE["top_ports"]), filename="top_destination_ports.csv")


@app.callback(Output("dl-dstips-csv", "data"), Input("btn-dstips-csv", "n_clicks"), prevent_initial_call=True)
def download_dstips_csv(_n):
    return dict(content=_csv_bytes(_STATE["top_dst_ips"]), filename="top_destination_ips.csv")


if __name__ == "__main__":
    # threaded=True keeps the UI (filters, tab switches, other downloads)
    # responsive while a big "Generate fake logs" run or PDF export is still
    # crunching in the background, instead of blocking on one request at a time.
    app.run(debug=False, host="127.0.0.1", port=8050, threaded=True)
