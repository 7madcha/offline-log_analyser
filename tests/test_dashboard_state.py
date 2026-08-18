import base64

import pandas as pd

import app


def test_new_layout_discards_previous_analysis_results():
    app._STATE["logs"] = pd.DataFrame({"event": ["old result"]})
    app._STATE["filtered_alerts"] = pd.DataFrame({"alert": ["old alert"]})
    app._STATE["summary"] = {"total_events": 1}
    app._STATE["label"] = "previous analysis"
    app._STATE["baselining_enabled"] = True
    app._STATE["ai_fit_cache"] = {"old": object()}

    layout = app.build_layout()

    assert layout is not None
    assert app._STATE["logs"].empty
    assert app._STATE["filtered_alerts"].empty
    assert app._STATE["summary"] == {}
    assert app._STATE["label"] == ""
    assert app._STATE["baselining_enabled"] is False
    assert app._STATE["ai_fit_cache"] == {}
    assert app._STATE["comparison_result"] is None


def _csv_upload(frame: pd.DataFrame) -> str:
    encoded = base64.b64encode(frame.to_csv(index=False).encode("utf-8")).decode("ascii")
    return f"data:text/csv;base64,{encoded}"


def test_dashboard_two_file_comparison_populates_result_view(event_factory):
    start = pd.Timestamp("2026-08-01 10:00:00")
    first = pd.DataFrame([event_factory(start, action="ALLOW")])
    second = pd.DataFrame([event_factory(start, src_ip="10.0.0.9", dst_port=3389, action="BLOCK")])

    response = app.run_analysis(
        1,
        "upload",
        "Normal",
        100,
        _csv_upload(first),
        "before.csv",
        ["on"],
        _csv_upload(second),
        "after.csv",
        [],
        0,
    )

    assert response[0] == 1
    assert response[1] == ""
    assert app._STATE["comparison_result"]["file_a"].label == "before.csv"
    assert app._STATE["comparison_result"]["file_b"].label == "after.csv"
    assert app.open_result_tab(1, ["on"]) == "comparison"
    rendered, download_style = app.render_comparison(1)
    assert rendered is not None
    assert download_style["display"] == "block"


def test_comparison_controls_are_hidden_until_enabled():
    assert app.toggle_comparison_controls([])["display"] == "none"
    assert app.toggle_comparison_controls(["on"])["display"] == "block"
