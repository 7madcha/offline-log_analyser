# Offline Log Analyzer — Code Study Guide

This guide follows the order in which the application runs. Every code file uses the same study format:

- **Role** — why the file exists.
- **Logic** — what it does internally.
- **Main functions** — the important functions in the file.
- **Called from** — where the function starts being used.
- **Input → return → next** — what enters, what leaves, and where it goes.

The two entry points are `app.py` for the Streamlit dashboard and `main.py` for the command line. Both use the same core analysis pipeline.

---

## 1. `app.py` — dashboard entry point

**Role:** Creates the web dashboard. It lets the user upload a CSV, generate fake logs, choose a local file, run the analysis, see charts, and download results.

**Logic:** The user chooses an input. `app.py` loads the configuration, validates and cleans the logs, runs the rule-based detectors, correlates alerts into incidents, and displays the results. AI analysis is calculated when the AI/Analytics area is displayed.

### `analyze_dataframe(raw, config_path)`

- **Called from:** `analyze_default_file`, `analyze_generated_profile`, and `analyze_uploaded_file` in this same file.
- **Input:** `raw`, a DataFrame containing CSV rows; `config_path`, normally `config.yaml`.
- **Logic:** Calls `load_config()`, `validate_dataset()`, `validate_columns()`, `clean_logs()`, `run_all_detectors()`, and `correlate_alerts()` in order.
- **Return:** cleaned logs, cleaning summary, alerts, incidents, and config.
- **Next:** `get_analysis()` gives those results to the dashboard display functions.

### Input helper functions

`analyze_default_file(path)` reads the synthetic/local default CSV with pandas, then calls `analyze_dataframe()`.

`analyze_generated_profile(name, rows)` calls `generate_firewall_logs()` to create fake log rows, then calls `analyze_dataframe()`.

`analyze_uploaded_file(uploaded_file)` calls `pd.read_csv(uploaded_file, dtype=str)`, then calls `analyze_dataframe()`.

### `get_analysis(source, profile, rows, uploaded_file)`

- **Called from:** `main()` in `app.py` after the user clicks **Run analysis**.
- **Logic:** Chooses one of the three input helper functions based on the sidebar choice.
- **Return:** the same analysis package returned by `analyze_dataframe()`.

### `apply_filters(logs, alerts, incidents, ...)`

- **Called from:** `main()` before dashboard tables/charts are shown.
- **Logic:** Filters analysis results by date, source IP, action, severity, or other selected dashboard filters.
- **Return:** filtered logs, alerts, and incidents.
- **Next:** the charts use the filtered results, so the dashboard view follows the user’s selections.

### Display functions

`render_overview()` shows basic metrics and charts.

`render_alerts()` shows detector alerts.

`render_incidents()` shows correlated incidents.

`render_ai_analytics()` creates AI results and traffic summaries for its dashboard tab.

`render_investigation()` shows related events/alerts for a selected incident.

`render_downloads()` creates browser download buttons. It does not automatically save the uploaded CSV to the project.

### `cached_ai_analysis(logs, model_config, working_hours)`

- **Called from:** `render_ai_analytics()`.
- **Logic:** Calls `build_behavioral_features()` and then `detect_ai_anomalies()`. Streamlit caches the result so it does not need to rebuild the forest every time the page redraws with unchanged inputs.
- **Return:** feature rows with AI columns added.

---

## 2. `main.py` — command-line entry point

**Role:** Runs the full pipeline without the dashboard and writes results to files.

**Logic:** It runs the same analysis as `app.py`, then exports cleaned logs, alerts, incidents, anomalies, traffic analytics, and a PDF report.

### `run_pipeline(input_path, config_path, output_root)`

- **Called from:** `main()` in this file.
- **Input:** path to a CSV, path to `config.yaml`, and an output folder.
- **Logic:**
  1. Loads config with `load_config()`.
  2. Loads CSV with `load_logs()`.
  3. Validates raw logs.
  4. Cleans logs with `clean_logs()`.
  5. Runs all rule detectors with `run_all_detectors()`.
  6. Creates incidents with `correlate_alerts()`.
  7. Builds AI features and runs `detect_ai_anomalies()` if AI is enabled.
  8. Creates source-IP and destination-port summaries.
  9. Exports all results.
- **Return:** a dictionary of counts and output file paths.
- **Next:** `main()` prints that dictionary’s summary to the terminal.

### `main()`

- **Called from:** Python when this condition is true:

  ```python
  if __name__ == "__main__":
      main()
  ```

- **Logic:** Reads terminal options such as `--input`, then calls `run_pipeline()`.

---

## 3. `src/utils.py` — configuration and small shared helpers

**Role:** Loads the YAML configuration and contains small reusable utility functions.

### `load_config(config_path="config.yaml")`

- **Called from:** `app.py` and `main.py` before analysis begins.
- **Input:** the YAML file path.
- **Logic:** Opens `config.yaml`, converts YAML into a Python dictionary, and applies safe defaults for AI, analytics, and working-hours settings if they are missing or invalid.
- **Return:** the `config` dictionary.
- **Next:** validators, detectors, correlator, AI, and analytics read their settings from this dictionary.

### Other helpers

`ensure_directory(path)` creates a folder if it does not exist. It is used by exporters.

`severity_rank(severity)` converts `Low`, `Medium`, `High`, and `Critical` into sortable numbers.

`safe_join(values)` combines valid non-empty values into safe display text.

---

## 4. `src/loader.py` — read a CSV file

**Role:** Reads a CSV file for the CLI pipeline.

### `load_logs(file_path)`

- **Called from:** `run_pipeline()` in `main.py`.
- **Input:** CSV path from `--input`.
- **Logic:** Checks the path and uses pandas to read the CSV. It raises a clear error for missing, empty, or unreadable data.
- **Return:** raw pandas DataFrame.
- **Next:** `validate_dataset(raw_df)`.

The dashboard does not normally use this file for uploads; it directly calls `pd.read_csv(uploaded_file, dtype=str)` in `app.py`.

---

## 5. `src/validator.py` — stop invalid data early

**Role:** Checks that a table is usable before later code tries to analyze it.

### `ValidationResult`

**Role:** A small data object that represents the result of a column validation, including whether the data is valid and which columns are missing.

### `validate_dataset(df)`

- **Called from:** `app.py` and `main.py`, before and after cleaning.
- **Input:** a pandas DataFrame.
- **Logic:** Checks that the DataFrame exists and has rows.
- **Return:** no data on success; raises an error on failure.
- **Next:** `validate_columns()` or the following analysis stage.

### `validate_columns(df, required_columns)`

- **Called from:** `app.py` and `main.py` before `clean_logs()`.
- **Input:** raw DataFrame and `config["required_columns"]`.
- **Logic:** Compares actual CSV header names with required column names. It detects missing and duplicate column names.
- **Return:** a validation result / raises an error when columns are not acceptable.
- **Next:** `clean_logs()` only runs if the schema is valid.

---

## 6. `src/cleaner.py` — make logs safe and consistent

**Role:** Normalizes raw firewall rows into clean analysis data.

### Helper functions

`_valid_ipv4(value)` checks whether a value is a valid IPv4 address.

`_valid_port(series)` checks port numbers are in the valid range.

These are called only by `clean_logs()`.

### `clean_logs(df)`

- **Called from:** `analyze_dataframe()` in `app.py` and `run_pipeline()` in `main.py`.
- **Input:** validated raw log DataFrame.
- **Logic:** Makes a deep copy; removes duplicates; parses timestamps; normalizes action and protocol text; turns ports and byte fields into numbers; removes rows with invalid IPs, invalid ports, or invalid timestamps.
- **Return:** `(cleaned_dataframe, cleaning_summary)`.
- **Next:** cleaned logs go to detectors, AI feature building, and traffic analytics. The summary is shown in the dashboard and added to the PDF report.

---

## 7. `src/detectors.py` — rule-based threat detection

**Role:** Finds known suspicious firewall patterns using configured thresholds.

**Logic:** Each detector reads the same cleaned logs and returns zero or more standardized alert rows. `run_all_detectors()` combines them.

### Individual detector functions

`detect_repeated_blocked_connections(df, config)` looks for many blocked connections from one source to sensitive ports in a short period. This can indicate brute-force attempts.

`detect_port_scan(df, config)` looks for one source contacting many different destination ports within a time window.

`detect_host_scan(df, config)` looks for one source contacting many different destination IPs within a time window.

`detect_large_outbound_transfer(df, config)` looks for unusually high outgoing bytes.

`detect_off_hours_activity(df, config)` looks for risky traffic outside configured working hours.

All are **called from** `run_all_detectors()` in the same file. They receive cleaned logs plus the detector settings from `config` and return alert DataFrames.

### `run_all_detectors(df, config)`

- **Called from:** `app.py` and `main.py`, immediately after cleaning.
- **Input:** cleaned logs and config.
- **Logic:** Runs every detector, joins their alert tables, removes duplicate alerts, orders them by time/severity, and assigns alert IDs such as `ALT-000001`.
- **Return:** `alerts` DataFrame.
- **Next:** `correlate_alerts(alerts, config)`.

---

## 8. `src/correlator.py` — turn alerts into incidents

**Role:** Combines related alerts into one security incident.

### `correlate_alerts(alerts, config)`

- **Called from:** `app.py` and `main.py` after `run_all_detectors()`.
- **Input:** alert DataFrame and correlation settings from config.
- **Logic:** Groups alerts from the same `src_ip` that occur near each other in time. For each group, it collects alert types, ports, time range, and affected targets. It then gets a risk score, severity, explanation, and recommendations.
- **Return:** `incidents` DataFrame.
- **Next:** dashboard incident tables, source-IP analytics, exports, and PDF reporting.

### Internal helpers

`_split_values()` separates and de-duplicates combined text values.

`_incident_from_group()` builds one final incident dictionary from one group of alerts.

`_empty_incidents()` returns an empty DataFrame using the correct incident columns.

---

## 9. `src/scoring.py` — calculate risk level

**Role:** Converts incident alert types into a risk score and severity.

### `score_for_alert_type(alert_type, config)`

- **Called from:** `calculate_incident_score()`.
- **Logic:** Reads the configured score for one alert type.
- **Return:** numeric score.

### `calculate_incident_score(alert_types, config)`

- **Called from:** `_incident_from_group()` in `correlator.py`.
- **Logic:** Adds the configured score for each alert type and caps the final value at 100.
- **Return:** incident risk score.

### `score_to_severity(score, config)`

- **Called from:** `_incident_from_group()` in `correlator.py`.
- **Logic:** Maps the score to `Low`, `Medium`, `High`, or `Critical` using config thresholds.
- **Return:** severity text.

---

## 10. `src/explanations.py` — incident explanation text

**Role:** Creates a cautious, human-readable explanation for a rule-based incident.

### `build_incident_explanation(incident)`

- **Called from:** `_incident_from_group()` in `correlator.py`.
- **Input:** one incident dictionary.
- **Logic:** Uses real evidence from that incident: alert types, source IP, time range, ports, and risk level. It does not claim a machine is compromised without evidence.
- **Return:** explanation string.
- **Next:** stored in the `explanation` field of an incident row.

---

## 11. `src/recommendations.py` — investigation advice

**Role:** Provides advice for a human analyst; it does not block IPs or change a firewall.

### `recommendations_for_alert_types(alert_types)`

- **Called from:** `_incident_from_group()` in `correlator.py`.
- **Input:** list of alert types within an incident.
- **Logic:** Maps each alert type to relevant investigation steps, removes duplicate advice, and returns the combined list.
- **Return:** recommendations text/list for the incident.

---

## 12. `src/ai_features.py` — convert log behavior into numbers

**Role:** Prepares numerical behavior rows for the Isolation Forest. It does not build the forest.

### `build_behavioral_features(logs, window_minutes=5, working_start_hour=5, working_end_hour=24)`

- **Called from:** `cached_ai_analysis()` in `app.py` and `run_pipeline()` in `main.py`.
- **Input:** cleaned logs, AI time-window setting, and working-hours settings.
- **Logic:**
  1. Copies logs so the original cleaned table is unchanged.
  2. Parses time and normalizes bytes, action, and protocol.
  3. Groups rows by `src_ip` and a five-minute `window_start`.
  4. Calculates numerical values: counts, blocked ratio, unique targets/ports, byte totals/averages, TCP/UDP ratio, activity hour, and off-hours flag.
  5. Uses optional `label` values to identify reliable known-normal windows.
- **Return:** one numerical feature row per source IP per time window.
- **Next:** passed as `features` to `detect_ai_anomalies()`.

---

## 13. `src/ai_detector.py` — build and use the Isolation Forest

**Role:** Builds a temporary local AI model and finds unusual behavior windows.

### `detect_ai_anomalies(features, config)`

- **Called from:** `cached_ai_analysis()` in `app.py` and `run_pipeline()` in `main.py`.
- **Input:** features created by `build_behavioral_features()` and `config["ai_detection"]`.
- **Logic:**
  1. Selects `MODEL_FEATURES` numeric columns.
  2. Uses `RobustScaler` from scikit-learn to scale values.
  3. Creates `IsolationForest` from `sklearn.ensemble`.
  4. Builds `n_estimators` trees, normally 200.
  5. Trains only with trustworthy normal-labelled windows if at least five exist; otherwise trains with all current windows.
  6. Scores every window and marks it as anomalous only when the forest predicts `-1` and its normalized score meets the configured threshold.
  7. Adds explanations from `explain_anomalies()`.
- **Return:** original feature table plus AI score, prediction, anomaly flag, and explanation.
- **Next:** dashboard AI table/charts or CLI `outputs/ai/anomalies.csv`.

The model exists only in memory as the local `model` variable. It is not stored in a database or model file.

---

## 14. `src/ai_explanation.py` — explain AI results

**Role:** Turns unusually high numerical values into readable reasons.

### `explain_anomalies(features)`

- **Called from:** `detect_ai_anomalies()` in `ai_detector.py`.
- **Input:** the behavior feature table.
- **Logic:** Calculates median values for selected features across the loaded dataset. For every feature row, it compares values such as destination ports, outbound bytes, destination IPs, connection count, and block ratio with their medians. It returns up to three strongest reasons, plus an off-hours reason if applicable.
- **Return:** one explanation string per feature row.
- **Next:** saved in `output["ai_explanation"]` by `ai_detector.py`.

`LABELS` in this file only translates internal column names into readable wording. It does not affect AI training or anomaly decisions.

---

## 15. `src/traffic_analytics.py` — dashboard statistics

**Role:** Builds ranking tables for source IPs and destination ports. It does not detect threats.

### `_prepared(logs)`

- **Called from:** both main analytics functions in this file.
- **Logic:** Copies logs, converts byte values, normalizes `action`, and creates numeric `allowed` and `blocked` columns.
- **Return:** prepared analytics table.

### `top_source_ips(logs, alerts, incidents, top_n=10)`

- **Called from:** `render_ai_analytics()` in `app.py` and `run_pipeline()` in `main.py`.
- **Input:** cleaned logs plus alerts/incidents, and how many IPs to return.
- **Logic:** Groups logs by source IP and calculates total events, ALLOW/BLOCK totals, blocked ratio, unique targets/ports, traffic totals, alert count, and highest incident risk.
- **Return:** top source IP table.
- **Next:** dashboard chart/table and `outputs/analytics/top_source_ips.csv` in the CLI.

### `top_destination_ports(logs, top_n=10)`

- **Called from:** `render_ai_analytics()` in `app.py` and `run_pipeline()` in `main.py`.
- **Logic:** Groups logs by destination port and calculates traffic/actions/diversity totals. It uses `COMMON_PORTS` to attach names such as `443 → HTTPS`.
- **Return:** top destination-port table.
- **Next:** dashboard chart/table and `outputs/analytics/top_destination_ports.csv` in the CLI.

---

## 16. `src/exporter.py` — write CSV output files

**Role:** Saves DataFrames as local CSV files when the CLI is used.

### `safe_filename(filename)`

- **Called from:** export helper code in this file.
- **Logic:** Removes unsafe path/file characters from a filename.
- **Return:** safe filename text.

### `export_dataframe(df, path)`

- **Called from:** `main.py` for AI anomalies and analytics exports; also by specialized export functions.
- **Input:** a DataFrame and output path.
- **Logic:** Creates the parent folder if needed, then writes UTF-8 CSV data.
- **Return:** written file path.

### Specialized exports

`export_cleaned_data()`, `export_alerts()`, and `export_incidents()` call `export_dataframe()` with their expected output locations.

**Called from:** `run_pipeline()` in `main.py`.

---

## 17. `src/reporting.py` — CSV template and PDF report

**Role:** Produces a sample CSV header and a local PDF incident report.

### `csv_schema_template()`

- **Called from:** `app.py` for the dashboard CSV-template download.
- **Logic:** Returns example CSV header/content using the required schema.
- **Return:** text that the browser downloads as a CSV template.

### `build_report_lines(...)`

- **Called from:** `export_pdf_report()`.
- **Logic:** Builds readable report lines containing cleaning summary, alert/incident counts, and incident information.
- **Return:** list of text lines.

### `export_pdf_report(...)`

- **Called from:** `main.py` for CLI output and `app.py` for dashboard PDF download.
- **Input:** cleaned logs, alerts, incidents, output path, and cleaning summary.
- **Logic:** builds report lines, converts them into valid local PDF bytes, then writes or supplies the PDF.
- **Return:** output path/bytes depending on use.
- **Next:** CLI saves `outputs/reports/incident_report.pdf`; dashboard offers a download.

The remaining private helper functions format/wrap text and generate PDF internals. They are called only by `export_pdf_report()` and its helper chain.

---

## 18. `src/generate_logs.py` — create fake firewall logs

**Role:** Creates safe synthetic data for testing the application without company logs.

### `generate_firewall_logs(rows=50000, seed=..., profile=...)`

- **Called from:** `analyze_generated_profile()` in `app.py`; can also be run directly as a script.
- **Input:** requested normal row count, random seed, and profile (`normal`, `noisy`, or `attack-heavy`).
- **Logic:** Generates normal firewall-like events, then injects scenario rows based on the selected profile. Attack-heavy data deliberately includes scans, repeated blocks, large transfers, and off-hours activity.
- **Return:** synthetic log DataFrame.
- **Next:** `app.py` sends it into `analyze_dataframe()`.

The internal helpers create IP addresses/events and inject the scenarios. They are called only by `generate_firewall_logs()`.

Important: in attack-heavy mode, injected attack rows are added **after** the requested normal `rows`. Therefore the final row count can be higher than the number selected in the dashboard.

---

## Supporting non-code files

### `config.yaml`

Contains the required CSV column names, detector thresholds, incident scoring rules, AI settings, analytics `top_n`, and working-hour boundaries. It is read by `load_config()`.

### `requirements.txt`

Lists required libraries, including pandas, Streamlit, Plotly, PyYAML, NumPy, and scikit-learn.

### `.streamlit/config.toml`

Contains Streamlit application settings.

### `data/`

- `data/raw/`: optional local real CSV files; dashboard uploads are not automatically stored here.
- `data/synthetic/firewall_logs.csv`: fake data generated by the application.
- `data/processed/cleaned_logs.csv`: written by the CLI after cleaning.

### `outputs/`

Written by the CLI. It holds alerts, incidents, AI anomaly CSV, analytics CSVs, and the PDF report. Dashboard results mostly remain in memory until the user downloads them.

### `tests/`

Pytest files that check the behavior of loaders, cleaning, detectors, correlation, scoring, fake-data generation, and reporting.

---

## Full pipeline in one line

```text
CSV/fake logs → validation → cleaning → rule-based alerts → correlated incidents
→ AI feature numbers → Isolation Forest anomalies → analytics → dashboard or exports
```
