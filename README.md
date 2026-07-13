# Offline Log Forensic Analyzer

Offline Log Forensic Analyzer is a local, offline Python project for analyzing static firewall logs stored in CSV files. It generates synthetic firewall events, validates and cleans the data, detects suspicious behaviors, correlates alerts into incidents, calculates explainable risk scores, and displays results in a simple Streamlit dashboard.

The project is designed as a readable 3-4 week internship project. It does not require firewall access, VPN access, company infrastructure, credentials, real logs, external APIs, Docker, or a database.

## Main Features

- Generate synthetic firewall events with normal, noisy, and attack-heavy sample profiles.
- Load and validate CSV firewall logs.
- Normalize timestamps, actions, protocols, ports, byte fields, and IPv4 addresses.
- Detect repeated blocked connections, port scans, host scans, large outbound transfers, and suspicious off-hours activity.
- Correlate related alerts from the same source IP into incidents.
- Calculate an explainable risk score from configured alert weights.
- Export cleaned logs, alerts, and incidents as CSV files.
- Export a local PDF incident and risk summary report.
- Download a CSV schema template from the dashboard.
- Explore results in a simple Streamlit and Plotly dashboard.


## Architecture

The project is split into small modules under `src/`:

- `generate_logs.py`: creates synthetic firewall logs and sample profiles.
- `loader.py`: loads CSV files and reports file errors.
- `validator.py`: validates required columns and dataset shape.
- `cleaner.py`: normalizes and filters invalid rows.
- `detectors.py`: runs independent detection rules.
- `correlator.py`: groups alerts into incidents.
- `scoring.py`: calculates risk scores and severity.
- `explanations.py`: builds evidence-based incident explanations.
- `recommendations.py`: provides advisory next steps.
- `exporter.py`: writes CSV outputs.
- `reporting.py`: builds local PDF reports and CSV templates.
- `utils.py`: shared configuration and helper functions.

`main.py` runs the command-line pipeline. `app.py` runs the dashboard.

## Installation

### Windows PowerShell

```powershell
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Linux and macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Synthetic Log Generation

```bash
python -m src.generate_logs --rows 50000 --output data/synthetic/firewall_logs.csv
```

Sample profile options:

```bash
python -m src.generate_logs --profile normal --rows 8000 --output data/synthetic/normal_logs.csv
python -m src.generate_logs --profile noisy --rows 12000 --output data/synthetic/noisy_logs.csv
python -m src.generate_logs --profile attack-heavy --rows 50000 --output data/synthetic/firewall_logs.csv
```

The generator uses a reproducible seed and only uses fictional private or documentation IP ranges:

- `10.0.0.0/8`
- `172.16.0.0/12`
- `192.168.0.0/16`
- `192.0.2.0/24`
- `198.51.100.0/24`
- `203.0.113.0/24`

## Command-Line Analysis

```bash
python main.py --input data/synthetic/firewall_logs.csv
```

Optional parameters:

```bash
python main.py --input data/synthetic/firewall_logs.csv --config config.yaml --output outputs
```

Generated files:

- `data/processed/cleaned_logs.csv`
- `outputs/alerts/alerts.csv`
- `outputs/incidents/incidents.csv`
- `outputs/reports/incident_report.pdf`

## Dashboard Execution

```bash
streamlit run app.py
```

The dashboard includes:

- One-click Run analysis button.
- Default file, upload CSV, and local sample profile selector.
- Normal, noisy, and attack-heavy sample profiles.
- Date, source IP, severity, and alert type filters.
- Overview KPIs and charts.
- Searchable alerts table with CSV download.
- Incident table sorted by risk score with CSV download.
- Investigation page with explanation, risk score breakdown, recommendations, improved timeline, and related raw events.
- PDF report download.
- CSV schema template download.

## Test Execution

```bash
pytest -v
```

The tests cover loading, cleaning, detector thresholds, scoring, incident correlation, sample generation, and local report generation.

## Project Structure

```text
offline-log-analyzer/
|-- app.py
|-- main.py
|-- requirements.txt
|-- README.md
|-- config.yaml
|-- .gitignore
|-- .streamlit/
|   `-- config.toml
|-- data/
|   |-- raw/
|   |-- processed/
|   `-- synthetic/
|-- outputs/
|   |-- alerts/
|   |-- incidents/
|   `-- reports/
|-- src/
|   |-- __init__.py
|   |-- generate_logs.py
|   |-- loader.py
|   |-- validator.py
|   |-- cleaner.py
|   |-- detectors.py
|   |-- correlator.py
|   |-- scoring.py
|   |-- explanations.py
|   |-- recommendations.py
|   |-- exporter.py
|   |-- reporting.py
|   `-- utils.py
`-- tests/
    |-- __init__.py
    |-- conftest.py
    |-- test_loader.py
    |-- test_cleaner.py
    |-- test_detectors.py
    |-- test_correlator.py
    |-- test_scoring.py
    |-- test_generate_logs.py
    `-- test_reporting.py
```

## Data Format

Normalized CSV columns:

```text
timestamp
src_ip
dst_ip
src_port
dst_port
protocol
action
bytes_sent
bytes_received
label
```

The `label` column is used only for synthetic data evaluation. Detection logic does not use it.

## Detection Rules

All thresholds are configured in `config.yaml`.

- Repeated blocked connections: detects at least 50 blocked connections from the same source IP within one minute, focused on ports 22, 23, and 3389.
- Port scan: detects at least 20 unique destination ports contacted by one source IP within five minutes.
- Host scan: detects at least 30 unique destination IP addresses contacted by one source IP within five minutes.
- Large outbound transfer: detects unusually high `bytes_sent` values using the configured percentile and minimum byte threshold.
- Suspicious off-hours activity: detects off-hours events only when paired with suspicious characteristics such as blocked traffic, rare ports, large transfer behavior, or repeated activity.

## Risk Scoring

Scores are calculated from alert types:

```text
Repeated blocked connections: +30
Port scan: +25
Host scan: +20
Large outbound transfer: +20
Suspicious off-hours activity: +10
Multiple alert types bonus: +15
Final score capped at 100
```

Severity mapping:

```text
0-29: Low
30-59: Medium
60-79: High
80-100: Critical
```

The incident output, dashboard, and PDF report show the score breakdown.

## Limitations

- This project is a proof of concept.
- Synthetic data may not represent all production conditions.
- Threshold-based detections may generate false positives.
- An alert is not proof of compromise.
- Real-world deployment would require authorized validation.
- Firewall formats vary between vendors.
- No automatic response is performed.
- No production infrastructure is accessed.

## Ethical Considerations

This application is defensive and offline. It never scans a network, never connects to company infrastructure, never sends data to external APIs, never executes attacks, never blocks IP addresses, never modifies firewall configurations, never requires credentials, and never collects personal information.
