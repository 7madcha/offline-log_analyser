# Supervisor Demonstration Guide — Offline Log Forensic Analyzer

Use this as a speaking guide rather than reading every line word for word. The main goal is to show that the project has a clear security purpose, a sound pipeline, explainable outputs, and realistic boundaries.

---

## 1. Opening (30 seconds)

> This project is an offline-first firewall-log forensic analyzer. It takes static CSV firewall logs, validates and normalizes them, identifies suspicious behaviours, correlates related alerts into incidents, assigns explainable risk scores, and presents the results in a local dashboard and reports.
>
> I built it as a defensive decision-support prototype. It does not connect to a network, firewall, VPN, cloud service, or external API. Its purpose is to turn a large raw log file into prioritized investigation leads that an analyst can validate.

Then show the repository root briefly and point out `app.py`, `main.py`, `config.yaml`, `src/`, and `tests/`.

---

## 2. The problem it solves

> Firewall logs can contain thousands or millions of events. Looking at them line by line makes it difficult to identify repeated failures, reconnaissance patterns, unusual transfers, or activity outside expected hours. This tool reduces that volume into alerts and incidents while retaining the raw evidence needed for investigation.

> The project intentionally separates detection from response. An alert is not proof of compromise, and the tool never blocks an IP or changes firewall configuration. It produces evidence and recommendations for a human analyst.

---

## 3. High-level architecture

Describe the pipeline while showing `src/` or the dashboard:

```text
CSV or synthetic logs
        |
Load -> Validate -> Clean / normalize
        |
Rule-based detection + AI anomaly detection
        |
Alert correlation -> Incidents -> Explainable scoring
        |
Dashboard, CSV exports, and local PDF report
```

Say:

> I used small, single-purpose modules so each stage can be tested independently. The command-line interface runs the same core analysis pipeline as the Streamlit dashboard; the dashboard is a presentation and investigation layer, not a separate detector implementation.

Module overview:

| Module | What to say |
|---|---|
| `loader.py`, `validator.py` | Safely loads CSV input and rejects missing columns, invalid files, duplicate columns, or unusable datasets early. |
| `cleaner.py` | Normalizes timestamps, actions, protocols, numeric fields, IPv4 addresses, and ports; removes invalid or duplicate records. |
| `detectors.py` | Runs deterministic rules for known suspicious patterns. |
| `ai_features.py`, `ai_detector.py` | Builds per-source behavioural windows and runs local unsupervised anomaly detection. |
| `correlator.py` | Groups related alerts from the same source IP within a time window into incidents. |
| `scoring.py`, `explanations.py` | Produces an explainable score, severity, evidence summary, and advisory recommendations. |
| `reporting.py`, `exporter.py` | Produces reproducible local CSV and PDF outputs. |

---

## 4. Input and data preparation

> The expected input is a firewall-log CSV. The normalized schema includes timestamp, source and destination IPs, source and destination ports, protocol, action, bytes sent, bytes received, and an optional label.

> Input quality is critical in log analytics, so before detecting anything the pipeline validates required columns and normalizes the fields. For example, ports must be in range, IP addresses must be valid IPv4 values, timestamps are parsed using the expected format, and action/protocol values are normalized. Invalid rows are removed and included in a cleaning summary.

> For safe demonstrations, I added a reproducible synthetic-log generator. It supports normal, noisy, and attack-heavy profiles, using only private and documentation IP ranges. The synthetic `label` field is for evaluation only; it is never used by the detection logic to decide whether an event is suspicious.

If asked why labels are not used:

> That prevents label leakage. The detection system should operate on observable traffic behaviour, not on a field that would not reliably exist in real firewall logs.

---

## 5. Rule-based detection

> The deterministic layer handles known, interpretable patterns. Thresholds live in `config.yaml` rather than being hardcoded, so an analyst can tune them for a particular environment without modifying detector code.

Explain each rule:

| Rule | What it identifies | Why it matters |
|---|---|---|
| Repeated blocked connections | Many blocked attempts from one source, particularly against SSH, Telnet, or RDP ports | Can indicate password guessing, probing, or a misconfigured client. |
| Port scan | One source contacts many unique destination ports within a short window | Common reconnaissance behaviour before exploitation. |
| Host scan | One source contacts many destination hosts within a short window | Can indicate network discovery or enumeration. |
| Large outbound transfer | `bytes_sent` is unusually high relative to a configured percentile and minimum | A lead for reviewing potential exfiltration, backup traffic, or other large transfers. |
| Suspicious off-hours activity | Off-hours activity combined with suspicious characteristics | Timing alone is not enough; it is used as contextual evidence. |

Important expert-level point:

> These are signals, not attack verdicts. For example, a vulnerability scanner or backup system can legitimately trigger a rule. The design makes the evidence visible so the investigator can decide whether it is expected behaviour.

---

## 6. Correlation, scoring, and explainability

> Individual alerts are often noisy. The correlator groups alerts from the same source IP within the configured correlation window into an incident. That gives the analyst a more useful unit of investigation than a flat list of alerts.

> Risk scoring is deterministic and explainable. Each alert type has a configured weight, multiple distinct alert types receive a bonus, the score is capped at 100, and a severity is then mapped from the score. The dashboard and report show the score breakdown rather than returning an unexplained severity label.

Current scoring model:

```text
Repeated blocked connections: +30
Port scan:                  +25
Host scan:                  +20
Large outbound transfer:    +20
Suspicious off-hours:       +10
Multiple alert types:       +15
Maximum score:              100
```

> The explanation text is generated from actual incident evidence, and recommendations are advisory. I avoid claiming that a host is compromised because the available data is firewall telemetry, not proof of compromise.

---

## 7. AI anomaly detection

> In addition to explicit rules, the project includes an offline unsupervised anomaly-detection view using Isolation Forest. This is useful for behaviour that looks unusual but does not cross one of the predefined rule thresholds.

> The model does not use raw IP strings or timestamps as features. Instead, it groups each source IP into configurable five-minute behavioural windows and calculates numeric features such as connection count, blocked ratio, unique destinations, unique ports, byte volume, protocol ratios, and time-of-day behaviour.

> I use `RobustScaler` before Isolation Forest so extreme values have less influence during scaling. Isolation Forest then isolates behaviour that differs from the learned baseline. The resulting score is normalized to 0–100 for presentation, while the raw model score and prediction are retained in the export for traceability.

> If at least five reliable normal-labelled windows are available, those are used as the training baseline. Otherwise, the model trains on the current dataset and raises a warning. This fallback keeps the tool usable with real unlabeled logs, but it also makes baseline quality an explicit limitation.

Key limitation to state clearly:

> An anomaly means “different from the baseline,” not “malicious.” Maintenance work, backups, new services, or contaminated training data can appear anomalous. AI findings must be reviewed against raw events and business context.

If asked why use both rules and AI:

> Rules are best for known behaviours and are easy to audit. Unsupervised ML can surface unknown or threshold-free deviations. They are complementary: the rules give reliable known-pattern coverage, while AI broadens investigation leads.

---

## 8. Dashboard walkthrough (recommended order)

Start the dashboard with:

```powershell
.venv\Scripts\streamlit.exe run app.py
```

Talk through it in this order:

1. **Choose a safe dataset.** Select `Generate fake logs`, use the `attack-heavy` profile for a visible demonstration, and choose a manageable row count.
2. **Run analysis.** Explain that the dashboard invokes the same load-to-export analysis pipeline.
3. **Overview KPIs and charts.** Show total events, alert count, incident count, severity/risk distribution, and filtered views.
4. **Alerts table.** Explain that this is the evidence-level output from individual detectors. Filter by time, source IP, severity, or alert type.
5. **Incidents table.** Explain that incidents are correlated alert groups, sorted by risk score to prioritize triage.
6. **Investigation view.** Choose one high-risk incident and show its score breakdown, evidence-based explanation, recommendations, timeline, and related raw events.
7. **AI and traffic views.** Show anomalous behavioural windows, then the top source-IP and destination-port summaries. Explain that these help analysts find high-volume or diverse traffic patterns quickly.
8. **Exports.** Show downloadable alerts/incidents CSVs, the local PDF report, and the CSV schema template.

While showing an incident, say:

> The analyst can move from a risk-ranked incident to its exact alert types and then to the related raw events. That traceability is important: the score summarizes evidence, but it does not hide it.

---

## 9. CLI and reproducibility

> The project can also run without the UI, which makes analysis reproducible and easier to automate later. The CLI accepts an input path, configuration path, and output path.

```powershell
.venv\Scripts\python.exe main.py --input data\synthetic\firewall_logs.csv --config config.yaml --output outputs
```

> The pipeline exports cleaned logs, rule alerts, incidents, AI anomalies, source-IP analytics, destination-port analytics, and a local PDF report. The configuration file centralizes thresholds, risk weights, AI parameters, working hours, and ranking limits.

---

## 10. Testing and code quality

> The core pipeline is covered with pytest tests. Tests cover file loading, cleaning, detector thresholds, correlation behaviour, risk scoring, synthetic-data generation, report generation, CLI paths, AI exports, and analytics exports.

Run:

```powershell
.venv\Scripts\python.exe -m pytest -v
```

> I focused on testing the transformations and detection boundaries because small data-quality or windowing errors can materially change security findings.

---

## 11. Security, privacy, and ethics

> The project is deliberately offline and defensive. It works with local CSV files only; it does not scan networks, access company infrastructure, require credentials, transmit logs externally, execute attacks, block IPs, or change firewall settings.

> This is especially useful where log sensitivity, network restrictions, or privacy requirements make cloud processing undesirable.

---

## 12. Limitations (state these proactively)

> This is a proof of concept, not a replacement for a production SIEM or SOAR platform.

- The input schema is designed around static CSV firewall logs; real vendors have different fields and semantics.
- Thresholds need tuning against normal traffic and operational context.
- The model is unsupervised, so anomaly findings can include legitimate but rare activity.
- Synthetic traffic helps demonstrate functionality, but it cannot fully represent production traffic distributions.
- The system does not enrich IPs with threat intelligence, ingest streaming logs, manage user authentication, or automate response.
- Incident grouping is based on source IP and time windows; a production system would likely incorporate identity, assets, session context, and richer correlation rules.

Say this after the list:

> These are deliberate scope boundaries for an internship-scale offline prototype. The important outcome is that the core processing, explainability, and investigation flow are reliable enough to extend.

---

## 13. Strong next steps

If asked how you would productionize or extend it:

1. Add parsers/adapters for specific firewall vendors and support JSON/syslog ingestion.
2. Create a schema mapping layer and preserve raw event identifiers for stronger forensic traceability.
3. Evaluate detections against labelled real or curated datasets using precision, recall, false-positive rate, and alert-volume reduction.
4. Add baseline learning by asset, user, subnet, service, and day-of-week instead of relying mainly on global source-IP windows.
5. Add alert deduplication, analyst feedback labels, and threshold-tuning workflows.
6. Introduce a local database and job queue for larger files, historical comparisons, and scheduled ingestion.
7. Add role-based access control, audit trails, encryption at rest, retention policies, and secure deployment practices.
8. Integrate authorized threat-intelligence enrichment and ticketing only when privacy and operational requirements permit it.

---

## 14. Likely expert questions and concise answers

### Why use CSV instead of live firewall logs?

> CSV keeps the prototype safe, portable, reproducible, and independent of infrastructure access. The pipeline architecture allows vendor-specific ingestion adapters to be added later.

### How do you prevent false positives?

> I do not claim to eliminate them. I use configurable thresholds, correlation, explainable scoring, raw-event drill-down, and human validation. Production tuning would use historical baselines and measured precision/recall.

### Why Isolation Forest?

> It is a practical unsupervised method for finding unusual behaviour when labelled attack data is limited. It works well with numeric aggregate features and does not require identifying every attack type in advance.

### Why use five-minute windows?

> It is a configurable compromise between detecting short bursts such as scans and retaining enough events for a meaningful behavioural profile. Different environments may need different windows.

### How is the AI result explainable?

> The project retains the raw score and prediction, normalizes the presentation score, and compares the anomalous window’s numeric features with dataset medians to list the strongest differences. It does not present the model as a black-box attack classifier.

### How do the rules and AI interact?

> They do not override each other. Rule alerts identify known patterns; AI anomalies highlight deviations. Both appear as investigation evidence, and the analyst validates them using related raw events.

### Why not use deep learning?

> The dataset and scope do not justify it. A simpler, local model is easier to run, explain, and validate. Model complexity should follow evidence that it improves operational outcomes.

### How do you handle sensitive data?

> Processing is local and offline. For real deployment, I would add access controls, encryption, retention rules, audit logs, and data minimization based on organizational policy.

### What does a high risk score mean?

> It means the incident accumulated multiple weighted suspicious signals according to the configured policy. It is a prioritization score, not a probability of compromise.

### What would you measure in a real evaluation?

> Precision, recall, false-positive rate, time-to-triage, alert-volume reduction, and the stability of anomaly baselines over time.

---

## 15. Closing (20 seconds)

> In summary, the project demonstrates an end-to-end, offline log-analysis workflow: reliable preparation of raw logs, explainable rule-based detection, complementary AI anomaly detection, incident correlation, risk prioritization, and analyst-facing reporting. Its value is not to automatically declare attacks; it is to make forensic investigation faster, more structured, and auditable while keeping sensitive logs local.

---

## Demo checklist

Before showing the project:

- Activate the virtual environment: `.venv\Scripts\activate`
- Confirm dependencies are installed: `pip install -r requirements.txt`
- Run tests once: `.venv\Scripts\python.exe -m pytest -v`
- Start the dashboard: `.venv\Scripts\streamlit.exe run app.py`
- Use the `attack-heavy` synthetic profile for visible alerts/incidents.
- Have `config.yaml` open to show that thresholds and scoring are configurable.
- Have one high-risk incident ready to open in the investigation view.
- Keep the limitations section ready; it demonstrates engineering judgment.
