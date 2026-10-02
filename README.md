# 🛡️ MiniSOC — Mini Security Operations Center

> A hands-on, fully functional **Security Operations Center** built with Python & Flask. Monitor logs, detect attacks, investigate alerts, and respond to threats — all from a dark-themed web dashboard.

---

## 📸 Overview

MiniSOC simulates a real-world SOC pipeline in a single lightweight Python application:

```
Server Logs → Log Collector → Detection Rules → Alert Engine → Risk Score → Dashboard → Incident Response
```

It is designed as an **educational project** to demonstrate how enterprise SIEM tools like Splunk, IBM QRadar, and Wazuh work under the hood.

---

## ✨ Features

- 📥 **Log Ingestion** — Automatically reads and parses structured server log files
- 🔍 **Rule-Based Detection** — Pattern (regex) and Threshold (frequency) detection rules
- ⚡ **Real-Time Scanning** — Background scheduler scans for new log entries every 5 seconds
- 📊 **SOC Dashboard** — Live pipeline status, stat cards, severity charts, and top offenders
- 🔔 **Alert Management** — View, filter, update status, and add investigation notes to alerts
- 🔗 **Alert Correlation** — Automatically links alerts from the same IP or user
- 📁 **Incident Response** — Group alerts into incidents and execute simulated response actions
- 🧮 **Risk Scoring** — 0–100 risk score per alert based on severity, base score, and evidence count
- 📋 **Audit Trail** — Every analyst action is logged with timestamps
- ⚙️ **REST API** — Full JSON API for programmatic interaction
- 🗄️ **SQLite Persistence** — All alerts, incidents, and actions stored in a local database

---

## 🗂️ Project Structure

```
mini Soc/
├── app.py                  # 🚀 Main Flask application (entry point)
├── config.py               # ⚙️  Configuration constants & thresholds
├── db.py                   # 🗄️  Database operations (SQLite)
├── log_collector.py        # 📥 Reads and parses log files with offset tracking
├── alert_engine.py         # 🔍 Matches detection rules against log entries
├── detection_rules.py      # 📋 Default rule definitions (Python fallback)
├── detection_rules.json    # 📋 Active rule definitions (editable JSON)
├── test_run.py             # 🧪 Quick terminal test (no web UI needed)
├── requirements.txt        # 📦 Python dependencies
│
├── logs/                   # 📁 Server log files (drop your .log files here)
│   ├── attack_scenarios.log    # Simulated attack traffic
│   └── normal_activity.log     # Normal user activity
│
├── static/
│   └── style.css           # 🎨 Dark-themed stylesheet
│
└── templates/              # 🌐 Jinja2 HTML templates
    ├── base.html               # Sidebar layout
    ├── dashboard.html          # SOC Dashboard + pipeline status
    ├── logs.html               # Log Viewer with filters
    ├── alerts.html             # Alerts list
    ├── alert_detail.html       # Alert deep-dive + correlations
    ├── incidents.html          # Incidents list
    ├── incident_detail.html    # Investigation + response actions
    └── settings.html           # Detection rules viewer
```

---

## 🚀 Quick Start

### Prerequisites

- Python **3.10+**

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-username/mini-soc.git
cd mini-soc

# 2. (Optional) Create a virtual environment
python -m venv venv
venv\Scripts\activate       # Windows
# source venv/bin/activate  # macOS/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
python app.py
```

### Access the Dashboard

Open your browser and go to: **http://127.0.0.1:5000**

On startup, MiniSOC will:
1. Initialize the SQLite database
2. Run an initial scan of all log files
3. Start the background scheduler (scans every 5 seconds)
4. Launch the Flask web server

---

## 🌐 Web Interface

| Page | URL | Description |
|------|-----|-------------|
| **Dashboard** | `/dashboard` | Live pipeline status, stat cards, charts |
| **Log Viewer** | `/logs` | Browse and search all parsed log entries |
| **Alerts** | `/alerts` | Filter alerts by status and severity |
| **Alert Detail** | `/alert/<id>` | Risk breakdown, raw log, correlated alerts |
| **Incidents** | `/incidents` | List all incidents |
| **Incident Detail** | `/incident/<id>` | Investigation notes + response actions |
| **Detection Rules** | `/settings` | View active detection rules |

---

## 🔌 REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scan` | Trigger a manual log scan |
| `POST` | `/api/scan/reset` | Reset offsets and run a full re-scan |
| `GET` | `/api/stats` | Dashboard statistics (JSON) |
| `GET` | `/api/logs` | All parsed log entries (JSON) |
| `POST` | `/api/alert/<id>/status` | Update alert status/notes |
| `GET` | `/api/alert/<id>/correlations` | Get correlated alerts |
| `POST` | `/api/incident` | Create a new incident |
| `POST` | `/api/incident/<id>/status` | Update incident status |
| `POST` | `/api/incident/<id>/notes` | Update investigation notes |
| `POST` | `/api/incident/<id>/response` | Add a response action |
| `POST` | `/api/response/<id>/execute` | Execute a response action |

**Examples:**

```bash
# Trigger a scan
curl -X POST http://127.0.0.1:5000/api/scan

# Create an incident
curl -X POST http://127.0.0.1:5000/api/incident \
  -H "Content-Type: application/json" \
  -d '{"title": "Brute Force Attack", "severity": "high", "alert_ids": [1,2,3]}'
```

---

## 🔍 Detection Rules

Two rule types are supported, defined in `detection_rules.json`:

### Pattern Rules (Instant Match)
Fires when a **regex** matches a field in a log entry:

```json
{
    "id": "SQLI_ATTEMPT",
    "name": "SQL Injection Attempt",
    "severity": "critical",
    "base_score": 45,
    "detect": "pattern",
    "field": "detail",
    "pattern": "(UNION SELECT|OR 1=1|DROP TABLE|--)"
}
```

### Threshold Rules (Frequency-Based)
Fires when an event occurs **too many times** within a time window:

```json
{
    "id": "BRUTE_FORCE",
    "name": "Brute Force Login Attempt",
    "severity": "high",
    "base_score": 40,
    "detect": "threshold",
    "field": "user",
    "condition": "action == 'LOGIN_FAIL'",
    "threshold": 5,
    "window_seconds": 300
}
```

### Active Rules

| Rule ID | Name | Type | Severity |
|---------|------|------|----------|
| `BRUTE_FORCE` | Brute Force Login Attempt | threshold | high |
| `MULTI_FAIL_LOGIN` | Repeated Failed Logins | threshold | high |
| `SUSPICIOUS_IP` | Suspicious IP Activity | threshold | medium |
| `PRIV_ESC` | Privilege Escalation Pattern | pattern | critical |
| `SQLI_ATTEMPT` | SQL Injection Attempt | pattern | critical |
| `UNUSUAL_LOCATION` | Unusual Login Location | pattern | medium |
| `SENSITIVE_ACCESS` | Repeated Sensitive Resource Access | threshold | high |
| `COMMAND_INJECTION` | Command Injection Attempt | pattern | critical |
| `PATH_TRAVERSAL` | Path Traversal Attempt | pattern | high |
| `PORT_SCAN` | Port Scanning Activity | threshold | medium |

---

## 🧮 Risk Scoring

Each alert receives a **0–100 risk score**:

```
Risk Score = Base Score + Severity Bonus + Evidence Bonus  (capped at 100)
```

| Component | Calculation |
|-----------|-------------|
| Base Score | Defined per rule (e.g., SQLI = 45) |
| Severity Bonus | critical +50 / high +35 / medium +20 / low +10 |
| Evidence Bonus | evidence_count × 3 (max 20) |

| Score | Risk Level |
|-------|------------|
| 85–100 | CRITICAL |
| 60–84 | HIGH |
| 30–59 | MEDIUM |
| 0–29 | LOW |

---

## 📝 Log Format

Log files must follow this format:

```
[TIMESTAMP] LEVEL SOURCE ACTION USER IP DETAIL
```

**Example:**
```
[2026-09-01 08:01:00] WARNING auth.server LOGIN_FAIL unknown 203.0.113.50 user=admin password incorrect attempt 1
[2026-09-01 08:15:00] CRITICAL web.server REQUEST attacker 45.33.32.156 GET /api/search?q=UNION SELECT username,password FROM users--
```

Drop any `.log` files following this format into the `logs/` folder and they will be automatically ingested on the next scan.

---

## 🔄 Resetting the Database

To start fresh and re-process all logs:

```bash
# Windows
del soc.db
del .log_offsets.json
python app.py

# macOS/Linux
rm soc.db .log_offsets.json
python app.py
```

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Python 3 + Flask |
| Database | SQLite (soc.db) |
| Scheduler | APScheduler |
| Frontend | HTML + Jinja2 + Vanilla CSS |
| Styling | Custom dark-themed CSS |

---

## 🗺️ MITRE ATT&CK Coverage

| Tactic | Technique | Rule |
|--------|-----------|------|
| Initial Access | Brute Force (T1110) | BRUTE_FORCE, MULTI_FAIL_LOGIN |
| Privilege Escalation | Abuse Elevation Control (T1548) | PRIV_ESC |
| Collection | Data from Local System (T1005) | SENSITIVE_ACCESS |
| Execution | Command & Scripting (T1059) | COMMAND_INJECTION |
| Discovery | Network Service Scanning (T1046) | PORT_SCAN |
| Initial Access | Exploit Public-Facing App (T1190) | SQLI_ATTEMPT, PATH_TRAVERSAL |

---

## 🔮 Extending the System

- **Add custom rules** — Edit `detection_rules.json` and add new pattern or threshold rules
- **Add log sources** — Place additional `.log` files in the `logs/` directory
- **Add authentication** — Integrate Flask-Login to protect the dashboard
- **Connect real APIs** — Replace simulated responses with real firewall, AD, or EDR API calls
- **Add ML detection** — Plug in anomaly detection models for behavioral analysis
- **Live log streaming** — Replace file-based reading with a Syslog receiver

---

## 📚 Learn More

See [HOW_IT_WORKS.md](HOW_IT_WORKS.md) for a comprehensive deep-dive into every component, the full database schema, and a step-by-step walkthrough of how a real attack flows through the system.

---

## 📄 License

This project is open-source and available under the [MIT License](LICENSE).

---

> Built for learning cybersecurity concepts — SOC workflows, SIEM logic, threat detection, and incident response.
