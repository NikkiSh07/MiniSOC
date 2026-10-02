# 🛡️ MiniSOC — Complete Learning Guide

> A hands-on guide to understanding how this Mini Security Operations Center works, from raw server logs all the way to incident response.

---

## Table of Contents

1. [What is a SOC?](#1-what-is-a-soc)
2. [Architecture Overview](#2-architecture-overview)
3. [The Complete Pipeline](#3-the-complete-pipeline)
4. [Project Structure](#4-project-structure)
5. [Deep Dive: Each Component](#5-deep-dive-each-component)
   - [5.1 Server Logs](#51-server-logs)
   - [5.2 Log Collector](#52-log-collector)
   - [5.3 Detection Rules](#53-detection-rules)
   - [5.4 Alert Engine](#54-alert-engine)
   - [5.5 Risk Scoring](#55-risk-scoring)
   - [5.6 SOC Dashboard](#56-soc-dashboard)
   - [5.7 Incident Investigation](#57-incident-investigation)
   - [5.8 Response Actions](#58-response-actions)
6. [Database Schema](#6-database-schema)
7. [How to Run](#7-how-to-run)
8. [API Reference](#8-api-reference)
9. [How a Real Attack Flows Through the System](#9-how-a-real-attack-flows-through-the-system)
10. [Key Security Concepts](#10-key-security-concepts)
11. [Extending the System](#11-extending-the-system)

---

## 1. What is a SOC?

A **Security Operations Center (SOC)** is a centralized team/facility that monitors, detects, analyzes, and responds to cybersecurity threats in real time. Think of it as the "nerve center" of an organization's cyber defense.

**What a SOC does:**
- **Monitor** — Continuously watch logs, network traffic, and system events
- **Detect** — Identify suspicious patterns using rules and analytics
- **Analyze** — Investigate alerts to determine if they're real threats
- **Respond** — Take action to contain and remediate threats

This MiniSOC simulates all of these functions in a single Python web application.

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        MiniSOC Architecture                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   ┌──────────┐     ┌───────────┐     ┌────────────┐                │
│   │  Server   │────▶│    Log    │────▶│ Detection  │                │
│   │   Logs    │     │ Collector │     │   Rules    │                │
│   │ (.log)    │     │  (Python) │     │  (.json)   │                │
│   └──────────┘     └───────────┘     └─────┬──────┘                │
│                                            │                        │
│                                            ▼                        │
│   ┌──────────┐     ┌───────────┐     ┌────────────┐                │
│   │   SOC    │◀────│   Risk    │◀────│   Alert    │                │
│   │Dashboard │     │  Scoring  │     │  Engine    │                │
│   │ (Flask)  │     │  (Python) │     │  (Python)  │                │
│   └────┬─────┘     └───────────┘     └────────────┘                │
│        │                                                            │
│        ▼                                                            │
│   ┌──────────┐     ┌───────────┐                                   │
│   │ Incident │────▶│ Response  │                                   │
│   │ Invest.  │     │  Actions  │                                   │
│   │ (Web UI) │     │ (Simulate)│                                   │
│   └──────────┘     └───────────┘                                   │
│                                                                     │
│   ┌─────────────────────────────────────────────────────────────┐   │
│   │                    SQLite Database (soc.db)                  │   │
│   │    alerts  │  incidents  │  response_actions  │  audit_log   │   │
│   └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

**Tech Stack:**
| Component | Technology |
|-----------|-----------|
| Backend | Python 3 + Flask |
| Database | SQLite (soc.db) |
| Scheduler | APScheduler (background scanning) |
| Frontend | HTML + Jinja2 Templates + CSS |
| Styling | Dark-themed custom CSS (GitHub-inspired) |

---

## 3. The Complete Pipeline

The system follows this exact flow — every step feeds into the next:

```
Server Logs → Log Collector → Detection Rules → Alert Engine → Risk Score → SOC Dashboard → Incident Investigation → Response
```

Here's what happens at each stage:

| Step | What Happens | Input | Output |
|------|-------------|-------|--------|
| **Server Logs** | Raw log files sit in the `logs/` folder | `.log` files | Raw text lines |
| **Log Collector** | Parses each line using regex, extracts fields | Raw lines | Structured dicts |
| **Detection Rules** | Defines what "suspicious" looks like | JSON config | Rule definitions |
| **Alert Engine** | Matches rules against parsed entries | Entries + Rules | Alert objects |
| **Risk Score** | Calculates a 0-100 score per alert | Alert data | Scored alerts |
| **SOC Dashboard** | Displays stats, charts, and recent alerts | DB queries | Web page |
| **Investigation** | Analyst drills into an alert, views correlations | Alert details | Investigation notes |
| **Response** | Actions taken to neutralize the threat | Analyst input | Block IP, disable user, etc. |

---

## 4. Project Structure

```
mini Soc/
├── app.py                  # 🚀 Main Flask application (entry point)
├── config.py               # ⚙️ Configuration constants
├── db.py                   # 🗄️ Database operations (SQLite)
├── log_collector.py        # 📥 Reads and parses log files
├── alert_engine.py         # 🔍 Matches rules against log entries
├── detection_rules.py      # 📋 Default rule definitions (Python)
├── detection_rules.json    # 📋 Active rule definitions (JSON)
├── test_run.py             # 🧪 Quick test script
├── requirements.txt        # 📦 Python dependencies
├── soc.db                  # 🗄️ SQLite database (created at runtime)
├── .log_offsets.json       # 📍 Tracks which log lines were already read
│
├── logs/                   # 📁 Server log files
│   ├── attack_scenarios.log    # Simulated attack events
│   └── normal_activity.log     # Normal server traffic
│
├── static/
│   └── style.css           # 🎨 Dark-themed stylesheet
│
└── templates/              # 🌐 HTML templates (Jinja2)
    ├── base.html               # Layout with sidebar navigation
    ├── dashboard.html          # SOC Dashboard with pipeline status
    ├── logs.html               # Log Viewer page
    ├── alerts.html             # Alerts list page
    ├── alert_detail.html       # Single alert deep-dive
    ├── incidents.html          # Incidents list page
    ├── incident_detail.html    # Incident investigation + response
    └── settings.html           # Detection rules viewer
```

---

## 5. Deep Dive: Each Component

### 5.1 Server Logs

**File:** `logs/*.log`

Server logs are the **raw material** of any SOC. In the real world, these come from web servers, firewalls, authentication systems, and operating systems.

**Log Format:**
```
[TIMESTAMP] LEVEL SOURCE ACTION USER IP DETAIL
```

**Example entries:**
```
[2026-09-01 08:01:00] WARNING auth.server LOGIN_FAIL unknown 203.0.113.50 user=admin password incorrect attempt 1
[2026-09-01 08:15:00] CRITICAL web.server REQUEST attacker 45.33.32.156 GET /api/search?q=UNION SELECT username,password FROM users--
[2026-09-01 08:20:00] CRITICAL shell.server EXECUTE admin 192.168.1.10 sudo rm -rf /important_data
```

**What each field means:**
| Field | Description | Example |
|-------|-------------|---------|
| `TIMESTAMP` | When the event happened | `2026-09-01 08:01:00` |
| `LEVEL` | Severity: INFO, WARNING, CRITICAL | `WARNING` |
| `SOURCE` | Which system generated it | `auth.server` |
| `ACTION` | What happened | `LOGIN_FAIL` |
| `USER` | Who did it | `admin` |
| `IP` | Where it came from | `203.0.113.50` |
| `DETAIL` | Additional context | `password incorrect attempt 3` |

**In this project**, we have two log files:
- **`attack_scenarios.log`** — Contains simulated attacks (brute force, SQL injection, privilege escalation, etc.)
- **`normal_activity.log`** — Contains normal user behavior (logins, page views)

---

### 5.2 Log Collector

**File:** `log_collector.py`

The Log Collector is responsible for **reading raw log files and converting them into structured data** that the detection engine can analyze.

**How it works:**

```python
# 1. Regex pattern extracts fields from each log line
LOG_PATTERN = re.compile(
    r"\[(?P<timestamp>[^\]]+)\] "   # [2026-09-01 08:01:00]
    r"(?P<level>\w+) "              # WARNING
    r"(?P<source>[\w\.]+) "         # auth.server
    r"(?P<action>\w+) "             # LOGIN_FAIL
    r"(?P<user>\S+) "               # unknown
    r"(?P<ip>[\d\.]+|[\w:]+) "      # 203.0.113.50
    r"(?P<detail>.*)"               # user=admin password incorrect
)

# 2. Each matching line becomes a dictionary:
{
    "timestamp": datetime(2026, 9, 1, 8, 1, 0),
    "level": "WARNING",
    "source": "auth.server",
    "action": "LOGIN_FAIL",
    "user": "unknown",
    "ip": "203.0.113.50",
    "detail": "user=admin password incorrect attempt 1",
    "raw": "[2026-09-01 08:01:00] WARNING auth.server LOGIN_FAIL ...",
    "file": "attack_scenarios.log"
}
```

**Key feature — Offset Tracking (deduplication):**

The collector tracks **how far it has read** in each file using `.log_offsets.json`. This prevents re-reading and re-alerting on the same log lines:

```
First scan:  reads lines 1–48 → saves offset = 5013 bytes
Second scan: starts at byte 5013 → 0 new lines → no duplicate alerts
```

If new lines are appended to a log file, only those new lines get processed on the next scan.

**Key functions:**
| Function | Purpose |
|----------|---------|
| `collect_logs()` | Reads only NEW lines since last scan |
| `collect_all_logs()` | Reads ALL lines (for the Log Viewer page) |
| `get_log_files_info()` | Returns metadata about each log file |
| `reset_offsets()` | Deletes offset tracking to force full re-scan |

---

### 5.3 Detection Rules

**Files:** `detection_rules.py` (defaults) + `detection_rules.json` (active)

Detection rules define **what suspicious activity looks like**. There are two types:

#### Pattern Rules (instant match)
These use **regex** to detect a single dangerous event:

```json
{
    "id": "SQLI_ATTEMPT",
    "name": "SQL Injection Attempt",
    "description": "SQL injection patterns detected in request details.",
    "severity": "critical",
    "base_score": 45,
    "detect": "pattern",
    "field": "detail",
    "pattern": "(UNION SELECT|OR 1=1|DROP TABLE|--\\s|;\\s*DROP|'\\s*OR\\s*')"
}
```
→ If the `detail` field of any log entry matches the regex, an alert fires **immediately**.

#### Threshold Rules (frequency-based)
These detect **suspicious volume** of similar events:

```json
{
    "id": "BRUTE_FORCE",
    "name": "Brute Force Login Attempt",
    "description": "Multiple failed login attempts from the same IP/user.",
    "severity": "high",
    "base_score": 40,
    "detect": "threshold",
    "field": "user",
    "condition": "action == 'LOGIN_FAIL'",
    "threshold": 5,
    "window_seconds": 300
}
```
→ If the same `user` has **5 or more** `LOGIN_FAIL` events within **300 seconds** (5 minutes), an alert fires.

**Currently active rules:**

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

### 5.4 Alert Engine

**File:** `alert_engine.py`

The Alert Engine is the **brain** of detection. It takes parsed log entries + rules and produces alerts.

**How detection works:**

```
For each log entry:
    For each rule:
        If rule is "pattern" type:
            → Run regex against the specified field
            → If match → create alert (dedupe by rule+ip+user)

        If rule is "threshold" type:
            → Count matching events for same entity within time window
            → If count >= threshold → create alert (dedupe by rule+ip+user)
```

**Deduplication:** The engine prevents the same alert from firing multiple times for the same (rule, IP, user) combination within a single scan.

**Safe Condition Evaluation:**

For threshold rules, conditions like `action == 'LOGIN_FAIL'` are evaluated safely using regex parsing instead of Python's dangerous `eval()`:

```python
# Instead of: eval("action == 'LOGIN_FAIL'")  ← DANGEROUS!
# We use safe parsing:
def _safe_eval_condition(condition, entry):
    # Handles: field == 'value'
    # Handles: field in ('val1', 'val2')
    # No arbitrary code execution possible
```

**Output — an alert dict:**
```python
{
    "rule_id": "SQLI_ATTEMPT",
    "rule_name": "SQL Injection Attempt",
    "severity": "critical",
    "description": "SQL injection patterns detected...",
    "base_score": 45,
    "timestamp": datetime(2026, 9, 1, 8, 15, 0),
    "source_ip": "45.33.32.156",
    "user": "attacker",
    "action": "REQUEST",
    "detail": "GET /api/search?q=UNION SELECT...",
    "raw": "[2026-09-01 08:15:00] CRITICAL web.server...",
    "evidence_count": 1,
    "file": "attack_scenarios.log"
}
```

---

### 5.5 Risk Scoring

**File:** `db.py` — functions `_calc_risk()` and `get_risk_level()`

Risk scoring assigns a **0–100 numerical score** to each alert, helping analysts prioritize what to investigate first.

**Formula:**
```
Risk Score = Base Score + Severity Bonus + Evidence Bonus
             (capped at 100)
```

| Component | How It's Calculated |
|-----------|-------------------|
| **Base Score** | Defined per rule (e.g., SQLI = 45, Brute Force = 40) |
| **Severity Bonus** | critical = +50, high = +35, medium = +20, low = +10 |
| **Evidence Bonus** | `min(evidence_count × 3, 20)` — more evidence = higher score |

**Example calculation:**
```
SQL Injection Alert:
  Base Score     = 45 (from rule definition)
  Severity Bonus = 50 (critical severity)
  Evidence Bonus =  3 (1 hit × 3, capped at 20)
  ─────────────────────
  Risk Score     = 98 (capped at 100)
```

**Risk Levels (thresholds defined in `config.py`):**

| Score Range | Risk Level | Color |
|------------|------------|-------|
| 85–100 | **CRITICAL** | 🔴 Red |
| 60–84 | **HIGH** | 🟠 Orange |
| 30–59 | **MEDIUM** | 🟡 Yellow |
| 0–29 | **LOW** | 🟢 Green |

---

### 5.6 SOC Dashboard

**File:** `templates/dashboard.html` + `app.py` route `/dashboard`

The Dashboard is the **command center** where an analyst gets a high-level view of the security posture.

**What it shows:**

1. **Pipeline Status Bar** — Visual representation of the full SOC flow with live counts:
   ```
   Server Logs (2 files) → Log Collector (66 entries) → Detection Rules (9 rules) → Alert Engine (18 alerts) → Risk Score (Max 98) → Dashboard (Live)
   ```

2. **Stat Cards** — Key metrics at a glance:
   - Open Alerts count
   - Open Incidents count
   - Total Alerts count
   - Max Risk Score (with severity label)

3. **Panels:**
   - Alerts by Severity (bar chart)
   - Top Offending IPs
   - Top Targeted Users
   - Most Triggered Rules
   - Recent Alerts table (clickable rows)

**Auto-refresh:** The scheduler runs `run_scan()` every 5 seconds (configurable in `config.py`), so new alerts appear automatically.

---

### 5.7 Incident Investigation

**Files:** `templates/alert_detail.html`, `templates/incident_detail.html`

When a SOC analyst sees a suspicious alert, they **investigate** it to determine if it's a real threat.

**Investigation flow:**

```
1. Analyst sees alert on Dashboard/Alerts page
   ↓
2. Clicks alert → Alert Detail page
   ↓
3. Reviews: rule info, raw log, risk score breakdown
   ↓
4. Checks Correlated Alerts (same IP / same user)
   ↓
5. Adds investigation notes
   ↓
6. Changes status: open → investigating → resolved
   ↓
7. If real threat → "Create Incident" button
   ↓
8. Incident page: links multiple alerts, adds response actions
```

**Correlated Alerts** help the analyst see the bigger picture:
- "This IP also triggered 5 other alerts" → probably an attacker
- "This user also had sensitive file access" → possible insider threat

**Audit Timeline** — Every action is logged:
- Status changes
- Notes updates
- Incident creation
- Response actions

---

### 5.8 Response Actions

**File:** `templates/incident_detail.html` + `db.py` function `execute_response_action()`

Once a threat is confirmed, the SOC analyst takes **response actions** to neutralize it.

**Available response types:**

| Action Type | What It Simulates |
|------------|------------------|
| 🚫 **Block IP** | "Firewall rule added: DENY x.x.x.x — all ports blocked" |
| 🔒 **Disable User** | "User account 'admin' disabled in Active Directory" |
| 🔌 **Isolate Host** | "Host 'x.x.x.x' isolated from network via EDR agent" |
| 🔔 **Notify Admin** | "Alert notification sent to SOC admin" |
| ✏️ **Manual Action** | Free-text description of a manual step taken |

**Response lifecycle:**
```
pending → [Analyst clicks "Execute"] → executed
```

Each response action records:
- When it was created
- When it was executed
- The result message
- Full audit trail

> **Note:** In this learning project, execution is **simulated** — no actual firewall rules are created. In a real SOC, these would integrate with firewalls, SIEM, EDR, and Active Directory APIs.

---

## 6. Database Schema

**File:** `soc.db` (SQLite)

```
┌─────────────────────────────────┐
│           alerts                │
├─────────────────────────────────┤
│ id (PK)          INTEGER        │
│ rule_id           TEXT          │
│ rule_name         TEXT          │
│ severity          TEXT          │  ← critical/high/medium/low
│ description       TEXT          │
│ base_score        INTEGER       │
│ risk_score        INTEGER       │  ← calculated 0-100
│ risk_level        TEXT          │  ← critical/high/medium/low
│ timestamp         TEXT          │
│ source_ip         TEXT          │
│ user              TEXT          │
│ action            TEXT          │
│ detail            TEXT          │
│ raw               TEXT          │  ← original log line
│ evidence_count    INTEGER       │
│ file              TEXT          │  ← which log file
│ status            TEXT          │  ← open/investigating/linked/resolved
│ notes             TEXT          │
│ created_at        TEXT          │
│ updated_at        TEXT          │
└─────────────────────────────────┘

┌─────────────────────────────────┐
│          incidents              │
├─────────────────────────────────┤
│ id (PK)          INTEGER        │
│ title             TEXT          │
│ severity          TEXT          │
│ status            TEXT          │  ← open/investigating/resolved/closed
│ description       TEXT          │
│ risk_score        INTEGER       │
│ risk_level        TEXT          │
│ alert_ids         TEXT (JSON)   │  ← [1, 5, 12] linked alert IDs
│ assigned_to       TEXT          │
│ resolution        TEXT          │
│ investigation_notes TEXT        │
│ created_at        TEXT          │
│ updated_at        TEXT          │
└─────────────────────────────────┘

┌─────────────────────────────────┐
│       response_actions          │
├─────────────────────────────────┤
│ id (PK)          INTEGER        │
│ incident_id (FK)  INTEGER       │  → incidents.id
│ action_type       TEXT          │  ← block_ip/disable_user/isolate_host/...
│ target            TEXT          │  ← IP, username, hostname
│ description       TEXT          │
│ status            TEXT          │  ← pending/executed/failed
│ executed_at       TEXT          │
│ completed_at      TEXT          │
│ result            TEXT          │  ← execution result message
└─────────────────────────────────┘

┌─────────────────────────────────┐
│          audit_log              │
├─────────────────────────────────┤
│ id (PK)          INTEGER        │
│ entity_type       TEXT          │  ← "alert" or "incident"
│ entity_id         INTEGER       │
│ action            TEXT          │  ← what happened
│ details           TEXT          │
│ user              TEXT          │  ← who did it
│ created_at        TEXT          │
└─────────────────────────────────┘
```

---

## 7. How to Run

### Prerequisites
```bash
# Python 3.10+ required
python --version

# Install dependencies
pip install -r requirements.txt
```

The `requirements.txt` contains:
```pytho
flask==3.1.1
apscheduler==3.11.0
```

### Starting the Application
```bash
# From the mini Soc directory:
python app.py
```

**What happens on startup:**
1. `init_db()` — Creates database tables if they don't exist
2. `run_scan()` — Runs initial scan of log files
3. `scheduler.start()` — Begins background scanning every 5 seconds
4. Flask starts on `http://127.0.0.1:5000`

### Accessing the Web UI

| Page | URL | Purpose |
|------|-----|---------|
| Dashboard | http://127.0.0.1:5000/dashboard | Overview + pipeline status |
| Log Viewer | http://127.0.0.1:5000/logs | Browse raw server logs |
| Alerts | http://127.0.0.1:5000/alerts | List and filter alerts |
| Alert Detail | http://127.0.0.1:5000/alert/1 | Deep-dive into an alert |
| Incidents | http://127.0.0.1:5000/incidents | List incidents |
| Incident Detail | http://127.0.0.1:5000/incident/1 | Investigation + response |
| Rules | http://127.0.0.1:5000/settings | View detection rules |

### Quick Test (without web UI)
```bash
python test_run.py
```
This runs the pipeline in the terminal and prints results:
```
Parsed 66 log entries
Generated 18 alerts
  [high    ] Brute Force Login Attempt    203.0.113.50    user=unknown
  [critical] SQL Injection Attempt        45.33.32.156    user=attacker
  ...
Inserted 18 alerts into database
```

### Resetting the Database
```bash
# Delete the database and offset tracker to start fresh
del soc.db
del .log_offsets.json
python app.py
```

---

## 8. API Reference

All APIs are accessible for programmatic interaction:

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `POST` | `/api/scan` | Trigger a manual scan |
| `POST` | `/api/scan/reset` | Reset offsets and full re-scan |
| `GET` | `/api/stats` | Get dashboard statistics (JSON) |
| `GET` | `/api/logs` | Get all parsed log entries (JSON) |
| `POST` | `/api/alert/<id>/status` | Update alert status |
| `GET` | `/api/alert/<id>/correlations` | Get correlated alerts |
| `POST` | `/api/incident` | Create a new incident |
| `POST` | `/api/incident/<id>/status` | Update incident status |
| `POST` | `/api/incident/<id>/notes` | Update investigation notes |
| `POST` | `/api/incident/<id>/response` | Add a response action |
| `POST` | `/api/response/<id>/execute` | Execute a response action |

**Example — Trigger a scan:**
```bash
curl -X POST http://127.0.0.1:5000/api/scan
# Response: {"ok": true, "message": "Scan completed"}
```

**Example — Create an incident:**
```bash
curl -X POST http://127.0.0.1:5000/api/incident \
  -H "Content-Type: application/json" \
  -d '{"title": "Brute Force Attack", "severity": "high", "alert_ids": [1,2,3], "risk_score": 75}'
```

---

## 9. How a Real Attack Flows Through the System

Let's trace a **brute force attack** end-to-end:

### Step 1: Attacker sends login attempts → Server Logs
```
[2026-09-01 08:01:00] WARNING auth.server LOGIN_FAIL unknown 203.0.113.50 user=admin password incorrect attempt 1
[2026-09-01 08:01:03] WARNING auth.server LOGIN_FAIL unknown 203.0.113.50 user=admin password incorrect attempt 2
[2026-09-01 08:01:06] WARNING auth.server LOGIN_FAIL unknown 203.0.113.50 user=admin password incorrect attempt 3
[2026-09-01 08:01:09] WARNING auth.server LOGIN_FAIL unknown 203.0.113.50 user=admin password incorrect attempt 4
[2026-09-01 08:01:12] WARNING auth.server LOGIN_FAIL unknown 203.0.113.50 user=admin password incorrect attempt 5
[2026-09-01 08:01:15] WARNING auth.server LOGIN_FAIL unknown 203.0.113.50 user=admin password incorrect attempt 6
```

### Step 2: Log Collector parses them
```python
# Each line becomes a dict with timestamp, level, action, user, ip, detail
# 6 entries extracted, sorted by timestamp
```

### Step 3: Detection Rules match
```python
# BRUTE_FORCE rule: threshold=5, field="user", condition="action == 'LOGIN_FAIL'"
# 6 events for user "unknown" with LOGIN_FAIL within 300s → THRESHOLD EXCEEDED ✓
```

### Step 4: Alert Engine generates alert
```python
{
    "rule_id": "BRUTE_FORCE",
    "rule_name": "Brute Force Login Attempt",
    "severity": "high",
    "source_ip": "203.0.113.50",
    "user": "unknown",
    "evidence_count": 6
}
```

### Step 5: Risk Score calculated
```
Base (40) + Severity High (35) + Evidence 6×3=18 = 93 → CRITICAL risk level
```

### Step 6: Dashboard shows the alert
- Open Alerts counter increases
- Alert appears in "Recent Alerts" table
- IP appears in "Top Offending IPs"
- Risk score shows as 93 (red)

### Step 7: Analyst investigates
- Clicks the alert → sees raw log, risk breakdown
- Checks correlated alerts → same IP also triggered MULTI_FAIL_LOGIN and SUSPICIOUS_IP
- Conclusion: confirmed brute force attack from 203.0.113.50
- Creates incident

### Step 8: Response
- Adds response action: **Block IP** → target: `203.0.113.50`
- Clicks **Execute** → "Firewall rule added: DENY 203.0.113.50 — all ports blocked"
- Changes incident status to **Resolved**

---

## 10. Key Security Concepts

### SIEM (Security Information and Event Management)
This MiniSOC is a simplified SIEM. Real SIEMs like Splunk, IBM QRadar, and Wazuh do the same thing at enterprise scale with millions of events per second.

### Detection Methods
| Method | How It Works | Example in This Project |
|--------|-------------|----------------------|
| **Signature/Pattern** | Match known attack strings | SQL injection regex `UNION SELECT` |
| **Threshold/Anomaly** | Flag unusual volume of events | 5+ failed logins in 5 minutes |
| **Correlation** | Connect related events | Same IP triggering multiple rules |

### Alert Fatigue
SOC analysts often face thousands of alerts daily. Risk scoring helps **prioritize** — a critical SQL injection (score 98) gets attention before a medium info-gathering probe (score 43).

### MITRE ATT&CK Mapping (what our rules detect)

| Tactic | Technique | Our Rule |
|--------|-----------|----------|
| Initial Access | Brute Force (T1110) | BRUTE_FORCE, MULTI_FAIL_LOGIN |
| Privilege Escalation | Sudo/Chmod (T1548) | PRIV_ESC |
| Collection | Data from Local System (T1005) | SENSITIVE_ACCESS |
| Command & Control | Application Layer (T1071) | COMMAND_INJECTION |
| Discovery | Network Service Scanning (T1046) | PORT_SCAN |
| Initial Access | Web Application Exploit (T1190) | SQLI_ATTEMPT, PATH_TRAVERSAL |

### Incident Response Lifecycle
```
   Preparation → Detection → Analysis → Containment → Eradication → Recovery → Lessons Learned
                  ────────────── This project covers ──────────────
```

---

## 11. Extending the System

Here are ideas to enhance this MiniSOC further:

### Add New Detection Rules
Edit `detection_rules.json` and add new entries:
```json
{
    "id": "DATA_EXFIL",
    "name": "Data Exfiltration Attempt",
    "description": "Large data transfer to external IP detected.",
    "severity": "critical",
    "base_score": 50,
    "detect": "pattern",
    "field": "detail",
    "pattern": "(large_transfer|export_data|download_all)"
}
```

### Add More Log Sources
Drop new `.log` files into the `logs/` folder. As long as they follow the format `[TIMESTAMP] LEVEL SOURCE ACTION USER IP DETAIL`, they'll be automatically parsed on the next scan.

### Add Real-Time Log Streaming
Replace file-based log reading with a live socket or Syslog receiver to process events as they happen.

### Add User Authentication
Add Flask-Login to protect the SOC dashboard so only authorized analysts can access it.

### Connect Real Response APIs
Replace the simulated `execute_response_action()` with actual API calls to:
- Firewall API (iptables, pfSense, AWS Security Groups)
- Active Directory API (disable user accounts)
- EDR API (CrowdStrike, SentinelOne) to isolate hosts
- Email/Slack API for notifications

### Add Machine Learning
Use anomaly detection models to identify unusual behavior patterns that rules can't catch (e.g., a user logging in at 3 AM for the first time).

---

> **Built for learning.** This project demonstrates the core concepts behind enterprise SOC tools like Splunk SOAR, IBM QRadar, and Wazuh. Understanding this pipeline is fundamental to a career in cybersecurity and SOC analysis.
