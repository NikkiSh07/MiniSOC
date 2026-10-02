import sqlite3
import json
from datetime import datetime, timedelta
from config import DB_PATH
from config import RISK_LOW, RISK_MEDIUM, RISK_HIGH


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT,
            base_score INTEGER,
            risk_score INTEGER DEFAULT 0,
            risk_level TEXT DEFAULT 'low',
            timestamp TEXT,
            source_ip TEXT,
            user TEXT,
            action TEXT,
            detail TEXT,
            raw TEXT,
            evidence_count INTEGER DEFAULT 1,
            file TEXT,
            status TEXT DEFAULT 'open',
            notes TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT DEFAULT 'open',
            description TEXT,
            risk_score INTEGER DEFAULT 0,
            risk_level TEXT DEFAULT 'low',
            alert_ids TEXT DEFAULT '[]',
            assigned_to TEXT DEFAULT '',
            resolution TEXT DEFAULT '',
            investigation_notes TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS response_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER,
            action_type TEXT NOT NULL,
            target TEXT,
            description TEXT,
            status TEXT DEFAULT 'pending',
            executed_at TEXT DEFAULT (datetime('now')),
            completed_at TEXT,
            result TEXT DEFAULT '',
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_type TEXT NOT NULL,
            entity_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            details TEXT DEFAULT '',
            user TEXT DEFAULT 'system',
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
        CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
        CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);
        CREATE INDEX IF NOT EXISTS idx_alerts_user ON alerts(user);
        CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
        CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_log(entity_type, entity_id);
    """)
    conn.commit()
    conn.close()


def _calc_risk(alert: dict) -> int:
    sev_map = {"critical": 50, "high": 35, "medium": 20, "low": 10}
    base = alert.get("base_score", 10)
    sev_bonus = sev_map.get(alert.get("severity", "low"), 10)
    evidence_bonus = min(alert.get("evidence_count", 1) * 3, 20)
    return min(base + sev_bonus + evidence_bonus, 100)


def get_risk_level(score: int) -> str:
    if score >= RISK_HIGH:
        return "critical"
    elif score >= RISK_MEDIUM:
        return "high"
    elif score >= RISK_LOW:
        return "medium"
    return "low"


def _is_duplicate(conn, alert: dict) -> bool:
    """Check if an alert with the same rule_id, source_ip, user, and nearby timestamp already exists."""
    ts = str(alert.get("timestamp", ""))
    row = conn.execute("""
        SELECT COUNT(*) as c FROM alerts
        WHERE rule_id=? AND source_ip=? AND user=? AND timestamp=?
    """, (alert["rule_id"], alert["source_ip"], alert["user"], ts)).fetchone()
    return row["c"] > 0


def insert_alerts(alerts: list[dict]) -> int:
    conn = get_db()
    count = 0
    for a in alerts:
        if _is_duplicate(conn, a):
            continue
        risk = _calc_risk(a)
        risk_level = get_risk_level(risk)
        conn.execute("""
            INSERT INTO alerts (rule_id, rule_name, severity, description, base_score,
                risk_score, risk_level, timestamp, source_ip, user, action, detail, raw,
                evidence_count, file)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            a["rule_id"], a["rule_name"], a["severity"], a["description"],
            a["base_score"], risk, risk_level, str(a["timestamp"]), a["source_ip"],
            a["user"], a["action"], a["detail"], a["raw"],
            a["evidence_count"], a["file"],
        ))
        count += 1
    conn.commit()
    conn.close()
    return count


def get_dashboard_stats() -> dict:
    conn = get_db()
    stats = {}
    row = conn.execute("SELECT COUNT(*) as c FROM alerts WHERE status='open'").fetchone()
    stats["open_alerts"] = row["c"]
    row = conn.execute("SELECT COUNT(*) as c FROM alerts").fetchone()
    stats["total_alerts"] = row["c"]
    row = conn.execute("SELECT COUNT(*) as c FROM incidents WHERE status='open'").fetchone()
    stats["open_incidents"] = row["c"]
    row = conn.execute("SELECT COUNT(*) as c FROM incidents").fetchone()
    stats["total_incidents"] = row["c"]

    sev_rows = conn.execute(
        "SELECT severity, COUNT(*) as c FROM alerts WHERE status='open' GROUP BY severity"
    ).fetchall()
    stats["by_severity"] = {r["severity"]: r["c"] for r in sev_rows}

    row = conn.execute("SELECT COALESCE(MAX(risk_score),0) as m FROM alerts WHERE status='open'").fetchone()
    stats["max_risk"] = row["m"]
    stats["max_risk_level"] = get_risk_level(row["m"])

    recent = conn.execute(
        "SELECT * FROM alerts ORDER BY created_at DESC LIMIT 10"
    ).fetchall()
    stats["recent_alerts"] = [dict(r) for r in recent]

    top_ips = conn.execute(
        "SELECT source_ip, COUNT(*) as c FROM alerts WHERE status='open' GROUP BY source_ip ORDER BY c DESC LIMIT 5"
    ).fetchall()
    stats["top_offending_ips"] = [dict(r) for r in top_ips]

    top_users = conn.execute(
        "SELECT user, COUNT(*) as c FROM alerts WHERE status='open' GROUP BY user ORDER BY c DESC LIMIT 5"
    ).fetchall()
    stats["top_targeted_users"] = [dict(r) for r in top_users]

    top_rules = conn.execute(
        "SELECT rule_id, rule_name, COUNT(*) as c FROM alerts WHERE status='open' GROUP BY rule_id ORDER BY c DESC LIMIT 5"
    ).fetchall()
    stats["top_triggered_rules"] = [dict(r) for r in top_rules]

    # Pipeline status counts
    stats["total_log_files"] = 0
    stats["total_log_entries"] = 0
    stats["total_rules"] = 0

    conn.close()
    return stats


def get_alerts(status=None, severity=None, limit=100) -> list[dict]:
    conn = get_db()
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []
    if status:
        query += " AND status=?"
        params.append(status)
    if severity:
        query += " AND severity=?"
        params.append(severity)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_alert(alert_id: int) -> dict | None:
    conn = get_db()
    row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    conn.close()
    if not row:
        return None
    alert = dict(row)
    alert["risk_level"] = get_risk_level(alert.get("risk_score", 0))
    return alert


def update_alert_status(alert_id: int, status: str, notes: str = ""):
    conn = get_db()
    conn.execute(
        "UPDATE alerts SET status=?, notes=?, updated_at=datetime('now') WHERE id=?",
        (status, notes, alert_id),
    )
    # Log the status change
    conn.execute(
        "INSERT INTO audit_log (entity_type, entity_id, action, details) VALUES (?, ?, ?, ?)",
        ("alert", alert_id, f"status_changed_to_{status}", notes),
    )
    conn.commit()
    conn.close()


def get_correlated_alerts(alert_id: int, limit: int = 20) -> dict:
    """Find alerts correlated by same source_ip or same user."""
    conn = get_db()
    alert = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if not alert:
        conn.close()
        return {"by_ip": [], "by_user": []}

    alert = dict(alert)

    by_ip = conn.execute(
        "SELECT * FROM alerts WHERE source_ip=? AND id!=? ORDER BY created_at DESC LIMIT ?",
        (alert["source_ip"], alert_id, limit),
    ).fetchall()

    by_user = conn.execute(
        "SELECT * FROM alerts WHERE user=? AND id!=? ORDER BY created_at DESC LIMIT ?",
        (alert["user"], alert_id, limit),
    ).fetchall()

    conn.close()
    return {
        "by_ip": [dict(r) for r in by_ip],
        "by_user": [dict(r) for r in by_user],
    }


def create_incident(title: str, severity: str, description: str, alert_ids: list[int], risk_score: int) -> int:
    conn = get_db()
    risk_level = get_risk_level(risk_score)
    cur = conn.execute("""
        INSERT INTO incidents (title, severity, description, alert_ids, risk_score, risk_level)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (title, severity, description, json.dumps(alert_ids), risk_score, risk_level))
    inc_id = cur.lastrowid
    for aid in alert_ids:
        conn.execute("UPDATE alerts SET status='linked' WHERE id=?", (aid,))
    # Audit log
    conn.execute(
        "INSERT INTO audit_log (entity_type, entity_id, action, details) VALUES (?, ?, ?, ?)",
        ("incident", inc_id, "created", f"Linked alerts: {alert_ids}"),
    )
    conn.commit()
    conn.close()
    return inc_id


def get_incidents(status=None, limit=50) -> list[dict]:
    conn = get_db()
    query = "SELECT * FROM incidents WHERE 1=1"
    params = []
    if status:
        query += " AND status=?"
        params.append(status)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    results = []
    for r in rows:
        d = dict(r)
        d["risk_level"] = get_risk_level(d.get("risk_score", 0))
        results.append(d)
    return results


def get_incident(incident_id: int) -> dict | None:
    conn = get_db()
    row = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if not row:
        conn.close()
        return None
    inc = dict(row)
    inc["risk_level"] = get_risk_level(inc.get("risk_score", 0))

    alert_ids = json.loads(inc.get("alert_ids", "[]"))
    if alert_ids:
        placeholders = ",".join("?" * len(alert_ids))
        alert_rows = conn.execute(
            f"SELECT * FROM alerts WHERE id IN ({placeholders})", alert_ids
        ).fetchall()
        inc["alerts"] = [dict(r) for r in alert_rows]
    else:
        inc["alerts"] = []

    actions = conn.execute(
        "SELECT * FROM response_actions WHERE incident_id=? ORDER BY executed_at", (incident_id,)
    ).fetchall()
    inc["response_actions"] = [dict(r) for r in actions]

    # Audit timeline
    timeline = conn.execute(
        "SELECT * FROM audit_log WHERE entity_type='incident' AND entity_id=? ORDER BY created_at DESC",
        (incident_id,),
    ).fetchall()
    inc["timeline"] = [dict(r) for r in timeline]

    conn.close()
    return inc


def update_incident(incident_id: int, **kwargs):
    conn = get_db()
    sets = []
    vals = []
    for k, v in kwargs.items():
        sets.append(f"{k}=?")
        vals.append(v)
    sets.append("updated_at=datetime('now')")
    vals.append(incident_id)
    conn.execute(f"UPDATE incidents SET {','.join(sets)} WHERE id=?", vals)
    # Audit log
    changes = ", ".join(f"{k}={v}" for k, v in kwargs.items())
    conn.execute(
        "INSERT INTO audit_log (entity_type, entity_id, action, details) VALUES (?, ?, ?, ?)",
        ("incident", incident_id, "updated", changes),
    )
    conn.commit()
    conn.close()


def update_incident_notes(incident_id: int, notes: str):
    conn = get_db()
    conn.execute(
        "UPDATE incidents SET investigation_notes=?, updated_at=datetime('now') WHERE id=?",
        (notes, incident_id),
    )
    conn.execute(
        "INSERT INTO audit_log (entity_type, entity_id, action, details) VALUES (?, ?, ?, ?)",
        ("incident", incident_id, "notes_updated", "Investigation notes updated"),
    )
    conn.commit()
    conn.close()


def add_response_action(incident_id: int, action_type: str, target: str, description: str) -> int:
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO response_actions (incident_id, action_type, target, description, status) VALUES (?, ?, ?, ?, ?)",
        (incident_id, action_type, target, description, "pending"),
    )
    action_id = cur.lastrowid
    conn.execute(
        "INSERT INTO audit_log (entity_type, entity_id, action, details) VALUES (?, ?, ?, ?)",
        ("incident", incident_id, "response_added", f"{action_type} on {target}"),
    )
    conn.commit()
    conn.close()
    return action_id


def execute_response_action(action_id: int) -> dict:
    """Simulate executing a response action."""
    conn = get_db()
    row = conn.execute("SELECT * FROM response_actions WHERE id=?", (action_id,)).fetchone()
    if not row:
        conn.close()
        return {"ok": False, "error": "Action not found"}

    action = dict(row)
    # Simulate execution based on action type
    result_map = {
        "block_ip": f"Firewall rule added: DENY {action['target']} — all ports blocked",
        "disable_user": f"User account '{action['target']}' disabled in Active Directory",
        "isolate_host": f"Host '{action['target']}' isolated from network via EDR agent",
        "notify_admin": f"Alert notification sent to SOC admin re: {action['target']}",
        "manual": f"Manual action recorded: {action['description']}",
    }
    result = result_map.get(action["action_type"], f"Action '{action['action_type']}' executed on {action['target']}")

    conn.execute(
        "UPDATE response_actions SET status='executed', completed_at=datetime('now'), result=? WHERE id=?",
        (result, action_id),
    )
    conn.execute(
        "INSERT INTO audit_log (entity_type, entity_id, action, details) VALUES (?, ?, ?, ?)",
        ("incident", action["incident_id"], "response_executed", result),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "result": result}


def get_audit_log(entity_type: str, entity_id: int) -> list[dict]:
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM audit_log WHERE entity_type=? AND entity_id=? ORDER BY created_at DESC",
        (entity_type, entity_id),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
