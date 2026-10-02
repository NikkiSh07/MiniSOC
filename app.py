import os
import json
from flask import Flask, render_template, request, jsonify, redirect, url_for
from db import (
    init_db, get_db, get_dashboard_stats, get_alerts, get_alert,
    update_alert_status, create_incident, get_incidents, get_incident,
    update_incident, update_incident_notes, add_response_action,
    execute_response_action, insert_alerts, get_risk_level,
    get_correlated_alerts, get_audit_log,
)
from log_collector import collect_logs, collect_all_logs, get_log_files_info, reset_offsets
from alert_engine import run_detection, load_rules
from config import SCAN_INTERVAL_SECONDS, RULES_PATH
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime

app = Flask(__name__)


def run_scan():
    try:
        entries = collect_logs()
        if not entries:
            return
        alerts = run_detection(entries)
        if alerts:
            insert_alerts(alerts)
    except Exception as e:
        print(f"[SCAN ERROR] {e}")


scheduler = BackgroundScheduler()
scheduler.add_job(run_scan, "interval", seconds=SCAN_INTERVAL_SECONDS, id="log_scan")


# ─── Pages ────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    stats = get_dashboard_stats()
    # Inject pipeline data
    log_files = get_log_files_info()
    stats["total_log_files"] = len(log_files)
    stats["total_log_entries"] = sum(f["lines"] for f in log_files)
    rules = load_rules()
    stats["total_rules"] = len(rules)
    return render_template("dashboard.html", stats=stats)


@app.route("/logs")
def logs_page():
    entries = collect_all_logs()
    log_files = get_log_files_info()
    file_filter = request.args.get("file")
    level_filter = request.args.get("level")
    search = request.args.get("search", "").strip()

    if file_filter:
        entries = [e for e in entries if e["file"] == file_filter]
    if level_filter:
        entries = [e for e in entries if e["level"].upper() == level_filter.upper()]
    if search:
        entries = [e for e in entries if search.lower() in e["raw"].lower()]

    # Serialize timestamps for template
    for e in entries:
        if isinstance(e["timestamp"], datetime):
            e["timestamp"] = e["timestamp"].strftime("%Y-%m-%d %H:%M:%S")

    return render_template(
        "logs.html",
        entries=entries,
        log_files=log_files,
        current_file=file_filter,
        current_level=level_filter,
        search=search,
    )


@app.route("/alerts")
def alerts_page():
    status = request.args.get("status", "open")
    severity = request.args.get("severity")
    alerts = get_alerts(status=status if status != "all" else None, severity=severity)
    return render_template("alerts.html", alerts=alerts, current_status=status, current_severity=severity)


@app.route("/alert/<int:alert_id>")
def alert_detail(alert_id):
    alert = get_alert(alert_id)
    if not alert:
        return "Alert not found", 404
    correlations = get_correlated_alerts(alert_id)
    timeline = get_audit_log("alert", alert_id)
    return render_template("alert_detail.html", alert=alert, correlations=correlations, timeline=timeline)


@app.route("/incidents")
def incidents_page():
    status = request.args.get("status")
    incidents = get_incidents(status=status)
    return render_template("incidents.html", incidents=incidents, current_status=status)


@app.route("/incident/<int:incident_id>")
def incident_detail(incident_id):
    incident = get_incident(incident_id)
    if not incident:
        return "Incident not found", 404
    return render_template("incident_detail.html", incident=incident)


@app.route("/settings")
def settings_page():
    from detection_rules import DEFAULT_RULES
    rules = DEFAULT_RULES
    if os.path.exists(RULES_PATH):
        with open(RULES_PATH, "r") as f:
            rules = json.load(f)
    return render_template("settings.html", rules=rules)


# ─── APIs ─────────────────────────────────────────────────────────────────

@app.route("/api/alert/<int:alert_id>/status", methods=["POST"])
def api_update_alert(alert_id):
    data = request.get_json()
    update_alert_status(alert_id, data.get("status", "open"), data.get("notes", ""))
    return jsonify({"ok": True})


@app.route("/api/alert/<int:alert_id>/correlations")
def api_alert_correlations(alert_id):
    return jsonify(get_correlated_alerts(alert_id))


@app.route("/api/incident", methods=["POST"])
def api_create_incident():
    data = request.get_json()
    inc_id = create_incident(
        title=data["title"],
        severity=data.get("severity", "medium"),
        description=data.get("description", ""),
        alert_ids=data.get("alert_ids", []),
        risk_score=data.get("risk_score", 0),
    )
    return jsonify({"ok": True, "id": inc_id})


@app.route("/api/incident/<int:incident_id>/status", methods=["POST"])
def api_update_incident(incident_id):
    data = request.get_json()
    update_incident(incident_id, status=data.get("status", "open"))
    return jsonify({"ok": True})


@app.route("/api/incident/<int:incident_id>/notes", methods=["POST"])
def api_update_incident_notes(incident_id):
    data = request.get_json()
    update_incident_notes(incident_id, data.get("notes", ""))
    return jsonify({"ok": True})


@app.route("/api/incident/<int:incident_id>/response", methods=["POST"])
def api_add_response(incident_id):
    data = request.get_json()
    action_id = add_response_action(
        incident_id=incident_id,
        action_type=data.get("action_type", "manual"),
        target=data.get("target", ""),
        description=data.get("description", ""),
    )
    return jsonify({"ok": True, "id": action_id})


@app.route("/api/response/<int:action_id>/execute", methods=["POST"])
def api_execute_response(action_id):
    result = execute_response_action(action_id)
    return jsonify(result)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    run_scan()
    return jsonify({"ok": True, "message": "Scan completed"})


@app.route("/api/scan/reset", methods=["POST"])
def api_scan_reset():
    reset_offsets()
    run_scan()
    return jsonify({"ok": True, "message": "Offsets reset and full scan completed"})


@app.route("/api/stats")
def api_stats():
    return jsonify(get_dashboard_stats())


@app.route("/api/logs")
def api_logs():
    entries = collect_all_logs()
    for e in entries:
        if isinstance(e["timestamp"], datetime):
            e["timestamp"] = e["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
    return jsonify(entries)


if __name__ == "__main__":
    init_db()
    run_scan()
    scheduler.start()
    app.run(debug=True, port=5000)
