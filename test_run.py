from log_collector import collect_logs
from alert_engine import run_detection
from db import init_db, insert_alerts

init_db()
entries = collect_logs()
print(f"Parsed {len(entries)} log entries")

alerts = run_detection(entries)
print(f"Generated {len(alerts)} alerts")

for a in alerts[:15]:
    print(f"  [{a['severity']:8}] {a['rule_name']:35} {a['source_ip']:16} user={a['user']}")

inserted = insert_alerts(alerts)
print(f"\nInserted {inserted} alerts into database")
