import json
import re
import os
from datetime import datetime, timedelta
from collections import defaultdict
from detection_rules import DEFAULT_RULES
from config import RULES_PATH


def load_rules() -> list[dict]:
    if os.path.exists(RULES_PATH):
        with open(RULES_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    with open(RULES_PATH, "w", encoding="utf-8") as f:
        json.dump(DEFAULT_RULES, f, indent=2)
    return list(DEFAULT_RULES)


def match_pattern(rule: dict, entry: dict) -> bool:
    field_val = str(entry.get(rule["field"], ""))
    return bool(re.search(rule["pattern"], field_val, re.IGNORECASE))


def match_threshold(rule: dict, entry: dict, all_entries: list[dict]) -> list[dict]:
    field = rule["field"]
    condition = rule["condition"]
    threshold = rule["threshold"]
    window = timedelta(seconds=rule.get("window_seconds", 300))
    target_val = entry.get(field, "")
    ts = entry.get("timestamp", datetime.now())

    matching = []
    for e in all_entries:
        if e.get(field) != target_val:
            continue
        if e.get("timestamp", datetime.now()) < ts - window:
            continue
        if e.get("timestamp", datetime.now()) > ts + timedelta(seconds=5):
            continue
        if _safe_eval_condition(condition, e):
            matching.append(e)

    if len(matching) >= threshold:
        return matching
    return []


def _safe_eval_condition(condition: str, entry: dict) -> bool:
    """Safely evaluate rule conditions without using eval().

    Supports these patterns:
      - action == 'VALUE'
      - action in ('VAL1', 'VAL2')
      - level == 'VALUE'
    """
    try:
        action = entry.get("action", "")
        level = entry.get("level", "")
        detail = entry.get("detail", "")

        # Handle:  field == 'value'
        eq_match = re.match(r"^(\w+)\s*==\s*'([^']*)'$", condition.strip())
        if eq_match:
            var_name, expected = eq_match.groups()
            actual = {"action": action, "level": level, "detail": detail}.get(var_name, "")
            return actual == expected

        # Handle:  field in ('val1', 'val2', ...)
        in_match = re.match(r"^(\w+)\s+in\s+\(([^)]+)\)$", condition.strip())
        if in_match:
            var_name, vals_str = in_match.groups()
            actual = {"action": action, "level": level, "detail": detail}.get(var_name, "")
            values = [v.strip().strip("'\"") for v in vals_str.split(",")]
            return actual in values

        return False
    except Exception:
        return False


def run_detection(entries: list[dict]) -> list[dict]:
    rules = load_rules()
    alerts = []
    # For threshold rules, dedupe per (rule, ip, user) so we only raise one
    # alert per offending entity within the detection window.
    threshold_fired = set()
    pattern_fired = set()

    for entry in entries:
        for rule in rules:
            matched = False
            evidence = []

            if rule["detect"] == "pattern":
                matched = match_pattern(rule, entry)
                if matched:
                    evidence = [entry]
                    dedup_key = ("pattern", rule["id"], entry.get("ip", ""), entry.get("user", ""))
                    if dedup_key in pattern_fired:
                        continue
                    pattern_fired.add(dedup_key)
            elif rule["detect"] == "threshold":
                hits = match_threshold(rule, entry, entries)
                if hits:
                    matched = True
                    evidence = hits
                    dedup_key = ("thresh", rule["id"], entry.get("ip", ""), entry.get("user", ""))
                    if dedup_key in threshold_fired:
                        continue
                    threshold_fired.add(dedup_key)

            if matched:
                alerts.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "base_score": rule["base_score"],
                    "timestamp": entry["timestamp"],
                    "source_ip": entry.get("ip", "unknown"),
                    "user": entry.get("user", "unknown"),
                    "action": entry.get("action", "unknown"),
                    "detail": entry.get("detail", ""),
                    "raw": entry.get("raw", ""),
                    "evidence_count": len(evidence),
                    "file": entry.get("file", ""),
                })
    return alerts
