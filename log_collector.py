import json
import re
import os
from datetime import datetime
from config import LOG_DIR, BASE_DIR

LOG_PATTERN = re.compile(
    r"\[(?P<timestamp>[^\]]+)\] "
    r"(?P<level>\w+) "
    r"(?P<source>[\w\.]+) "
    r"(?P<action>\w+) "
    r"(?P<user>\S+) "
    r"(?P<ip>[\d\.]+|[\w:]+) "
    r"(?P<detail>.*)"
)

OFFSETS_FILE = os.path.join(BASE_DIR, ".log_offsets.json")


def _load_offsets() -> dict:
    """Load the saved file-read offsets so we only process new lines."""
    if os.path.exists(OFFSETS_FILE):
        try:
            with open(OFFSETS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def _save_offsets(offsets: dict):
    """Persist file-read offsets to disk."""
    with open(OFFSETS_FILE, "w", encoding="utf-8") as f:
        json.dump(offsets, f, indent=2)


def reset_offsets():
    """Reset all offsets to force a full re-scan of all log files."""
    if os.path.exists(OFFSETS_FILE):
        os.remove(OFFSETS_FILE)


def parse_line(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None
    m = LOG_PATTERN.match(line)
    if not m:
        return None
    d = m.groupdict()
    d["raw"] = line
    try:
        d["timestamp"] = datetime.strptime(d["timestamp"], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        try:
            d["timestamp"] = datetime.strptime(d["timestamp"], "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            d["timestamp"] = datetime.now()
    return d


def collect_logs() -> list[dict]:
    """Collect only NEW log lines since the last scan, using file-offset tracking."""
    offsets = _load_offsets()
    entries = []

    for fname in sorted(os.listdir(LOG_DIR)):
        if not fname.endswith(".log"):
            continue
        fpath = os.path.join(LOG_DIR, fname)
        file_size = os.path.getsize(fpath)
        last_offset = offsets.get(fname, 0)

        # If the file shrank (e.g. rotation), re-read from the start
        if last_offset > file_size:
            last_offset = 0

        with open(fpath, "r", encoding="utf-8") as f:
            f.seek(last_offset)
            for line in f:
                parsed = parse_line(line)
                if parsed:
                    parsed["file"] = fname
                    entries.append(parsed)
            offsets[fname] = f.tell()

    _save_offsets(offsets)
    entries.sort(key=lambda e: e["timestamp"])
    return entries


def collect_all_logs() -> list[dict]:
    """Collect ALL log entries regardless of offsets (for the Log Viewer page)."""
    entries = []
    for fname in sorted(os.listdir(LOG_DIR)):
        if not fname.endswith(".log"):
            continue
        fpath = os.path.join(LOG_DIR, fname)
        with open(fpath, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                parsed = parse_line(line)
                if parsed:
                    parsed["file"] = fname
                    parsed["line_num"] = line_num
                    entries.append(parsed)
    entries.sort(key=lambda e: e["timestamp"])
    return entries


def get_log_files_info() -> list[dict]:
    """Return metadata about each log file for the pipeline status."""
    files = []
    for fname in sorted(os.listdir(LOG_DIR)):
        if not fname.endswith(".log"):
            continue
        fpath = os.path.join(LOG_DIR, fname)
        stat = os.stat(fpath)
        with open(fpath, "r", encoding="utf-8") as f:
            line_count = sum(1 for _ in f)
        files.append({
            "name": fname,
            "size": stat.st_size,
            "lines": line_count,
            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        })
    return files
