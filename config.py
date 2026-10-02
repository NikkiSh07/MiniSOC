import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
DB_PATH = os.path.join(BASE_DIR, "soc.db")

RULES_PATH = os.path.join(BASE_DIR, "detection_rules.json")
SCAN_INTERVAL_SECONDS = 5

# Risk score thresholds
RISK_LOW = 30
RISK_MEDIUM = 60
RISK_HIGH = 85

# Rate-limit thresholds (within WINDOW_SECONDS)
BRUTE_FORCE_THRESHOLD = 5
FAILED_LOGIN_THRESHOLD = 3
SENSITIVE_ACCESS_THRESHOLD = 4
SQLI_THRESHOLD = 2
PRIV_ESC_THRESHOLD = 1
UNUSUAL_LOCATION_THRESHOLD = 2
SUSPICIOUS_IP_THRESHOLD = 3

WINDOW_SECONDS = 300
