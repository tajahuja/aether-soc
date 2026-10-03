"""Explicit thresholds for this synthetic lab, not universal SOC defaults."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / 'data/processed/aether.db'
FAILURE_THRESHOLD = 5
AUTH_WINDOW_SECONDS = 300
MULTI_ACCOUNT_THRESHOLD = 4
CORRELATION_SECONDS = 1800
UNUSUAL_LOGIN_SECONDS = 120
SUSPICIOUS_DESTINATIONS = {'203.0.113.200'}
