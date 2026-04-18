#!/usr/bin/env python3
"""
============================================================
config.py — Configuration & API Keys
Author: Anvesh Raju Vishwaraju

Set environment variables before running:
  export OTX_API_KEY="your_key"
  export ANTHROPIC_API_KEY="your_key"
============================================================
"""
import os

# ── API Keys (set as environment variables — never hardcode) ─
OTX_API_KEY       = os.getenv("OTX_API_KEY", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

# ── OTX Settings ─────────────────────────────────────────────
OTX_BASE          = "https://otx.alienvault.com/api/v1"
OTX_HOURS_BACK    = 24        # Fetch pulses from last N hours
OTX_MAX_PULSES    = 20        # Max pulses to fetch per run

# ── Claude Settings ───────────────────────────────────────────
CLAUDE_MODEL      = "claude-opus-4-5"
CLAUDE_MAX_TOKENS = 1500

# ── RSS Feed Sources ──────────────────────────────────────────
RSS_FEEDS = [
    ("Krebs on Security",     "https://krebsonsecurity.com/feed/"),
    ("SANS ISC",              "https://isc.sans.edu/rssfeed_full.xml"),
    ("BleepingComputer",      "https://www.bleepingcomputer.com/feed/"),
    ("The Hacker News",       "https://feeds.feedburner.com/TheHackersNews"),
    ("Dark Reading",          "https://www.darkreading.com/rss.xml"),
    ("SecurityWeek",          "https://feeds.feedburner.com/securityweek"),
]
RSS_MAX_PER_FEED  = 3         # Articles per feed per run

# ── Output Settings ───────────────────────────────────────────
REPORTS_DIR       = "reports"
LOG_DIR           = "logs"
REPORT_PREFIX     = "threat-brief"
IOC_PREFIX        = "iocs"

# ── Sector Focus ──────────────────────────────────────────────
TARGET_SECTOR     = "BFSI"
TARGET_REGION     = "India"

# ── Validation ────────────────────────────────────────────────
def validate_config():
    errors = []
    if not OTX_API_KEY:
        errors.append("OTX_API_KEY not set. Export: export OTX_API_KEY='your_key'")
    if not ANTHROPIC_API_KEY:
        errors.append("ANTHROPIC_API_KEY not set. Export: export ANTHROPIC_API_KEY='your_key'")
    if errors:
        for e in errors:
            print(f"[!] {e}")
        return False
    return True
