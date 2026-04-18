#!/usr/bin/env python3
"""
============================================================
report_generator.py — Threat Brief Report Generator
Author: Anvesh Raju Vishwaraju
============================================================
"""
import os
import csv
import json
from datetime import datetime
from config import REPORTS_DIR, REPORT_PREFIX, IOC_PREFIX


def save_report(brief: str, pulses: list, articles: list) -> dict:
    """
    Save threat brief and IOC CSV to reports/ directory.

    Returns:
        dict with paths to saved files
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)
    date_str = datetime.now().strftime("%Y-%m-%d")
    saved    = {}

    # ── Save Markdown report ──────────────────────────────
    report_path = os.path.join(REPORTS_DIR, f"{REPORT_PREFIX}-{date_str}.md")
    header = _build_header(pulses, articles)

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(header + brief)

    saved["report"] = report_path
    print(f"[✓] Report saved:    {report_path}")

    # ── Save IOC CSV ──────────────────────────────────────
    ioc_path = os.path.join(REPORTS_DIR, f"{IOC_PREFIX}-{date_str}.csv")
    iocs     = _extract_iocs(pulses, date_str)

    if iocs:
        with open(ioc_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f, fieldnames=["date", "type", "indicator", "pulse", "tags"]
            )
            writer.writeheader()
            writer.writerows(iocs)
        saved["iocs"] = ioc_path
        print(f"[✓] IOCs saved:      {ioc_path} ({len(iocs)} indicators)")

    # ── Save raw data JSON (for debugging) ────────────────
    raw_path = os.path.join(REPORTS_DIR, f"raw-{date_str}.json")
    with open(raw_path, "w", encoding="utf-8") as f:
        json.dump(
            {"pulses": pulses, "articles": articles,
             "generated": datetime.now().isoformat()},
            f, indent=2, default=str
        )
    saved["raw"] = raw_path

    return saved


def _build_header(pulses: list, articles: list) -> str:
    """Build report header with metadata."""
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    return f"""# 🛡️ Daily Threat Brief — {datetime.now().strftime('%Y-%m-%d')}

| Field | Value |
|---|---|
| **Generated** | {date_str} |
| **Analyst** | Anvesh Raju Vishwaraju |
| **OTX Pulses** | {len(pulses)} new pulses |
| **News Sources** | {len(set(a.get('source','') for a in articles))} feeds |
| **Classification** | TLP:WHITE |
| **Sector Focus** | BFSI — India |

---

"""


def _extract_iocs(pulses: list, date_str: str) -> list:
    """Extract and flatten all IOCs from pulses."""
    iocs = []
    for pulse in pulses:
        tags = ", ".join(pulse.get("tags", [])[:5])
        for ioc in pulse.get("iocs", []):
            iocs.append({
                "date":      date_str,
                "type":      ioc.get("type", ""),
                "indicator": ioc.get("indicator", ""),
                "pulse":     pulse.get("title", ""),
                "tags":      tags,
            })
    return iocs


def list_reports() -> list:
    """List all saved reports."""
    if not os.path.exists(REPORTS_DIR):
        return []
    return sorted([
        f for f in os.listdir(REPORTS_DIR)
        if f.startswith(REPORT_PREFIX)
    ], reverse=True)


def load_latest_report() -> str:
    """Load the most recent threat brief."""
    reports = list_reports()
    if not reports:
        return ""
    path = os.path.join(REPORTS_DIR, reports[0])
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


if __name__ == "__main__":
    reports = list_reports()
    print(f"Saved reports ({len(reports)}):")
    for r in reports[:5]:
        print(f"  {r}")
