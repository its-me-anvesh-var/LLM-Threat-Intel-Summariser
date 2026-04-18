#!/usr/bin/env python3
"""
============================================================
fetch_otx.py — OTX AlienVault Feed Ingestion
Author: Anvesh Raju Vishwaraju
============================================================
"""
import requests
from datetime import datetime, timedelta
from config import OTX_API_KEY, OTX_BASE, OTX_HOURS_BACK, OTX_MAX_PULSES


def fetch_subscribed_pulses() -> list:
    """
    Fetch latest threat pulses from OTX AlienVault subscriptions.
    Returns list of structured pulse dicts.
    """
    headers  = {"X-OTX-API-KEY": OTX_API_KEY}
    since    = (datetime.utcnow() - timedelta(hours=OTX_HOURS_BACK)
                ).strftime("%Y-%m-%dT%H:%M:%S")

    print(f"[*] Fetching OTX pulses (last {OTX_HOURS_BACK}h)...")

    try:
        r = requests.get(
            f"{OTX_BASE}/pulses/subscribed",
            headers=headers,
            params={"modified_since": since, "limit": OTX_MAX_PULSES},
            timeout=15
        )
        r.raise_for_status()
        raw_pulses = r.json().get("results", [])
        print(f"    Found {len(raw_pulses)} pulses")
        return [_parse_pulse(p) for p in raw_pulses]

    except requests.exceptions.RequestException as e:
        print(f"    [!] OTX fetch error: {e}")
        return []


def fetch_pulse_by_id(pulse_id: str) -> dict:
    """Fetch a single pulse by its ID."""
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        r = requests.get(
            f"{OTX_BASE}/pulses/{pulse_id}",
            headers=headers, timeout=10
        )
        return _parse_pulse(r.json())
    except Exception as e:
        return {"error": str(e)}


def fetch_ip_reputation(ip: str) -> dict:
    """Get reputation data for a specific IP."""
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        r = requests.get(
            f"{OTX_BASE}/indicators/IPv4/{ip}/general",
            headers=headers, timeout=10
        )
        data = r.json()
        return {
            "ip":          ip,
            "pulse_count": data.get("pulse_info", {}).get("count", 0),
            "reputation":  data.get("reputation", 0),
            "country":     data.get("country_name", "unknown"),
            "asn":         data.get("asn", "unknown"),
        }
    except Exception as e:
        return {"ip": ip, "error": str(e)}


def _parse_pulse(p: dict) -> dict:
    """Extract relevant fields from a raw OTX pulse."""
    return {
        "id":                  p.get("id", ""),
        "title":               p.get("name", ""),
        "description":         p.get("description", "")[:600],
        "author":              p.get("author_name", ""),
        "created":             p.get("created", ""),
        "modified":            p.get("modified", ""),
        "tags":                p.get("tags", [])[:10],
        "targeted_countries":  p.get("targeted_countries", []),
        "industries":          p.get("industries", []),
        "attack_ids":          [a.get("id") for a in p.get("attack_ids", [])],
        "iocs": [
            {
                "type":      i.get("type"),
                "indicator": i.get("indicator"),
            }
            for i in p.get("indicators", [])[:15]
        ],
        "references":          p.get("references", [])[:3],
    }


def extract_iocs_from_pulses(pulses: list) -> list:
    """Flatten all IOCs from a list of pulses into one list."""
    iocs = []
    for pulse in pulses:
        for ioc in pulse.get("iocs", []):
            iocs.append({
                "type":      ioc["type"],
                "indicator": ioc["indicator"],
                "source":    "OTX",
                "pulse":     pulse["title"],
                "tags":      pulse.get("tags", []),
            })
    return iocs


if __name__ == "__main__":
    pulses = fetch_subscribed_pulses()
    iocs   = extract_iocs_from_pulses(pulses)
    print(f"\nTotal IOCs extracted: {len(iocs)}")
    for ioc in iocs[:5]:
        print(f"  {ioc['type']:10} {ioc['indicator']}")
