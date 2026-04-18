#!/usr/bin/env python3
"""
============================================================
main.py — LLM Threat Intel Summariser Pipeline
Author: Anvesh Raju Vishwaraju

Run: python src/main.py
     Generates daily threat brief in reports/ directory
============================================================
"""
import os
import json
import requests
import feedparser
import anthropic
from datetime import datetime, timedelta

# ── Config ───────────────────────────────────────────────
OTX_API_KEY       = os.getenv("OTX_API_KEY", "YOUR_OTX_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "YOUR_CLAUDE_KEY")
OTX_BASE          = "https://otx.alienvault.com/api/v1"

RSS_FEEDS = [
    ("Krebs on Security",   "https://krebsonsecurity.com/feed/"),
    ("SANS ISC",            "https://isc.sans.edu/rssfeed_full.xml"),
    ("BleepingComputer",    "https://www.bleepingcomputer.com/feed/"),
    ("The Hacker News",     "https://feeds.feedburner.com/TheHackersNews"),
]


# ── Step 1: Fetch OTX Pulses ─────────────────────────────

def fetch_otx_pulses(hours_back: int = 24) -> list:
    """Fetch latest OTX AlienVault threat pulses."""
    print(f"[*] Fetching OTX pulses (last {hours_back}hrs)...")
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    since = (datetime.utcnow() - timedelta(hours=hours_back)).strftime(
        "%Y-%m-%dT%H:%M:%S"
    )
    try:
        r = requests.get(
            f"{OTX_BASE}/pulses/subscribed",
            headers=headers,
            params={"modified_since": since, "limit": 20},
            timeout=15
        )
        pulses = r.json().get("results", [])
        print(f"    Found {len(pulses)} new pulses")

        extracted = []
        for p in pulses:
            extracted.append({
                "title": p.get("name", ""),
                "description": p.get("description", "")[:500],
                "tags": p.get("tags", []),
                "iocs": [
                    {"type": i.get("type"), "indicator": i.get("indicator")}
                    for i in p.get("indicators", [])[:10]
                ],
                "targeted_countries": p.get("targeted_countries", []),
                "industries": p.get("industries", []),
            })
        return extracted
    except Exception as e:
        print(f"    [!] OTX error: {e}")
        return []


# ── Step 2: Fetch RSS Feeds ──────────────────────────────

def fetch_rss_articles(max_per_feed: int = 3) -> list:
    """Fetch latest articles from cybersecurity RSS feeds."""
    print(f"[*] Fetching RSS feeds...")
    articles = []
    for name, url in RSS_FEEDS:
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries[:max_per_feed]:
                articles.append({
                    "source": name,
                    "title": entry.get("title", ""),
                    "summary": entry.get("summary", "")[:400],
                    "published": entry.get("published", ""),
                    "link": entry.get("link", ""),
                })
            print(f"    {name}: {min(max_per_feed, len(feed.entries))} articles")
        except Exception as e:
            print(f"    [!] {name} error: {e}")
    return articles


# ── Step 3: Summarise with Claude ────────────────────────

def summarise_with_claude(pulses: list, articles: list) -> str:
    """Use Claude API to generate a threat intelligence brief."""
    print("[*] Generating threat brief with Claude API...")

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

    context = f"""
You are a senior threat intelligence analyst specialising in the BFSI 
(Banking, Financial Services, Insurance) sector in India.

Today's date: {datetime.now().strftime('%Y-%m-%d')}

--- OTX THREAT PULSES (last 24 hours) ---
{json.dumps(pulses[:10], indent=2)}

--- LATEST CYBERSECURITY NEWS ---
{json.dumps(articles[:12], indent=2)}
"""

    prompt = """
Based on the threat intelligence data above, generate a concise daily 
threat brief for a BFSI security team. Format your response as Markdown.

Structure:
1. ## 🔴 Priority Alerts (immediate action required)
2. ## 🟠 Trending Threats (monitor closely)
3. ## 📋 IOCs to Block (top 10, table format: Type | Indicator | Confidence)
4. ## 📰 Key Security News (3-5 bullet points, most relevant to BFSI India)
5. ## 💡 Analyst Recommendation (1 paragraph, what the team should focus on today)

Keep it concise — security teams read this in 3 minutes.
"""

    message = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=1500,
        messages=[
            {"role": "user", "content": context + prompt}
        ]
    )

    return message.content[0].text


# ── Step 4: Save Report ──────────────────────────────────

def save_report(content: str, pulses: list, articles: list):
    """Save threat brief and IOC list to reports/ directory."""
    os.makedirs("reports", exist_ok=True)
    date_str = datetime.now().strftime("%Y-%m-%d")

    # Save main report
    report_path = f"reports/threat-brief-{date_str}.md"
    header = f"""# 🛡️ Daily Threat Brief — {date_str}
**Generated by:** LLM Threat Intel Summariser  
**Analyst:** Anvesh Raju Vishwaraju  
**Sources:** OTX AlienVault ({len(pulses)} pulses) + {len(RSS_FEEDS)} RSS feeds  
**Classification:** TLP:WHITE  

---

"""
    with open(report_path, "w") as f:
        f.write(header + content)
    print(f"\n[✓] Report saved: {report_path}")

    # Save IOC CSV
    ioc_path = f"reports/iocs-{date_str}.csv"
    iocs = []
    for p in pulses:
        for ioc in p.get("iocs", []):
            iocs.append({
                "date": date_str,
                "type": ioc.get("type"),
                "indicator": ioc.get("indicator"),
                "pulse": p.get("title"),
            })

    if iocs:
        import csv
        with open(ioc_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["date", "type", "indicator", "pulse"])
            writer.writeheader()
            writer.writerows(iocs)
        print(f"[✓] IOCs saved: {ioc_path} ({len(iocs)} indicators)")


# ── Main Orchestrator ────────────────────────────────────

def main():
    print("\n" + "="*55)
    print("  LLM THREAT INTEL SUMMARISER")
    print("  Author: Anvesh Raju Vishwaraju")
    print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*55 + "\n")

    # Step 1: Collect intel
    pulses   = fetch_otx_pulses(hours_back=24)
    articles = fetch_rss_articles(max_per_feed=3)

    if not pulses and not articles:
        print("[!] No data fetched. Check API keys and network.")
        return

    # Step 2: AI summarisation
    brief = summarise_with_claude(pulses, articles)

    # Step 3: Save outputs
    save_report(brief, pulses, articles)

    print("\n[✓] Pipeline complete.")
    print("    Share reports/ directory with your security team.")


if __name__ == "__main__":
    main()
