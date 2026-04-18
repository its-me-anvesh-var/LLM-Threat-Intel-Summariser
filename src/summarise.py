#!/usr/bin/env python3
"""
============================================================
summarise.py — Claude API Threat Intel Summarisation
Author: Anvesh Raju Vishwaraju
============================================================
"""
import json
import anthropic
from datetime import datetime
from config import ANTHROPIC_API_KEY, CLAUDE_MODEL, CLAUDE_MAX_TOKENS, TARGET_SECTOR, TARGET_REGION


def build_prompt(pulses: list, articles: list) -> str:
    """Build the summarisation prompt for Claude."""
    today = datetime.now().strftime("%Y-%m-%d")

    context = f"""
You are a senior threat intelligence analyst specialising in the {TARGET_SECTOR} sector in {TARGET_REGION}.
Today's date: {today}

=== OTX THREAT PULSES (Last 24 hours) ===
{json.dumps(pulses[:10], indent=2, default=str)}

=== LATEST CYBERSECURITY NEWS ===
{json.dumps(articles[:12], indent=2, default=str)}
"""

    instruction = f"""
Based on the threat intelligence above, generate a concise daily threat brief for a {TARGET_SECTOR} security team in {TARGET_REGION}.

Format your response in clean Markdown with these exact sections:

## 🔴 Priority Alerts
List 2-3 immediate threats requiring action today. Be specific — name threat actors, malware families, CVEs if present.

## 🟠 Trending Threats
List 3-4 emerging threats to monitor. Include MITRE ATT&CK technique IDs where relevant.

## 📋 Top IOCs to Block
Create a markdown table with columns: Type | Indicator | Threat | Confidence
List the top 8-10 actionable IOCs from the OTX pulses.

## 📰 Key Security News
5 bullet points of the most relevant news for {TARGET_SECTOR} teams in {TARGET_REGION}.
Focus on: ransomware, phishing, regulatory changes, data breaches, zero-days.

## 💡 Analyst Recommendation
One paragraph (3-4 sentences) on what the security team should prioritise today and why.

Keep the entire brief scannable — a security analyst should be able to read it in under 3 minutes.
"""
    return context + instruction


def summarise(pulses: list, articles: list) -> str:
    """
    Call Claude API to generate threat intelligence brief.

    Args:
        pulses:   List of OTX pulse dicts
        articles: List of RSS article dicts

    Returns:
        Markdown-formatted threat brief string
    """
    print("[*] Calling Claude API for summarisation...")

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    prompt = build_prompt(pulses, articles)

    try:
        message = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=CLAUDE_MAX_TOKENS,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        brief = message.content[0].text
        print(f"    Generated {len(brief.split())} words")
        return brief

    except anthropic.APIError as e:
        print(f"    [!] Claude API error: {e}")
        return _fallback_brief(pulses, articles)


def _fallback_brief(pulses: list, articles: list) -> str:
    """
    Simple fallback if Claude API fails.
    Generates a basic brief from raw data.
    """
    lines = [
        f"# Daily Threat Brief — {datetime.now().strftime('%Y-%m-%d')}",
        f"*Note: AI summarisation unavailable. Raw data below.*\n",
        "## OTX Pulses",
    ]
    for p in pulses[:5]:
        lines.append(f"- **{p.get('title', 'Unknown')}** — {p.get('description', '')[:200]}")

    lines.append("\n## Latest News")
    for a in articles[:5]:
        lines.append(f"- [{a.get('source')}] {a.get('title', '')}")

    return "\n".join(lines)


if __name__ == "__main__":
    # Test with dummy data
    test_pulses   = [{"title": "Test Pulse", "description": "Test", "iocs": []}]
    test_articles = [{"source": "Test", "title": "Test Article", "summary": "Test"}]
    result = summarise(test_pulses, test_articles)
    print(result[:500])
