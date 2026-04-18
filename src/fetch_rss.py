#!/usr/bin/env python3
"""
============================================================
fetch_rss.py — Cybersecurity RSS Feed Ingestion
Author: Anvesh Raju Vishwaraju
============================================================
"""
import feedparser
from datetime import datetime
from config import RSS_FEEDS, RSS_MAX_PER_FEED, TARGET_SECTOR, TARGET_REGION


def fetch_all_feeds() -> list:
    """
    Fetch articles from all configured RSS feeds.
    Returns list of structured article dicts.
    """
    print(f"[*] Fetching RSS feeds ({len(RSS_FEEDS)} sources)...")
    all_articles = []

    for name, url in RSS_FEEDS:
        articles = _fetch_single_feed(name, url)
        all_articles.extend(articles)
        print(f"    {name}: {len(articles)} articles")

    print(f"    Total: {len(all_articles)} articles fetched")
    return all_articles


def _fetch_single_feed(name: str, url: str) -> list:
    """Fetch and parse a single RSS feed."""
    try:
        feed     = feedparser.parse(url)
        articles = []

        for entry in feed.entries[:RSS_MAX_PER_FEED]:
            articles.append({
                "source":    name,
                "title":     entry.get("title", ""),
                "summary":   _clean_summary(entry.get("summary", "")),
                "published": entry.get("published", ""),
                "link":      entry.get("link", ""),
                "tags":      [t.get("term", "") for t in entry.get("tags", [])],
            })

        return articles

    except Exception as e:
        print(f"    [!] Error fetching {name}: {e}")
        return []


def _clean_summary(text: str) -> str:
    """Strip HTML tags and truncate summary."""
    import re
    clean = re.sub(r"<[^>]+>", "", text)
    return clean[:500].strip()


def filter_bfsi_relevant(articles: list) -> list:
    """
    Filter articles most relevant to BFSI sector.
    Scores each article by keyword relevance.
    """
    BFSI_KEYWORDS = [
        "bank", "banking", "fintech", "payment", "upi", "swift",
        "ransomware", "phishing", "credential", "fraud", "financial",
        "india", "rbi", "sebi", "nbfc", "insurance", "stock",
        "cryptocurrency", "breach", "data leak", "apt", "zero-day",
    ]

    scored = []
    for article in articles:
        text  = (article["title"] + " " + article["summary"]).lower()
        score = sum(1 for kw in BFSI_KEYWORDS if kw in text)
        scored.append((score, article))

    # Sort by relevance, return all (let Claude prioritise)
    scored.sort(key=lambda x: x[0], reverse=True)
    return [a for _, a in scored]


def get_top_headlines(articles: list, n: int = 5) -> list:
    """Return top N most relevant headlines."""
    relevant = filter_bfsi_relevant(articles)
    return relevant[:n]


if __name__ == "__main__":
    articles = fetch_all_feeds()
    top      = get_top_headlines(articles)
    print(f"\nTop {len(top)} BFSI-relevant headlines:")
    for a in top:
        print(f"  [{a['source']}] {a['title']}")
