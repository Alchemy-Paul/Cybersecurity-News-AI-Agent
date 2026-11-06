#!/usr/bin/env python3
"""
Cybersecurity Daily Evidence Briefing Agent
Fetches and summarizes the latest cybersecurity news, vulnerabilities, and threats
Perfect for busy SOC analysts
"""

import argparse
import html
import os
import re
import smtplib
import sys
import json
import requests
import feedparser
from difflib import SequenceMatcher
from datetime import datetime, timedelta, timezone
from textwrap import dedent
from email.message import EmailMessage
from email.utils import parsedate_to_datetime
from pathlib import Path

from enrichment import VulnEnricher, extract_cve_ids, severity_from_score
from watchlist import load_watchlist, match_watchlist


def load_env_file(path=".env"):
    env_path = Path(path)
    if not env_path.exists():
        return

    with env_path.open("r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and value and key not in os.environ:
                os.environ[key] = value


load_env_file()

# Configuration
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent / "output"

CONFIG = {
    "news_sources": [
        {
            "name": "Hacker News - Security",
            "url": "https://hn.algolia.com/api/v1/search?tags=story&query=cybersecurity,security,vulnerability,breach,exploit",
            "type": "hn"
        },
        {
            "name": "Hacker News - CVE",
            "url": "https://hn.algolia.com/api/v1/search?tags=story&query=CVE,zero-day,vulnerability,patch",
            "type": "hn"
        },
        {
            "name": "Cybersecurity News",
            "url": "https://cybersecuritynews.com/feed/",
            "type": "rss"
        },
        {
            "name": "The Hacker News",
            "url": "https://feeds.feedburner.com/TheHackersNews",
            "type": "rss"
        },
        {
            "name": "BleepingComputer",
            "url": "https://www.bleepingcomputer.com/feed/",
            "type": "rss"
        },
        {
            "name": "Securelist",
            "url": "https://securelist.com/feed/",
            "type": "rss"
        }
    ],
    "keywords_priority": [
        "zero-day", "CVE", "ransomware", "APT", "threat actor",
        "vulnerability", "exploit", "breach", "malware", "phishing",
        "SIEM", "SOC", "incident response", "threat intelligence"
    ],
    "output_dir": Path(os.getenv("OUTPUT_DIR", str(DEFAULT_OUTPUT_DIR))),
    "slack_webhook_url": os.getenv("SLACK_WEBHOOK_URL", ""),
    "smtp_host": os.getenv("SMTP_HOST", ""),
    "smtp_port": int(os.getenv("SMTP_PORT", "587")),
    "smtp_user": os.getenv("SMTP_USER", ""),
    "smtp_password": os.getenv("SMTP_PASSWORD", ""),
    "smtp_from": os.getenv("SMTP_FROM", ""),
    "smtp_to": os.getenv("SMTP_TO", ""),
    "discord_webhook_url": os.getenv("DISCORD_WEBHOOK_URL", ""),
    "nvd_api_key": os.getenv("NVD_API_KEY", ""),
    "watchlist_file": os.getenv("WATCHLIST_FILE", str(Path(__file__).resolve().parent / "watchlist.txt")),
}

class CybersecNewsAgent:
    def __init__(self):
        self.config = CONFIG
        self.stories = []
        self.iocs = {}
        self.config["output_dir"].mkdir(parents=True, exist_ok=True)
        self.config["output_dir"] = Path(self.config["output_dir"]).resolve()
        self.config["briefing_dir"] = self.config["output_dir"] / "briefings"
        self.config["ioc_dir"] = self.config["output_dir"] / "ioc_watchlists"
        self.config["briefing_dir"].mkdir(parents=True, exist_ok=True)
        self.config["ioc_dir"].mkdir(parents=True, exist_ok=True)
        self.config.setdefault("max_story_count", int(os.getenv("MAX_STORY_COUNT", "12")))
        self.config.setdefault("send_to_slack", bool(os.getenv("SLACK_WEBHOOK_URL", "")))
        self.config.setdefault("save_outputs", True)
        self.config.setdefault("enrich", True)
        self.watchlist = load_watchlist(self.config.get("watchlist_file"))
        self.enricher = None

    def fetch_hackernews(self, source):
        """Fetch stories from Hacker News API"""
        try:
            response = requests.get(source["url"], timeout=10)
            data = response.json()
            
            for hit in data.get("hits", [])[:10]:
                self.stories.append({
                    "title": hit.get("title", ""),
                    "url": hit.get("url", f"https://news.ycombinator.com/item?id={hit.get('objectID')}"),
                    "source": source["name"],
                    "points": hit.get("points", 0),
                    "comments": hit.get("num_comments", 0),
                    "created": hit.get("created_at", "")
                })
        except Exception as e:
            print(f"Error fetching {source['name']}: {e}")
    
    def fetch_reddit(self, source):
        """Fetch posts from Reddit"""
        try:
            headers = {"User-Agent": "CybersecNewsAgent/1.0"}
            response = requests.get(source["url"], headers=headers, timeout=10)
            data = response.json()
            
            for post in data.get("data", {}).get("children", [])[:10]:
                post_data = post.get("data", {})
                self.stories.append({
                    "title": post_data.get("title", ""),
                    "url": post_data.get("url", ""),
                    "source": source["name"],
                    "points": post_data.get("score", 0),
                    "comments": post_data.get("num_comments", 0),
                    "created": datetime.fromtimestamp(post_data.get("created_utc", 0)).isoformat()
                })
        except Exception as e:
            print(f"Error fetching {source['name']}: {e}")
    
    def fetch_rss(self, source):
        """Fetch stories from RSS feeds"""
        try:
            response = requests.get(source["url"], timeout=10, headers={"User-Agent": "CybersecNewsAgent/1.0"})
            response.raise_for_status()

            import feedparser
            feed = feedparser.parse(response.content)
            
            for entry in feed.entries[:12]:
                self.stories.append({
                    "title": entry.get("title", ""),
                    "url": entry.get("link", ""),
                    "source": source["name"],
                    "points": 0,
                    "comments": 0,
                    "created": entry.get("published", ""),
                    "summary": entry.get("summary", "")
                })
        except Exception as e:
            print(f"Error fetching {source['name']}: {e}")

    def fetch_story_summary(self, url):
        """Fetch a short article summary from the page for richer briefing context."""
        if not url or url.startswith("https://news.ycombinator.com"):
            return ""
        headers = {"User-Agent": "CybersecNewsAgent/1.0"}
        try:
            response = requests.get(url, headers=headers, timeout=10)
            html_text = response.text
            for pattern in [
                r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']',
                r'<meta[^>]+property=["\']og:description["\'][^>]+content=["\']([^"\']+)["\']',
                r'<meta[^>]+name=["\']twitter:description["\'][^>]+content=["\']([^"\']+)["\']'
            ]:
                match = re.search(pattern, html_text, re.IGNORECASE)
                if match:
                    summary = html.unescape(match.group(1)).strip()
                    if summary:
                        return summary.replace("\n", " ").strip()[:320]
            match = re.search(r"<p[^>]*>(.*?)</p>", html_text, re.IGNORECASE | re.DOTALL)
            if match:
                summary = re.sub(r"<[^>]+>", "", match.group(1))
                summary = html.unescape(summary).strip().replace("\n", " ")
                if summary:
                    return summary[:320]
        except Exception:
            pass
        return ""

    def parse_date(self, date_value):
        if isinstance(date_value, datetime):
            return date_value if date_value.tzinfo else date_value.replace(tzinfo=timezone.utc)
        if isinstance(date_value, (int, float)):
            return datetime.fromtimestamp(date_value, tz=timezone.utc)
        if not date_value:
            return None
        if isinstance(date_value, str):
            try:
                parsed = datetime.fromisoformat(date_value.replace("Z", "+00:00"))
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
            except Exception:
                pass
            try:
                parsed = parsedate_to_datetime(date_value)
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
            except Exception:
                pass
        return None

    @staticmethod
    def _title_tokens(title):
        ignored = {
            "a", "an", "and", "are", "as", "at", "by", "for", "from",
            "in", "into", "is", "its", "of", "on", "or", "the", "to",
            "with", "after", "amid", "could", "how", "new", "says", "say",
            "security", "cybersecurity", "hackers", "attacker", "attackers",
            "exploit", "exploits", "exploited", "flaw", "flaws",
            "vulnerability", "vulnerabilities", "critical", "zero", "day",
            "patch", "patches", "issue", "issues", "discovered", "lets",
            "let", "allow", "allows", "allowing",
        }
        tokens = set(re.findall(r"[a-z0-9]+", (title or "").lower()))
        return {token for token in tokens if token not in ignored and not token.startswith("cve")}

    @classmethod
    def _same_story_cluster(cls, first, second):
        first_title = first.get("title", "")
        second_title = second.get("title", "")
        if first_title.strip() and first_title.strip().lower() == second_title.strip().lower():
            return True

        first_cves = set(extract_cve_ids(first_title, first.get("summary", "")))
        second_cves = set(extract_cve_ids(second_title, second.get("summary", "")))
        if first_cves and second_cves and not first_cves.intersection(second_cves):
            return False

        first_tokens = cls._title_tokens(first_title)
        second_tokens = cls._title_tokens(second_title)
        shared = first_tokens & second_tokens
        if len(shared) >= 3 and len(shared) / min(len(first_tokens), len(second_tokens)) >= 0.5:
            return True

        # Catch editorially different headlines for the same underlying report.
        first_normalized = " ".join(sorted(first_tokens))
        second_normalized = " ".join(sorted(second_tokens))
        return bool(
            first_normalized
            and second_normalized
            and SequenceMatcher(None, first_normalized, second_normalized).ratio() >= 0.78
        )

    def sanitize_text(self, text, max_length=0):
        if not text:
            return ""

        cleaned = re.sub(r"<[^>]+>", " ", str(text))
        cleaned = html.unescape(cleaned)
        cleaned = re.sub(r"\s+", " ", cleaned).strip()

        if max_length and len(cleaned) > max_length:
            if len(cleaned) <= max_length + 3:
                return cleaned

            truncated = cleaned[:max_length].rstrip()
            if truncated:
                truncated = truncated.rstrip(".,;:!? ")
                if " " in truncated:
                    truncated = truncated.rsplit(" ", 1)[0].rstrip()
                if truncated and truncated != cleaned:
                    truncated += "…"
                cleaned = truncated or cleaned[:max_length].rstrip()

        return cleaned

    @staticmethod
    def describe_cve(cve):
        """One-line description of the available CVE enrichment fields."""
        kev = cve.get("kev")
        kev_text = "KEV: unknown" if kev is None else ("KEV: EXPLOITED IN THE WILD" if kev else "KEV: not listed")
        if cve.get("kev_ransomware"):
            kev_text += " (used in ransomware)"
        score = cve.get("score")
        cvss_text = f"CVSS {score}" if score is not None else "CVSS unknown"
        epss = cve.get("epss")
        epss_text = f"EPSS {epss:.1%}" if epss is not None else "EPSS unknown"
        return f"{cve['id']} [{cve.get('tag', '⚪ UNKNOWN')} | {cvss_text} | {epss_text} | {kev_text}]"

    def normalize_story(self, story):
        story.setdefault("points", 0)
        story.setdefault("comments", 0)
        story.setdefault("source", "Unknown")
        story.setdefault("title", "")
        story.setdefault("url", "")
        story.setdefault("created", "")
        story.setdefault("summary", "")

        story["title"] = self.sanitize_text(story.get("title", ""), max_length=220)
        story["summary"] = self.sanitize_text(story.get("summary", ""), max_length=360)

        published = self.parse_date(story.get("created") or story.get("published") or story.get("updated"))
        story["published"] = published.isoformat() if published else ""
        story["age_hours"] = (
            max(0.0, (datetime.now(tz=timezone.utc) - published).total_seconds() / 3600)
            if published else None
        )
        if not story["summary"]:
            story["summary"] = self.fetch_story_summary(story["url"])
            story["summary"] = self.sanitize_text(story["summary"], max_length=360)
        story["key_phrases"] = [kw for kw in self.config["keywords_priority"] if kw.lower() in story["title"].lower() or kw.lower() in story["summary"].lower()]
        story["priority_score"] = story.get("points", 0)

    def deduplicate_stories(self):
        clusters = []
        for story in self.stories:
            title = (story.get("title") or "").strip()
            url = (story.get("url") or "").strip().lower()
            if not title and not url:
                continue
            cluster = next(
                (
                    candidate for candidate in clusters
                    if any(
                        url and url == (member.get("url") or "").strip().lower()
                        for member in candidate
                    )
                    or self._same_story_cluster(story, candidate[0])
                ),
                None,
            )
            if cluster is None:
                clusters.append([story])
            else:
                cluster.append(story)

        unique = []
        for cluster in clusters:
            def representative_key(story):
                published = self.parse_date(
                    story.get("created") or story.get("published") or story.get("updated")
                )
                timestamp = published.timestamp() if published else float("-inf")
                return timestamp, story.get("points", 0), story.get("comments", 0)

            representative = max(cluster, key=representative_key).copy()
            sources = list(dict.fromkeys(
                member.get("source", "Unknown") for member in cluster
                if member.get("source")
            ))
            representative["coverage_sources"] = sources
            representative["related_stories"] = len(cluster) - 1
            unique.append(representative)

        duplicates = len(self.stories) - len(unique)
        if duplicates > 0:
            print(f"🔁 Grouped {duplicates} duplicate or closely related stories")
        self.stories = unique

    def fetch_all_news(self):
        """Fetch news from all configured sources"""
        print("🔍 Fetching latest cybersecurity news...")
        
        for source in self.config["news_sources"]:
            if source["type"] == "hn":
                self.fetch_hackernews(source)
            elif source["type"] == "rss":
                self.fetch_rss(source)
        
        self.deduplicate_stories()
        for story in self.stories:
            self.normalize_story(story)

        # Sort by relevance (initial points) before deeper prioritization
        self.stories.sort(key=lambda x: x.get("points", 0), reverse=True)
        print(f"✅ Found {len(self.stories)} stories")
    
    def score_story_relevance(self, story, return_reasons=False):
        """Score stories based on engagement, recency, CVEs, severity, and keyword relevance."""
        title_lower = (story.get("title", "") or "").lower()
        summary_lower = (story.get("summary", "") or "").lower()
        # Engagement is capped so a viral thread can't outrank a KEV or in-stack story.
        score = min(int(story.get("points", 0)), 100) * 1.5 + min(int(story.get("comments", 0)), 50) * 0.8
        reasons = []

        if story.get("cves"):
            score += 140
            reasons.append("cve")

        if any(keyword.lower() in title_lower or keyword.lower() in summary_lower for keyword in self.config["keywords_priority"]):
            keyword_hits = sum(1 for keyword in self.config["keywords_priority"] if keyword.lower() in title_lower or keyword.lower() in summary_lower)
            score += keyword_hits * 18
            reasons.append("keyword")

        if "ransomware" in title_lower or "ransomware" in summary_lower:
            score += 60
            reasons.append("ransomware")

        if "phishing" in title_lower or "phishing" in summary_lower:
            score += 40
            reasons.append("phishing")

        if "zero-day" in title_lower or "zero-day" in summary_lower:
            score += 70
            reasons.append("zero-day")

        if "breach" in title_lower or "breach" in summary_lower:
            score += 30
            reasons.append("breach")

        age_hours = story.get("age_hours")
        if age_hours is not None:
            age_hours = float(age_hours)
            age_bonus = max(0.0, 48.0 - age_hours)
            score += age_bonus * 2.2
            if age_hours <= 24:
                reasons.append("fresh")

        for cve in story.get("cves", []):
            tag = (cve.get("tag") or "").lower()
            if "critical" in tag:
                score += 80
                reasons.append("critical-cve")
            elif "high" in tag:
                score += 50
                reasons.append("high-cve")

        cves = story.get("cves", [])
        if any(c.get("kev") for c in cves):
            score += 200
            reasons.append("kev")
            if any(c.get("kev_ransomware") for c in cves):
                score += 60
                reasons.append("kev-ransomware")

        top_epss = max((c.get("epss") for c in cves if c.get("epss") is not None), default=None)
        if top_epss is not None:
            if top_epss >= 0.5:
                score += 90
                reasons.append("epss-high")
            elif top_epss >= 0.1:
                score += 40
                reasons.append("epss-elevated")

        if story.get("watchlist_hits"):
            # Must exceed the most popularity + freshness can add (~296) so in-stack always wins.
            score += 350
            reasons.append("watchlist")

        score += len(story.get("key_phrases", [])) * 12
        story["priority_score"] = round(score, 2)

        if return_reasons:
            return story["priority_score"], reasons
        return story["priority_score"]

    def prioritize_stories(self):
        """Score stories based on relevance, recency, CVEs, and priority keywords."""
        for story in self.stories:
            self.score_story_relevance(story)

        self.stories.sort(key=lambda x: x["priority_score"], reverse=True)
    
    def generate_evidence_briefing(self):
        """Render a briefing only from fetched stories and structured enrichment data."""
        print("🧾 Building a source-grounded briefing (no generated recommendations)...")
        briefing = "# Cybersecurity Daily Evidence Briefing\n\n"
        briefing += f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"
        briefing += (
            "> Publisher titles and summaries are reported claims, not independently "
            "verified facts. CVE fields are shown only when returned by enrichment "
            "sources. A watchlist match does not confirm that a product is deployed "
            "or affected. Verify details with the linked source and your asset inventory "
            "before taking action.\n\n"
        )

        top = self.stories[: self.config.get("max_story_count", 12)]
        flagged = [story for story in top if story.get("watchlist_hits")]
        if self.watchlist:
            briefing += "## Possible Watchlist Matches (not confirmed exposure)\n\n"
            if flagged:
                for story in flagged:
                    hits = ", ".join(story["watchlist_hits"])
                    briefing += (
                        f"- [{self.sanitize_text(story.get('title', 'Untitled'))}]"
                        f"({story.get('url', '')}) — matched watchlist term(s): {hits}. "
                        "This is not confirmation that the product is deployed or affected.\n"
                    )
            else:
                briefing += "- No top stories matched the configured watchlist terms.\n"
            briefing += "\n"

        briefing += "## Reported Stories\n\n"
        for index, story in enumerate(top, 1):
            title = self.sanitize_text(story.get("title", "Untitled"))
            url = story.get("url", "")
            briefing += f"### {index}. [{title}]({url})\n"
            age_hours = story.get("age_hours")
            age_text = f"{age_hours:.1f} hours" if age_hours is not None else "unknown"
            briefing += (
                f"- **Reported by:** {self.sanitize_text(story.get('source', 'Unknown'))}\n"
                f"- **Published:** {story.get('published') or 'unknown'} "
                f"(age: {age_text})\n"
            )
            summary = self.sanitize_text(story.get("summary", ""), max_length=360)
            if summary:
                briefing += f"- **Publisher-provided summary (unverified):** {summary}\n"
            if story.get("related_stories", 0):
                sources = ", ".join(story.get("coverage_sources", [])) or "unknown"
                briefing += (
                    f"- **Related coverage:** {story['related_stories']} other stories "
                    f"from {sources}\n"
                )
            for cve in story.get("cves", []):
                briefing += f"- **Enrichment:** {self.describe_cve(cve)}\n"
                affected = cve.get("vendors", []) + cve.get("products", [])
                if affected:
                    values = ", ".join(self.sanitize_text(value) for value in affected)
                    briefing += f"  - **NVD affected-product entries:** {values}\n"
                if cve.get("score") is None and cve.get("severity_hint"):
                    briefing += (
                        f"  - **Unverified headline severity hint:** "
                        f"{cve['severity_hint']}\n"
                    )
            briefing += "\n"

        briefing += (
            "## Verification\n\n"
            "- Open the linked publisher report and confirm important claims against "
            "the relevant vendor advisory or official source.\n"
            "- Confirm product and version applicability against your asset inventory "
            "before prioritizing remediation.\n"
            "- No incident-specific remediation instructions are inferred by this report.\n"
        )
        return briefing
    
    def extract_iocs(self):
        """Extract Indicators of Compromise from story titles and URLs"""
        import re
        
        print("🔍 Extracting IOCs from stories...")
        
        # Patterns for common IOCs
        patterns = {
            "ipv4": re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'),
            "domain": re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|mil|co|ru|cn|tk|top|xyz|info|biz)\b'),
            "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
            "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
            "cve": re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
        }
        
        # Known false positives to filter out
        false_positives = {
            "github.com", "google.com", "microsoft.com", "apple.com",
            "reddit.com", "twitter.com", "linkedin.com", "youtube.com",
            "amazon.com", "cloudflare.com", "wikipedia.org",
            "news.ycombinator.com", "duo.com", "threatpost.com",
            "www.cytidel.com", "ycombinator.com",
            # Our own news sources — links to these are article URLs, not IOCs
            "hn.algolia.com", "cybersecuritynews.com",
            "www.cybersecuritynews.com", "feeds.feedburner.com",
            "thehackernews.com", "www.thehackernews.com",
            "bleepingcomputer.com", "www.bleepingcomputer.com",
            "securelist.com", "www.securelist.com"
        }
        
        iocs = {
            "ipv4": set(),
            "domain": set(),
            "md5": set(),
            "sha256": set(),
            "cve": set()
        }
        
        for story in self.stories:
            text = story["title"] + " " + story.get("url", "")
            
            for ioc_type, pattern in patterns.items():
                matches = pattern.findall(text)
                for match in matches:
                    if ioc_type == "domain" and match.lower() in false_positives:
                        continue
                    iocs[ioc_type].add(match.upper() if ioc_type == "cve" else match)
        
        # Convert sets to sorted lists
        self.iocs = {k: sorted(list(v)) for k, v in iocs.items()}
        
        # Print summary
        total = sum(len(v) for v in self.iocs.values())
        if total > 0:
            print(f"✅ Extracted {total} candidate IOC references from news metadata:")
            for ioc_type, values in self.iocs.items():
                if values:
                    print(f"  {ioc_type.upper()}: {len(values)} found")
        else:
            print("  No IOCs found in current stories")
        
        return self.iocs

    def save_ioc_report(self):
        """Save IOCs to a separate watchlist file"""
        timestamp = datetime.now().strftime("%Y-%m-%d")
        filename = self.config["ioc_dir"] / f"ioc_watchlist_{timestamp}.txt"
        
        with open(filename, "w") as f:
            f.write(f"# Candidate IOC references — {timestamp}\n")
            f.write("# Extracted from news titles and URLs; not validated for detection use.\n")
            f.write("# Generated by Cybersecurity News Evidence Briefing Agent\n\n")
            
            for ioc_type, values in self.iocs.items():
                if values:
                    f.write(f"## {ioc_type.upper()}\n")
                    for ioc in values:
                        f.write(f"{ioc}\n")
                    f.write("\n")
        
        print(f"💾 IOC watchlist saved to: {filename}")
        return filename

    def infer_severity_hint(self, title="", summary=""):
        """Keyword guess at severity from the headline. A hint only, never a score."""
        text = f"{title} {summary}".lower()
        if any(k in text for k in ["critical", "rce", "remote code execution", "auth bypass", "zero-day"]):
            return "critical"
        if any(k in text for k in ["high severity", "privilege escalation", "exploit"]):
            return "high"
        return ""

    def enrich_cve_entry(self, cve_id, title="", summary="", record=None):
        """Build the CVE entry stored on a story.

        ``record`` comes from VulnEnricher. Without one (offline, lookup failure)
        severity stays "unknown": we never fabricate a CVSS score. A keyword-based
        ``severity_hint`` is kept separately and is clearly not a score.
        """
        record = record or {}
        score = record.get("score")
        severity, tag = severity_from_score(score)

        summary_text = (
            self.sanitize_text(record.get("description", ""), max_length=280)
            or self.sanitize_text(summary, max_length=280)
            or self.sanitize_text(title, max_length=280)
        )
        if "auth bypass" in f"{title} {summary}".lower() and "auth bypass" not in summary_text.lower():
            summary_text = f"Auth bypass issue: {summary_text}".strip()

        kev_info = record.get("kev_info") or {}
        return {
            "id": cve_id.upper(),
            "score": score,
            "tag": tag,
            "severity": severity,
            "severity_hint": self.infer_severity_hint(title, summary) if score is None else "",
            "summary": summary_text,
            "kev": record.get("kev"),
            "kev_ransomware": bool(kev_info.get("ransomware")),
            "kev_date_added": kev_info.get("date_added", ""),
            "epss": record.get("epss"),
            "epss_percentile": record.get("epss_percentile"),
            "vendors": record.get("vendors", []),
            "products": record.get("products", []),
        }

    def get_enricher(self):
        if self.enricher is None:
            cache_path = self.config["output_dir"] / "cache" / "enrichment_cache.json"
            self.enricher = VulnEnricher(cache_path=cache_path, nvd_api_key=self.config.get("nvd_api_key", ""))
        return self.enricher

    def tag_cve_stories(self):
        """Find CVE IDs in each story (title and summary) and enrich them with
        KEV, EPSS and NVD data. Must run before scoring so the data counts."""
        print("🔎 Scanning for CVEs and enriching with KEV / EPSS / NVD...")

        per_story = {}
        for index, story in enumerate(self.stories):
            ids = extract_cve_ids(story.get("title", ""), story.get("summary", ""))
            if ids:
                per_story[index] = ids

        all_ids = list(dict.fromkeys(cve_id for ids in per_story.values() for cve_id in ids))
        records = self.get_enricher().enrich(all_ids) if (all_ids and self.config.get("enrich", True)) else {}

        for index, ids in per_story.items():
            story = self.stories[index]
            story["cves"] = [
                self.enrich_cve_entry(cve_id, story.get("title", ""), story.get("summary", ""), records.get(cve_id))
                for cve_id in ids
            ]
            for entry in story["cves"]:
                print(f"  {self.describe_cve(entry)} — {story['title'][:60]}...")

    def apply_watchlist(self):
        """Flag stories that mention, or whose CVEs affect, products on the watchlist."""
        if not self.watchlist:
            return
        flagged = 0
        for story in self.stories:
            vendor_products = []
            for cve in story.get("cves", []):
                vendor_products.extend(cve.get("vendors", []))
                vendor_products.extend(cve.get("products", []))
            hits = match_watchlist(
                self.watchlist,
                texts=[story.get("title", ""), story.get("summary", "")],
                vendors_products=vendor_products,
            )
            story["watchlist_hits"] = hits
            if hits:
                flagged += 1
        print(f"🎯 {flagged} stories match your watchlist ({len(self.watchlist)} terms)")

    def save_briefing(self, briefing):
        """Save briefing to file"""
        timestamp = datetime.now().strftime("%Y-%m-%d")
        filename = self.config["briefing_dir"] / f"briefing_{timestamp}.md"

        with open(filename, "w") as f:
            f.write(f"# Cybersecurity Daily Evidence Briefing\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("---\n\n")
            f.write(briefing)

        print(f"\n💾 Briefing saved to: {filename}")
        return filename

    def save_html_report(self, briefing):
        """Save a polished HTML report for local viewing in a browser."""
        timestamp = datetime.now().strftime("%Y-%m-%d")
        filename = self.config["briefing_dir"] / f"briefing_{timestamp}.html"
        stories = self.stories[:8]
        story_rows = "".join(
            f"<li><strong>{html.escape(story.get('title',''))}</strong><br/>{html.escape(story.get('source',''))} — {story.get('points',0)} points</li>"
            for story in stories
        )
        html_body = dedent(f"""
        <!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <title>Cybersecurity Daily Evidence Briefing</title>
          <style>
            body {{ font-family: Arial, sans-serif; margin: 2rem; color: #111827; }}
            h1, h2 {{ color: #0f172a; }}
            .card {{ border: 1px solid #d1d5db; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }}
            code {{ background: #f3f4f6; padding: 0.2rem 0.4rem; border-radius: 4px; }}
          </style>
        </head>
        <body>
          <h1>Cybersecurity Daily Evidence Briefing</h1>
          <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
          <div class="card">
            <h2>Briefing</h2>
            <pre>{html.escape(briefing)}</pre>
          </div>
          <div class="card">
            <h2>Top Stories</h2>
            <ul>{story_rows}</ul>
          </div>
        </body>
        </html>
        """)

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_body)

        print(f"🌐 HTML report saved to: {filename}")
        return filename

    def send_to_email(self, briefing):
        """Send the briefing to an email recipient when configured."""
        smtp_host = self.config.get("smtp_host", "")
        smtp_port = int(self.config.get("smtp_port", 587))
        smtp_user = self.config.get("smtp_user", "")
        smtp_password = self.config.get("smtp_password", "")
        smtp_from = self.config.get("smtp_from", "")
        smtp_to = self.config.get("smtp_to", "")

        if not all([smtp_host, smtp_from, smtp_to]):
            print("⚠️  Email delivery not configured. Set SMTP_HOST, SMTP_FROM, and SMTP_TO to enable it.")
            return

        try:
            msg = EmailMessage()
            msg["Subject"] = "Cybersecurity Daily Briefing"
            msg["From"] = smtp_from
            msg["To"] = smtp_to
            msg.set_content(briefing)

            with smtplib.SMTP(smtp_host, smtp_port) as server:
                if smtp_user and smtp_password:
                    server.starttls()
                    server.login(smtp_user, smtp_password)
                server.send_message(msg)

            print("✅ Briefing sent to email successfully!")
        except Exception as e:
            print(f"❌ Error sending email: {e}")

    def send_to_discord(self, briefing):
        """Send the briefing to Discord via webhook when configured."""
        webhook_url = self.config.get("discord_webhook_url", "")
        if not webhook_url:
            print("⚠️  No Discord webhook URL configured. Set DISCORD_WEBHOOK_URL to enable Discord delivery.")
            return

        try:
            payload = {"content": briefing[:1900]}
            response = requests.post(webhook_url, json=payload, timeout=10)
            if response.status_code in {200, 204}:
                print("✅ Briefing sent to Discord successfully!")
            else:
                print(f"❌ Discord error: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"❌ Error sending to Discord: {e}")

    def send_to_slack(self, briefing):
        """Send briefing to Slack channel"""
        webhook_url = self.config.get("slack_webhook_url", "")
        if not webhook_url:
            print("⚠️  No Slack webhook URL configured. Set SLACK_WEBHOOK_URL in your environment or .env file.")
            return
    
        # Format for Slack - keep it concise
        date_str = datetime.now().strftime("%B %d, %Y")
    
        slack_message = {
            "text": f"🛡️ *DAILY SOC BRIEFING — {date_str}*",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"🛡️ Daily SOC Briefing — {date_str}"
                    }
                },
                {
                    "type": "divider"
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": briefing[:2900]  # Slack block limit
                    }
                },
                {
                    "type": "divider"
                },
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": "Generated by Cybersecurity News Evidence Briefing Agent | Full briefing saved locally"
                        }
                    ]
                }
            ]
        }
        
        try:
            response = requests.post(
                webhook_url,
                json=slack_message,
                timeout=10
            )
            if response.status_code == 200:
                print("✅ Briefing sent to Slack successfully!")
            else:
                print(f"❌ Slack error: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"❌ Error sending to Slack: {e}")

    def display_briefing(self, briefing):
        """Display briefing in terminal"""
        print("\n" + "="*80)
        print("📰 CYBERSECURITY DAILY EVIDENCE BRIEFING")
        print("="*80 + "\n")
        print(briefing)
        print("\n" + "="*80)
    
    def run(self):
        """Main execution flow"""
        print("🛡️  Cybersecurity News Briefing Agent Starting...\n")
        
        # Fetch news
        self.fetch_all_news()
        
        if not self.stories:
            print("❌ No stories found. Check your internet connection.")
            return
        
        # Enrich first (CVEs, KEV, EPSS, watchlist) so prioritisation can use it
        self.tag_cve_stories()
        self.apply_watchlist()

        # Prioritize
        self.prioritize_stories()

        # Extract IOCs
        self.extract_iocs()
        # Generate briefing content
        briefing = self.generate_evidence_briefing()
        if not briefing:
            print("❌ Failed to generate briefing.")
            return

        # Display
        self.display_briefing(briefing)

        # Send to Slack
        if self.config.get("send_to_slack", True):
            self.send_to_slack(briefing)

        # Send to email/Discord if configured
        self.send_to_email(briefing)
        self.send_to_discord(briefing)

        # Save
        if self.config.get("save_outputs", True):
            filepath = self.save_briefing(briefing)
            self.save_ioc_report()
            self.save_html_report(briefing)
        
        print(f"\n✅ Done! Your briefing is ready.")
        print(f"📁 Briefings: {self.config['briefing_dir']}")
        print(f"📁 IOC watchlists: {self.config['ioc_dir']}")


def parse_args():
    parser = argparse.ArgumentParser(description="Fetch and summarize cybersecurity news")
    parser.add_argument("--output-dir", default=os.getenv("OUTPUT_DIR", str(DEFAULT_OUTPUT_DIR)), help="Directory for generated briefings and IOC watchlists")
    parser.add_argument("--no-slack", action="store_true", help="Skip sending the briefing to Slack")
    parser.add_argument("--no-save", action="store_true", help="Skip saving the briefing and IOC report to disk")
    parser.add_argument("--max-stories", type=int, default=int(os.getenv("MAX_STORY_COUNT", "12")), help="Maximum number of stories to include in the briefing")
    parser.add_argument("--no-enrich", action="store_true", help="Skip KEV / EPSS / NVD lookups (CVE severity will be unknown)")
    parser.add_argument("--watchlist", default=None, help="Path to a watchlist file of vendors/products you run (default: watchlist.txt or WATCHLIST_FILE)")
    parser.add_argument("--print-only", action="store_true", help="Display the briefing without saving or sending it")
    return parser.parse_args()


def build_scheduler_files(output_dir):
    """Create sample systemd and cron files for scheduled runs."""
    output_dir = Path(output_dir).resolve()
    service_dir = output_dir / "systemd"
    service_dir.mkdir(parents=True, exist_ok=True)

    systemd_unit = f"""[Unit]
Description=Cybersecurity Daily Briefing Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory={output_dir}
ExecStart={Path(sys.executable).resolve()} {output_dir / 'cybersec_agent.py'} --output-dir {output_dir} --no-slack
User={os.getenv('USER', 'root')}
Environment=PYTHONPATH={output_dir}

[Install]
WantedBy=multi-user.target
"""

    cron_entry = f"""{os.getenv('CRON_SCHEDULE', '0 8 * * *')} {os.getenv('USER', 'root')} {Path(sys.executable).resolve()} {output_dir / 'cybersec_agent.py'} --output-dir {output_dir} --no-slack > {output_dir / 'cron.log'} 2>&1
"""

    (service_dir / "cybersec-agent.service").write_text(systemd_unit, encoding="utf-8")
    (output_dir / "cybersec-agent.cron").write_text(cron_entry, encoding="utf-8")

    print(f"🗓️ Scheduler files written to {service_dir} and {output_dir}")
    return service_dir / "cybersec-agent.service", output_dir / "cybersec-agent.cron"


def main():
    """Entry point"""
    args = parse_args()

    CONFIG["output_dir"] = Path(args.output_dir).resolve()
    CONFIG["max_story_count"] = args.max_stories
    CONFIG["send_to_slack"] = not args.no_slack and not args.print_only
    CONFIG["save_outputs"] = not args.no_save and not args.print_only
    CONFIG["enrich"] = not args.no_enrich
    if args.watchlist:
        CONFIG["watchlist_file"] = args.watchlist

    if os.getenv("GENERATE_SCHEDULER_FILES", "").lower() in {"1", "true", "yes"}:
        build_scheduler_files(CONFIG["output_dir"])

    agent = CybersecNewsAgent()
    agent.run()


if __name__ == "__main__":
    main()
