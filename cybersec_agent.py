#!/usr/bin/env python3
"""
Cybersecurity Daily Briefing AI Agent
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
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import parsedate_to_datetime
from pathlib import Path


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
            if key and key not in os.environ:
                os.environ[key] = value


load_env_file()

# Configuration
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent / "output"

CONFIG = {
    "groq_api_key": os.getenv("GROQ_API_KEY", ""),
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
    "discord_webhook_url": os.getenv("DISCORD_WEBHOOK_URL", "")
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
        self.config.setdefault("use_ai", True)
        
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
            return datetime.now(tz=timezone.utc)
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
        return datetime.now(tz=timezone.utc)

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

    def build_briefing_prompt(self, stories=None):
        stories = stories or self.stories[: self.config.get("max_story_count", 12)]
        stories_text = "\n\n".join([
            self.format_story_for_prompt(i + 1, story)
            for i, story in enumerate(stories)
        ])

        return f"""You are a cybersecurity analyst assistant supporting a SOC team.
Analyze these cybersecurity news stories and produce a concise daily briefing with the following sections:
1. EXECUTIVE SUMMARY
2. CRITICAL HIGHLIGHTS (top 3-5 stories and why they matter)
3. CVE ALERTS (critical/high vulnerabilities and any impacted assets)
4. TRENDING THEMES (threat vectors, malware, actors, ransomware, phishing, supply chain, etc.)
5. RECOMMENDED ACTIONS (immediate SOC actions, detection, and mitigation guidance)

Keep the briefing short, actionable, and SOC-focused. Use bullet points and clear headings.

Today's Cybersecurity News Stories:
{stories_text}
"""

    def format_story_for_prompt(self, index, story):
        title = self.sanitize_text(story.get("title", ""), max_length=180)
        summary = self.sanitize_text(story.get("summary", ""), max_length=320)
        cves = story.get("cves", [])
        cve_text = ", ".join([f"{c['id']} {c.get('tag', 'UNKNOWN')}" for c in cves]) or "None detected"

        return (
            f"{index}. {title}\n"
            f"Source: {self.sanitize_text(story.get('source', 'Unknown'))} | "
            f"Points: {story.get('points', 0)} | Comments: {story.get('comments', 0)} | "
            f"Age: {story.get('age_hours', 0):.1f}h\n"
            f"Summary: {summary or 'No summary available.'}\n"
            f"CVEs: {cve_text}\n"
            f"URL: {story.get('url', '')}"
        )

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
        story["published"] = published.isoformat()
        story["age_hours"] = max(0.0, (datetime.now(tz=timezone.utc) - published).total_seconds() / 3600)
        if not story["summary"]:
            story["summary"] = self.fetch_story_summary(story["url"])
            story["summary"] = self.sanitize_text(story["summary"], max_length=360)
        story["key_phrases"] = [kw for kw in self.config["keywords_priority"] if kw.lower() in story["title"].lower() or kw.lower() in story["summary"].lower()]
        story["priority_score"] = story.get("points", 0)

    def deduplicate_stories(self):
        unique = {}
        for story in self.stories:
            key = (story.get("url") or story.get("title", "")).strip().lower()
            if not key:
                continue
            existing = unique.get(key)
            if existing:
                if story.get("points", 0) > existing.get("points", 0):
                    unique[key] = story
            else:
                unique[key] = story

        duplicates = len(self.stories) - len(unique)
        if duplicates > 0:
            print(f"🔁 Removed {duplicates} duplicate stories")
        self.stories = list(unique.values())

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
        score = int(story.get("points", 0)) * 1.5 + int(story.get("comments", 0)) * 0.8
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

        age_hours = float(story.get("age_hours", 0.0) or 0.0)
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
    
    def generate_ai_briefing(self):
        """Use Groq to generate an intelligent briefing"""
        groq_api_key = os.getenv("GROQ_API_KEY", "")
        if not groq_api_key:
            print("⚠️  No Groq API key found. Set GROQ_API_KEY environment variable.")
            return self.generate_basic_briefing()
        
        if not self.config.get("use_ai", True):
            print("⚠️  AI generation disabled. Falling back to basic briefing.")
            return self.generate_basic_briefing()

        print("🤖 Generating AI-powered briefing with Groq...")

        prompt = self.build_briefing_prompt(self.stories[: self.config.get("max_story_count", 12)])

        try:
            # Allow configuring model and endpoint via environment if needed
            groq_model = os.getenv("GROQ_MODEL", "meta-llama/llama-4-scout-17b-16e-instruct")
            groq_endpoint = os.getenv("GROQ_ENDPOINT", "https://api.groq.com/openai/v1/chat/completions")

            response = requests.post(
                groq_endpoint,
                headers={
                    "Authorization": f"Bearer {groq_api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": groq_model,
                    "max_tokens": 1500,
                    "messages": [
                        {"role": "user", "content": prompt}
                    ]
                },
                timeout=30
            )

            if response.status_code == 200:
                result = response.json()
                # OpenAI/Groq-compatible chat response
                briefing = None
                try:
                    briefing = result["choices"][0]["message"]["content"]
                except Exception:
                    # Fallback to other possible fields
                    if isinstance(result.get("text"), str):
                        briefing = result.get("text")
                    elif isinstance(result.get("output"), list) and result["output"]:
                        first_output = result["output"][0]
                        briefing = (first_output.get("content") if isinstance(first_output, dict) else str(first_output))

                if briefing:
                    return briefing

                print("⚠️  Unexpected Groq response format, falling back to basic briefing.")
                return self.generate_basic_briefing()
            else:
                print(f"❌ Groq API error: {response.status_code} - {response.text}")
                return self.generate_basic_briefing()

        except Exception as e:
            print(f"❌ Error calling Groq API: {e}")
            return self.generate_basic_briefing()
    
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
        "www.cytidel.com", "ycombinator.com"
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
            print(f"✅ Extracted {total} IOCs:")
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
            f.write(f"# IOC Watchlist — {timestamp}\n")
            f.write(f"# Generated by Cybersecurity News AI Agent\n\n")
            
            for ioc_type, values in self.iocs.items():
                if values:
                    f.write(f"## {ioc_type.upper()}\n")
                    for ioc in values:
                        f.write(f"{ioc}\n")
                    f.write("\n")
        
        print(f"💾 IOC watchlist saved to: {filename}")
        return filename

    def enrich_cve_entry(self, cve_id, title="", summary=""):
        """Fetch CVE details from NVD when available, otherwise use heuristic fallback."""
        score, tag = self.get_cve_severity(cve_id)
        if score is None and tag is None:
            title_lower = (title or "").lower()
            summary_lower = (summary or "").lower()
            text = f"{title_lower} {summary_lower}"

            if any(keyword in text for keyword in ["critical", "rce", "auth bypass", "privilege", "zero-day", "remote code execution"]):
                tag = "🔴 CRITICAL"
                score = 9.8
            elif any(keyword in text for keyword in ["high", "vulnerability", "bypass", "exploit"]):
                tag = "🟠 HIGH"
                score = 7.8
            elif any(keyword in text for keyword in ["medium", "denial", "spoofing"]):
                tag = "🟡 MEDIUM"
                score = 5.5
            else:
                tag = "🟢 LOW"
                score = 3.2

        severity = "unknown"
        if tag:
            severity = "critical" if "critical" in tag.lower() else "high" if "high" in tag.lower() else "medium" if "medium" in tag.lower() else "low"

        return {
            "id": cve_id.upper(),
            "score": score,
            "tag": tag,
            "severity": severity,
            "summary": self.sanitize_text(summary, max_length=280) or self.sanitize_text(title, max_length=280),
        }

    def get_cve_severity(self, cve_id):
        """Fetch CVE severity from NVD API"""
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                if vulnerabilities:
                    cve_data = vulnerabilities[0].get("cve", {})
                    metrics = cve_data.get("metrics", {})

                    if metrics.get("cvssMetricV31"):
                        score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    elif metrics.get("cvssMetricV30"):
                        score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                    elif metrics.get("cvssMetricV2"):
                        score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                    else:
                        return None, None

                    if score >= 9.0:
                        tag = "🔴 CRITICAL"
                    elif score >= 7.0:
                        tag = "🟠 HIGH"
                    elif score >= 4.0:
                        tag = "🟡 MEDIUM"
                    else:
                        tag = "🟢 LOW"

                    return score, tag
        except Exception as e:
            print(f"⚠️  Could not fetch severity for {cve_id}: {e}")
        return None, None

    def tag_cve_stories(self):
        """Scan stories for CVE IDs and enrich with severity data"""
        import re
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
        
        print("🔎 Scanning for CVEs and fetching severity scores...")
        
        for story in self.stories:
            cves = cve_pattern.findall(story["title"])
            if cves:
                story["cves"] = []
                for cve_id in set(cves):
                    cve_id = cve_id.upper()
                    enriched = self.enrich_cve_entry(cve_id, title=story.get("title", ""), summary=story.get("summary", ""))
                    story["cves"].append(enriched)
                    if enriched.get("tag"):
                        print(f"  {enriched['tag']} | {enriched['id']} (CVSS: {enriched['score']}) — {story['title'][:60]}...")
                    else:
                        print(f"  ⚪ UNKNOWN | {enriched['id']} — {story['title'][:60]}...")
    
    def generate_basic_briefing(self):
        """Generate a basic briefing without AI"""
        briefing = "# Cybersecurity Daily Briefing\n\n"
        briefing += f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"
        briefing += "## Top Stories\n\n"
        
        for i, story in enumerate(self.stories[:10], 1):
            briefing += f"### {i}. {story['title']}\n"
            briefing += f"- **Source:** {story['source']}\n"
            briefing += f"- **Engagement:** {story['points']} points, {story['comments']} comments\n"
            briefing += f"- **Link:** {story['url']}\n\n"
        
        return briefing
    
    def save_briefing(self, briefing):
        """Save briefing to file"""
        timestamp = datetime.now().strftime("%Y-%m-%d")
        filename = self.config["briefing_dir"] / f"briefing_{timestamp}.md"

        with open(filename, "w") as f:
            f.write(f"# Cybersecurity Daily Briefing\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("---\n\n")
            f.write(briefing)

        print(f"\n💾 Briefing saved to: {filename}")
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
                            "text": "🤖 Generated by Cybersecurity News AI Agent | Full briefing saved locally"
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
        print("📰 CYBERSECURITY DAILY BRIEFING")
        print("="*80 + "\n")
        print(briefing)
        print("\n" + "="*80)
    
    def run(self):
        """Main execution flow"""
        print("🛡️  Cybersecurity News AI Agent Starting...\n")
        
        # Fetch news
        self.fetch_all_news()
        
        if not self.stories:
            print("❌ No stories found. Check your internet connection.")
            return
        
        # Prioritize
        self.prioritize_stories()
        
        # Tag CVE severity
        self.tag_cve_stories()        
        # Extract IOCs
        self.extract_iocs()
        # Generate briefing content
        briefing = self.generate_ai_briefing()
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
        
        print(f"\n✅ Done! Your briefing is ready.")
        print(f"📁 Briefings: {self.config['briefing_dir']}")
        print(f"📁 IOC watchlists: {self.config['ioc_dir']}")


def parse_args():
    parser = argparse.ArgumentParser(description="Fetch and summarize cybersecurity news")
    parser.add_argument("--output-dir", default=os.getenv("OUTPUT_DIR", str(DEFAULT_OUTPUT_DIR)), help="Directory for generated briefings and IOC watchlists")
    parser.add_argument("--no-slack", action="store_true", help="Skip sending the briefing to Slack")
    parser.add_argument("--no-save", action="store_true", help="Skip saving the briefing and IOC report to disk")
    parser.add_argument("--max-stories", type=int, default=int(os.getenv("MAX_STORY_COUNT", "12")), help="Maximum number of stories to include in the briefing")
    parser.add_argument("--no-ai", action="store_true", help="Disable Groq AI generation and use the basic briefing")
    parser.add_argument("--print-only", action="store_true", help="Display the briefing without saving or sending it")
    return parser.parse_args()


def main():
    """Entry point"""
    args = parse_args()

    CONFIG["output_dir"] = Path(args.output_dir).resolve()
    CONFIG["max_story_count"] = args.max_stories
    CONFIG["send_to_slack"] = not args.no_slack and not args.print_only
    CONFIG["save_outputs"] = not args.no_save and not args.print_only
    CONFIG["use_ai"] = not args.no_ai

    agent = CybersecNewsAgent()
    agent.run()


if __name__ == "__main__":
    main()
