#!/usr/bin/env python3
"""
Cybersecurity Daily Briefing AI Agent
Fetches and summarizes the latest cybersecurity news, vulnerabilities, and threats
Perfect for busy SOC analysts
"""

import os
import sys
import json
import requests
import feedparser
from datetime import datetime, timedelta
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
    "output_dir": Path(os.getenv("OUTPUT_DIR", str(Path.home() / "Documents/cybersec_briefings"))),
    "slack_webhook_url": os.getenv("SLACK_WEBHOOK_URL", "")
}

class CybersecNewsAgent:
    def __init__(self):
        self.config = CONFIG
        self.stories = []
        self.config["output_dir"].mkdir(parents=True, exist_ok=True)
        
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
            import feedparser
            feed = feedparser.parse(source["url"])
            
            for entry in feed.entries[:10]:
                self.stories.append({
                    "title": entry.get("title", ""),
                    "url": entry.get("link", ""),
                    "source": source["name"],
                    "points": 0,
                    "comments": 0,
                    "created": entry.get("published", "")
                })
        except Exception as e:
            print(f"Error fetching {source['name']}: {e}")
    
    def fetch_all_news(self):
        """Fetch news from all configured sources"""
        print("🔍 Fetching latest cybersecurity news...")
        
        for source in self.config["news_sources"]:
            if source["type"] == "hn":
                self.fetch_hackernews(source)
            elif source["type"] == "reddit":
                self.fetch_reddit(source)
            elif source["type"] == "rss":
                self.fetch_rss(source)
        
        # Sort by relevance (points/score)
        self.stories.sort(key=lambda x: x.get("points", 0), reverse=True)
        print(f"✅ Found {len(self.stories)} stories")
    
    def prioritize_stories(self):
        """Score stories based on priority keywords"""
        for story in self.stories:
            score = story.get("points", 0)
            title_lower = story["title"].lower()
            
            # Boost score for priority keywords
            for keyword in self.config["keywords_priority"]:
                if keyword.lower() in title_lower:
                    score += 50
            
            story["priority_score"] = score
        
        self.stories.sort(key=lambda x: x["priority_score"], reverse=True)
    
    def generate_ai_briefing(self):
        """Use Groq to generate an intelligent briefing"""
        groq_api_key = os.getenv("GROQ_API_KEY", "")
        if not groq_api_key:
            print("⚠️  No Groq API key found. Set GROQ_API_KEY environment variable.")
            return self.generate_basic_briefing()
        
        print("🤖 Generating AI-powered briefing with Groq...")
        
        # Prepare top stories
        top_stories = self.stories[:20]
        stories_text = "\n\n".join([
            f"{i+1}. {story['title']}\n"
            f"Source: {story['source']} | Points: {story['points']} | Comments: {story['comments']}\n"
            f"CVEs: {', '.join([c['id'] + ' ' + (c['tag'] or 'UNKNOWN') for c in story.get('cves', [])]) or 'None detected'}\n"
            f"URL: {story['url']}"
            for i, story in enumerate(top_stories)
        ])
        
        prompt = f"""You are a cybersecurity analyst assistant. Analyze these news stories and create a concise daily briefing for a SOC analyst.

Today's Cybersecurity News Stories:
{stories_text}

Please provide:
1. EXECUTIVE SUMMARY (2-3 sentences on the overall threat landscape today)
2. CRITICAL ITEMS (Top 3-5 most important stories for a SOC analyst, with brief explanation of why they matter)
3. TRENDING TOPICS (What themes are emerging?)
4. RECOMMENDED ACTIONS (Any immediate steps a SOC analyst should consider based on today's news)

Keep it concise, actionable, and focused on what matters for security operations."""

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
        filename = self.config["output_dir"] / f"ioc_watchlist_{timestamp}.txt"
        
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
                    
                    # Try CVSSv3 first, then CVSSv2
                    if metrics.get("cvssMetricV31"):
                        score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    elif metrics.get("cvssMetricV30"):
                        score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                    elif metrics.get("cvssMetricV2"):
                        score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                    else:
                        return None, None
                    
                    # Tag by severity
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
                for cve_id in set(cves):  # deduplicate
                    cve_id = cve_id.upper()
                    score, tag = self.get_cve_severity(cve_id)
                    story["cves"].append({
                        "id": cve_id,
                        "score": score,
                        "tag": tag
                    })
                    if tag:
                        print(f"  {tag} | {cve_id} (CVSS: {score}) — {story['title'][:60]}...")
                    else:
                        print(f"  ⚪ UNKNOWN | {cve_id} — {story['title'][:60]}...")
    
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
        filename = self.config["output_dir"] / f"briefing_{timestamp}.md"
        
        with open(filename, "w") as f:
            f.write(f"# Cybersecurity Daily Briefing\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("---\n\n")
            f.write(briefing)
        
        print(f"\n💾 Briefing saved to: {filename}")
        return filename

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
        self.send_to_slack(briefing)
        
        # Save
        filepath = self.save_briefing(briefing)
        self.save_ioc_report()
        
        print(f"\n✅ Done! Your briefing is ready.")
        print(f"📁 All briefings are saved in: {self.config['output_dir']}")


def main():
    """Entry point"""
    agent = CybersecNewsAgent()
    agent.run()


if __name__ == "__main__":
    main()
