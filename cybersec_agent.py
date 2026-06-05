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
            "name": "Reddit r/netsec",
            "url": "https://www.reddit.com/r/netsec/hot.json?limit=15",
            "type": "reddit"
        },
        {
            "name": "Reddit r/cybersecurity", 
            "url": "https://www.reddit.com/r/cybersecurity/hot.json?limit=15",
            "type": "reddit"
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
    
    def fetch_all_news(self):
        """Fetch news from all configured sources"""
        print("🔍 Fetching latest cybersecurity news...")
        
        for source in self.config["news_sources"]:
            if source["type"] == "hn":
                self.fetch_hackernews(source)
            elif source["type"] == "reddit":
                self.fetch_reddit(source)
        
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
            response = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {groq_api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "llama3-8b-8192",
                    "max_tokens": 1500,
                    "messages": [
                        {"role": "user", "content": prompt}
                    ]
                },
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                briefing = result["choices"][0]["message"]["content"]
                return briefing
            else:
                print(f"❌ Groq API error: {response.status_code} - {response.text}")
                return self.generate_basic_briefing()
                
        except Exception as e:
            print(f"❌ Error calling Groq API: {e}")
            return self.generate_basic_briefing()
    
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
        
        # Generate briefing
        briefing = self.generate_ai_briefing()
        
        # Display
        self.display_briefing(briefing)
        
        # Send to Slack
        self.send_to_slack(briefing)
        
        # Save
        filepath = self.save_briefing(briefing)
        
        print(f"\n✅ Done! Your briefing is ready.")
        print(f"📁 All briefings are saved in: {self.config['output_dir']}")


def main():
    """Entry point"""
    agent = CybersecNewsAgent()
    agent.run()


if __name__ == "__main__":
    main()
