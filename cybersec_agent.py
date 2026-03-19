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

# Configuration
CONFIG = {
    "anthropic_api_key": os.getenv("ANTHROPIC_API_KEY", ""),
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
    "output_dir": Path.home() / ".cybersec_briefings"
}

class CybersecNewsAgent:
    def __init__(self):
        self.config = CONFIG
        self.stories = []
        self.config["output_dir"].mkdir(exist_ok=True)
        
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
        """Use Claude to generate an intelligent briefing"""
        if not self.config["anthropic_api_key"]:
            print("⚠️  No Anthropic API key found. Set ANTHROPIC_API_KEY environment variable.")
            print("Generating basic briefing without AI analysis...")
            return self.generate_basic_briefing()
        
        print("🤖 Generating AI-powered briefing with Claude...")
        
        # Prepare top stories for Claude
        top_stories = self.stories[:20]
        stories_text = "\n\n".join([
            f"**{i+1}. {story['title']}**\n"
            f"Source: {story['source']} | Points: {story['points']} | Comments: {story['comments']}\n"
            f"URL: {story['url']}"
            for i, story in enumerate(top_stories)
        ])
        
        prompt = f"""You are a cybersecurity analyst assistant. Analyze these news stories and create a concise daily briefing for a SOC analyst.

Today's Cybersecurity News Stories:
{stories_text}

Please provide:
1. **Executive Summary** (2-3 sentences on the overall threat landscape today)
2. **Critical Items** (Top 3-5 most important stories for a SOC analyst, with brief explanation of why they matter)
3. **Trending Topics** (What themes are emerging?)
4. **Recommended Actions** (Any immediate steps a SOC analyst should consider based on today's news)

Keep it concise, actionable, and focused on what matters for security operations. Use clear headings and bullet points."""

        try:
            response = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.config["anthropic_api_key"],
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                },
                json={
                    "model": "claude-sonnet-4-20250514",
                    "max_tokens": 2000,
                    "messages": [
                        {"role": "user", "content": prompt}
                    ]
                },
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                briefing = result["content"][0]["text"]
                return briefing
            else:
                print(f"❌ API error: {response.status_code}")
                return self.generate_basic_briefing()
                
        except Exception as e:
            print(f"❌ Error calling Claude API: {e}")
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
