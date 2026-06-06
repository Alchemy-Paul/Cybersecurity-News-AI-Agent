Cybersecurity News AI Agent

I got tired of spending 30 minutes every morning sifting through security blogs just to stay updated on threats. So I built this.

An AI-powered SOC briefing agent that automatically fetches cybersecurity news, scores CVE severity, and delivers a daily threat digest to Slack so you can focus on defending, not reading.

## Features

- **AI-Powered Analysis** using Groq
- **Multi-Source Aggregation** (Hacker News, Reddit r/netsec, r/cybersecurity)
- **Smart Prioritization** based on SOC-relevant keywords
- **CVE Detection from headlines** using regex extraction of CVE IDs
- **NVD/CVSS Enrichment** to fetch severity scores and tag critical vulnerabilities
- **Automatic Archiving** of daily briefings
- **Scheduled Execution** via systemd or cron
- **Executive Summaries** tailored for security operations

## Quick Start

### Prerequisites

- Pop!_OS 24.04 (or any Debian/Ubuntu-based Linux) - my setup
- Python 3.8+
- Internet connection
- Groq API key (optional but recommended)

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/YOUR-USERNAME/cybersec-news-agent.git
cd cybersec-news-agent
```

2. **Configure your environment:**
```bash
cp .env.example .env
nano .env  # Add your Groq API key and Slack webhook URL
```

3. **Create and activate a virtual environment:**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

4. **Test the agent:**
```bash
.venv/bin/python cybersec_agent.py
```