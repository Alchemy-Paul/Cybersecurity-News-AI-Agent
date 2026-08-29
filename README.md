Cybersecurity News AI Agent

Cybersecurity News AI Agent is an automated security briefing tool designed for SOC analysts and security teams. It collects cybersecurity news from multiple sources, prioritizes the most relevant stories, enriches them with CVE severity context, extracts indicators of compromise, and generates a daily briefing that can be saved locally or shared through Slack, email, or Discord. The project combines news aggregation, threat intelligence enrichment, and automation to help users stay informed with minimal manual effort.

## Features

- **AI-powered analysis** using Groq with fallback basic briefing when AI is disabled or unavailable
- **Multi-source aggregation** from Hacker News security searches and RSS feeds (Cybersecurity News, The Hacker News, BleepingComputer, Securelist)
- **Smart prioritization** based on SOC-relevant keywords, recency, and CVE severity
- **CVE detection** from headlines and automatic NVD/CVSS severity enrichment
- **IOC extraction** for domains, IPv4 addresses, MD5, SHA256, and CVE IDs
- **Email and Discord delivery support** via SMTP and Discord webhook
- **Slack delivery** via Slack webhook
- **Automatic archiving** of daily markdown and HTML briefings
- **Structured output** into `output/briefings` and `output/ioc_watchlists`
- **Scheduler support** with sample systemd and cron configuration files
- **Configurable runtime options** including `--output-dir`, `--max-stories`, `--no-slack`, `--no-save`, `--print-only`, and `--no-ai`

## Screenshots

![Agent briefing output](Cybersecurity-new-agent.png)

![CVE enrichment and scoring](2026-06-06_22-46.png)

![IOC watchlist report](2026-06-06_23-49.png)

## Quick Start

### Prerequisites

- Linux / Debian/Ubuntu-based system
- Python 3.8+
- Internet connection
- Groq API key for AI-generated briefings (optional)
- Slack webhook URL for Slack delivery (optional)

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/Alchemy-Paul/Cybersecurity-News-AI-Agent.git cybersec-agent
cd cybersec-agent
```

2. **Configure your environment:**
```bash
cp .env.example .env
nano .env
```
Add the following values as needed:
- `GROQ_API_KEY`
- `SLACK_WEBHOOK_URL`
- `OUTPUT_DIR` (optional)
- `MAX_STORY_COUNT` (optional, default 12)
- `GROQ_MODEL` (optional)
- `GROQ_ENDPOINT` (optional)
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_TO` (optional)
- `DISCORD_WEBHOOK_URL` (optional)
- `CRON_SCHEDULE` (optional)
- `GENERATE_SCHEDULER_FILES` (optional)

3. **Create and activate a virtual environment:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

4. **Install dependencies:**
```bash
pip install -r requirements.txt
```

5. **Run the agent:**
```bash
.venv/bin/python cybersec_agent.py
```

### Optional scheduler generation

Set `GENERATE_SCHEDULER_FILES=1` and run the script to create sample scheduler files:
```bash
GENERATE_SCHEDULER_FILES=1 .venv/bin/python cybersec_agent.py
```
This generates `systemd/cybersec-agent.service` and `cybersec-agent.cron` in the configured output directory.

### Scheduler setup examples

Using systemd:
```bash
sudo cp systemd/cybersec-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cybersec-agent.service
```

Using cron:
```bash
crontab -e
# add a line similar to:
0 8 * * * /home/youruser/cybersec-agent/.venv/bin/python /home/youruser/cybersec-agent/cybersec_agent.py --output-dir /home/youruser/cybersec-agent/output --no-slack > /home/youruser/cybersec-agent/output/cron.log 2>&1
```

## Runtime options

```bash
.venv/bin/python cybersec_agent.py --output-dir output --max-stories 8
.venv/bin/python cybersec_agent.py --no-slack
.venv/bin/python cybersec_agent.py --no-save
.venv/bin/python cybersec_agent.py --print-only
.venv/bin/python cybersec_agent.py --no-ai
```

- `--output-dir`: Choose a custom output directory (default is `output/`)
- `--max-stories`: Limit the number of stories included in the briefing
- `--no-slack`: Skip sending the briefing to Slack
- `--no-save`: Skip saving briefing and IOC files to disk
- `--print-only`: Display the briefing in the terminal only; disables Slack send and saving
- `--no-ai`: Skip Groq AI generation and use the basic briefing instead.

## Output

- Markdown briefings are saved to `output/briefings`
- HTML briefings are saved to `output/briefings`
- IOC watchlists are saved to `output/ioc_watchlists`

## Environment variables

Supported environment variables:

- `GROQ_API_KEY`
- `SLACK_WEBHOOK_URL`
- `OUTPUT_DIR`
- `MAX_STORY_COUNT`
- `GROQ_MODEL`
- `GROQ_ENDPOINT`
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `SMTP_PASSWORD`
- `SMTP_FROM`
- `SMTP_TO`
- `DISCORD_WEBHOOK_URL`
- `CRON_SCHEDULE`
- `GENERATE_SCHEDULER_FILES`

These drive output location, delivery channels, AI configuration, and scheduler generation.
