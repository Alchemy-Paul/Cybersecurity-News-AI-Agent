Cybersecurity News AI Agent

An intelligent daily briefing system for SOC analysts and cybersecurity professionals. Automatically fetches, analyzes, and summarizes the latest cybersecurity news, vulnerabilities, and threats.

## Features

- **AI-Powered Analysis** using Claude (Anthropic)
- **Multi-Source Aggregation** (Hacker News, Reddit r/netsec, r/cybersecurity)
- **Smart Prioritization** based on SOC-relevant keywords
- **Automatic Archiving** of daily briefings
- **Scheduled Execution** via systemd or cron
- **Executive Summaries** tailored for security operations

## Quick Start

### Prerequisites

- Pop!_OS 24.04 (or any Debian/Ubuntu-based Linux) - my setup
- Python 3.8+
- Internet connection
- Anthropic API key (optional but recommended)

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/YOUR-USERNAME/cybersec-news-agent.git
cd cybersec-news-agent
```

2. **Run the setup script:**
```bash
chmod +x setup.sh
./setup.sh
```

3. **Configure your API key:**
```bash
cp .env.example .env
nano .env  # Add your Anthropic API key
```

4. **Test the agent:**
```bash
python3 cybersec_agent.py