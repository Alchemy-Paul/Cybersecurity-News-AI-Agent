# Cybersecurity News AI Agent

This project automatically gathers cybersecurity news, prioritizes stories for a SOC workflow, enriches CVEs, extracts potential indicators, and generates a source-grounded daily evidence briefing. It can print the briefing locally, save markdown and HTML reports, and deliver the result to Slack, email, or Discord.

## What it does

- Aggregates stories from Hacker News security searches and RSS feeds
- Groups closely related headlines, preserves their source coverage, and scores stories by engagement, known recency, keyword relevance, and CVE impact
- Enriches CVEs with CISA KEV, EPSS and NVD data, showing `unknown` instead of guessing when a source is unavailable
- Flags possible watchlist matches without claiming that the product is deployed or affected
- Extracts common IOCs from story titles and URLs, including IPv4s, domains, MD5, SHA256, and CVE IDs
- Saves daily briefing reports in markdown and HTML format
- Sends the briefing to Slack, email, or Discord when configured
- Supports scheduler generation for systemd and cron-based automation

## Core features

- Deterministic briefing generation from fetched stories and structured CVE enrichment; no LLM-generated claims or remediation instructions are published
- Publisher-provided headlines and summaries are explicitly labeled as unverified, and watchlist matches are not presented as confirmed exposure
- Daily archive folders under the configured output directory
- Optional scheduler file generation via environment variables
- CLI switches for output directory, story count, saving, and print-only mode

## Repository layout

- `cybersec_agent.py` — main application and CLI entry point
- `enrichment.py` — CISA KEV, EPSS and NVD lookups with an on-disk cache
- `watchlist.py` — watchlist loading and matching
- `tests/` — offline unit tests (the network is faked; no internet needed)
- `output/briefings/` — generated markdown and HTML briefing files
- `output/ioc_watchlists/` — IOC watchlist files grouped by date
- `systemd/` — sample systemd service unit
- `cybersec-agent.cron` — sample cron entry

## Screenshots

![Cybersecurity briefing output](Cybersecurity-new-agent.png)

![CVE enrichment and scoring](2026-06-06_22-46.png)

![IOC watchlist report](2026-06-06_23-49.png)

## Prerequisites

- Linux or another Unix-like environment
- Python 3.8+
- Internet access for fetching feeds and NVD data
- Optional: Slack webhook URL, Discord webhook URL, or SMTP credentials for delivery

## Quick start

1. Clone the repository:

```bash
git clone https://github.com/Alchemy-Paul/Cybersecurity-News-AI-Agent.git cybersec-agent
cd cybersec-agent
```

2. Copy the sample environment file and fill in the values you need:

```bash
cp .env.example .env
nano .env
```

Example settings:

```env
SLACK_WEBHOOK_URL=<your-slack-webhook-url>
OUTPUT_DIR=/absolute/path/to/output
MAX_STORY_COUNT=12
CRON_SCHEDULE=0 8 * * *
GENERATE_SCHEDULER_FILES=0

SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
SMTP_FROM=
SMTP_TO=

DISCORD_WEBHOOK_URL=
```

3. Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

4. Install dependencies:

```bash
pip install -r requirements.txt
```

5. Run the agent:

```bash
.venv/bin/python cybersec_agent.py
```

The generated report is a deterministic rendering of feed content and CVE enrichment; it does not use a language model to create analysis or remediation advice. Treat publisher summaries as unverified claims and confirm applicability against vendor advisories and your asset inventory.

## Vulnerability enrichment and "affects our stack"

CVEs found in a story's title or summary are enriched from authoritative sources instead of guessed from the headline:

- **CISA KEV** - is the CVE confirmed exploited in the wild (and used in ransomware)?
- **FIRST EPSS** - probability of exploitation in the next 30 days
- **NVD** - CVSS base score and the affected vendors/products

Stories are ranked KEV first, then EPSS and CVSS, then everything else. Results are cached under `output/cache/`.

If a source is unreachable the field is shown as `unknown` (never invented). In particular, `KEV: unknown` means the feed could not be checked, which is not the same as "not exploited". Without NVD data, severity is `unknown`; a headline-based hint may be shown but is labelled unverified.

**Watchlist.** Copy `watchlist.example.txt` to `watchlist.txt` and list the vendors/products you run. Stories that mention them, or whose CVEs affect them (via NVD CPE or KEV data), are marked as possible matches and ranked higher. A match is not confirmation that a product is deployed or affected. Use specific terms ("microsoft exchange", not "exchange").

Set `NVD_API_KEY` (free) to raise the NVD rate limit. Use `--no-enrich` to skip all lookups, or `--watchlist PATH` to use another file.

## Runtime options

```bash
.venv/bin/python cybersec_agent.py --output-dir output --max-stories 8
.venv/bin/python cybersec_agent.py --no-slack
.venv/bin/python cybersec_agent.py --no-save
.venv/bin/python cybersec_agent.py --print-only
```

Command-line flags:

- `--output-dir`: Set the output directory for generated briefing and IOC files
- `--max-stories`: Limit the number of stories included in the briefing
- `--no-slack`: Disable Slack delivery
- `--no-save`: Skip writing reports to disk
- `--print-only`: Print the briefing to the terminal without saving or sending it
- `--no-enrich`: Skip KEV / EPSS / NVD lookups (CVE severity will be unknown)
- `--watchlist`: Path to your watchlist file (default `watchlist.txt` or `WATCHLIST_FILE`)

## Output artifacts

The script creates these folders automatically when needed:

- `output/briefings/` — markdown and HTML briefing reports named like `briefing_YYYY-MM-DD.md` and `briefing_YYYY-MM-DD.html`
- `output/ioc_watchlists/` — candidate IOC reference files extracted from news titles and URLs; validate them before detection or blocking use

Each run also prints a summary of extracted IOCs and the final output paths.

## Environment variables

The application reads the following variables from the environment or a `.env` file:

- `SLACK_WEBHOOK_URL`
- `OUTPUT_DIR`
- `MAX_STORY_COUNT`
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `SMTP_PASSWORD`
- `SMTP_FROM`
- `SMTP_TO`
- `DISCORD_WEBHOOK_URL`
- `CRON_SCHEDULE`
- `GENERATE_SCHEDULER_FILES`

These control the output location, delivery channels, and scheduler generation behavior.

## Scheduler setup

You can generate sample cron and systemd files automatically:

```bash
GENERATE_SCHEDULER_FILES=1 .venv/bin/python cybersec_agent.py
```

This writes sample files to the configured output directory, including:

- `systemd/cybersec-agent.service`
- `cybersec-agent.cron`

Example systemd activation:

```bash
sudo cp systemd/cybersec-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cybersec-agent.service
```

Example cron entry:

```bash
crontab -e
```

Add a line similar to:

```bash
0 8 * * * /home/youruser/cybersec-agent/.venv/bin/python /home/youruser/cybersec-agent/cybersec_agent.py --output-dir /home/youruser/cybersec-agent/output --no-slack > /home/youruser/cybersec-agent/output/cron.log 2>&1
```

## Notes

- The script automatically creates the output folders if they do not already exist.
- Story prioritization is based on keyword relevance, age, engagement, and detected CVE severity.
- Closely related headlines are grouped into one story with contributing sources shown. Stories without a usable publication date are marked unknown and receive no freshness bonus.
- When a CVE cannot be fetched from NVD, the agent assigns a heuristic severity tag to keep the briefing useful even during upstream issues.
- The project includes a small unittest suite to verify sanitization, evidence reporting, scoring behavior, and CVE fallback logic.
