# Cyber Scam & Phishing Detection Bot

A lightweight Telegram bot that analyzes messages and links to detect possible scams and phishing, returning a confidence score and a risk visualization image.

## Features

- Link and message analysis using keyword heuristics
- Integrations with Google Safe Browsing, VirusTotal, and AbuseIPDB (optional APIs)
- Image-based risk visualization
- Bilingual responses (English & Malayalam)
- Simple Dockerfile included for containerized deployment

## Requirements

- Python 3.9+
- Dependencies listed in `requirements.txt`

## Environment Variables

The bot reads these environment variables (set at runtime):

- `BOT_TOKEN` — Telegram bot token (required)
- `GOOGLE_SAFE_BROWSING_KEY` — (optional) Google Safe Browsing API key
- `VIRUSTOTAL_API_KEY` — (optional) VirusTotal API key
- `ABUSEIPDB_API_KEY` — (optional) AbuseIPDB API key
- `PORT` — (optional) port for the lightweight health HTTP server (default: `10000`)

If you do not provide the optional API keys, the bot will still run but external checks will be skipped.

## Installation (local)

1. Clone the repository and cd into it:

```bash
git clone <repo-url>
cd cyber_bot-main
```

2. Create a virtual environment and install dependencies:

```bash
python -m venv .venv
# Windows (PowerShell)
.\.venv\Scripts\Activate.ps1
# or Windows (cmd)
.\.venv\Scripts\activate.bat
pip install -r requirements.txt
```

3. Set required environment variables (example PowerShell):

```powershell
$env:BOT_TOKEN = "<your-telegram-bot-token>"
$env:GOOGLE_SAFE_BROWSING_KEY = "<your-google-key>"
$env:VIRUSTOTAL_API_KEY = "<your-virustotal-key>"
$env:ABUSEIPDB_API_KEY = "<your-abuseipdb-key>"
$env:PORT = "10000"
python bot.py
```

## Running with Docker

Build the image:

```bash
docker build -t cyber-bot .
```

Run the container (example):

```bash
docker run -e BOT_TOKEN="<your-token>" \
  -e GOOGLE_SAFE_BROWSING_KEY="<key>" \
  -e VIRUSTOTAL_API_KEY="<key>" \
  -e ABUSEIPDB_API_KEY="<key>" \
  -p 10000:10000 \
  cyber-bot
```

Notes:

- The repository contains an `images/` folder referenced by the bot for risk visuals. Keep that folder or ensure the `RISK_IMAGES` URLs remain reachable.
- The bot exposes a tiny HTTP endpoint (used by some free-tier hosts) to keep the process alive; set `PORT` if needed by your hosting platform.

## How it works (short)

- The bot parses incoming text for links and keywords.
- For each link it optionally queries Google Safe Browsing, VirusTotal, and AbuseIPDB (if keys exist).
- It computes a heuristic risk/confidence score and returns a classification with an illustrative image.

## Contributing

Contributions, bug reports, and improvements are welcome — open an issue or a PR.

## License

MIT License — see LICENSE or add one if desired.

## Contact

For questions, leave an issue in the repository.
