# Network Audit Probe

## Overview

This project is a web-based network audit application developed in Python using Flask. Users interact exclusively through a user-friendly web interface, which orchestrates underlying scanning and analysis scripts in the background.

## How It Works

* Users access the Flask web interface to launch scans, view results, browse history, explore network mapping, and more.
* The UI allows selection of scan types, IP ranges, and additional parameters.
* The web app coordinates the scanning scripts, aggregates and enriches data (such as device roles and vulnerabilities), then stores everything in a SQLite database.
* Results are presented in the interface with powerful search, mapping, and export features.

## Project Structure

* `app.py` — Main entry point, Flask server, web routes, and orchestration logic
* `scan_ia.py`, `scan.py`, `scan_passif.py`, `scanV2.py` — Network scanning scripts, called by `app.py` only
* `ai_local.py` — Local classification of device roles
* `BD/scan_db.py`, `BD/packet_db.py` — SQLite database management
* `templates/` — Jinja2 HTML templates for the UI
* `static/` — Static assets (icons, CSS, JS)
* `requirements.txt` — Python dependencies
* `rules.json` — Categorization rules

## Installation

### Prerequisites

* Python 3.8 or higher
* Nmap installed (`sudo apt install nmap` or `brew install nmap`)
* MongoDB (optional, for local CVE database)

### Python Dependencies

```bash
pip install -r requirements.txt
```

### Vulners API Key (Optional)

To enable online vulnerability detection:

```bash
export VULNERS_API_KEY="your_api_key_here"
```

Add this to your shell configuration (`~/.zshrc`, `~/.bashrc`, etc.).

## Usage

1. Start the web application:

```bash
python3 app.py
```

2. Open your browser and go to:

```
http://localhost:5000
```

3. Use the interface to launch scans, review results, explore history, and visualize network maps.

**Notes:**

* Scanning scripts should never be run manually; interaction is exclusively via the web UI.
* Scan results are stored in a SQLite database and accessible through the interface.

## Data Storage

* JSON files (auto-generated)
* SQLite database for scan and service history
* MongoDB for local CVE data (optional)

## Security

* Flask secret key configured in `app.py`
* Vulners API key stored securely in environment variables (never in code)
* UTF-8 JSON encoding with robust error handling

## Future Enhancements

* CVE severity level filters
* Admin authentication and access control
* CSV and PDF export options
* Advanced passive scanning
* Anomaly detection and behavioral analysis

## Authors

Open source project — contributions welcome!


