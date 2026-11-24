# Custom Apache Log Analyzer

A lightweight, streaming Python CLI tool for parsing and analyzing custom Apache access logs. Built to quickly diagnose server load spikes, identify aggressive crawlers, and detect common WordPress security threats.

## Features

- **Custom Log Parsing:** Extracts virtual host, client IP, timestamp, HTTP method/path, status code, response size, and User-Agent using compiled regular expressions.
- **Memory-Efficient Streaming:** Processes log files line-by-line, allowing fast analysis of large files with minimal RAM footprint.
- **Traffic Overview:** Displays the Top *N* most active IP addresses, most requested paths, and HTTP status code distribution.
- **Security & Threat Detection:**
  - Flags WordPress brute-force and XML-RPC amplification attempts (`/wp-login.php`, `/xmlrpc.php`).
  - Detects vulnerability probes targeting sensitive files (`/.env`, `/.git`, `/wp-config.php`, `/phpmyadmin`).
- **Categorized Bot & Crawler Analysis:** Classifies traffic into Search Engines, SEO Crawlers, AI Scrapers, Security Scanners, and Generic Scripts.

## Project Structure

```text
log_analyzer/
├── analyzer.py     # Main CLI entry point, aggregation logic, and report formatting
├── parser.py       # Regex-based Apache log line parser
├── config.py       # Security rules, sensitive paths, and categorized bot signatures
└── README.md       # Project documentation
```
## Requirements & Installation

Requires **Python 3.10+** (uses only the Python Standard Library — no external dependencies or `pip install` required).

```bash
git clone https://github.com/BranislavAdamove/log_analyzer.git
cd log_analyzer
```

## Usage

```bash
# Run standard analysis (displays Top 5 IPs and paths by default)
python3 analyzer.py sample.log

# Customize the number of displayed top items
python3 analyzer.py sample.log --top 10

# Filter output to show only security threats and bot activity
python3 analyzer.py sample.log --security-only

# Display CLI help and available options
python3 analyzer.py --help
```

## Example Output

```text
=============================================
     APACHE LOG ANALYSIS     
=============================================
Parsed lines: 50/50
---------------------------------------------

[TOP 5 IP]
    185.220.101.42     -> 8 requests
    45.134.26.89       -> 6 requests
    54.36.148.112      -> 4 requests
    47.128.45.210      -> 4 requests
    172.70.230.50      -> 4 requests

[TOP 5 PATHS]
    /wp-login.php      -> 10x
    /                  -> 5x
    /kontakt/          -> 2x
    /xmlrpc.php        -> 2x
    /wp-content/themes/astra/assets/css/minified/main.min.css -> 1x

[HTTP STATUSES]
    200                -> 35x
    403                -> 2x
    404                -> 7x
    503                -> 1x
    509                -> 5x
=============================================

[SECURITY AND BOT REPORT]

Brute-force attempts:
    IP:185.220.101.42   | Path:/wp-login.php         ->6x
    IP:172.70.230.50    | Path:/wp-login.php         ->4x
    IP:185.220.101.42   | Path:/xmlrpc.php           ->2x

Sensitive file scans:
    IP:45.134.26.89     | Path:/.env                 ->1x
    IP:45.134.26.89     | Path:/.git/config          ->1x
    IP:91.121.88.204    | Path:/wp-config.php        ->1x

Detected bots and crawlers:
    [Generic Script]     python-requests           -> 6x
    [SEO Crawler]        ahrefsbot                 -> 4x
    [AI Scraper]         bytespider                -> 4x
    [Search Engine]      googlebot                 -> 3x
    [Security/Scanner]   wpscan                    -> 3x
```