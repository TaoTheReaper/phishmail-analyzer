# phishmail-analyzer

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python)
![VirusTotal](https://img.shields.io/badge/VirusTotal-API-blue?style=for-the-badge)
![URLhaus](https://img.shields.io/badge/URLhaus-Intel-orange?style=for-the-badge)

## Overview

Python tool that analyzes `.eml` phishing emails and produces a structured risk report. Covers header analysis, URL/attachment extraction, IOC identification, and optional threat intel enrichment via VirusTotal and URLhaus.

## Why this project

Phishing analysis represents ~30% of SOC L1 daily work. This tool demonstrates Python development, email forensics, threat intelligence API integration, and structured IOC extraction — core skills for any SOC analyst role.

## Features

- **Header analysis** — SPF, DKIM, DMARC validation; Reply-To mismatch detection; Received chain parsing
- **URL extraction** — regex-based, deduped, checked against VirusTotal + URLhaus
- **Attachment analysis** — MD5/SHA256 hashing, dangerous extension detection, VirusTotal hash lookup
- **IOC extraction** — IPs, domains, email addresses
- **Risk scoring** — 0-100 score with LOW/MEDIUM/HIGH level and human-readable flags
- **Output** — colored terminal report + optional JSON export

## Setup

```bash
git clone https://github.com/TaoTheReaper/phishmail-analyzer
cd phishmail-analyzer
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# Basic analysis
python3 phishmail.py sample.eml

# With VirusTotal enrichment
python3 phishmail.py sample.eml --vt-key YOUR_FREE_VT_API_KEY

# Save JSON report
python3 phishmail.py sample.eml --vt-key $VT_API_KEY -o report.json

# All options
python3 phishmail.py --help
```

## Output Example

```
============================================================
 PHISHMAIL ANALYZER — sample.eml
============================================================

Risk: HIGH (85/100)
  [!] SPF failed or missing
  [!] DKIM failed or missing
  [!] Reply-To domain mismatch: paypal.com vs attacker-domain.ru
  [!] Dangerous attachment: invoice.exe
  [!] VT malicious URL: http://evil.example.com (12 engines)

Headers
  From     : PayPal Security <security@paypal.com.attacker-domain.ru>
  Reply-To : reply@attacker-domain.ru
  SPF      : fail/missing  |  DKIM: fail/missing  |  DMARC: fail/missing

URLs (3)
  http://evil.example.com/steal  [VT: 12 malicious]
  ...
```

## Architecture

```
phishmail.py
├── parse_eml()          — email.message parsing
├── extract_headers()    — SPF/DKIM/DMARC + received chain
├── extract_body()       — text/html body extraction
├── extract_urls()       — URL regex from body
├── extract_attachments()— hash + metadata per attachment
├── extract_iocs()       — IPs, domains, emails
├── check_virustotal_*() — VT API v3
├── check_urlhaus()      — URLhaus abuse.ch API
├── calculate_risk()     — weighted scoring engine
└── print_report()       — colored terminal output
```

## Lessons Learned

- SPF/DKIM/DMARC alone don't guarantee legitimacy — header spoofing is trivial on misconfigured domains
- Reply-To mismatch is one of the most reliable phishing indicators
- VirusTotal free tier limits to 4 requests/minute — rate limiting matters in production
- email.policy.default is required for proper Python 3 email parsing (legacy policy breaks unicode)

## References

- [VirusTotal API v3](https://developers.virustotal.com/reference/overview)
- [URLhaus API](https://urlhaus-api.abuse.ch/)
- [RFC 7208 — SPF](https://datatracker.ietf.org/doc/html/rfc7208)
- [MITRE T1566 — Phishing](https://attack.mitre.org/techniques/T1566/)
