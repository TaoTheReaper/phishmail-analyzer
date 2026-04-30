#!/usr/bin/env python3
"""
phishmail-analyzer — Phishing Email Analysis Tool
Analyzes .eml files for suspicious headers, URLs, attachments and IOCs.
"""

import argparse
import email
import hashlib
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from email import policy
from pathlib import Path
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("[!] Missing: pip install requests")
    sys.exit(1)

log = logging.getLogger("phishmail")

# ---------- constants ----------
VT_API_URL  = "https://www.virustotal.com/api/v3"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"

SPF_PASS_RE  = re.compile(r"spf=pass",  re.I)
DKIM_PASS_RE = re.compile(r"dkim=pass", re.I)
DMARC_PASS_RE = re.compile(r"dmarc=pass", re.I)

URL_RE = re.compile(
    r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+",
    re.I
)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

SUSPICIOUS_KEYWORDS = [
    "verify your account", "confirm your identity", "unusual activity",
    "your account will be suspended", "click here to login",
    "update your payment", "urgent action required", "limited time offer",
    "won a prize", "dear customer", "dear user",
]

# ---------- setup ----------
def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler(sys.stderr)],
    )

# ---------- parsing ----------
def parse_eml(path: Path) -> email.message.EmailMessage:
    raw = path.read_bytes()
    return email.message_from_bytes(raw, policy=policy.default)

def extract_headers(msg) -> dict:
    headers = {}
    headers["from"]       = msg.get("From", "")
    headers["to"]         = msg.get("To", "")
    headers["reply_to"]   = msg.get("Reply-To", "")
    headers["subject"]    = msg.get("Subject", "")
    headers["date"]       = msg.get("Date", "")
    headers["message_id"] = msg.get("Message-ID", "")
    headers["x_mailer"]   = msg.get("X-Mailer", "")
    headers["received"]   = msg.get_all("Received", [])

    # Auth results
    auth_results = msg.get("Authentication-Results", "")
    headers["spf"]   = "pass" if SPF_PASS_RE.search(auth_results)  else "fail/missing"
    headers["dkim"]  = "pass" if DKIM_PASS_RE.search(auth_results) else "fail/missing"
    headers["dmarc"] = "pass" if DMARC_PASS_RE.search(auth_results) else "fail/missing"
    headers["auth_results_raw"] = auth_results

    # Received chain — extract IPs
    received_ips = []
    for r in headers["received"]:
        received_ips.extend(IP_RE.findall(r))
    headers["received_ips"] = list(dict.fromkeys(received_ips))

    return headers

def extract_body(msg) -> str:
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct in ("text/plain", "text/html"):
                try:
                    body += part.get_content() or ""
                except Exception:
                    pass
    else:
        try:
            body = msg.get_content() or ""
        except Exception:
            pass
    return body

def extract_urls(body: str) -> list[str]:
    return sorted(set(URL_RE.findall(body)))

def extract_attachments(msg) -> list[dict]:
    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            filename = part.get_filename() or "unknown"
            payload  = part.get_payload(decode=True) or b""
            md5    = hashlib.md5(payload).hexdigest()
            sha256 = hashlib.sha256(payload).hexdigest()
            attachments.append({
                "filename": filename,
                "content_type": part.get_content_type(),
                "size_bytes": len(payload),
                "md5": md5,
                "sha256": sha256,
            })
    return attachments

def extract_iocs(headers: dict, urls: list[str], body: str) -> dict:
    iocs: dict = {"ips": [], "domains": [], "urls": [], "emails": []}

    # IPs from received chain
    iocs["ips"] = headers.get("received_ips", [])

    # Domains and URLs
    for url in urls:
        iocs["urls"].append(url)
        try:
            domain = urlparse(url).hostname or ""
            if domain and domain not in iocs["domains"]:
                iocs["domains"].append(domain)
        except Exception:
            pass

    # Emails in body
    email_re = re.compile(r"\b[A-Za-z0-9_.+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}\b")
    iocs["emails"] = sorted(set(email_re.findall(body)))

    return iocs

# ---------- threat intel ----------
def check_virustotal_url(url: str, api_key: str) -> dict:
    headers = {"x-apikey": api_key}
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        resp = requests.get(f"{VT_API_URL}/urls/{url_id}", headers=headers, timeout=10)
        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)}
        return {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def check_virustotal_hash(sha256: str, api_key: str) -> dict:
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(f"{VT_API_URL}/files/{sha256}", headers=headers, timeout=10)
        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)}
        elif resp.status_code == 404:
            return {"note": "not found in VT"}
        return {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def check_urlhaus(url: str) -> dict:
    try:
        resp = requests.post(URLHAUS_URL, data={"url": url}, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return {"query_status": data.get("query_status"), "threat": data.get("threat")}
        return {"error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}

# ---------- scoring ----------
def calculate_risk(headers: dict, urls: list, attachments: list, body: str, vt_results: dict) -> dict:
    score = 0
    flags = []

    # Auth checks
    if headers["spf"] != "pass":
        score += 20
        flags.append("SPF failed or missing")
    if headers["dkim"] != "pass":
        score += 20
        flags.append("DKIM failed or missing")
    if headers["dmarc"] != "pass":
        score += 15
        flags.append("DMARC failed or missing")

    # Reply-To mismatch
    from_addr  = re.search(r"@([\w.-]+)", headers.get("from", ""))
    reply_addr = re.search(r"@([\w.-]+)", headers.get("reply_to", ""))
    if from_addr and reply_addr and from_addr.group(1) != reply_addr.group(1):
        score += 15
        flags.append(f"Reply-To domain mismatch: {from_addr.group(1)} vs {reply_addr.group(1)}")

    # URLs
    if len(urls) > 5:
        score += 10
        flags.append(f"High URL count: {len(urls)}")

    # Attachments
    dangerous_exts = {".exe", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".zip", ".iso", ".docm", ".xlsm"}
    for att in attachments:
        ext = Path(att["filename"]).suffix.lower()
        if ext in dangerous_exts:
            score += 25
            flags.append(f"Dangerous attachment: {att['filename']}")

    # Suspicious keywords
    body_lower = body.lower()
    found_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in body_lower]
    if found_kw:
        score += min(len(found_kw) * 5, 20)
        flags.append(f"Suspicious keywords: {', '.join(found_kw[:3])}")

    # VirusTotal hits
    for url, result in vt_results.items():
        if isinstance(result, dict) and result.get("malicious", 0) > 0:
            score += 30
            flags.append(f"VT malicious URL: {url} ({result['malicious']} engines)")

    # Risk level
    if score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {"score": min(score, 100), "level": level, "flags": flags}

# ---------- reporting ----------
def build_report(eml_path: Path, headers: dict, urls: list, attachments: list,
                 body: str, iocs: dict, vt_results: dict, risk: dict) -> dict:
    return {
        "file": str(eml_path),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "risk": risk,
        "headers": headers,
        "urls": urls,
        "attachments": attachments,
        "iocs": iocs,
        "virustotal": vt_results,
    }

def print_report(report: dict):
    r = report["risk"]
    colors = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[92m"}
    reset = "\033[0m"
    color = colors.get(r["level"], reset)

    print("\n\033[96m" + "=" * 60)
    print(f" PHISHMAIL ANALYZER — {report['file']}")
    print("=" * 60 + reset)

    print(f"\n\033[1mRisk: {color}{r['level']} ({r['score']}/100){reset}")
    for flag in r["flags"]:
        print(f"  \033[91m[!] {flag}{reset}")

    h = report["headers"]
    print("\n\033[92mHeaders\033[0m")
    print(f"  From     : {h['from']}")
    print(f"  Reply-To : {h['reply_to'] or '(none)'}")
    print(f"  Subject  : {h['subject']}")
    print(f"  SPF      : {h['spf']}  |  DKIM: {h['dkim']}  |  DMARC: {h['dmarc']}")
    print(f"  Received IPs: {', '.join(h['received_ips']) or '(none)'}")

    print(f"\n\033[92mURLs ({len(report['urls'])})\033[0m")
    for url in report["urls"][:10]:
        vt = report["virustotal"].get(url, {})
        vt_str = f"  [VT: {vt.get('malicious',0)} malicious]" if "malicious" in vt else ""
        print(f"  {url}{vt_str}")

    print(f"\n\033[92mAttachments ({len(report['attachments'])})\033[0m")
    for att in report["attachments"]:
        print(f"  {att['filename']} ({att['size_bytes']} bytes)")
        print(f"    SHA256: {att['sha256']}")

    print(f"\n\033[92mIOCs\033[0m")
    print(f"  IPs     : {', '.join(report['iocs']['ips']) or '(none)'}")
    print(f"  Domains : {', '.join(report['iocs']['domains'][:5]) or '(none)'}")
    print(f"  Emails  : {', '.join(report['iocs']['emails'][:5]) or '(none)'}")

    print("\n\033[96m" + "=" * 60 + reset + "\n")

# ---------- main ----------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phishmail",
        description="Phishing email analyzer — headers, URLs, attachments, IOCs, risk score.",
        epilog=(
            "Examples:\n"
            "  python phishmail.py sample.eml\n"
            "  python phishmail.py sample.eml --vt-key YOUR_API_KEY -o report.json\n"
            "  python phishmail.py sample.eml --no-urlhaus -v"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("eml",         help="Path to .eml file")
    p.add_argument("--vt-key",    metavar="KEY", default=os.environ.get("VT_API_KEY"),
                   help="VirusTotal API key (or set VT_API_KEY env var)")
    p.add_argument("--no-urlhaus", action="store_true", help="Skip URLhaus checks")
    p.add_argument("-o", "--output", metavar="FILE", help="Save JSON report to FILE")
    p.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    setup_logging(args.verbose)

    eml_path = Path(args.eml)
    if not eml_path.exists():
        print(f"[!] File not found: {eml_path}")
        sys.exit(1)

    log.info("Parsing %s", eml_path)
    msg         = parse_eml(eml_path)
    headers     = extract_headers(msg)
    body        = extract_body(msg)
    urls        = extract_urls(body)
    attachments = extract_attachments(msg)
    iocs        = extract_iocs(headers, urls, body)

    # Threat intel
    vt_results: dict = {}
    if args.vt_key:
        log.info("Checking %d URLs on VirusTotal...", len(urls[:5]))
        for url in urls[:5]:  # free tier: 4 req/min
            vt_results[url] = check_virustotal_url(url, args.vt_key)
        for att in attachments:
            vt_results[att["sha256"]] = check_virustotal_hash(att["sha256"], args.vt_key)
    else:
        log.info("No VT API key — skipping VirusTotal checks (use --vt-key or VT_API_KEY env var)")

    if not args.no_urlhaus:
        log.info("Checking URLs on URLhaus...")
        for url in urls[:10]:
            result = check_urlhaus(url)
            if result.get("query_status") == "is_host":
                vt_results[f"urlhaus:{url}"] = result

    risk   = calculate_risk(headers, urls, attachments, body, vt_results)
    report = build_report(eml_path, headers, urls, attachments, body, iocs, vt_results, risk)

    print_report(report)

    if args.output:
        tmp = args.output + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        os.replace(tmp, args.output)
        print(f"[+] Report saved: {args.output}")
        log.info("Report saved to %s", args.output)


if __name__ == "__main__":
    main()
