from typing import Optional
"""
AutoVuln - Automated Vulnerability Scanner
Author: Nithilaa Karthikeyan
Description: Scans target hosts for open ports, fingerprints services,
             matches against a CVE database, and generates structured reports.
"""

import socket
import json
import argparse
import datetime
import subprocess
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

CVE_DATABASE = {
    21: [
        {"cve": "CVE-2011-2523", "severity": "HIGH", "service": "FTP (vsftpd 2.3.4)",
         "description": "Backdoor command execution via smiley face username"},
        {"cve": "CVE-2015-3306", "severity": "HIGH", "service": "FTP (ProFTPD 1.3.5)",
         "description": "Unauthenticated arbitrary file copy via mod_copy module"},
    ],
    22: [
        {"cve": "CVE-2018-15473", "severity": "MEDIUM", "service": "SSH (OpenSSH)",
         "description": "Username enumeration via timing attack on authentication"},
        {"cve": "CVE-2023-38408", "severity": "CRITICAL", "service": "SSH (OpenSSH < 9.3p2)",
         "description": "Remote code execution via ssh-agent forwarding"},
    ],
    23: [
        {"cve": "CVE-2020-10188", "severity": "CRITICAL", "service": "Telnet",
         "description": "Remote code execution via telnetd utility overflow"},
    ],
    25: [
        {"cve": "CVE-2020-7247", "severity": "CRITICAL", "service": "SMTP (OpenSMTPD)",
         "description": "Remote code execution via malformed sender address"},
    ],
    80: [
        {"cve": "CVE-2021-41773", "severity": "CRITICAL", "service": "HTTP (Apache 2.4.49)",
         "description": "Path traversal and remote code execution"},
        {"cve": "CVE-2022-22965", "severity": "CRITICAL", "service": "HTTP (Spring Framework)",
         "description": "Spring4Shell — RCE via data binding on JDK 9+"},
    ],
    443: [
        {"cve": "CVE-2014-0160", "severity": "HIGH", "service": "HTTPS (OpenSSL)",
         "description": "Heartbleed — memory disclosure via TLS heartbeat extension"},
        {"cve": "CVE-2022-0778", "severity": "HIGH", "service": "HTTPS (OpenSSL < 1.0.2zd)",
         "description": "Infinite loop via crafted certificate, causing denial of service"},
    ],
    445: [
        {"cve": "CVE-2017-0144", "severity": "CRITICAL", "service": "SMB (EternalBlue)",
         "description": "Remote code execution via SMBv1 — used in WannaCry ransomware"},
        {"cve": "CVE-2020-0796", "severity": "CRITICAL", "service": "SMB (SMBGhost)",
         "description": "Remote code execution via SMBv3 compression bug"},
    ],
    3306: [
        {"cve": "CVE-2016-6662", "severity": "CRITICAL", "service": "MySQL",
         "description": "Remote code execution via malicious config file injection"},
    ],
    3389: [
        {"cve": "CVE-2019-0708", "severity": "CRITICAL", "service": "RDP (BlueKeep)",
         "description": "Unauthenticated RCE via Remote Desktop Services — pre-auth wormable"},
        {"cve": "CVE-2021-34535", "severity": "CRITICAL", "service": "RDP",
         "description": "Remote code execution via Remote Desktop client vulnerability"},
    ],
    5432: [
        {"cve": "CVE-2019-9193", "severity": "HIGH", "service": "PostgreSQL",
         "description": "Arbitrary code execution via COPY TO/FROM PROGRAM"},
    ],
    6379: [
        {"cve": "CVE-2022-0543", "severity": "CRITICAL", "service": "Redis",
         "description": "Sandbox escape via Lua scripting engine on Debian/Ubuntu"},
    ],
    8080: [
        {"cve": "CVE-2021-44228", "severity": "CRITICAL", "service": "HTTP Alt (Log4Shell)",
         "description": "Log4j2 JNDI injection — unauthenticated RCE on Java apps"},
    ],
    8443: [
        {"cve": "CVE-2021-44228", "severity": "CRITICAL", "service": "HTTPS Alt (Log4Shell)",
         "description": "Log4j2 JNDI injection — unauthenticated RCE on Java apps"},
    ],
    27017: [
        {"cve": "CVE-2013-3969", "severity": "HIGH", "service": "MongoDB",
         "description": "Denial of service via crafted GeoJSON object in geospatial query"},
    ],
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",  #r
    "HIGH":     "\033[93m",  # y
    "MEDIUM":   "\033[94m",  # b
    "LOW":      "\033[92m",  # g
    "INFO":     "\033[97m",  # w
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def scan_port(host: str, port: int, timeout: float = 1.0) -> Optional[dict]:
    """Attempt TCP connection to host:port. Returns result dict or None."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = ""
            try:
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            except Exception:
                pass
            return {"port": port, "state": "open", "banner": banner}
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def scan_ports(host: str, ports: list[int], threads: int = 50) -> list[dict]:
    """Scan multiple ports concurrently. Returns list of open port results."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, host, p): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    return sorted(open_ports, key=lambda x: x["port"])

def match_cves(open_ports: list[dict]) -> list[dict]:
    """Match open ports against CVE database. Returns enriched vulnerability list."""
    findings = []
    for port_info in open_ports:
        port = port_info["port"]
        if port in CVE_DATABASE:
            for cve in CVE_DATABASE[port]:
                findings.append({
                    **cve,
                    "port": port,
                    "banner": port_info.get("banner", ""),
                })
    return sorted(findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))


def resolve_host(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return "unresolved"


def generate_html_report(target: str, ip: str, open_ports: list[dict],
                          findings: list[dict], scan_time: str) -> str:
    severity_counts = {}
    for f in findings:
        s = f["severity"]
        severity_counts[s] = severity_counts.get(s, 0) + 1

    badge_colors = {
        "CRITICAL": "#e74c3c", "HIGH": "#e67e22",
        "MEDIUM": "#3498db", "LOW": "#2ecc71", "INFO": "#95a5a6"
    }

    findings_html = ""
    for f in findings:
        color = badge_colors.get(f["severity"], "#95a5a6")
        findings_html += f"""
        <div class="finding">
            <div class="finding-header">
                <span class="cve-id">{f['cve']}</span>
                <span class="badge" style="background:{color}">{f['severity']}</span>
                <span class="port-tag">Port {f['port']}</span>
            </div>
            <div class="service">{f['service']}</div>
            <div class="desc">{f['description']}</div>
            {"<div class='banner'>Banner: <code>" + f['banner'] + "</code></div>" if f['banner'] else ""}
        </div>"""

    ports_html = "".join(
        f"<span class='port-chip'>:{p['port']}</span>" for p in open_ports
    )

    summary_html = "".join(
        f"<div class='stat'><span class='stat-num' style='color:{badge_colors[s]}'>{c}</span>"
        f"<span class='stat-label'>{s}</span></div>"
        for s, c in sorted(severity_counts.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 99))
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AutoVuln Report — {target}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }}
  .header {{ background: linear-gradient(135deg, #161b22, #1f2937); padding: 40px; border-bottom: 1px solid #30363d; }}
  .header h1 {{ font-size: 28px; color: #58a6ff; font-weight: 700; letter-spacing: -0.5px; }}
  .header h1 span {{ color: #f0883e; }}
  .meta {{ margin-top: 12px; font-size: 13px; color: #8b949e; display: flex; gap: 24px; flex-wrap: wrap; }}
  .meta strong {{ color: #c9d1d9; }}
  .container {{ max-width: 960px; margin: 0 auto; padding: 32px 24px; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 16px; margin-bottom: 32px; }}
  .stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; text-align: center; }}
  .stat-num {{ display: block; font-size: 36px; font-weight: 700; }}
  .stat-label {{ display: block; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: #8b949e; margin-top: 4px; }}
  .section-title {{ font-size: 16px; font-weight: 600; color: #58a6ff; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid #21262d; }}
  .port-chip {{ display: inline-block; background: #21262d; border: 1px solid #30363d; color: #79c0ff; border-radius: 4px; padding: 2px 10px; font-size: 13px; margin: 4px; font-family: monospace; }}
  .ports-section {{ margin-bottom: 32px; }}
  .finding {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 16px; transition: border-color 0.2s; }}
  .finding:hover {{ border-color: #58a6ff; }}
  .finding-header {{ display: flex; align-items: center; gap: 12px; margin-bottom: 8px; flex-wrap: wrap; }}
  .cve-id {{ font-family: monospace; font-size: 15px; font-weight: 700; color: #f0883e; }}
  .badge {{ font-size: 11px; font-weight: 700; padding: 2px 10px; border-radius: 12px; color: white; text-transform: uppercase; letter-spacing: 0.5px; }}
  .port-tag {{ font-size: 12px; color: #8b949e; background: #21262d; padding: 2px 8px; border-radius: 4px; font-family: monospace; }}
  .service {{ font-size: 13px; color: #8b949e; margin-bottom: 6px; }}
  .desc {{ font-size: 14px; color: #c9d1d9; }}
  .banner {{ margin-top: 10px; font-size: 12px; color: #8b949e; }}
  .banner code {{ background: #0d1117; padding: 2px 6px; border-radius: 3px; color: #79c0ff; }}
  .no-findings {{ text-align: center; padding: 60px; color: #8b949e; font-size: 16px; }}
  .footer {{ text-align: center; padding: 32px; font-size: 12px; color: #484f58; border-top: 1px solid #21262d; margin-top: 32px; }}
</style>
</head>
<body>
<div class="header">
  <div style="max-width:960px;margin:0 auto">
    <h1>Auto<span>Vuln</span> Scan Report</h1>
    <div class="meta">
      <span><strong>Target:</strong> {target}</span>
      <span><strong>IP:</strong> {ip}</span>
      <span><strong>Scan Time:</strong> {scan_time}</span>
      <span><strong>Open Ports:</strong> {len(open_ports)}</span>
      <span><strong>Findings:</strong> {len(findings)}</span>
    </div>
  </div>
</div>
<div class="container">
  <div class="summary-grid">{summary_html if summary_html else '<div class="stat"><span class="stat-num" style="color:#2ecc71">0</span><span class="stat-label">Findings</span></div>'}</div>
  <div class="ports-section">
    <div class="section-title">Open Ports ({len(open_ports)})</div>
    {ports_html if ports_html else '<span style="color:#8b949e">No open ports detected</span>'}
  </div>
  <div class="section-title">Vulnerability Findings ({len(findings)})</div>
  {findings_html if findings_html else '<div class="no-findings">✓ No known CVEs matched for open ports</div>'}
</div>
<div class="footer">AutoVuln — Built by Nithilaa Karthikeyan &nbsp;|&nbsp; {scan_time}</div>
</body>
</html>"""


def generate_json_report(target: str, ip: str, open_ports: list[dict],
                          findings: list[dict], scan_time: str) -> dict:
    return {
        "autovuln_report": {
            "target": target,
            "resolved_ip": ip,
            "scan_timestamp": scan_time,
            "summary": {
                "open_ports": len(open_ports),
                "total_findings": len(findings),
                "by_severity": {
                    s: sum(1 for f in findings if f["severity"] == s)
                    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
                }
            },
            "open_ports": open_ports,
            "findings": findings
        }
    }


def print_banner():
    print(f"""
{BOLD}\033[94m
  ╔═══════════════════════════════════════╗
  ║         A U T O V U L N              ║
  ║   Automated Vulnerability Scanner    ║
  ║   github.com/nithikarthikeyan        ║
  ╚═══════════════════════════════════════╝
{RESET}""")


def print_results(target: str, ip: str, open_ports: list[dict], findings: list[dict]):
    print(f"\n{BOLD}Target:{RESET}  {target} ({ip})")
    print(f"{BOLD}Ports Scanned:{RESET}  {len(open_ports)} open\n")

    if open_ports:
        print(f"{BOLD}── Open Ports ──────────────────────────{RESET}")
        for p in open_ports:
            banner = f"  └─ {p['banner'][:60]}" if p['banner'] else ""
            print(f"  {BOLD}\033[92m:{p['port']}{RESET}{banner}")

    print(f"\n{BOLD}── Vulnerability Findings ──────────────{RESET}")
    if not findings:
        print(f"  {BOLD}\033[92m✓ No known CVEs matched{RESET}")
        return

    for f in findings:
        color = SEVERITY_COLORS.get(f["severity"], RESET)
        print(f"\n  {color}{BOLD}[{f['severity']}]{RESET}  {BOLD}{f['cve']}{RESET}  (Port {f['port']})")
        print(f"  Service: {f['service']}")
        print(f"  {f['description']}")

def main():
    parser = argparse.ArgumentParser(
        description="AutoVuln — Automated Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scanner.py --target scanme.nmap.org
  python3 scanner.py --target 192.168.1.1 --ports 22 80 443 3306
  python3 scanner.py --target example.com --full --output report
        """
    )
    parser.add_argument("--target", required=True, help="Target hostname or IP address")
    parser.add_argument("--ports", nargs="+", type=int, help="Specific ports to scan")
    parser.add_argument("--full", action="store_true", help="Scan all ports in CVE database")
    parser.add_argument("--threads", type=int, default=50, help="Concurrent scan threads (default: 50)")
    parser.add_argument("--output", type=str, help="Output file prefix (generates .html and .json)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Connection timeout in seconds")
    args = parser.parse_args()

    print_banner()

    if args.ports:
        ports = args.ports
    elif args.full:
        ports = list(CVE_DATABASE.keys()) + list(range(1, 1025))
        ports = sorted(set(ports))
    else:
        ports = sorted(CVE_DATABASE.keys())

    print(f"  Scanning {args.target} on {len(ports)} ports...")
    print(f"  Threads: {args.threads}  |  Timeout: {args.timeout}s\n")

    ip = resolve_host(args.target)
    scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    open_ports = scan_ports(args.target, ports, threads=args.threads)
    findings = match_cves(open_ports)

    print_results(args.target, ip, open_ports, findings)

    if args.output:
        html = generate_html_report(args.target, ip, open_ports, findings, scan_time)
        json_report = generate_json_report(args.target, ip, open_ports, findings, scan_time)

        html_path = f"{args.output}.html"
        json_path = f"{args.output}.json"

        with open(html_path, "w") as f:
            f.write(html)
        with open(json_path, "w") as f:
            json.dump(json_report, f, indent=2)

        print(f"\n{BOLD}── Reports Saved ───────────────────────{RESET}")
        print(f"  HTML: {html_path}")
        print(f"  JSON: {json_path}")

    print(f"\n{BOLD}\033[92m  Scan complete.{RESET}\n")


if __name__ == "__main__":
    main()
