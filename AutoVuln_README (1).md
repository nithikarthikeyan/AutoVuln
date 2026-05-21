# AutoVuln — Automated Vulnerability Scanner

A lightweight, fast vulnerability scanner built in Python and Bash. AutoVuln performs concurrent TCP port scanning, fingerprints open services, matches findings against a curated CVE database, and generates structured HTML and JSON reports.

---

## Features

- **Concurrent port scanning** via Python ThreadPoolExecutor (50 threads default)
- **CVE matching** against 20+ high-profile vulnerabilities across common services
- **Severity classification** — CRITICAL / HIGH / MEDIUM / LOW
- **Dual report output** — interactive HTML dashboard + machine-readable JSON
- **Bash wrapper** with pre-flight checks, logging, and auto-report naming
- **Banner grabbing** for service fingerprinting
- **Zero dependencies** — pure Python standard library

---

## Usage

```bash
# Quick scan (CVE-tracked ports only)
./autovuln.sh scanme.nmap.org

# Full scan with saved report
./autovuln.sh 192.168.1.1 --full --output reports/host_scan

# Targeted port scan
./autovuln.sh example.com --ports 22 80 443 3306 8080

# Python directly
python3 scanner.py --target scanme.nmap.org --full --output my_report
```

---

## Output

### HTML Report
Interactive dark-themed dashboard showing:
- Severity summary (CRITICAL / HIGH / MEDIUM / LOW counts)
- All open ports with banner info
- Full CVE findings with descriptions

### JSON Report
```json
{
  "autovuln_report": {
    "target": "scanme.nmap.org",
    "resolved_ip": "45.33.32.156",
    "scan_timestamp": "2026-06-15 14:32:01",
    "summary": {
      "open_ports": 4,
      "total_findings": 3,
      "by_severity": { "CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 0 }
    },
    "open_ports": [...],
    "findings": [...]
  }
}
```

---

## CVE Coverage

| Port | Service | Example CVEs |
|------|---------|-------------|
| 22 | SSH | CVE-2023-38408 (RCE), CVE-2018-15473 (enum) |
| 80/443 | HTTP/S | CVE-2021-41773 (Apache), Log4Shell, Heartbleed |
| 445 | SMB | EternalBlue (CVE-2017-0144), SMBGhost |
| 3389 | RDP | BlueKeep (CVE-2019-0708) |
| 6379 | Redis | CVE-2022-0543 (sandbox escape) |
| 8080/8443 | HTTP Alt | Log4Shell (CVE-2021-44228) |
| + more | MySQL, PostgreSQL, MongoDB, FTP, Telnet, SMTP | |

---

## Ethical Use

This tool is intended for use on systems **you own or have explicit written permission to test**. Unauthorized scanning is illegal under the Computer Fraud and Abuse Act (CFAA) and equivalent laws globally.

---

## Tech Stack

- **Python 3.8+** — scanner, CVE matching, report generation
- **Bash** — launcher, pre-flight checks, logging
- Standard library only (`socket`, `concurrent.futures`, `json`, `argparse`)

---

## Author

**Nithilaa Karthikeyan**  
Virginia Tech — B.S. Business Information Technology, Cybersecurity Management & Analytics  
[nithikarthikeyan@vt.edu](mailto:nithikarthikeyan@vt.edu)
