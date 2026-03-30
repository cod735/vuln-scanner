from datetime import datetime

# MITRE ATT&CK mapping — finding type → technique
MITRE_MAPPINGS = {

    # Open ports / services
    "port_22":  {
        "technique_id":   "T1021.004",
        "technique_name": "Remote Services: SSH",
        "tactic":         "Lateral Movement",
        "description":    "SSH port open — attackers use SSH for remote access and lateral movement",
    },
    "port_23":  {
        "technique_id":   "T1021.004",
        "technique_name": "Remote Services: Telnet",
        "tactic":         "Lateral Movement",
        "description":    "Telnet is unencrypted — credentials sent in cleartext",
    },
    "port_3389": {
        "technique_id":   "T1021.001",
        "technique_name": "Remote Services: RDP",
        "tactic":         "Lateral Movement",
        "description":    "RDP exposed — common target for brute force and exploitation",
    },
    "port_445": {
        "technique_id":   "T1021.002",
        "technique_name": "Remote Services: SMB",
        "tactic":         "Lateral Movement",
        "description":    "SMB open — used for file sharing exploitation and lateral movement",
    },
    "port_21": {
        "technique_id":   "T1071.002",
        "technique_name": "Application Layer Protocol: FTP",
        "tactic":         "Command and Control",
        "description":    "FTP is unencrypted — credentials and data sent in cleartext",
    },
    "port_5900": {
        "technique_id":   "T1021.005",
        "technique_name": "Remote Services: VNC",
        "tactic":         "Lateral Movement",
        "description":    "VNC exposed — graphical remote access, often weakly protected",
    },

    # OWASP findings
    "A01": {
        "technique_id":   "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic":         "Discovery",
        "description":    "Broken access control enables unauthorized file and directory access",
    },
    "A02": {
        "technique_id":   "T1040",
        "technique_name": "Network Sniffing",
        "tactic":         "Credential Access",
        "description":    "Weak/no TLS allows interception of credentials and sensitive data",
    },
    "A03": {
        "technique_id":   "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic":         "Initial Access",
        "description":    "Injection vulnerabilities allow exploitation of the application layer",
    },
    "A04": {
        "technique_id":   "T1592",
        "technique_name": "Gather Victim Host Information",
        "tactic":         "Reconnaissance",
        "description":    "Missing security headers reveal information about the target",
    },
    "A05": {
        "technique_id":   "T1082",
        "technique_name": "System Information Discovery",
        "tactic":         "Discovery",
        "description":    "Misconfigured server exposes system and version information",
    },
    "A06": {
        "technique_id":   "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic":         "Initial Access",
        "description":    "Vulnerable components with known CVEs can be directly exploited",
    },
    "A07": {
        "technique_id":   "T1110",
        "technique_name": "Brute Force",
        "tactic":         "Credential Access",
        "description":    "Weak auth mechanisms enable brute force and credential attacks",
    },
    "A08": {
        "technique_id":   "T1195.002",
        "technique_name": "Supply Chain Compromise",
        "tactic":         "Initial Access",
        "description":    "Missing SRI allows compromised CDN scripts to execute on the page",
    },
    "A09": {
        "technique_id":   "T1562.006",
        "technique_name": "Impair Defenses: Indicator Blocking",
        "tactic":         "Defense Evasion",
        "description":    "Poor logging means attacker activity may go undetected",
    },
    "A10": {
        "technique_id":   "T1090",
        "technique_name": "Proxy",
        "tactic":         "Command and Control",
        "description":    "SSRF allows attackers to use the server as a proxy to internal systems",
    },

    # CVE findings
    "cve_critical": {
        "technique_id":   "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic":         "Initial Access",
        "description":    "Critical CVE gives attacker direct exploitation path",
    },
    "cve_high": {
        "technique_id":   "T1203",
        "technique_name": "Exploitation for Client Execution",
        "tactic":         "Execution",
        "description":    "High severity CVE may allow remote code execution",
    },

    # OS / service fingerprinting
    "info_disclosure": {
        "technique_id":   "T1592.002",
        "technique_name": "Gather Victim Host Information: Software",
        "tactic":         "Reconnaissance",
        "description":    "Software version disclosure aids targeted exploitation",
    },
    "open_database": {
        "technique_id":   "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic":         "Initial Access",
        "description":    "Database port exposed to network — direct attack surface",
    },
}

# Database ports
DB_PORTS = [3306, 5432, 27017, 6379, 1433, 5984, 9200, 9300]


def map_port_findings(open_ports: list) -> list:
    """Map open ports to MITRE ATT&CK techniques."""
    mapped = []
    seen   = set()

    for port_info in open_ports:
        port    = port_info.get("port", 0)
        key     = f"port_{port}"
        software = port_info.get("software", "unknown")
        version  = port_info.get("version",  "unknown")

        # Direct port mapping
        if key in MITRE_MAPPINGS and key not in seen:
            entry = dict(MITRE_MAPPINGS[key])
            entry["source"]   = f"Port {port} open ({port_info.get('service', '')})"
            entry["port"]     = port
            entry["evidence"] = f"Port {port}/tcp open"
            mapped.append(entry)
            seen.add(key)

        # Info disclosure from version fingerprinting
        if software != "unknown" and version != "unknown":
            key2 = f"info_{port}"
            if key2 not in seen:
                entry = dict(MITRE_MAPPINGS["info_disclosure"])
                entry["source"]   = f"Service fingerprinting on port {port}"
                entry["port"]     = port
                entry["evidence"] = f"{software} {version} detected"
                mapped.append(entry)
                seen.add(key2)

        # Database exposure
        if port in DB_PORTS:
            key3 = f"db_{port}"
            if key3 not in seen:
                entry = dict(MITRE_MAPPINGS["open_database"])
                entry["source"]   = f"Database port {port} exposed"
                entry["port"]     = port
                entry["evidence"] = f"{port_info.get('service', 'Database')} accessible from network"
                mapped.append(entry)
                seen.add(key3)

    return mapped


def map_owasp_findings(owasp_results: list) -> list:
    """Map OWASP FAIL/WARN results to MITRE ATT&CK techniques."""
    mapped = []

    for result in owasp_results:
        if result["status"] not in ["FAIL", "WARN"]:
            continue

        # Extract OWASP ID from check name (e.g. "A01 — Broken Access Control")
        check_name = result.get("check", "")
        owasp_id   = check_name[:3].strip()

        if owasp_id in MITRE_MAPPINGS:
            entry = dict(MITRE_MAPPINGS[owasp_id])
            entry["source"]   = check_name
            entry["status"]   = result["status"]
            entry["evidence"] = result.get("detail", "")
            entry["findings"] = result.get("findings", [])
            mapped.append(entry)

    return mapped


def map_cve_findings(all_cves: list) -> list:
    """Map CVE severity to MITRE ATT&CK techniques."""
    mapped   = []
    seen_sev = set()

    for cve in all_cves:
        severity = cve.get("severity", "NONE")

        if severity == "CRITICAL" and "cve_critical" not in seen_sev:
            entry = dict(MITRE_MAPPINGS["cve_critical"])
            entry["source"]   = f"Critical CVE: {cve['cve_id']}"
            entry["evidence"] = f"Score {cve['score']} — {cve['description'][:100]}"
            entry["cve_id"]   = cve["cve_id"]
            mapped.append(entry)
            seen_sev.add("cve_critical")

        elif severity == "HIGH" and "cve_high" not in seen_sev:
            entry = dict(MITRE_MAPPINGS["cve_high"])
            entry["source"]   = f"High CVE: {cve['cve_id']}"
            entry["evidence"] = f"Score {cve['score']} — {cve['description'][:100]}"
            entry["cve_id"]   = cve["cve_id"]
            mapped.append(entry)
            seen_sev.add("cve_high")

    return mapped


def group_by_tactic(mapped_techniques: list) -> dict:
    """Group techniques by ATT&CK tactic for dashboard display."""
    grouped = {}
    for technique in mapped_techniques:
        tactic = technique.get("tactic", "Unknown")
        if tactic not in grouped:
            grouped[tactic] = []
        grouped[tactic].append(technique)
    return grouped


def run_mitre_mapping(scan_result: dict) -> dict:
    """
    Main entry — maps all findings to MITRE ATT&CK framework.

    Args:
        scan_result: Output from owasp_checks.run_owasp_checks()

    Returns:
        Same dict with mitre_results and mitre_by_tactic added
    """
    if "error" in scan_result:
        return scan_result

    open_ports    = scan_result.get("open_ports",    [])
    owasp_results = scan_result.get("owasp_results", [])
    all_cves      = scan_result.get("all_cves",      [])

    print(f"\n[*] Mapping findings to MITRE ATT&CK...")

    port_techniques  = map_port_findings(open_ports)
    owasp_techniques = map_owasp_findings(owasp_results)
    cve_techniques   = map_cve_findings(all_cves)

    all_techniques   = port_techniques + owasp_techniques + cve_techniques
    by_tactic        = group_by_tactic(all_techniques)

    for tactic, techniques in by_tactic.items():
        print(f"  [+] {tactic}: {len(techniques)} technique(s)")
        for t in techniques:
            print(f"      {t['technique_id']} — {t['technique_name']}")

    scan_result["mitre_results"]  = all_techniques
    scan_result["mitre_by_tactic"] = by_tactic
    scan_result["mitre_summary"]  = {
        "total_techniques": len(all_techniques),
        "total_tactics":    len(by_tactic),
        "tactics":          list(by_tactic.keys()),
    }

    return scan_result


if __name__ == "__main__":
    from scanner.port_scanner import run_port_scan
    from scanner.fingerprint  import run_fingerprint
    from scanner.cve_lookup   import run_cve_lookup
    from scanner.owasp_checks import run_owasp_checks

    scan   = run_port_scan("127.0.0.1")
    scan   = run_fingerprint(scan)
    scan   = run_cve_lookup(scan)
    scan   = run_owasp_checks(scan)
    result = run_mitre_mapping(scan)

    print(f"\nTotal techniques mapped: {result['mitre_summary']['total_techniques']}")
    print(f"Tactics covered: {', '.join(result['mitre_summary']['tactics'])}")