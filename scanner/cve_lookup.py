import requests
import time
import json
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv("config/.env")

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY  = os.getenv("NVD_API_KEY", "")

# Local cache — avoids hitting API repeatedly for same version
_cache = {}

# Severity thresholds based on CVSS v3 score
def get_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score >  0.0: return "LOW"
    return "NONE"


def build_cpe_keyword(software: str, version: str) -> str:
    """Build a search keyword from software + version for NVD query."""
    if software == "unknown" or version == "unknown":
        return ""
    return f"{software} {version}"


def query_nvd(keyword: str, max_results: int = 5) -> list:
    """
    Query the NVD API for CVEs matching a keyword.
    Returns list of CVE dicts.
    """
    if not keyword:
        return []

    # Check cache first
    if keyword in _cache:
        return _cache[keyword]

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    }

    try:
        response = requests.get(
            NVD_API_BASE,
            headers=headers,
            params=params,
            timeout=10
        )

        if response.status_code == 403:
            print(f"  [!] NVD API key invalid or rate limited")
            return []

        if response.status_code != 200:
            print(f"  [!] NVD API error: {response.status_code}")
            return []

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        cves = []

        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            cve_id   = cve_data.get("id", "Unknown")

            # Extract description
            descriptions = cve_data.get("descriptions", [])
            description  = next(
                (d["value"] for d in descriptions if d["lang"] == "en"),
                "No description available"
            )

            # Extract CVSS v3 score
            score    = 0.0
            vector   = ""
            metrics  = cve_data.get("metrics", {})

            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
                score  = cvss.get("baseScore", 0.0)
                vector = cvss.get("vectorString", "")
            elif "cvssMetricV30" in metrics:
                cvss = metrics["cvssMetricV30"][0]["cvssData"]
                score  = cvss.get("baseScore", 0.0)
                vector = cvss.get("vectorString", "")
            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0]["cvssData"]
                score  = cvss.get("baseScore", 0.0)
                vector = cvss.get("vectorString", "")

            # Extract published date
            published = cve_data.get("published", "")[:10]

            # Extract references
            refs = cve_data.get("references", [])
            ref_urls = [r["url"] for r in refs[:3]]

            cves.append({
                "cve_id":      cve_id,
                "description": description[:300],
                "score":       score,
                "severity":    get_severity(score),
                "vector":      vector,
                "published":   published,
                "references":  ref_urls,
                "keyword":     keyword,
            })

        # Cache result
        _cache[keyword] = cves
        return cves

    except requests.exceptions.Timeout:
        print(f"  [!] NVD API timeout for: {keyword}")
        return []
    except requests.exceptions.ConnectionError:
        print(f"  [!] NVD API connection error")
        return []
    except Exception as e:
        print(f"  [!] NVD query error: {e}")
        return []


def lookup_cves_for_port(port_info: dict) -> dict:
    """
    Look up CVEs for a single fingerprinted port.
    Adds cve_results list to the port dict.
    """
    software = port_info.get("software", "unknown")
    version  = port_info.get("version",  "unknown")
    port     = port_info.get("port", 0)

    result = dict(port_info)
    result["cve_results"]  = []
    result["cve_count"]    = 0
    result["max_severity"] = "NONE"
    result["max_score"]    = 0.0

    keyword = build_cpe_keyword(software, version)
    if not keyword:
        print(f"  [-] Port {port:5d} — skipping CVE lookup (unknown software/version)")
        return result

    print(f"  [*] Port {port:5d} — querying NVD for: {keyword}")
    cves = query_nvd(keyword)

    if cves:
        max_score = max(c["score"] for c in cves)
        result["cve_results"]  = cves
        result["cve_count"]    = len(cves)
        result["max_severity"] = get_severity(max_score)
        result["max_score"]    = max_score
        print(f"  [+] Port {port:5d} — {len(cves)} CVEs found | Max: {max_score} {get_severity(max_score)}")
    else:
        print(f"  [-] Port {port:5d} — no CVEs found for {keyword}")

    # NVD rate limit — 5 requests/sec without key, 50/sec with key
    time.sleep(0.5 if NVD_API_KEY else 1.5)

    return result


def run_cve_lookup(scan_result: dict) -> dict:
    """
    Main entry — takes fingerprinted scan result, enriches every
    open port with CVE data from NVD.

    Args:
        scan_result: Output from fingerprint.run_fingerprint()

    Returns:
        Same dict with CVE data added to each port
    """
    if "error" in scan_result:
        return scan_result

    open_ports = scan_result.get("open_ports", [])
    print(f"\n[*] Running CVE lookup for {len(open_ports)} open ports...")

    enriched_ports  = []
    all_cves        = []
    critical_count  = 0
    high_count      = 0
    medium_count    = 0
    low_count       = 0

    for port_info in open_ports:
        enriched = lookup_cves_for_port(port_info)
        enriched_ports.append(enriched)

        for cve in enriched.get("cve_results", []):
            all_cves.append({**cve, "port": port_info["port"],
                             "service": port_info["service"]})
            sev = cve["severity"]
            if sev == "CRITICAL": critical_count += 1
            elif sev == "HIGH":   high_count     += 1
            elif sev == "MEDIUM": medium_count   += 1
            elif sev == "LOW":    low_count      += 1

    scan_result["open_ports"]     = enriched_ports
    scan_result["all_cves"]       = all_cves
    scan_result["cve_summary"]    = {
        "total":    len(all_cves),
        "critical": critical_count,
        "high":     high_count,
        "medium":   medium_count,
        "low":      low_count,
    }

    print(f"\n[*] CVE lookup complete:")
    print(f"    Critical: {critical_count} | High: {high_count} | Medium: {medium_count} | Low: {low_count}")

    return scan_result


if __name__ == "__main__":
    from scanner.port_scanner  import run_port_scan
    from scanner.fingerprint   import run_fingerprint

    scan   = run_port_scan("127.0.0.1")
    scan   = run_fingerprint(scan)
    result = run_cve_lookup(scan)

    print(f"\nTotal CVEs found: {result['cve_summary']['total']}")
    for cve in result["all_cves"][:5]:
        print(f"  {cve['cve_id']} — {cve['severity']} ({cve['score']}) — {cve['description'][:80]}")