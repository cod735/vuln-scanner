import argparse
import json
import os
import sys
from datetime import datetime

from scanner.port_scanner  import run_port_scan
from scanner.fingerprint   import run_fingerprint
from scanner.cve_lookup    import run_cve_lookup
from scanner.owasp_checks  import run_owasp_checks
from scanner.mitre_mapper  import run_mitre_mapping


BANNER = """
╔══════════════════════════════════════════════════════════════╗
║         VULNERABILITY ASSESSMENT SCANNER  v1.0.0            ║
║         by Abbas Khan  |  github.com/cod735               ║
║         Python 3.12  |  NVD API  |  OWASP Top 10           ║
╚══════════════════════════════════════════════════════════════╝
"""


def print_banner():
    print(BANNER)


def save_results(result: dict, output_path: str = "data/scan_results.json"):
    """Save full scan result to JSON file."""
    os.makedirs("data", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2, default=str)
    print(f"\n[*] Results saved to {output_path}")


def save_history(result: dict, history_path: str = "data/history.json"):
    """Append scan summary to history file."""
    os.makedirs("data", exist_ok=True)

    # Load existing history
    history = []
    if os.path.exists(history_path):
        try:
            with open(history_path) as f:
                history = json.load(f)
        except Exception:
            history = []

    # Build summary entry
    summary = {
        "scan_id":       datetime.now().strftime("%Y%m%d_%H%M%S"),
        "target":        result.get("target", ""),
        "ip":            result.get("ip", ""),
        "scan_time":     result.get("scan_time", ""),
        "elapsed_sec":   result.get("elapsed_sec", 0),
        "open_count":    result.get("open_count", 0),
        "cve_summary":   result.get("cve_summary", {}),
        "owasp_summary": result.get("owasp_summary", {}),
        "mitre_summary": result.get("mitre_summary", {}),
        "has_web":       result.get("has_web", False),
    }

    history.append(summary)

    with open(history_path, "w") as f:
        json.dump(history, f, indent=2, default=str)

    print(f"[*] Scan added to history ({len(history)} total scans)")


def print_summary(result: dict):
    """Print a clean final summary to terminal."""
    print("\n" + "═" * 62)
    print("  SCAN COMPLETE — SUMMARY")
    print("═" * 62)
    print(f"  Target      : {result.get('target')} ({result.get('ip')})")
    print(f"  Scan Time   : {result.get('scan_time')}")
    print(f"  Duration    : {result.get('elapsed_sec')}s")
    print(f"  Open Ports  : {result.get('open_count')}")
    print(f"  Web Target  : {'Yes' if result.get('has_web') else 'No'}")

    # OS
    os_info = result.get("os_detection", {})
    print(f"  OS Guess    : {os_info.get('os_guess', 'Unknown')}")

    # CVE summary
    cve = result.get("cve_summary", {})
    if cve:
        print(f"\n  CVE Results :")
        print(f"    Critical  : {cve.get('critical', 0)}")
        print(f"    High      : {cve.get('high', 0)}")
        print(f"    Medium    : {cve.get('medium', 0)}")
        print(f"    Low       : {cve.get('low', 0)}")
        print(f"    Total     : {cve.get('total', 0)}")

    # OWASP summary
    owasp = result.get("owasp_summary", {})
    if owasp and owasp.get("total", 0) > 0:
        print(f"\n  OWASP Top 10:")
        print(f"    Pass      : {owasp.get('pass', 0)}")
        print(f"    Warn      : {owasp.get('warn', 0)}")
        print(f"    Fail      : {owasp.get('fail', 0)}")
        print(f"    Skip      : {owasp.get('skip', 0)}")

    # MITRE summary
    mitre = result.get("mitre_summary", {})
    if mitre:
        print(f"\n  MITRE ATT&CK:")
        print(f"    Techniques: {mitre.get('total_techniques', 0)}")
        print(f"    Tactics   : {mitre.get('total_tactics', 0)}")
        tactics = mitre.get("tactics", [])
        if tactics:
            for t in tactics:
                print(f"      - {t}")

    print("\n" + "═" * 62)


def run_scan(target: str, ports: list = None, threads: int = 100,
             timeout: float = 1.0, skip_owasp: bool = False,
             skip_cve: bool = False) -> dict:
    """
    Run the full 5-layer scan pipeline against a target.

    Args:
        target:      IP, domain, or URL
        ports:       Custom port list (None = top 1000)
        threads:     Concurrent threads for port scan
        timeout:     Per-port timeout in seconds
        skip_owasp:  Skip OWASP checks (faster for non-web targets)
        skip_cve:    Skip CVE lookup (faster, no NVD API needed)

    Returns:
        Full scan result dict
    """
    print_banner()
    print(f"[*] Target     : {target}")
    print(f"[*] Threads    : {threads}")
    print(f"[*] Timeout    : {timeout}s")
    print(f"[*] CVE Lookup : {'disabled' if skip_cve else 'enabled'}")
    print(f"[*] OWASP      : {'disabled' if skip_owasp else 'enabled'}")
    print(f"[*] Started    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # ── Layer 1: Port scan ────────────────────────────────────────
    print("─" * 62)
    print("  LAYER 1 — PORT DISCOVERY")
    print("─" * 62)
    result = run_port_scan(target, ports=ports,
                           max_threads=threads, timeout=timeout)

    if "error" in result:
        print(f"\n[!] Scan failed: {result['error']}")
        return result

    if result["open_count"] == 0:
        print("\n[!] No open ports found — scan complete")
        return result

    # ── Layer 2: Fingerprinting ───────────────────────────────────
    print("\n" + "─" * 62)
    print("  LAYER 2 — SERVICE FINGERPRINTING")
    print("─" * 62)
    result = run_fingerprint(result)

    # ── Layer 3: CVE lookup ───────────────────────────────────────
    if not skip_cve:
        print("\n" + "─" * 62)
        print("  LAYER 3 — CVE LOOKUP  (NVD API)")
        print("─" * 62)
        result = run_cve_lookup(result)
    else:
        result["all_cves"]    = []
        result["cve_summary"] = {"total": 0, "critical": 0,
                                  "high": 0, "medium": 0, "low": 0}

    # ── Layer 4: OWASP checks ─────────────────────────────────────
    if not skip_owasp:
        print("\n" + "─" * 62)
        print("  LAYER 4 — OWASP TOP 10 WEB CHECKS")
        print("─" * 62)
        result = run_owasp_checks(result)
    else:
        result["owasp_results"] = []
        result["owasp_summary"] = {"total": 0, "pass": 0,
                                    "warn": 0, "fail": 0, "skip": 10}

    # ── Layer 5: MITRE mapping ────────────────────────────────────
    print("\n" + "─" * 62)
    print("  LAYER 5 — MITRE ATT&CK MAPPING")
    print("─" * 62)
    result = run_mitre_mapping(result)

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Vulnerability Assessment Scanner v1.0.0",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "target",
        help="Target IP, domain, or URL\nExamples:\n"
             "  192.168.1.1\n"
             "  example.com\n"
             "  https://example.com"
    )
    parser.add_argument(
        "--threads", type=int, default=100,
        help="Concurrent threads for port scan (default: 100)"
    )
    parser.add_argument(
        "--timeout", type=float, default=1.0,
        help="Per-port timeout in seconds (default: 1.0)"
    )
    parser.add_argument(
        "--ports", type=str, default=None,
        help="Custom port list e.g. 80,443,8080 (default: top 1000)"
    )
    parser.add_argument(
        "--skip-cve", action="store_true",
        help="Skip CVE lookup (faster, no NVD API needed)"
    )
    parser.add_argument(
        "--skip-owasp", action="store_true",
        help="Skip OWASP checks (faster for non-web targets)"
    )
    parser.add_argument(
        "--output", type=str, default="data/scan_results.json",
        help="Output file path (default: data/scan_results.json)"
    )
    parser.add_argument(
        "--no-dashboard", action="store_true",
        help="Run scan only — do not launch dashboard"
    )

    args = parser.parse_args()

    # Parse custom ports if provided
    custom_ports = None
    if args.ports:
        try:
            custom_ports = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            print("[!] Invalid port list — use format: 80,443,8080")
            sys.exit(1)

    # Run the full pipeline
    result = run_scan(
        target      = args.target,
        ports       = custom_ports,
        threads     = args.threads,
        timeout     = args.timeout,
        skip_owasp  = args.skip_owasp,
        skip_cve    = args.skip_cve,
    )

    # Save results
    if "error" not in result:
        save_results(result, args.output)
        save_history(result)
        print_summary(result)

    # Launch dashboard
    if not args.no_dashboard and "error" not in result:
        print("\n[*] Launching SOC dashboard...")
        print("[*] Open your browser at: http://localhost:5004\n")
        try:
            from dashboard.app import create_app
            app, socketio = create_app()
            socketio.run(app, host="0.0.0.0", port=5004, debug=False)
        except ImportError:
            print("[!] Dashboard not yet built — run with --no-dashboard for now")


if __name__ == "__main__":
    main()