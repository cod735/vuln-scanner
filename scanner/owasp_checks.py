import requests
import re
import ssl
import socket
import urllib3
from urllib.parse import urljoin, urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Result states
PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"
SKIP = "SKIP"


def make_session() -> requests.Session:
    """Create a requests session with SSL verification off."""
    session = requests.Session()
    session.verify  = False
    session.timeout = 8
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (VulnScanner/1.0; Security Assessment)"
    })
    return session


def build_base_url(ip: str, open_ports: list) -> str:
    """Pick the best base URL from open ports."""
    https_ports = [p["port"] for p in open_ports
                   if p["port"] in [443, 8443, 4443, 7443, 9443]]
    http_ports  = [p["port"] for p in open_ports
                   if p["port"] in [80, 8080, 8000, 8081, 8082,
                                    8083, 8088, 8090, 3000, 5000]]

    if https_ports:
        port = https_ports[0]
        return f"https://{ip}" if port == 443 else f"https://{ip}:{port}"
    if http_ports:
        port = http_ports[0]
        return f"http://{ip}" if port == 80 else f"http://{ip}:{port}"
    return f"http://{ip}"


# ── A01: Broken Access Control ────────────────────────────────────
def check_a01_broken_access_control(session, base_url: str) -> dict:
    """Check for directory traversal and exposed sensitive paths."""
    name  = "A01 — Broken Access Control"
    paths = [
        "/etc/passwd", "/../etc/passwd", "/../../etc/passwd",
        "/.git/config", "/.env", "/.htaccess",
        "/admin", "/admin/", "/administrator",
        "/wp-admin", "/phpmyadmin", "/manager/html",
        "/api/users", "/api/admin", "/private",
    ]
    findings = []

    for path in paths:
        try:
            url      = urljoin(base_url, path)
            response = session.get(url, allow_redirects=False)

            # Flag 200 OK on sensitive paths or traversal indicators
            if response.status_code == 200:
                if "root:" in response.text or "[database]" in response.text:
                    findings.append(f"Path traversal evidence at {path}")
                elif path in ["/admin", "/administrator", "/wp-admin",
                              "/phpmyadmin", "/manager/html"]:
                    findings.append(f"Admin panel accessible at {path}")
                elif path in ["/.env", "/.git/config", "/.htaccess"]:
                    findings.append(f"Sensitive file exposed at {path}")
        except Exception:
            continue

    if findings:
        return {"check": name, "status": FAIL, "findings": findings,
                "detail": f"{len(findings)} access control issue(s) found"}
    return {"check": name, "status": PASS, "findings": [],
            "detail": "No obvious access control issues detected"}


# ── A02: Cryptographic Failures ───────────────────────────────────
def check_a02_cryptographic_failures(session, base_url: str,
                                     open_ports: list) -> dict:
    name     = "A02 — Cryptographic Failures"
    findings = []

    # Check if HTTP is open without HTTPS
    http_ports  = [p["port"] for p in open_ports
                   if p["port"] in [80, 8080, 8000]]
    https_ports = [p["port"] for p in open_ports
                   if p["port"] in [443, 8443]]

    if http_ports and not https_ports:
        findings.append("Service running on HTTP only — no HTTPS detected")

    # Check for sensitive files served over HTTP
    if base_url.startswith("http://"):
        sensitive_paths = ["/login", "/signin", "/account", "/password"]
        for path in sensitive_paths:
            try:
                r = session.get(urljoin(base_url, path), allow_redirects=False)
                if r.status_code == 200 and "password" in r.text.lower():
                    findings.append(f"Login form served over plain HTTP at {path}")
                    break
            except Exception:
                continue

    # Check HTTPS misconfiguration
    if https_ports:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode    = ssl.CERT_NONE
            with socket.create_connection(
                    (base_url.split("//")[1].split(":")[0], https_ports[0]),
                    timeout=5) as sock:
                with context.wrap_socket(sock) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        findings.append("TLS certificate could not be verified")
        except Exception:
            findings.append("TLS handshake failed — possible misconfiguration")

    if findings:
        return {"check": name, "status": FAIL, "findings": findings,
                "detail": f"{len(findings)} cryptographic issue(s) found"}
    return {"check": name, "status": PASS, "findings": [],
            "detail": "No obvious cryptographic failures detected"}


# ── A03: Injection ────────────────────────────────────────────────
def check_a03_injection(session, base_url: str) -> dict:
    name     = "A03 — Injection"
    findings = []

    # SQL injection probe payloads — look for error responses
    sqli_payloads = ["'", "\"", "1 OR 1=1", "' OR '1'='1", "1; DROP TABLE"]
    error_patterns = [
        r"sql syntax", r"mysql_fetch", r"ORA-\d+",
        r"sqlite_", r"pg_query", r"unterminated quoted",
        r"You have an error in your SQL",
        r"Warning.*mysql", r"valid MySQL result",
    ]

    test_paths = ["/?id=", "/?q=", "/?search=", "/?page=", "/?cat="]

    for path in test_paths:
        for payload in sqli_payloads[:2]:  # Limit probes
            try:
                url      = base_url + path + payload
                response = session.get(url)

                for pattern in error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        findings.append(
                            f"Possible SQLi error response at {path} "
                            f"with payload: {payload}"
                        )
                        break
            except Exception:
                continue

    # Command injection — look for obvious error leaks
    cmd_payloads = [";ls", "|whoami", "&dir"]
    for path in ["/?cmd=", "/?exec=", "/?command="]:
        for payload in cmd_payloads[:1]:
            try:
                url      = base_url + path + payload
                response = session.get(url)
                if any(x in response.text for x in
                       ["root:", "bin/bash", "Windows", "volume serial"]):
                    findings.append(f"Possible command injection at {path}")
            except Exception:
                continue

    status = FAIL if findings else WARN
    detail = (f"{len(findings)} injection indicator(s) found"
              if findings else
              "No injection errors triggered — manual testing recommended")

    return {"check": name, "status": status,
            "findings": findings, "detail": detail}


# ── A04: Insecure Design ─────────────────────────────────────────
def check_a04_insecure_design(session, base_url: str) -> dict:
    name     = "A04 — Insecure Design"
    findings = []

    try:
        response = session.get(base_url)
        headers  = response.headers

        # Missing security headers
        security_headers = {
            "X-Frame-Options":        "Clickjacking protection missing",
            "X-Content-Type-Options": "MIME sniffing protection missing",
            "Referrer-Policy":        "Referrer policy not set",
            "Permissions-Policy":     "Permissions policy not set",
        }

        for header, message in security_headers.items():
            if header not in headers:
                findings.append(message)

        # Check for open redirect
        redirect_paths = ["/?url=http://evil.com", "/?redirect=http://evil.com",
                          "/?next=http://evil.com"]
        for path in redirect_paths:
            try:
                r = session.get(base_url + path, allow_redirects=False)
                if r.status_code in [301, 302]:
                    location = r.headers.get("Location", "")
                    if "evil.com" in location:
                        findings.append(f"Open redirect confirmed at {path}")
            except Exception:
                continue

    except Exception as e:
        return {"check": name, "status": SKIP, "findings": [],
                "detail": f"Could not reach target: {e}"}

    status = FAIL if len(findings) >= 3 else WARN if findings else PASS
    detail = (f"{len(findings)} insecure design indicator(s)"
              if findings else "Security headers present")

    return {"check": name, "status": status,
            "findings": findings, "detail": detail}


# ── A05: Security Misconfiguration ───────────────────────────────
def check_a05_security_misconfiguration(session, base_url: str) -> dict:
    name     = "A05 — Security Misconfiguration"
    findings = []

    # Default/debug pages
    debug_paths = [
        "/server-status", "/server-info", "/.well-known/",
        "/debug", "/trace", "/actuator", "/actuator/health",
        "/actuator/env", "/actuator/mappings", "/swagger-ui.html",
        "/api/swagger", "/v2/api-docs", "/phpinfo.php",
        "/info.php", "/test.php", "/robots.txt",
    ]

    for path in debug_paths:
        try:
            r = session.get(urljoin(base_url, path))
            if r.status_code == 200:
                if path in ["/server-status", "/server-info"]:
                    findings.append(f"Apache server status page exposed at {path}")
                elif "actuator" in path:
                    findings.append(f"Spring Boot Actuator endpoint exposed: {path}")
                elif path in ["/phpinfo.php", "/info.php"]:
                    if "phpinfo" in r.text.lower():
                        findings.append(f"PHP info page exposed at {path}")
                elif "swagger" in path or "api-docs" in path:
                    findings.append(f"API documentation exposed at {path}")
        except Exception:
            continue

    # Verbose error messages
    try:
        r = session.get(base_url + "/nonexistent-page-12345")
        if r.status_code == 500:
            findings.append("Server returns 500 error with potential stack trace")
        if any(x in r.text for x in
               ["Traceback", "stack trace", "at line", "Exception in"]):
            findings.append("Verbose error messages leaking framework details")
    except Exception:
        pass

    # Server header info disclosure
    try:
        r       = session.get(base_url)
        server  = r.headers.get("Server", "")
        powered = r.headers.get("X-Powered-By", "")
        if server:
            findings.append(f"Server header discloses: {server}")
        if powered:
            findings.append(f"X-Powered-By discloses: {powered}")
    except Exception:
        pass

    status = FAIL if findings else PASS
    detail = (f"{len(findings)} misconfiguration(s) found"
              if findings else "No obvious misconfigurations detected")

    return {"check": name, "status": status,
            "findings": findings, "detail": detail}


# ── A06: Vulnerable & Outdated Components ─────────────────────────
def check_a06_vulnerable_components(open_ports: list) -> dict:
    name     = "A06 — Vulnerable & Outdated Components"
    findings = []

    # Known vulnerable version ranges (simplified)
    vulnerable_versions = {
        "Apache":   {"below": "2.4.54", "cve": "CVE-2021-41773"},
        "OpenSSH":  {"below": "8.0",    "cve": "CVE-2019-6111"},
        "Nginx":    {"below": "1.20.0", "cve": "CVE-2021-23017"},
        "MySQL":    {"below": "8.0.28", "cve": "CVE-2022-21417"},
        "PHP":      {"below": "8.1.0",  "cve": "CVE-2021-21708"},
    }

    for port in open_ports:
        software = port.get("software", "")
        version  = port.get("version",  "")
        cve_count = port.get("cve_count", 0)

        if cve_count > 0:
            findings.append(
                f"Port {port['port']} ({software} {version}) — "
                f"{cve_count} CVE(s) found from NVD lookup"
            )

        if software in vulnerable_versions and version != "unknown":
            info = vulnerable_versions[software]
            findings.append(
                f"{software} {version} may be affected by {info['cve']}"
            )

    status = FAIL if findings else PASS
    detail = (f"{len(findings)} vulnerable component(s) detected"
              if findings else "No known vulnerable components detected")

    return {"check": name, "status": status,
            "findings": findings, "detail": detail}


# ── A07: Auth & Session Failures ─────────────────────────────────
def check_a07_auth_failures(session, base_url: str) -> dict:
    name     = "A07 — Auth & Session Failures"
    findings = []

    # Check for login pages
    login_paths = ["/login", "/signin", "/wp-login.php",
                   "/admin/login", "/user/login"]

    for path in login_paths:
        try:
            r = session.get(urljoin(base_url, path))
            if r.status_code == 200 and any(
                    x in r.text.lower() for x in
                    ["password", "login", "username", "email"]):

                # Check for CSRF token
                if "csrf" not in r.text.lower() and \
                   "_token" not in r.text.lower():
                    findings.append(
                        f"Login form at {path} may lack CSRF protection"
                    )

                # Check for autocomplete on password fields
                if 'type="password"' in r.text and \
                   "autocomplete" not in r.text:
                    findings.append(
                        f"Password field at {path} missing autocomplete=off"
                    )
        except Exception:
            continue

    # Check session cookie flags
    try:
        r = session.get(base_url)
        for cookie in r.cookies:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("missing HttpOnly flag")
            if issues:
                findings.append(
                    f"Cookie '{cookie.name}': {', '.join(issues)}"
                )
    except Exception:
        pass

    status = WARN if findings else PASS
    detail = (f"{len(findings)} auth/session issue(s) found"
              if findings else "No obvious auth/session issues detected")

    return {"check": name, "status": status,
            "findings": findings, "detail": detail}


# ── A08: Software & Data Integrity Failures ───────────────────────
def check_a08_integrity_failures(session, base_url: str) -> dict:
    name     = "A08 — Software & Data Integrity Failures"
    findings = []

    try:
        r    = session.get(base_url)
        html = r.text

        # Find <script src="..."> tags without integrity attribute
        script_tags = re.findall(
            r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>', html, re.IGNORECASE
        )
        for tag in script_tags:
            # External scripts without SRI
            if tag.startswith("http") and "integrity" not in html:
                findings.append(
                    f"External script loaded without SRI: {tag[:80]}"
                )

        # Find <link> tags without integrity
        link_tags = re.findall(
            r'<link[^>]+href=["\']([^"\']+)["\'][^>]*>', html, re.IGNORECASE
        )
        for tag in link_tags:
            if tag.startswith("http") and "integrity" not in html:
                findings.append(
                    f"External stylesheet loaded without SRI: {tag[:80]}"
                )

    except Exception as e:
        return {"check": name, "status": SKIP, "findings": [],
                "detail": f"Could not fetch page: {e}"}

    # Deduplicate
    findings = list(set(findings))[:5]
    status   = WARN if findings else PASS
    detail   = (f"{len(findings)} integrity issue(s) found"
                if findings else "No SRI issues detected")

    return {"check": name, "status": status,
            "findings": findings, "detail": detail}


# ── A09: Logging & Monitoring Failures ───────────────────────────
def check_a09_logging_failures(session, base_url: str) -> dict:
    name     = "A09 — Logging & Monitoring Failures"
    findings = []

    # Check if invalid requests return any clues about logging
    try:
        r = session.get(base_url + "/nonexistent-page-probe-12345")
        if r.status_code not in [404, 403, 410]:
            findings.append(
                f"Unexpected response {r.status_code} to invalid path "
                f"— error handling may be misconfigured"
            )

        # Look for exposed log files
        log_paths = ["/logs/", "/log/", "/error.log",
                     "/access.log", "/debug.log"]
        for path in log_paths:
            try:
                lr = session.get(urljoin(base_url, path))
                if lr.status_code == 200 and len(lr.text) > 100:
                    findings.append(f"Log file may be exposed at {path}")
            except Exception:
                continue

    except Exception:
        pass

    status = WARN if findings else PASS
    detail = (f"{len(findings)} logging/monitoring issue(s) found"
              if findings else
              "No exposed logging issues detected — manual review recommended")

    return {"check": name, "status": status,
            "findings": findings, "detail": detail}


# ── A10: SSRF ─────────────────────────────────────────────────────
def check_a10_ssrf(session, base_url: str) -> dict:
    name     = "A10 — Server-Side Request Forgery (SSRF)"
    findings = []

    # SSRF probe — internal addresses a server should not fetch
    ssrf_payloads = [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://169.254.169.254/",        # AWS metadata
        "http://metadata.google.internal", # GCP metadata
    ]

    ssrf_params = ["?url=", "?uri=", "?path=", "?dest=",
                   "?redirect=", "?proxy=", "?fetch="]

    for param in ssrf_params:
        for payload in ssrf_payloads[:2]:
            try:
                r = session.get(base_url + param + payload,
                                allow_redirects=False, timeout=5)
                # If server returns 200 on internal URL probe — suspicious
                if r.status_code == 200 and len(r.text) > 50:
                    findings.append(
                        f"Possible SSRF via {param} with payload {payload}"
                    )
            except Exception:
                continue

    status = WARN if findings else PASS
    detail = (f"{len(findings)} SSRF indicator(s) found"
              if findings else
              "No SSRF indicators detected — manual testing recommended")

    return {"check": name, "status": status,
            "findings": findings, "detail": detail}


# ── Main runner ───────────────────────────────────────────────────
def run_owasp_checks(scan_result: dict) -> dict:
    """
    Main entry — runs all 10 OWASP checks against the target.
    Only activates if HTTP or HTTPS ports are open.

    Args:
        scan_result: Output from cve_lookup.run_cve_lookup()

    Returns:
        Same dict with owasp_results added
    """
    if "error" in scan_result:
        return scan_result

    has_web    = scan_result.get("has_web", False)
    open_ports = scan_result.get("open_ports", [])
    ip         = scan_result.get("ip", "")

    if not has_web:
        print("\n[*] No HTTP/HTTPS ports detected — skipping OWASP checks")
        scan_result["owasp_results"] = []
        scan_result["owasp_summary"] = {
            "total": 0, "pass": 0, "warn": 0, "fail": 0, "skip": 10
        }
        return scan_result

    base_url = build_base_url(ip, open_ports)
    print(f"\n[*] Running OWASP Top 10 checks against {base_url}...")

    session = make_session()
    results = []

    checks = [
        lambda: check_a01_broken_access_control(session, base_url),
        lambda: check_a02_cryptographic_failures(session, base_url, open_ports),
        lambda: check_a03_injection(session, base_url),
        lambda: check_a04_insecure_design(session, base_url),
        lambda: check_a05_security_misconfiguration(session, base_url),
        lambda: check_a06_vulnerable_components(open_ports),
        lambda: check_a07_auth_failures(session, base_url),
        lambda: check_a08_integrity_failures(session, base_url),
        lambda: check_a09_logging_failures(session, base_url),
        lambda: check_a10_ssrf(session, base_url),
    ]

    for check_fn in checks:
        result = check_fn()
        results.append(result)
        status_icon = {"PASS": "[+]", "WARN": "[!]",
                       "FAIL": "[X]", "SKIP": "[-]"}.get(result["status"], "[?]")
        print(f"  {status_icon} {result['check']:<45} {result['status']}")

    summary = {
        "total": len(results),
        "pass":  sum(1 for r in results if r["status"] == PASS),
        "warn":  sum(1 for r in results if r["status"] == WARN),
        "fail":  sum(1 for r in results if r["status"] == FAIL),
        "skip":  sum(1 for r in results if r["status"] == SKIP),
    }

    scan_result["owasp_results"] = results
    scan_result["owasp_summary"] = summary

    print(f"\n[*] OWASP complete — PASS:{summary['pass']} "
          f"WARN:{summary['warn']} FAIL:{summary['fail']}")

    return scan_result


if __name__ == "__main__":
    from scanner.port_scanner import run_port_scan
    from scanner.fingerprint  import run_fingerprint
    from scanner.cve_lookup   import run_cve_lookup

    scan   = run_port_scan("127.0.0.1")
    scan   = run_fingerprint(scan)
    scan   = run_cve_lookup(scan)
    result = run_owasp_checks(scan)

    for r in result.get("owasp_results", []):
        print(f"  {r['status']} — {r['check']}")