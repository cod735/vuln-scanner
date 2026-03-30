import socket
import re
import ssl
import struct
import time


# Version patterns — regex to extract software + version from banners
VERSION_PATTERNS = [
    (r"Apache[/ ]([\d.]+)",           "Apache"),
    (r"nginx[/ ]([\d.]+)",            "Nginx"),
    (r"OpenSSH[_/ ]([\d.p]+)",        "OpenSSH"),
    (r"OpenSSL[/ ]([\d.a-z]+)",       "OpenSSL"),
    (r"Microsoft-IIS[/ ]([\d.]+)",    "IIS"),
    (r"MySQL[/ ]([\d.]+)",            "MySQL"),
    (r"PostgreSQL[/ ]?([\d.]+)",      "PostgreSQL"),
    (r"MongoDB[/ ]?([\d.]+)",         "MongoDB"),
    (r"Redis[/ ]?([\d.]+)",           "Redis"),
    (r"vsftpd[/ ]?([\d.]+)",          "vsftpd"),
    (r"ProFTPD[/ ]?([\d.]+)",         "ProFTPD"),
    (r"Pure-FTPd[/ ]?([\d.]+)",       "Pure-FTPd"),
    (r"Postfix[/ ]?([\d.]+)",         "Postfix"),
    (r"Exim[/ ]?([\d.]+)",            "Exim"),
    (r"Dovecot[/ ]?([\d.]+)",         "Dovecot"),
    (r"Tomcat[/ ]?([\d.]+)",          "Tomcat"),
    (r"lighttpd[/ ]?([\d.]+)",        "lighttpd"),
    (r"Python[/ ]?([\d.]+)",          "Python"),
    (r"PHP[/ ]?([\d.]+)",             "PHP"),
    (r"Node[/ ]?([\d.]+)",            "Node.js"),
    (r"Werkzeug[/ ]?([\d.]+)",        "Werkzeug"),
    (r"Flask[/ ]?([\d.]+)",           "Flask"),
    (r"Express[/ ]?([\d.]+)",         "Express"),
    (r"Ubuntu[/ ]?([\d.]+)",          "Ubuntu"),
    (r"Debian[/ ]?([\d.]+)",          "Debian"),
    (r"CentOS[/ ]?([\d.]+)",          "CentOS"),
]

# OS TTL fingerprinting — TTL ranges map to likely OS families
TTL_OS_MAP = [
    (range(60,  66),  "Linux / Android"),
    (range(126, 130), "Windows"),
    (range(252, 256), "Cisco / Network Device"),
    (range(240, 252), "Solaris / AIX"),
    (range(54,  60),  "FreeBSD / macOS"),
]


def grab_banner(ip: str, port: int, timeout: float = 3.0) -> str:
    """Connect to a port and grab its service banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Some services send banner immediately — try receiving first
        try:
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            if banner:
                sock.close()
                return banner
        except Exception:
            pass

        # For HTTP — send a HEAD request to get Server header
        if port in [80, 8080, 8000, 8081, 8082, 8083, 8088, 8090, 3000, 5000]:
            sock.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            response = sock.recv(2048).decode("utf-8", errors="ignore")
            sock.close()
            return response

        sock.close()
    except Exception:
        pass
    return ""


def grab_https_banner(ip: str, port: int, timeout: float = 3.0) -> str:
    """Grab banner from HTTPS port using SSL."""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=ip) as ssl_sock:
                ssl_sock.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                response = ssl_sock.recv(2048).decode("utf-8", errors="ignore")
                return response
    except Exception:
        return ""


def extract_version(banner: str) -> dict:
    """Extract software name and version from a banner string."""
    if not banner:
        return {"software": "unknown", "version": "unknown"}

    for pattern, software in VERSION_PATTERNS:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            return {"software": software, "version": match.group(1)}

    # No known pattern — return raw first line of banner as clue
    first_line = banner.split("\n")[0].strip()[:80]
    return {"software": "unknown", "version": "unknown", "raw_banner": first_line}


def detect_os_ttl(ip: str) -> dict:
    """Estimate OS from ICMP TTL using raw socket ping."""
    try:
        # Build ICMP echo request packet
        icmp_type = 8
        code = 0
        checksum = 0
        identifier = 1
        sequence = 1
        header = struct.pack("bbHHh", icmp_type, code, checksum, identifier, sequence)
        data = b"abcdefgh"

        # Calculate checksum
        s = 0
        for i in range(0, len(header + data), 2):
            w = (header + data)[i] + ((header + data)[i+1] << 8)
            s = (s + w) & 0xFFFF
        checksum = ~s & 0xFFFF
        header = struct.pack("bbHHh", icmp_type, code, checksum, identifier, sequence)

        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(2)
        sock.sendto(header + data, (ip, 0))
        recv_data, addr = sock.recvfrom(1024)
        sock.close()

        # TTL is byte 8 of IP header
        ttl = recv_data[8]

        for ttl_range, os_name in TTL_OS_MAP:
            if ttl in ttl_range:
                return {"ttl": ttl, "os_guess": os_name, "method": "ttl"}

        return {"ttl": ttl, "os_guess": "Unknown", "method": "ttl"}

    except PermissionError:
        # Raw socket needs root — fall back gracefully
        return {"ttl": None, "os_guess": "Unknown (run as root for TTL detection)", "method": "none"}
    except Exception:
        return {"ttl": None, "os_guess": "Unknown", "method": "none"}


def fingerprint_services(ip: str, open_ports: list) -> list:
    """
    Fingerprint all open ports — grab banners and extract versions.

    Args:
        ip:         Target IP
        open_ports: List of open port dicts from port_scanner

    Returns:
        Enriched list with banner + version info added to each port
    """
    print(f"\n[*] Fingerprinting {len(open_ports)} open ports...")
    enriched = []

    for port_info in open_ports:
        port = port_info["port"]
        result = dict(port_info)  # copy

        # Choose correct banner grab method
        if port in [443, 8443, 4443, 7443, 9443]:
            banner = grab_https_banner(ip, port)
        else:
            banner = grab_banner(ip, port)

        version_info = extract_version(banner)
        result["banner"]   = banner[:200] if banner else ""
        result["software"] = version_info["software"]
        result["version"]  = version_info["version"]

        if "raw_banner" in version_info:
            result["raw_banner"] = version_info["raw_banner"]

        label = f"{result['software']} {result['version']}" if result["software"] != "unknown" else result.get("raw_banner", "no banner")
        print(f"  [+] Port {port:5d}  {port_info['service']:<20} {label}")

        enriched.append(result)
        time.sleep(0.1)  # Be polite — don't hammer the target

    return enriched


def run_fingerprint(scan_result: dict) -> dict:
    """
    Main entry — takes port scan result, returns enriched result with
    fingerprinting data and OS detection added.

    Args:
        scan_result: Output dict from port_scanner.run_port_scan()

    Returns:
        Same dict with fingerprint data added
    """
    if "error" in scan_result:
        return scan_result

    ip         = scan_result["ip"]
    open_ports = scan_result["open_ports"]

    # OS detection
    print(f"\n[*] Running OS detection on {ip}...")
    os_info = detect_os_ttl(ip)
    print(f"  [+] OS guess: {os_info['os_guess']} (TTL: {os_info['ttl']})")

    # Service fingerprinting
    enriched_ports = fingerprint_services(ip, open_ports)

    scan_result["os_detection"] = os_info
    scan_result["open_ports"]   = enriched_ports

    return scan_result


if __name__ == "__main__":
    # Test against localhost
    from scanner.port_scanner import run_port_scan
    scan = run_port_scan("127.0.0.1")
    result = run_fingerprint(scan)
    print(f"\nOS: {result['os_detection']['os_guess']}")
    for p in result["open_ports"]:
        print(f"  Port {p['port']} — {p['software']} {p['version']}")