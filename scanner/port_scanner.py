import socket
import concurrent.futures
import time
from datetime import datetime

TOP_PORTS = list(set([
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888, 9090, 27017,
    20, 69, 79, 88, 102, 119, 123, 137, 138, 161, 162, 179, 194, 389,
    427, 465, 500, 515, 543, 544, 548, 554, 587, 631, 636, 646, 873,
    990, 992, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1755,
    1900, 2000, 2001, 2049, 2121, 2717, 3000, 3001, 3128, 3268, 3269,
    4000, 4443, 4848, 5000, 5001, 5432, 5631, 5666, 5800, 5985, 6000,
    6001, 6379, 7001, 7002, 7070, 7443, 7547, 8000, 8001, 8008, 8009,
    8081, 8082, 8083, 8085, 8086, 8087, 8088, 8089, 8090, 8181, 8280,
    8281, 8333, 8400, 8800, 8888, 8983, 9000, 9001, 9043, 9060, 9080,
    9090, 9091, 9100, 9200, 9300, 9443, 9800, 9981, 10000, 10001,
    10080, 10443, 11211, 27017, 27018, 28017, 50000, 50070
]))

SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1723: "PPTP", 3000: "Dev Server", 3001: "Dev Server",
    3306: "MySQL", 3389: "RDP", 5000: "Flask/Dev", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 7001: "WebLogic", 8000: "HTTP-Alt",
    8080: "HTTP-Proxy", 8081: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "Jupyter/HTTP", 9200: "Elasticsearch", 9300: "Elasticsearch",
    10000: "Webmin", 27017: "MongoDB", 28017: "MongoDB-HTTP",
    50070: "Hadoop-HDFS"
}


def resolve_target(target: str) -> str:
    """Resolve domain/hostname to IP address."""
    try:
        target = target.replace("https://", "").replace("http://", "")
        target = target.split("/")[0]
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror as e:
        raise ValueError(f"Cannot resolve target '{target}': {e}")


def scan_port(ip: str, port: int, timeout: float = 1.0) -> dict:
    """Scan a single port. Returns result dict."""
    result = {
        "port": port,
        "state": "closed",
        "service": SERVICE_MAP.get(port, "unknown"),
        "protocol": "tcp"
    }
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        connection = sock.connect_ex((ip, port))
        if connection == 0:
            result["state"] = "open"
        sock.close()
    except socket.timeout:
        result["state"] = "filtered"
    except OSError:
        result["state"] = "closed"
    return result


def run_port_scan(target: str, ports: list = None, max_threads: int = 100,
                  timeout: float = 1.0, progress_callback=None) -> dict:
    """
    Run a full port scan against a target.

    Args:
        target:            IP, domain, or URL
        ports:             List of ports to scan (defaults to TOP_PORTS)
        max_threads:       Concurrent threads
        timeout:           Per-port timeout in seconds
        progress_callback: Optional fn(scanned, total) for live updates

    Returns:
        Dictionary with full scan results
    """
    if ports is None:
        ports = TOP_PORTS

    ports = list(set(ports))
    start_time = time.time()

    try:
        ip = resolve_target(target)
    except ValueError as e:
        return {"error": str(e), "target": target}

    print(f"[*] Starting port scan on {target} ({ip})")
    print(f"[*] Scanning {len(ports)} ports with {max_threads} threads\n")

    open_ports = []
    scanned = 0
    total = len(ports)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_port = {
            executor.submit(scan_port, ip, port, timeout): port
            for port in ports
        }

        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            scanned += 1

            if result["state"] == "open":
                open_ports.append(result)
                print(f"  [+] Port {result['port']:5d}/tcp  OPEN  {result['service']}")

            if progress_callback:
                progress_callback(scanned, total)

    open_ports.sort(key=lambda x: x["port"])

    elapsed = round(time.time() - start_time, 2)

    summary = {
        "target":        target,
        "ip":            ip,
        "scan_time":     datetime.now().isoformat(),
        "elapsed_sec":   elapsed,
        "total_scanned": total,
        "open_count":    len(open_ports),
        "open_ports":    open_ports,
        "has_http":      any(p["port"] in [80, 8080, 8000, 8081, 8082, 8083, 8088, 8090] for p in open_ports),
        "has_https":     any(p["port"] in [443, 8443, 4443, 7443, 9443] for p in open_ports),
        "has_web":       False
    }

    summary["has_web"] = summary["has_http"] or summary["has_https"]

    print(f"\n[*] Scan complete in {elapsed}s — {len(open_ports)} open ports found")
    return summary


if __name__ == "__main__":
    results = run_port_scan("127.0.0.1")
    print(f"\nOpen ports: {[p['port'] for p in results['open_ports']]}")