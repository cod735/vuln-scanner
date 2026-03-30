import json
import os
import sys
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

RESULTS_FILE = "data/scan_results.json"
HISTORY_FILE = "data/history.json"

socketio = SocketIO()


def load_results() -> dict:
    if os.path.exists(RESULTS_FILE):
        try:
            with open(RESULTS_FILE) as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def load_history() -> list:
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE) as f:
                return json.load(f)
        except Exception:
            return []
    return []


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET", "vuln_scanner_secret")
    socketio.init_app(app, cors_allowed_origins="*", async_mode="eventlet")

    # ── Page routes ───────────────────────────────────────────────

    @app.route("/")
    def index():
        data = load_results()
        return render_template("index.html", data=data)

    @app.route("/ports")
    def ports():
        data = load_results()
        return render_template("ports.html", data=data)

    @app.route("/cves")
    def cves():
        data = load_results()
        return render_template("cves.html", data=data)

    @app.route("/owasp")
    def owasp():
        data = load_results()
        return render_template("owasp.html", data=data)

    @app.route("/mitre")
    def mitre():
        data = load_results()
        return render_template("mitre.html", data=data)

    @app.route("/history")
    def history():
        data = load_history()
        return render_template("history.html", history=data)

    # ── REST API ──────────────────────────────────────────────────

    @app.route("/api/summary")
    def api_summary():
        data = load_results()
        return jsonify({
            "target":        data.get("target", ""),
            "ip":            data.get("ip", ""),
            "scan_time":     data.get("scan_time", ""),
            "elapsed_sec":   data.get("elapsed_sec", 0),
            "open_count":    data.get("open_count", 0),
            "has_web":       data.get("has_web", False),
            "os_detection":  data.get("os_detection", {}),
            "cve_summary":   data.get("cve_summary", {}),
            "owasp_summary": data.get("owasp_summary", {}),
            "mitre_summary": data.get("mitre_summary", {}),
        })

    @app.route("/api/ports")
    def api_ports():
        data = load_results()
        return jsonify(data.get("open_ports", []))

    @app.route("/api/cves")
    def api_cves():
        data = load_results()
        return jsonify(data.get("all_cves", []))

    @app.route("/api/owasp")
    def api_owasp():
        data = load_results()
        return jsonify(data.get("owasp_results", []))

    @app.route("/api/mitre")
    def api_mitre():
        data = load_results()
        return jsonify({
            "techniques":  data.get("mitre_results", []),
            "by_tactic":   data.get("mitre_by_tactic", {}),
            "summary":     data.get("mitre_summary", {}),
        })

    @app.route("/api/history")
    def api_history():
        return jsonify(load_history())

    @app.route("/api/results")
    def api_results():
        return jsonify(load_results())

    # ── Scan trigger via API ──────────────────────────────────────

    @app.route("/api/scan/start", methods=["POST"])
    def api_scan_start():
        body   = request.get_json() or {}
        target = body.get("target", "")

        if not target:
            return jsonify({"error": "target is required"}), 400

        def run_background_scan(target):
            try:
                from scanner.port_scanner import run_port_scan
                from scanner.fingerprint  import run_fingerprint
                from scanner.cve_lookup   import run_cve_lookup
                from scanner.owasp_checks import run_owasp_checks
                from scanner.mitre_mapper import run_mitre_mapping

                def progress(scanned, total):
                    socketio.emit("scan_progress", {
                        "scanned": scanned,
                        "total":   total,
                        "percent": round((scanned / total) * 100)
                    })

                socketio.emit("scan_status", {"status": "running", "layer": 1,
                                              "message": "Port discovery..."})
                result = run_port_scan(target, progress_callback=progress)

                socketio.emit("scan_status", {"status": "running", "layer": 2,
                                              "message": "Fingerprinting services..."})
                result = run_fingerprint(result)

                socketio.emit("scan_status", {"status": "running", "layer": 3,
                                              "message": "CVE lookup..."})
                result = run_cve_lookup(result)

                socketio.emit("scan_status", {"status": "running", "layer": 4,
                                              "message": "OWASP checks..."})
                result = run_owasp_checks(result)

                socketio.emit("scan_status", {"status": "running", "layer": 5,
                                              "message": "MITRE mapping..."})
                result = run_mitre_mapping(result)

                # Save
                os.makedirs("data", exist_ok=True)
                with open(RESULTS_FILE, "w") as f:
                    json.dump(result, f, indent=2, default=str)

                socketio.emit("scan_status", {"status": "complete",
                                              "message": "Scan complete!"})
                socketio.emit("scan_complete", result.get("cve_summary", {}))

            except Exception as e:
                socketio.emit("scan_status", {"status": "error",
                                              "message": str(e)})

        thread = threading.Thread(target=run_background_scan,
                                  args=(target,), daemon=True)
        thread.start()

        return jsonify({"status": "started", "target": target})

    @app.route("/api/scan/status")
    def api_scan_status():
        data = load_results()
        return jsonify({
            "last_scan": data.get("scan_time", "No scan yet"),
            "target":    data.get("target", ""),
        })

    return app, socketio


if __name__ == "__main__":
    app, socketio = create_app()
    print("[*] Starting Vulnerability Scanner Dashboard")
    print("[*] Open: http://localhost:5004")
    socketio.run(app, host="0.0.0.0", port=5004, debug=False)