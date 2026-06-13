"""
OJS WAF — live web dashboard.

A dependency-free (stdlib + pandas) HTTP server that visualises the WAF's
activity and the host's health:

  * blocked / passed requests and block-rate
  * attack-type breakdown and top offending source IPs
  * a live requests-per-minute traffic chart
  * a table of the most recent requests (filterable to blocked only)
  * host CPU / memory / network usage read straight from /proc

Data source : dataset/labeled/YYYY-MM-DD.csv  (written by core/sidecar_agent.py)
System stats : /proc                            (tools/system_metrics.py)

Run
---
    python -m tools.waf_dashboard                 # 127.0.0.1:8088
    python -m tools.waf_dashboard --host 0.0.0.0 --port 9000

Bind to 127.0.0.1 (default) on a production WAF box and reach it via an SSH
tunnel; only expose 0.0.0.0 on a trusted management network.
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from tools import system_metrics, waf_logs
from tools.dashboard_page import PAGE


class Handler(BaseHTTPRequestHandler):
    server_version = "OJSWafDashboard/1.0"

    # --- helpers ----------------------------------------------------------
    def _send(self, body: bytes, ctype: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj: object, status: int = 200) -> None:
        self._send(json.dumps(obj).encode(), "application/json; charset=utf-8", status)

    # --- routing ----------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qs = parse_qs(parsed.query)
        try:
            if path == "/":
                self._send(PAGE.encode(), "text/html; charset=utf-8")
            elif path == "/api/stats":
                self._json({
                    "waf": waf_logs.summary(),
                    "system": system_metrics.snapshot(),
                })
            elif path == "/api/events":
                limit = min(int(qs.get("limit", ["60"])[0]), 500)
                only_blocked = qs.get("blocked", ["0"])[0] in ("1", "true")
                self._json(waf_logs.recent_events(limit=limit, only_blocked=only_blocked))
            elif path == "/api/timeseries":
                minutes = min(int(qs.get("minutes", ["60"])[0]), 720)
                self._json(waf_logs.timeseries(minutes=minutes))
            elif path == "/api/health":
                self._json({"status": "ok"})
            else:
                self._json({"error": "not found"}, status=404)
        except Exception as exc:  # keep the dashboard alive on any read error
            self._json({"error": str(exc)}, status=500)

    def log_message(self, fmt: str, *args) -> None:  # quieter logging
        return


def main() -> None:
    parser = argparse.ArgumentParser(description="OJS WAF live dashboard")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind address (default 127.0.0.1; use 0.0.0.0 only on a trusted net)")
    parser.add_argument("--port", type=int, default=8088)
    args = parser.parse_args()

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"[*] OJS WAF dashboard -> http://{args.host}:{args.port}")
    print(f"[*] Reading logs from : {waf_logs.LABELED_DIR}")
    print("[*] Ctrl-C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
        httpd.shutdown()


if __name__ == "__main__":
    main()
