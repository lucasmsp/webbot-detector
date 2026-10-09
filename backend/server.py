#!/usr/bin/env python3
"""
Risk Assessment and Automation Detection Server

Security Architecture:
- Serves the frontend application and passive telemetry sensor.
- POST /api/assess-risk route: Evaluates raw client signals and cross-references
  them with real HTTP headers on the server.
- Heuristic rules and decision logic remain hidden in the backend.
- Records each request and detailed evaluation in structured JSON logs.
"""

import http.server
import socketserver
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")
LOGS_DIR = os.path.join(BACKEND_DIR, "logs")
LOG_JSONL_FILE = os.path.join(LOGS_DIR, "access_logs.json")

# Ensure the backend directory is in sys.path
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from engine.risk_engine import RiskEngine
from engine.crypto_challenge import crypto_manager

PORT = int(os.environ.get("PORT", 8000))

# Ensure the logs directory exists
os.makedirs(LOGS_DIR, exist_ok=True)

risk_engine = RiskEngine()


def record_access_log(log_entry: dict):
    """
    Records detailed request and risk evaluation log in JSON format.
    - access_logs.json: Append-only format (1 JSON per line, industry standard JSONL).
    """
    try:
        with open(LOG_JSONL_FILE, "a", encoding="utf-8") as f_jsonl:
            f_jsonl.write(json.dumps(log_entry, ensure_ascii=False) + "\n")

    except Exception as e:
        print(f"Error saving access log: {e}", file=sys.stderr)


class SecureRiskHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=FRONTEND_DIR, **kwargs)

    def end_headers(self):
        # Allow CORS for full compatibility
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/challenge":
            challenge = crypto_manager.generate_challenge()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(challenge, ensure_ascii=False).encode("utf-8"))
            return

        if parsed.path == "/api/internal/session-evaluation":
            # Internal audit and test endpoint (server-to-server query)
            from urllib.parse import parse_qs
            query = parse_qs(parsed.query)
            query_session_id = query.get("sessionId", [""])[0]

            evaluation = None
            if os.path.exists(LOG_JSONL_FILE):
                with open(LOG_JSONL_FILE, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            if not query_session_id or entry.get("session_id") == query_session_id:
                                evaluation = entry.get("evaluation")
                        except json.JSONDecodeError:
                            continue

            if evaluation is not None:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(evaluation, ensure_ascii=False).encode("utf-8"))
            else:
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Session not found in risk records"}).encode("utf-8"))
            return

        if parsed.path == "/api/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "healthy",
                "service": "Incognia Bot Detection Risk Engine",
                "logging": {
                    "enabled": True,
                    "json_file": LOG_JSONL_FILE
                }
            }).encode("utf-8"))
            return

        super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/assess-risk":
            content_length = int(self.headers.get("Content-Length", 0))
            body_bytes = self.rfile.read(content_length)

            try:
                client_data = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"Invalid JSON: {str(e)}"}).encode("utf-8"))
                return

            payload_size_kb = content_length / 1024

            # Extract real HTTP request headers for server-side cross-validation
            request_headers = dict(self.headers)
            client_signals = client_data.get("signals", client_data)
            challenge_data = client_data.get("challenge")
            env_hash = client_data.get("environmentalHash")
            session_id = client_data.get("sessionId", f"sess_{uuid.uuid4().hex[:12]}")
            timestamp = datetime.now(timezone.utc).isoformat()
            client_ip = self.client_address[0] if self.client_address else "unknown"

            # Execute server-side risk evaluation rules engine with cryptographic validation
            assessment = risk_engine.assess(
                client_signals,
                request_headers,
                challenge=challenge_data,
                environmental_hash=env_hash,
                require_challenge=True
            )

            # Print request payload size and decision to server console
            print(f"[REQ] IP: {client_ip} | Session: {session_id} | Payload: {content_length:,} bytes ({payload_size_kb:.2f} KB) | Decision: {assessment['action']}")
            sys.stdout.flush()

            log_id = f"log_{uuid.uuid4().hex[:16]}"
            log_entry = {
                "timestamp": timestamp,
                "client_ip": client_ip,
                "session_id": session_id,
                "request": {
                    "method": "POST",
                    "path": "/api/assess-risk",
                    "payload_size_bytes": content_length,
                    "payload_size_kb": round(payload_size_kb, 2),
                    "headers": request_headers,
                    "challenge": challenge_data,
                    "environmentalHash": env_hash,
                    "signals": client_signals
                },
                "evaluation": {
                    "is_bot": assessment["isBot"],
                    "action": assessment["action"],
                    "total_categories_triggered": assessment["totalCategoriesTriggered"],
                    "reasons": assessment["reasons"],
                    "categories": assessment["categories"],
                    "server_engine": assessment.get("serverEvaluation", {})
                }
            }

            record_access_log(log_entry)

            is_bot = assessment["isBot"]
            client_response = {
                "sessionId": session_id,
                "timestamp": timestamp,
                "isBot": is_bot,
                "classification": "automacao" if is_bot else "humano",
                "label": "Acesso Automatizado / Bot" if is_bot else "Acesso Humano",
                "action": assessment["action"]
            }

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(client_response, indent=2, ensure_ascii=False).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()


def run_server(port=PORT):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(base_dir)

    socketserver.TCPServer.allow_reuse_address = True

    with socketserver.TCPServer(("", port), SecureRiskHandler) as httpd:
        print("=" * 65)
        print(f"Bot Detection Server & Risk Engine")
        print(f"Access in browser:    http://localhost:{port}")
        print(f"Risk Endpoint:        POST http://localhost:{port}/api/assess-risk")
        print("=" * 65)
        sys.stdout.flush()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped successfully.")


if __name__ == "__main__":
    port_arg = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    run_server(port_arg)
