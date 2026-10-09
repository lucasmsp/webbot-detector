#!/usr/bin/env python3
"""
Chrome DevTools Protocol (CDP) Automation Detection Test with Pytest:
Validates the V8 Inspector Trap (V8 Console & Getter Trap) when an attacker
attaches Playwright via connect_over_cdp("http://localhost:9222").
"""

import subprocess
import time
import os
import json
import shutil
import urllib.request
import pytest
from playwright.sync_api import sync_playwright


chrome_bin = shutil.which("google-chrome") or shutil.which("chromium")


@pytest.mark.skipif(not chrome_bin, reason="google-chrome or chromium not found in PATH")
def test_connect_over_cdp_v8_trap(server_url):
    """Validates CDP connection detection via the V8 Inspector Trap."""
    profile_dir = "/tmp/chrome_cdp_test_profile"
    chrome_proc = subprocess.Popen([
        chrome_bin,
        "--remote-debugging-port=9222",
        "--headless=new",
        "--no-sandbox",
        "--disable-gpu",
        f"--user-data-dir={profile_dir}"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    time.sleep(2)

    try:
        with sync_playwright() as p:
            browser = p.chromium.connect_over_cdp("http://localhost:9222")
            context = browser.contexts[0]
            page = context.new_page()

            # Listen to console events triggering inspection of V8 arguments
            page.on("console", lambda msg: [arg.json_value() for arg in msg.args if arg])

            page.goto(server_url)
            page.wait_for_function("window.__latestBotResult !== undefined", timeout=10000)

            client_receipt = page.evaluate("window.__latestBotResult")
            session_id = client_receipt.get("sessionId", "")
            assert session_id, "Session ID not returned to client"
            assert client_receipt.get("isBot") is True
            assert client_receipt.get("action") == "BLOCK"

            # Query confidential evaluation recorded on the server
            eval_req = urllib.request.Request(f"{server_url}/api/internal/session-evaluation?sessionId={session_id}")
            with urllib.request.urlopen(eval_req) as resp:
                server_eval = json.loads(resp.read().decode("utf-8"))

            browser.close()

            reasons = server_eval.get("reasons", [])
            assert server_eval.get("is_bot") is True
            assert any("CDP" in r or "V8" in r for r in reasons), f"V8 trap not identified in reasons: {reasons}"
    finally:
        chrome_proc.terminate()
        chrome_proc.wait()
