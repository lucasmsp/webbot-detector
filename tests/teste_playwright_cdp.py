#!/usr/bin/env python3
"""
Automation Detection Test via Chrome DevTools Protocol (CDP):
Validates the attack scenario where an attacker launches a real Google Chrome binary
with the remote debugging port enabled (--remote-debugging-port=9222) and connects Playwright
via `connect_over_cdp("http://localhost:9222")`.

The V8 Inspector Trap (V8 Console & Getter Trap) neutralizes this evasion technique
when CDP inspects the internal V8 console.
"""

import subprocess
import time
import os
import signal
import json
from playwright.sync_api import sync_playwright

def run_cdp_test():
    import sys
    target_url = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else os.environ.get("SERVER_URL", "http://localhost:8000")

    print("=" * 70)
    print(" TEST: DIRECT CONNECTION VIA CDP (connect_over_cdp)")
    print(" Validating V8 Inspector Trap (V8 Console & Getter Trap)")
    print(f" Target: {target_url}")
    print("=" * 70)

    # 1. Launch a real Chrome instance with remote debugging port 9222
    chrome_proc = None
    profile_dir = "/tmp/chrome_cdp_test_profile"
    
    print("\n[1/4] Launching Google Chrome with --remote-debugging-port=9222...")
    chrome_proc = subprocess.Popen([
        "google-chrome",
        "--remote-debugging-port=9222",
        "--headless=new",
        "--no-sandbox",
        "--disable-gpu",
        f"--user-data-dir={profile_dir}"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    time.sleep(2)

    try:
        with sync_playwright() as p:
            print("[2/4] Connecting Playwright via p.chromium.connect_over_cdp('http://localhost:9222')...")
            browser = p.chromium.connect_over_cdp("http://localhost:9222")
            context = browser.contexts[0]
            page = context.new_page()

            # Playwright listens to console events and inspects V8 objects
            page.on("console", lambda msg: [arg.json_value() for arg in msg.args if arg])

            print(f"[3/4] Navigating to protected application ({target_url})...")
            page.goto(target_url)
            
            # Wait for telemetry collection and server response
            page.wait_for_function("window.__latestBotResult !== undefined", timeout=10000)
            
            client_receipt = page.evaluate("window.__latestBotResult")
            session_id = client_receipt.get("sessionId", "")
            
            print("\n[4/4] Response delivered to Client:")
            print("-" * 50)
            print(f"Client Classification: {client_receipt.get('label')} (isBot={client_receipt.get('isBot')})")
            print(f"Action: {client_receipt.get('action')}")
            print(f"Session ID: {session_id}")
            print("-" * 50)
            
            # Query confidential evaluation recorded on server (Backend-to-Backend)
            import urllib.request
            eval_req = urllib.request.Request(f"{target_url}/api/internal/session-evaluation?sessionId={session_id}")
            with urllib.request.urlopen(eval_req) as resp:
                server_eval = json.loads(resp.read().decode("utf-8"))
            
            is_bot = server_eval.get("is_bot", False)
            action = server_eval.get("action", "")
            reasons = server_eval.get("reasons", [])
            
            print("\n[5/5] Confidential Verdict on Server (Risk Engine Audit):")
            print("-" * 50)
            status_icon = "🤖 DETECTED AS BOT" if is_bot else "👤 IDENTIFIED AS HUMAN"
            print(f"Server Verdict: {status_icon}")
            print(f"Server Action: {action}")
            print("Identified Evidence:")
            for r in reasons:
                print(f" - {r}")
            print("-" * 50)
            
            browser.close()
            
            if is_bot and any("CDP" in r or "V8" in r for r in reasons):
                print("\n✅ SUCCESS: The V8 Inspector Trap captured the CDP connection successfully!")
                return True
            else:
                print("\n⚠️ WARNING: CDP connection was not classified with the expected trap.")
                return False

    finally:
        if chrome_proc:
            chrome_proc.terminate()
            chrome_proc.wait()

if __name__ == "__main__":
    run_cdp_test()