#!/usr/bin/env python3
"""
E2E Playwright Evasion Test (Pytest):
Validates whether evasion scripts injected via Playwright (overriding navigator.webdriver,
plugins, and languages) are caught by prototype integrity detectors.
"""

import pytest
import shutil
import urllib.request
import json
from playwright.sync_api import sync_playwright


@pytest.mark.skipif(not shutil.which("google-chrome") and not shutil.which("chromium"), reason="Chromium browser not available")
def test_playwright_stealth_evasion_detected(server_url):
    """Verifies whether Playwright automation attempting evasion is detected."""
    chrome_bin = shutil.which("google-chrome") or shutil.which("chromium")
    with sync_playwright() as p:
        browser = p.chromium.launch(
            executable_path=chrome_bin,
            headless=True,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
                "--disable-dev-shm-usage"
            ]
        )

        context = browser.new_context(
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
            viewport={"width": 1366, "height": 768},
            locale="pt-BR"
        )

        # Inject typical bot evasion scripts
        context.add_init_script("""
            try {
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined,
                    configurable: true
                });
            } catch (e) {}

            try {
                Object.defineProperty(navigator, 'plugins', {
                    get: () => [1, 2, 3, 4, 5],
                    configurable: true
                });
            } catch (e) {}
        """)

        page = context.new_page()
        page.goto(server_url)

        # Wait for detector analysis
        page.wait_for_function("window.__latestBotResult !== undefined", timeout=10000)
        resultado = page.evaluate("window.__latestBotResult")

        assert resultado is not None, "window.__latestBotResult not populated"
        session_id = resultado.get("sessionId")
        assert session_id, "Session ID not returned"

        # Verdict delivered to client
        assert resultado.get("isBot") is True, "Playwright with evasion must be detected as bot"
        assert resultado.get("action") == "BLOCK"

        # Query internal server evaluation
        eval_req = urllib.request.Request(f"{server_url}/api/internal/session-evaluation?sessionId={session_id}")
        with urllib.request.urlopen(eval_req) as resp:
            server_eval = json.loads(resp.read().decode("utf-8"))

        browser.close()

        assert server_eval.get("is_bot") is True
        assert len(server_eval.get("reasons", [])) > 0
