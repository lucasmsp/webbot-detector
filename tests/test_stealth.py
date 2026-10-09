#!/usr/bin/env python3
"""
Advanced Evasion Test with Selenium-Stealth (Pytest):
Validates whether deep detector heuristics (prototype traps,
platform/GPU inconsistency, native function integrity)
catch and dismantle scripts based on `selenium-stealth`.
"""

import time
import json
import shutil
import urllib.request
import pytest
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium_stealth import stealth


@pytest.mark.skipif(not shutil.which("google-chrome") and not shutil.which("chromium"), reason="Chrome/Chromium browser not found in PATH")
def test_selenium_stealth_detected(server_url):
    """Verifies whether Selenium with stealth evasion is caught by detector."""
    options = webdriver.ChromeOptions()
    options.add_argument("start-maximized")
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)

    driver = webdriver.Chrome(options=options)

    # Apply stealth evasion patches
    stealth(
        driver,
        languages=["en-US", "en"],
        vendor="Google Inc.",
        platform="Win32",
        webgl_vendor="Intel Inc.",
        renderer="Intel Iris OpenGL Engine",
        fix_hairline=True,
    )

    try:
        driver.get(server_url)

        # Wait for risk engine response
        wait = WebDriverWait(driver, 10)
        wait.until(lambda d: d.execute_script("return window.__latestBotResult !== undefined;"))

        latest_result = driver.execute_script("return window.__latestBotResult;")
        assert latest_result is not None, "window.__latestBotResult not populated"
        session_id = latest_result.get("sessionId")
        assert session_id, "Session ID not returned"

        # Verdict returned to client
        assert latest_result.get("isBot") is True, "Selenium Stealth must not pass as human"
        assert latest_result.get("action") == "BLOCK"

        # Query internal evaluation on server
        eval_req = urllib.request.Request(f"{server_url}/api/internal/session-evaluation?sessionId={session_id}")
        with urllib.request.urlopen(eval_req) as resp:
            server_eval = json.loads(resp.read().decode("utf-8"))

        assert server_eval.get("is_bot") is True
        assert len(server_eval.get("reasons", [])) > 0
    finally:
        driver.quit()
