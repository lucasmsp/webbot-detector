#!/usr/bin/env python3
"""
Standalone test with Selenium + selenium-stealth.
Allows passing the server URL as a command-line argument:
    python tests/teste_stealth.py http://localhost:8000
    python tests/teste_stealth.py https://seu-app.onrender.com
"""

import sys
import os
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium_stealth import stealth

# Read URL passed as CLI argument or environment variable, or default to localhost:8000
target_url = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("SERVER_URL", "http://localhost:8000")
print(f"🎯 Test target: {target_url}")

options = webdriver.ChromeOptions()
options.add_argument("start-maximized")
# Uncomment the line below to run in headless mode:
# options.add_argument("--headless=new")
options.add_argument("--no-sandbox")
options.add_argument("--disable-dev-shm-usage")
options.add_experimental_option("excludeSwitches", ["enable-automation"])
options.add_experimental_option('useAutomationExtension', False)

driver = webdriver.Chrome(options=options)

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
    driver.get(target_url)

    # Wait for sensor and server response
    wait = WebDriverWait(driver, 10)
    wait.until(lambda d: d.execute_script("return window.__latestBotResult !== undefined;"))

    resultado = driver.execute_script("return window.__latestBotResult;")
    print("
" + "=" * 50)
    print("RESPONSE RECEIVED FROM DETECTOR:")
    print("=" * 50)
    print(f"Classification: {resultado.get('label')}")
    print(f"Is Bot?         {resultado.get('isBot')}")
    print(f"Action:          {resultado.get('action')}")
    print(f"Session ID:     {resultado.get('sessionId')}")
    print("=" * 50)

    time.sleep(3)
finally:
    driver.quit()
