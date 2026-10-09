from selenium import webdriver
import os
import time
import urllib.request
import sys

def is_server_running(url="http://localhost:8000/api/health"):
    try:
        with urllib.request.urlopen(url, timeout=1) as response:
            return response.status == 200
    except Exception:
        return False

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(TESTS_DIR)

target_arg = sys.argv[1] if len(sys.argv) > 1 else None

if target_arg:
    caminho_alvo = target_arg
    print(f"🌐 Connecting to server via parameter: {caminho_alvo}")
elif is_server_running():
    caminho_alvo = "http://localhost:8000"
    print("🌐 Connecting to Risk Assessment Server: http://localhost:8000")
else:
    caminho_alvo = "file://" + os.path.join(PROJECT_ROOT, "frontend", "index.html")
    print("⚠️ Server not detected at localhost:8000. Opening local file via file://")
    print("   (Tip: run 'python backend/server.py' for full multi-layer assessment)")

print("Starting browser via Automation (Selenium)...")
# Launch Google Chrome controlled by automation
driver = webdriver.Chrome()

# Navigate to target page
driver.get(caminho_alvo)

print("Page opened! Check the browser window opened by automation.")
# Keep the browser open for 5 seconds for visual inspection
time.sleep(5)

driver.quit()
print("Browser closed successfully.")
