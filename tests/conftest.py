import os
import sys
import time
import json
import subprocess
import urllib.request
import pytest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(TESTS_DIR)
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")

if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

DEFAULT_SERVER_URL = "http://localhost:8000"


def pytest_addoption(parser):
    """Allows passing server URL via command-line argument: pytest --url=<URL>"""
    parser.addoption(
        "--url",
        action="store",
        default=os.environ.get("SERVER_URL", None),
        help="Base server URL for test execution (e.g. --url=http://localhost:8000 or --url=https://your-app.onrender.com)"
    )


def is_server_healthy(url, timeout=2):
    try:
        with urllib.request.urlopen(f"{url}/api/health", timeout=timeout) as response:
            return response.status == 200
    except Exception:
        return False


@pytest.fixture(scope="session")
def server_url(request):
    """
    Fixture providing the target server URL for the test suite.
    - If specified via `--url` or `SERVER_URL` environment variable, uses that URL.
    - Otherwise, defaults to http://localhost:8000.
    - If URL is localhost and server is offline, starts the local backend automatically.
    """
    cli_url = request.config.getoption("--url")
    if cli_url:
        target_url = cli_url.rstrip("/")
        yield target_url
        return

    # Default behavior: localhost:8000
    if is_server_healthy(DEFAULT_SERVER_URL):
        yield DEFAULT_SERVER_URL
        return

    # Start local server if not running
    server_script = os.path.join(BACKEND_DIR, "server.py")
    proc = subprocess.Popen(
        [sys.executable, server_script],
        cwd=BACKEND_DIR,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    started = False
    for _ in range(30):
        time.sleep(0.2)
        if is_server_healthy(DEFAULT_SERVER_URL):
            started = True
            break

    if not started:
        proc.terminate()
        raise RuntimeError("Failed to start local server for test execution.")

    try:
        yield DEFAULT_SERVER_URL
    finally:
        proc.terminate()
        proc.wait()


@pytest.fixture
def browser_headers():
    return {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "Sec-CH-UA": '"Chromium";v="128", "Google Chrome";v="128"',
        "X-Requested-With": "Incognia-Case-Sensor"
    }
