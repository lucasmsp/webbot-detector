# 🧪 Automated Test Suite — Bot Detection & Automation

This directory contains the complete automated test suite for the bot detection and telemetry integrity system, implemented using the **pytest** framework.

---

## 🚀 How to Run the Tests

### 1. Prerequisites
Ensure that the virtual environment is activated and dependencies are installed:
```bash
source venv/bin/activate
pip install -r requirements.txt
```

---

### 2. Quick Run (Localhost with Auto-Start)
If no parameters are provided, pytest checks whether the local server is running on port 8000. If offline, **pytest automatically starts the backend server** for the test session and shuts it down upon completion:

```bash
pytest
```

---

### 3. Running Against a Custom URL (Deploy, Render, Docker)

You can target tests at any remote or custom local environment by passing the `--url` parameter:

```bash
# Test application hosted on Render
pytest --url=https://webbot-detector.onrender.com

# Test on another local port or Docker container
pytest --url=http://localhost:8000
```


---

### 4. Partial Execution and Filters

#### Run only a specific test file:
```bash
# Only cryptographic and anti-replay tests
pytest tests/test_crypto_challenges.py --url=http://localhost:8000

# Only Selenium Stealth test
pytest tests/test_stealth.py --url=http://localhost:8000

# Only V8 Inspector Trap via CDP test
pytest tests/test_playwright_cdp.py --url=http://localhost:8000
```

#### Filter by test name or keyword (`-k`):
```bash
# Run only tests that verify human access (Zero False Positives)
pytest -k "human"

# Run only tests simulating evasions and bots
pytest -k "stealth or cdp"

# Run only cryptographic tests
pytest -k "crypto"
```

---

## 📋 Test Suite Breakdown: What Each Test Does

The suite covers everything from network/protocol cryptographic integrity to adversarial emulation in real browsers with evasion libraries:

```
tests/
├── conftest.py                   # Pytest fixtures (--url support and server auto-start)
├── test_crypto_challenges.py     # Cryptographic Challenges, Anti-Replay, and Environmental Binding
├── test_multi_browser.py         # Multi-Browser Heuristics (Chrome, Firefox, Safari, Edge, Opera)
├── test_playwright_cdp.py        # Direct CDP Connection Detection (V8 Inspector & Getter Trap)
├── test_stealth.py               # Advanced Evasion with Selenium + selenium-stealth
└── test_playwright.py            # Playwright automation and stealth script injection
```

---

### 1. `test_crypto_challenges.py` — Cryptography, Anti-Replay, and Environmental Binding

Ensures that **no forged or simulated HTTP request** can submit telemetry directly to the API without executing through the genuine browser runtime.

* **`test_missing_challenge_blocked`:**
  * **What it does:** Sends telemetry without previously requesting a challenge from the `/api/challenge` endpoint.
  * **Objective:** Blocks standalone calls made via cURL, HTTP scrapers, or headless bots without a real browser.
* **`test_forged_hmac_signature_blocked`:**
  * **What it does:** Submits a challenge with a randomly generated HMAC-SHA256 signature.
  * **Objective:** Ensures attackers cannot forge challenge credentials without the server secret key.
* **`test_expired_challenge_blocked`:**
  * **What it does:** Generates a valid signature but with a timestamp older than 30 seconds.
  * **Objective:** Prevents replay and reuse of previously captured tokens.
* **`test_replay_attack_blocked`:**
  * **What it does:** Submits a legitimate request (approved) and immediately replays the exact same challenge and nonce.
  * **Objective:** Validates in-memory `NonceStore` with auto-expiration, stopping replay attacks (**Anti-Replay**).
* **`test_environmental_binding_tampering_blocked`:**
  * **What it does:** The client calculates a SHA-256 hash bound to machine characteristics (Web Crypto API), but an attacker modifies the GPU string in the JSON payload (`tampered_signals`) prior to POST.
  * **Objective:** Detects in-transit telemetry tampering (**Environmental Binding Mismatch**).
* **`test_legitimate_flow_allowed`:**
  * **What it does:** Complete fresh flow (fresh challenge + valid HMAC signature + environmental hash matching signals).
  * **Objective:** Proves that legitimate access receives human classification (`ALLOW`).

---

### 2. `test_multi_browser.py` — Multi-Browser Heuristics & Inconsistencies

Ensures that the engine accurately identifies multiple browser engines without producing false positives for humans, while catching User-Agent spoofing.

* **`test_human_legitimate_browsers` *(Parametrized — 5 scenarios)*:**
  * **Browsers tested:** Mozilla Firefox, Google Chrome, Opera, Apple Safari (macOS), and Microsoft Edge.
  * **Objective:** Guarantees **Zero False Positives** for genuine human users on their respective operating systems and browsers.
* **`test_bot_and_evasion_scenarios` *(Parametrized — 6 scenarios)*:**
  * **Firefox with GeckoDriver:** Detects W3C flag `navigator.webdriver = true`.
  * **Firefox with spoofed vendor:** Catches stealth scripts injecting `vendor = 'Google Inc.'` into Firefox.
  * **Firefox with mock `window.chrome`:** Identifies accidental Chrome mock injection into Gecko-based engines.
  * **Opera without `window.opr`:** Identifies fake Opera User-Agent where the native `window.opr` object is missing.
  * **Safari on Linux:** Identifies fake Safari claiming Linux platform (`navigator.platform = 'Linux x86_64'`).
  * **Edge with MSEdgeDriver:** Detects active Edge Driver automation.
* **`test_real_selenium_firefox`:**
  * **What it does:** Launches a real Firefox browser in headless mode via GeckoDriver (if installed) against the protected application.

---

### 3. `test_playwright_cdp.py` — CDP Connection Detection & V8 Inspector Trap

Tests the most sophisticated Chrome attack vector: attaching automation directly to a running browser with `--remote-debugging-port=9222` via Chrome DevTools Protocol (`connect_over_cdp`).

* **`test_connect_over_cdp_v8_trap`:**
  * **What it does:** Launches a genuine Google Chrome instance with remote debugging port 9222 and connects Playwright via CDP. Playwright registers console listeners (`page.on('console')`).
  * **Objective:** Validates the **V8 Inspector Trap** implemented in the frontend (`collector.js`), which injects getter traps into V8 log properties. When DevTools/CDP inspects the object, the secret getter fires, signaling active debugging tools.

---

### 4. `test_stealth.py` — Advanced Evasion with Selenium-Stealth

Tests whether the detector integrity traps defuse popular evasion libraries in the Python automation ecosystem.

* **`test_selenium_stealth_detected`:**
  * **What it does:** Launches an automated Chrome instance via Selenium and applies `selenium_stealth.stealth()` patching languages, vendor, Win32 platform, hairline, and WebGL renderer.
  * **Objective:** Proves that deep integrity checks (prototype traps, inherited properties, `Function.prototype.toString` integrity, and hardware anomalies) detect automation even when masked by `selenium-stealth`.

---

### 5. `test_playwright.py` — Playwright Evasion & Script Injection

Validates resilience against Playwright-based automations attempting to override native variables via `context.add_init_script`.

* **`test_playwright_stealth_evasion_detected`:**
  * **What it does:** Launches Chromium with `--disable-blink-features=AutomationControlled` and injects scripts overriding `navigator.webdriver` and `navigator.plugins`.
  * **Objective:** Confirms that Clean Realm (isolated iframe) and illegal getter invocation checks detect tampering at runtime.

---

## 📌 Standalone Legacy Scripts (Direct Execution)

If you wish to execute the standalone scripts directly with the Python interpreter without pytest, all of them accept the target URL as a command-line parameter:

```bash
# Selenium-Stealth test targeting a specific URL:
python tests/teste_stealth.py https://webbot-detector.onrender.com

# CDP connection test targeting the desired URL:
python tests/teste_playwright_cdp.py http://localhost:8000

# Cryptographic challenge test targeting the desired URL:
python tests/teste_crypto_challenges.py https://webbot-detector.onrender.com

# Basic Selenium bot test:
python tests/teste_bot.py http://localhost:8000
```
