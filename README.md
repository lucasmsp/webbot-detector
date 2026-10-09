# Bot Detection & Web Automation

Technical project for bot detection and web automation in a web environment with client-server architecture, multi-layered risk assessment, anti-CDP traps, and cryptographic challenges (Web Crypto API).

---

## Project Architecture

* **Frontend (`frontend/`):**
  * `index.html`: Visual access verification interface displaying the verdict (`Human Access` vs `Automated Access / Bot`).
  * `assets/collector.js`: Passive telemetry sensor collecting hardware and software signals, browser inconsistencies, and V8 Inspector Trap.
  * `assets/detector.js`: Client orchestrator that retrieves ephemeral cryptographic challenges, computes the Environmental Binding Hash via native Web Crypto API (`crypto.subtle.digest`), and dispatches the request.
  * `assets/utils.js`: Clean Realm utilities (isolated iframes), native getter validation, and interaction monitoring.

* **Backend (`backend/`):**
  * `server.py`: Pure Python HTTP server, providing static file endpoints and the `/api/challenge`, `/api/assess-risk`, `/api/health`, and internal audit routes.
  * `engine/risk_engine.py`: Deterministic multi-layered risk engine (Network/Protocol, W3C Automation, Browser Inconsistencies, Advanced Evasions, and Hardware Integrity).
  * `engine/crypto_challenge.py`: HMAC-SHA256 cryptographic challenge manager and auto-expiring `NonceStore` for blocking Replay Attacks.

* **Tests (`tests/`):**
  * Comprehensive automated test suite with **pytest** supporting URL override via command-line parameter (`--url`). See detailed documentation in [tests/README.md](tests/README.md).

---

## How to Run

The application is available at: **`https://webbot-detector.onrender.com`** (depending on whether it's running or not, it can take a few seconds to start). Besides that, one can run locally:

### Option 1: Pure Python

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

python run_server.py
```
Access the application in your browser at: **`http://localhost:8000`**

---

### Option 2: Docker

```bash
# 1.a) Build the Docker image
docker build -t lucasmsp/webbot-detector .

# 1.b) or pull the image from DockerHub
docker pull lucasmsp/webbot-detector

# 2. Run the container mapping port 8000
docker run -d -p 8000:8000 --name webbot-app lucasmsp/webbot-detector
```


Access the application at: **`http://localhost:8000`**

---

## 🧪 How to Run Tests

Run the full test suite with pytest:
```bash
# Default local execution (auto-starts backend if offline)
pytest

# Execution targeting a specific URL (Render, Docker, staging):
pytest --url=https://webbot-detector.onrender.com/
pytest --url=http://localhost:8000
```

For details on each test scenario and running individual scripts, refer to [tests/README.md](tests/README.md).
