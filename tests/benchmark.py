#!/usr/bin/env python3
"""
Performance Benchmark Suite for Bot Detection & Risk Assessment
Measures:
1. Server-side Risk Engine decision latency (microsecond resolution).
2. Cryptographic operations throughput (HMAC challenges, nonces, environmental binding).
3. Telemetry payload size analysis (breakdown and real-world log statistics).
4. Optional End-to-End HTTP roundtrip latency against local or remote deployment.
"""

import sys
import os
import time
import json
import statistics
import urllib.request
import argparse

# Setup imports
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from engine.risk_engine import RiskEngine
from engine.crypto_challenge import CryptoChallengeManager


def get_sample_telemetry():
    """Returns a realistic full telemetry payload for benchmarking."""
    return {
        "userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        "webdriver": False,
        "languages": ["pt-BR", "pt", "en-US"],
        "platform": "Linux x86_64",
        "vendor": "Google Inc.",
        "cookieEnabled": True,
        "windowProperties": [
            "getCleanRealm", "isNativeGetter", "collectTelemetrySignals",
            "getRiskApiEndpoint", "detectBot", "chrome"
        ],
        "documentProperties": [],
        "navigatorProperties": [],
        "browserFeatures": {
            "hasOpr": False,
            "hasSafari": False,
            "hasInstallTrigger": False,
            "mozInnerScreenX": None,
            "mozInnerScreenY": None,
            "oscpu": ""
        },
        "permissions": {"state": "prompt", "notificationPermission": "default"},
        "brokenImage": {"width": 16, "height": 16, "isZero": False},
        "chromeObject": {"hasChrome": True, "hasRuntime": True, "cleanRealmHasChrome": True},
        "seleniumExtended": {"cdcAttributeFound": False, "docElemAttrs": [], "sequentumFound": False},
        "pluginsInfo": {"length": 5, "isPluginArray": True, "firstPluginToString": "[object Plugin]"},
        "videoCodecs": {"h264": "probably"},
        "screen": {"width": 1920, "height": 1080, "colorDepth": 24},
        "windowDimensions": {"outerWidth": 1920, "outerHeight": 1040, "innerWidth": 1920, "innerHeight": 950},
        "webgl": {"renderer": "ANGLE (Intel, Intel(R) HD Graphics 530, OpenGL 4.5)", "vendor": "Google Inc."},
        "touch": {"hasTouchEvents": False, "maxTouchPoints": 0},
        "syntheticEvents": [],
        "prototypeIntegrity": {
            "webdriverIllegalInvocationFailed": False,
            "navigatorProtoMismatch": False,
            "functionToStringTampered": False
        },
        "sessionInfo": {"historyLength": 5, "referrer": "https://google.com"}
    }


def benchmark_risk_engine(iterations: int = 2000, warmup: int = 100):
    print(f"\n[1/4] Benchmarking Risk Engine Decision Latency ({iterations:,} iterations)...")
    engine = RiskEngine()
    crypto = CryptoChallengeManager()

    signals = get_sample_telemetry()
    challenge = crypto.generate_challenge()
    env_hash = crypto.compute_expected_environmental_hash(challenge["nonce"], signals)
    headers = {
        "user-agent": signals["userAgent"],
        "sec-ch-ua": '"Chromium";v="130", "Google Chrome";v="130"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate"
    }

    # Warmup
    for _ in range(warmup):
        engine.assess(signals, headers, challenge=challenge, environmental_hash=env_hash, require_challenge=False)

    latencies_us = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        engine.assess(signals, headers, challenge=challenge, environmental_hash=env_hash, require_challenge=False)
        t1 = time.perf_counter()
        latencies_us.append((t1 - t0) * 1_000_000)

    mean_us = statistics.mean(latencies_us)
    median_us = statistics.median(latencies_us)
    p95_us = statistics.quantiles(latencies_us, n=100)[94] if len(latencies_us) >= 100 else max(latencies_us)
    p99_us = statistics.quantiles(latencies_us, n=100)[98] if len(latencies_us) >= 100 else max(latencies_us)
    min_us = min(latencies_us)
    max_us = max(latencies_us)
    ops_per_sec = 1_000_000 / mean_us if mean_us > 0 else 0

    print("  +--------------------------------------------------------------+")
    print("  | Metric                           | Value                     |")
    print("  +--------------------------------------------------------------+")
    print(f"  | Mean Decision Latency            | {mean_us / 1000:8.4f} ms ({mean_us:7.1f} us)   |")
    print(f"  | Median Latency (p50)             | {median_us / 1000:8.4f} ms ({median_us:7.1f} us)   |")
    print(f"  | 95th Percentile (p95)            | {p95_us / 1000:8.4f} ms ({p95_us:7.1f} us)   |")
    print(f"  | 99th Percentile (p99)            | {p99_us / 1000:8.4f} ms ({p99_us:7.1f} us)   |")
    print(f"  | Min Latency                      | {min_us / 1000:8.4f} ms ({min_us:7.1f} us)   |")
    print(f"  | Max Latency                      | {max_us / 1000:8.4f} ms ({max_us:7.1f} us)   |")
    print(f"  | Throughput (Evaluations / Sec)   | {ops_per_sec:12,.0f} ops/s        |")
    print("  +--------------------------------------------------------------+")
    return mean_us


def benchmark_crypto_module(iterations: int = 5000):
    print(f"\n[2/4] Benchmarking Cryptographic Operations ({iterations:,} iterations)...")
    crypto = CryptoChallengeManager()
    signals = get_sample_telemetry()

    # 1. Challenge Generation
    t0 = time.perf_counter()
    challenges = [crypto.generate_challenge() for _ in range(iterations)]
    t1 = time.perf_counter()
    gen_time_us = ((t1 - t0) / iterations) * 1_000_000

    # 2. Challenge Verification
    # Create fresh manager to avoid replay on valid items
    verify_crypto = CryptoChallengeManager()
    t0 = time.perf_counter()
    for ch in challenges:
        verify_crypto.verify_challenge(ch)
    t1 = time.perf_counter()
    verify_time_us = ((t1 - t0) / iterations) * 1_000_000

    # 3. Environmental Hash Computation
    ch = challenges[0]
    t0 = time.perf_counter()
    for _ in range(iterations):
        crypto.compute_expected_environmental_hash(ch["nonce"], signals)
    t1 = time.perf_counter()
    env_time_us = ((t1 - t0) / iterations) * 1_000_000

    print("  +--------------------------------------------------------------+")
    print("  | Operation                        | Avg Latency   | Throughput|")
    print("  +--------------------------------------------------------------+")
    print(f"  | Challenge Generation (HMAC+Nonce)| {gen_time_us:7.2f} us   | {1_000_000/gen_time_us:9,.0f}/s |")
    print(f"  | Challenge Verification (Lifespan)| {verify_time_us:7.2f} us   | {1_000_000/verify_time_us:9,.0f}/s |")
    print(f"  | Environmental Binding Hash       | {env_time_us:7.2f} us   | {1_000_000/env_time_us:9,.0f}/s |")
    print("  +--------------------------------------------------------------+")


def benchmark_payload_size():
    print("\n[3/4] Analyzing Telemetry Payload Sizes...")
    crypto = CryptoChallengeManager()
    signals = get_sample_telemetry()
    challenge = crypto.generate_challenge()
    env_hash = crypto.compute_expected_environmental_hash(challenge["nonce"], signals)

    full_payload = {
        "signals": signals,
        "challenge": challenge,
        "environmentalHash": env_hash
    }

    full_json = json.dumps(full_payload)
    signals_json = json.dumps(signals)
    challenge_json = json.dumps(challenge)

    full_bytes = len(full_json.encode("utf-8"))
    signals_bytes = len(signals_json.encode("utf-8"))
    challenge_bytes = len(challenge_json.encode("utf-8"))
    hash_bytes = len(env_hash.encode("utf-8"))

    print("  +--------------------------------------------------------------+")
    print("  | Payload Component                | Bytes       | Size (KB)   |")
    print("  +--------------------------------------------------------------+")
    print(f"  | Signals (22 Hardware Categories) | {signals_bytes:6,d} B    | {signals_bytes/1024:6.2f} KB   |")
    print(f"  | Challenge Token (HMAC + Nonce)   | {challenge_bytes:6,d} B    | {challenge_bytes/1024:6.2f} KB   |")
    print(f"  | Environmental Hash               | {hash_bytes:6,d} B    | {hash_bytes/1024:6.2f} KB   |")
    print("  +--------------------------------------------------------------+")
    print(f"  | Total Synthesized Payload        | {full_bytes:6,d} B    | {full_bytes/1024:6.2f} KB   |")
    print("  +--------------------------------------------------------------+")

    # Check real-world logs if available
    log_file = os.path.join(BACKEND_DIR, "logs", "access_logs.json")
    if os.path.exists(log_file):
        sizes = []
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        entry = json.loads(line)
                        req = entry.get("request", {})
                        if "payload_size_bytes" in req:
                            sizes.append(req["payload_size_bytes"])
                    except Exception:
                        pass
        if sizes:
            avg_log_bytes = statistics.mean(sizes)
            print(f"  Real-World Log Sample ({len(sizes)} requests analyzed):")
            print(f"   - Average Size: {avg_log_bytes:,.0f} bytes ({avg_log_bytes/1024:.2f} KB)")
            print(f"   - Min Size:     {min(sizes):,d} bytes ({min(sizes)/1024:.2f} KB)")
            print(f"   - Max Size:     {max(sizes):,d} bytes ({max(sizes)/1024:.2f} KB)")


def benchmark_http_roundtrip(target_url: str, requests_count: int = 50):
    print(f"\n[4/4] Benchmarking End-to-End HTTP Round-Trip against {target_url} ({requests_count} requests)...")
    base_url = target_url.rstrip("/")
    health_url = f"{base_url}/api/health"
    challenge_url = f"{base_url}/api/challenge"
    assess_url = f"{base_url}/api/assess-risk"

    is_remote = not ("localhost" in base_url or "127.0.0.1" in base_url)
    timeout_sec = 15 if is_remote else 5

    # Health check probe
    try:
        probe_req = urllib.request.Request(
            health_url,
            headers={"User-Agent": "Incognia-Benchmark-Probe/1.0"}
        )
        with urllib.request.urlopen(probe_req, timeout=timeout_sec) as r:
            if r.status != 200:
                print(f"  Server healthcheck returned status {r.status}. Skipping HTTP benchmark.")
                return
    except Exception as e:
        print(f"  Unable to connect to {health_url} ({e}).")
        print("  (Tip: If running locally, execute 'python run_server.py' first)")
        return

    signals = get_sample_telemetry()
    crypto = CryptoChallengeManager()

    latencies_ms = []
    failed_requests = 0

    for i in range(requests_count):
        print(f"\r  Progress: [{i + 1}/{requests_count}] requests completed...", end="", flush=True)
        success = False
        attempts = 0
        max_attempts = 3 if is_remote else 1

        while not success and attempts < max_attempts:
            attempts += 1
            t0 = time.perf_counter()
            try:
                # 1. Fetch ephemeral cryptographic challenge
                req_ch = urllib.request.Request(
                    challenge_url,
                    headers={
                        "User-Agent": signals["userAgent"],
                        "Connection": "close"
                    }
                )
                with urllib.request.urlopen(req_ch, timeout=timeout_sec) as resp:
                    raw_ch = resp.read()
                    if not raw_ch:
                        raise ValueError("Empty response received from /api/challenge")
                    challenge_data = json.loads(raw_ch.decode("utf-8"))

                # 2. Compute expected environmental hash
                env_hash = crypto.compute_expected_environmental_hash(challenge_data["nonce"], signals)

                # 3. Submit full risk evaluation payload
                payload = json.dumps({
                    "signals": signals,
                    "challenge": challenge_data,
                    "environmentalHash": env_hash
                }).encode("utf-8")

                req_assess = urllib.request.Request(
                    assess_url,
                    data=payload,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": signals["userAgent"],
                        "Sec-CH-UA": '"Chromium";v="130", "Google Chrome";v="130"',
                        "Connection": "close"
                    }
                )
                with urllib.request.urlopen(req_assess, timeout=timeout_sec) as resp:
                    raw_assess = resp.read()
                    if not raw_assess:
                        raise ValueError("Empty response received from /api/assess-risk")
                    resp_data = json.loads(raw_assess.decode("utf-8"))
                    assert resp_data.get("action") == "ALLOW", f"Unexpected action: {resp_data.get('action')}"

                t1 = time.perf_counter()
                latencies_ms.append((t1 - t0) * 1000)
                success = True

            except Exception as e:
                if attempts >= max_attempts:
                    failed_requests += 1
                    # print warning only on final failure
                    print(f"\n  [Notice] Request {i + 1} failed after {max_attempts} attempts: {e}")
                else:
                    time.sleep(0.5)

    print() # newline after progress bar

    if not latencies_ms:
        print("  All HTTP roundtrip requests failed. Check network or server status.")
        return

    avg_ms = statistics.mean(latencies_ms)
    med_ms = statistics.median(latencies_ms)
    p95_ms = statistics.quantiles(latencies_ms, n=20)[18] if len(latencies_ms) >= 20 else max(latencies_ms)
    min_ms = min(latencies_ms)
    max_ms = max(latencies_ms)

    print("  +--------------------------------------------------------------+")
    print("  | HTTP Metric                      | Value                     |")
    print("  +--------------------------------------------------------------+")
    print(f"  | Average Round-Trip (Full Flow)   | {avg_ms:8.2f} ms               |")
    print(f"  | Median Round-Trip (p50)          | {med_ms:8.2f} ms               |")
    print(f"  | 95th Percentile Round-Trip (p95) | {p95_ms:8.2f} ms               |")
    print(f"  | Min Round-Trip                   | {min_ms:8.2f} ms               |")
    print(f"  | Max Round-Trip                   | {max_ms:8.2f} ms               |")
    if failed_requests > 0:
        print(f"  | Success Rate                     | {len(latencies_ms)}/{requests_count} ({len(latencies_ms)/requests_count*100:.1f}%)        |")
    print("  +--------------------------------------------------------------+")


def main():
    parser = argparse.ArgumentParser(description="Run technical benchmarks for the Bot Detection system.")
    parser.add_argument("--url", default="http://localhost:8000", help="Target server URL for HTTP roundtrip test")
    parser.add_argument("--iterations", type=int, default=2000, help="Number of iterations for RiskEngine benchmark")
    parser.add_argument("--skip-http", action="store_true", help="Skip HTTP network roundtrip benchmark")
    args = parser.parse_args()

    print("=" * 66)
    print(" BOT DETECTION & RISK ENGINE - PERFORMANCE BENCHMARK SUITE")
    print("=" * 66)

    benchmark_risk_engine(iterations=args.iterations)
    benchmark_crypto_module()
    benchmark_payload_size()

    if not args.skip_http:
        benchmark_http_roundtrip(target_url=args.url)

    print("\n" + "=" * 66)
    print(" BENCHMARK COMPLETED SUCCESSFULLY!")
    print("=" * 66 + "\n")


if __name__ == "__main__":
    main()
