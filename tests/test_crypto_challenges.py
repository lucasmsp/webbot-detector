#!/usr/bin/env python3
"""
Cryptographic, Anti-Replay, and Environmental Binding Tests (Pytest).
Validates:
1. Blocking standalone requests without prior challenge.
2. Blocking challenges with forged HMAC signatures.
3. Blocking expired challenges (> 30s).
4. Blocking Replay Attacks (reuse of consumed nonces).
5. Blocking telemetry tampering (Environmental Binding Mismatch).
6. Approving legitimate flows.
"""

import json
import urllib.request
import urllib.error
import hashlib
import time
import hmac
import pytest

from engine.crypto_challenge import CryptoChallengeManager

HMAC_SECRET = b"incognia-case-v8-crypto-secret-2026-key"


def get_challenge(base_url):
    req = urllib.request.Request(f"{base_url}/api/challenge")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def get_session_evaluation(base_url, session_id):
    req = urllib.request.Request(f"{base_url}/api/internal/session-evaluation?sessionId={session_id}")
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return {}


def send_assessment(base_url, payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}/api/assess-risk",
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": payload.get("signals", {}).get("userAgent", "Mozilla/5.0"),
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Sec-CH-UA": '"Chromium";v="128", "Google Chrome";v="128"',
            "X-Requested-With": "Incognia-Case-Sensor"
        }
    )
    with urllib.request.urlopen(req) as resp:
        client_receipt = json.loads(resp.read().decode("utf-8"))
        session_id = client_receipt.get("sessionId")
        server_eval = get_session_evaluation(base_url, session_id) if session_id else {}
        return {
            "clientReceipt": client_receipt,
            "isBot": client_receipt.get("isBot", server_eval.get("is_bot")),
            "action": client_receipt.get("action", server_eval.get("action")),
            "reasons": server_eval.get("reasons", []),
            "categories": server_eval.get("categories", {})
        }


def compute_env_hash(nonce, signals):
    screen = signals.get("screen", {})
    webgl = signals.get("webgl", {})
    parts = [
        str(nonce or ""),
        str(signals.get("userAgent", "")),
        str(screen.get("width", 0)),
        str(screen.get("height", 0)),
        str(screen.get("colorDepth", 0)),
        str(signals.get("hardwareConcurrency", "")),
        str(webgl.get("renderer", "")),
        str(signals.get("platform", ""))
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


@pytest.fixture
def clean_signals():
    return {
        "userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "webdriver": False,
        "languages": ["pt-BR", "en-US"],
        "hardwareConcurrency": 8,
        "deviceMemory": 16,
        "platform": "Linux x86_64",
        "vendor": "Google Inc.",
        "cookieEnabled": True,
        "windowProperties": ["getCleanRealm", "detectBot"],
        "documentProperties": [],
        "navigatorProperties": [],
        "permissions": {"state": "prompt", "notificationPermission": "default"},
        "brokenImage": {"width": 16, "height": 16, "isZero": False},
        "chromeObject": {"hasChrome": True, "hasRuntime": True, "cleanRealmHasChrome": True},
        "browserFeatures": {"hasOpr": False, "hasSafari": False, "hasInstallTrigger": False},
        "seleniumExtended": {"cdcAttributeFound": False, "docElemAttrs": [], "sequentumFound": False},
        "pluginsInfo": {"length": 5, "isPluginArray": True, "firstPluginToString": "[object Plugin]"},
        "videoCodecs": {"h264": "probably"},
        "screen": {"width": 1920, "height": 1080, "colorDepth": 24},
        "windowDimensions": {"outerWidth": 1920, "outerHeight": 1040, "innerWidth": 1920, "innerHeight": 950},
        "webgl": {"renderer": "Intel Iris Xe Graphics", "vendor": "Intel Inc."},
        "touch": {"hasTouchEvents": False, "maxTouchPoints": 0},
        "syntheticEvents": [],
        "prototypeIntegrity": {
            "webdriverIllegalInvocationFailed": False,
            "navigatorProtoMismatch": False,
            "functionToStringTampered": False
        }
    }


def test_missing_challenge_blocked(server_url, clean_signals):
    """Standalone requests without prior challenge must be blocked."""
    res = send_assessment(server_url, {"signals": clean_signals})
    assert res["isBot"] is True
    assert res["action"] == "BLOCK"
    assert any("desafio" in r.lower() or "challenge" in r.lower() for r in res["reasons"])


def test_forged_hmac_signature_blocked(server_url, clean_signals):
    """Challenges with forged arbitrary HMAC signatures must be blocked."""
    fake_challenge = {
        "challengeId": "ch_fake",
        "nonce": "fake_nonce_1234567890abcdef",
        "timestamp": int(time.time()),
        "signature": "0000000000000000000000000000000000000000000000000000000000000000"
    }
    env_hash = compute_env_hash(fake_challenge["nonce"], clean_signals)
    res = send_assessment(server_url, {
        "challenge": fake_challenge,
        "environmentalHash": env_hash,
        "signals": clean_signals
    })
    assert res["isBot"] is True
    assert res["action"] == "BLOCK"
    assert any("HMAC" in r for r in res["reasons"])


def test_expired_challenge_blocked(server_url, clean_signals):
    """Challenges generated more than 30s ago must expire and be blocked."""
    old_ts = int(time.time()) - 100
    old_nonce = "old_nonce_1234567890abcdef"
    old_sig = hmac.new(HMAC_SECRET, f"{old_nonce}:{old_ts}".encode(), hashlib.sha256).hexdigest()
    expired_challenge = {
        "challengeId": "ch_old",
        "nonce": old_nonce,
        "timestamp": old_ts,
        "signature": old_sig
    }
    env_hash = compute_env_hash(old_nonce, clean_signals)
    res = send_assessment(server_url, {
        "challenge": expired_challenge,
        "environmentalHash": env_hash,
        "signals": clean_signals
    })
    assert res["isBot"] is True
    assert res["action"] == "BLOCK"
    assert any("expired" in r.lower() or "expirado" in r.lower() for r in res["reasons"])


def test_replay_attack_blocked(server_url, clean_signals):
    """Reusing the same legitimate nonce a second time must trigger a replay block."""
    valid_ch = get_challenge(server_url)
    env_hash = compute_env_hash(valid_ch["nonce"], clean_signals)
    payload = {
        "challenge": valid_ch,
        "environmentalHash": env_hash,
        "signals": clean_signals
    }
    # 1st submission: legitimate
    res_first = send_assessment(server_url, payload)
    assert res_first["isBot"] is False
    assert res_first["action"] == "ALLOW"

    # 2nd submission: replay attack with identical data
    res_second = send_assessment(server_url, payload)
    assert res_second["isBot"] is True
    assert res_second["action"] == "BLOCK"
    assert any("Replay" in r for r in res_second["reasons"])


def test_environmental_binding_tampering_blocked(server_url, clean_signals):
    """Tampering with hardware/GPU signals after computing environmental hash must trigger a block."""
    valid_ch = get_challenge(server_url)
    env_hash = compute_env_hash(valid_ch["nonce"], clean_signals)

    tampered_signals = dict(clean_signals)
    tampered_signals["webgl"] = {"renderer": "NVIDIA GeForce RTX 4090", "vendor": "NVIDIA Corporation"}

    res = send_assessment(server_url, {
        "challenge": valid_ch,
        "environmentalHash": env_hash,
        "signals": tampered_signals
    })
    assert res["isBot"] is True
    assert res["action"] == "BLOCK"
    assert any("environmental" in r.lower() or "ambiental" in r.lower() for r in res["reasons"])


def test_legitimate_flow_allowed(server_url, clean_signals):
    """Fresh flow with valid challenge and intact environmental binding must be approved as human."""
    valid_ch = get_challenge(server_url)
    env_hash = compute_env_hash(valid_ch["nonce"], clean_signals)

    res = send_assessment(server_url, {
        "challenge": valid_ch,
        "environmentalHash": env_hash,
        "signals": clean_signals
    })
    assert res["isBot"] is False
    assert res["action"] == "ALLOW"
    assert res["clientReceipt"].get("classification") == "humano"
