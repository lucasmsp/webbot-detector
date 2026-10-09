#!/usr/bin/env python3
"""
Cryptographic and Anti-Replay / Environmental Binding Test Suite:
Validates protection against:
1. Replay Attacks (reuse of captured nonces).
2. HMAC Signature Forgery (attempts to generate tokens without secret key).
3. Temporal Expiration (attempts to reuse stale tokens).
4. Payload Tampering (Environmental Binding Hash Mismatch).
5. Standalone requests without prior challenge (cURL / direct scripts).
6. Legitimate Flow (Fresh challenge + intact environmental hash).
"""

import json
import urllib.request
import urllib.error
import hashlib
import time
import sys
import os

BASE_URL = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else os.environ.get("SERVER_URL", "http://localhost:8000")

def get_challenge():
    req = urllib.request.Request(f"{BASE_URL}/api/challenge")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

def get_session_evaluation(session_id):
    req = urllib.request.Request(f"{BASE_URL}/api/internal/session-evaluation?sessionId={session_id}")
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return {}

def send_assessment(payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE_URL}/api/assess-risk",
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
    try:
        with urllib.request.urlopen(req) as resp:
            client_receipt = json.loads(resp.read().decode("utf-8"))
            session_id = client_receipt.get("sessionId")
            # Query confidential evaluation saved on server
            server_eval = get_session_evaluation(session_id) if session_id else {}
            return {
                "clientReceipt": client_receipt,
                "isBot": client_receipt.get("isBot", server_eval.get("is_bot")),
                "action": client_receipt.get("action", server_eval.get("action")),
                "reasons": server_eval.get("reasons", []),
                "categories": server_eval.get("categories", {})
            }
    except urllib.error.HTTPError as e:
        return {"error": e.code, "body": e.read().decode("utf-8")}

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

def make_clean_signals():
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

def run_tests():
    print("=" * 70)
    print(" SUITE DE TESTES: CRIPTOGRAFIA, ANTI-REPLAY & AMARRAÇÃO AMBIENTAL")
    print("=" * 70)
    
    passed_all = True

    # -------------------------------------------------------------
    # Test 1: Standalone Request without Challenge (cURL / direct script)
    # -------------------------------------------------------------
    print("\n[CENÁRIO 1] Requisição avulsa direta sem obter desafio prévio...")
    signals = make_clean_signals()
    res1 = send_assessment({"signals": signals})
    b1 = res1.get("isBot") is True and any("Desafio criptográfico ausente" in r for r in res1.get("reasons", []))
    status1 = "✅ BLOQUEADO COM SUCESSO" if b1 else "❌ FALHA"
    print(f" {status1}: isBot={res1.get('isBot')}, ação={res1.get('action')}")
    if res1.get("reasons"):
        print(f" Evidência: {res1.get('reasons')[0]}")
    passed_all &= b1

    # -------------------------------------------------------------
    # Test 2: Challenge with Forged HMAC Signature
    # -------------------------------------------------------------
    print("\n[CENÁRIO 2] Envio de desafio com assinatura HMAC arbitrária forjada...")
    fake_challenge = {
        "challengeId": "ch_fake",
        "nonce": "fake_nonce_1234567890abcdef",
        "timestamp": int(time.time()),
        "signature": "0000000000000000000000000000000000000000000000000000000000000000"
    }
    env_hash2 = compute_env_hash(fake_challenge["nonce"], signals)
    res2 = send_assessment({
        "challenge": fake_challenge,
        "environmentalHash": env_hash2,
        "signals": signals
    })
    b2 = res2.get("isBot") is True and any("Assinatura HMAC" in r for r in res2.get("reasons", []))
    status2 = "✅ BLOQUEADO COM SUCESSO" if b2 else "❌ FALHA"
    print(f" {status2}: isBot={res2.get('isBot')}, ação={res2.get('action')}")
    if res2.get("reasons"):
        print(f" Evidência: {res2.get('reasons')[0]}")
    passed_all &= b2

    # -------------------------------------------------------------
    # Test 3: Expired Challenge (> 30s)
    # -------------------------------------------------------------
    print("\n[CENÁRIO 3] Tentativa de uso de desafio expirado no tempo...")
    # Generate valid signature with outdated timestamp
    import hmac
    secret = b"incognia-case-v8-crypto-secret-2026-key"
    old_ts = int(time.time()) - 100
    old_nonce = "old_nonce_1234567890abcdef"
    old_sig = hmac.new(secret, f"{old_nonce}:{old_ts}".encode(), hashlib.sha256).hexdigest()
    expired_challenge = {
        "challengeId": "ch_old",
        "nonce": old_nonce,
        "timestamp": old_ts,
        "signature": old_sig
    }
    env_hash3 = compute_env_hash(old_nonce, signals)
    res3 = send_assessment({
        "challenge": expired_challenge,
        "environmentalHash": env_hash3,
        "signals": signals
    })
    b3 = res3.get("isBot") is True and any("expirado" in r.lower() for r in res3.get("reasons", []))
    status3 = "✅ BLOQUEADO COM SUCESSO" if b3 else "❌ FALHA"
    print(f" {status3}: isBot={res3.get('isBot')}, ação={res3.get('action')}")
    if res3.get("reasons"):
        print(f" Evidência: {res3.get('reasons')[0]}")
    passed_all &= b3

    # -------------------------------------------------------------
    # Test 4: Replay Attack (Nonce Reuse)
    # -------------------------------------------------------------
    print("\n[CENÁRIO 4] Ataque de Replay (envio duplicado do mesmo desafio legítimo)...")
    valid_ch4 = get_challenge()
    env_hash4 = compute_env_hash(valid_ch4["nonce"], signals)
    payload4 = {
        "challenge": valid_ch4,
        "environmentalHash": env_hash4,
        "signals": signals
    }
    # 1st submission: should be allowed (legitimate human)
    res4_first = send_assessment(payload4)
    first_ok = res4_first.get("isBot") is False and res4_first.get("action") == "ALLOW"
    print(f" 1º Envio (Válido): isBot={res4_first.get('isBot')} (Ação: {res4_first.get('action')})")
    
    # 2nd submission with EXACTLY the same payload and challenge: MUST BE BLOCKED BY REPLAY!
    res4_second = send_assessment(payload4)
    second_blocked = res4_second.get("isBot") is True and any("Replay" in r for r in res4_second.get("reasons", []))
    status4 = "✅ BLOQUEADO COM SUCESSO" if second_blocked else "❌ FALHA"
    print(f" 2º Envio (Replay): {status4}: isBot={res4_second.get('isBot')} (Ação: {res4_second.get('action')})")
    if res4_second.get("reasons"):
        print(f" Evidência: {res4_second.get('reasons')[0]}")
    passed_all &= (first_ok and second_blocked)

    # -------------------------------------------------------------
    # Test 5: Payload Tampering (Environmental Binding Mismatch)
    # -------------------------------------------------------------
    print("\n[CENÁRIO 5] Adulteração de Telemetria no JSON (Environmental Binding Mismatch)...")
    valid_ch5 = get_challenge()
    # Client computed hash with Intel Iris Xe GPU
    env_hash5 = compute_env_hash(valid_ch5["nonce"], signals)
    
    # But attacker tampers payload with another GPU before sending!
    tampered_signals = dict(signals)
    tampered_signals["webgl"] = {"renderer": "NVIDIA GeForce RTX 4090", "vendor": "NVIDIA Corporation"}
    
    res5 = send_assessment({
        "challenge": valid_ch5,
        "environmentalHash": env_hash5, # Original environment hash does not match tampered GPU
        "signals": tampered_signals
    })
    b5 = res5.get("isBot") is True and any("ambiental" in r.lower() for r in res5.get("reasons", []))
    status5 = "✅ BLOQUEADO COM SUCESSO" if b5 else "❌ FALHA"
    print(f" {status5}: isBot={res5.get('isBot')}, ação={res5.get('action')}")
    if res5.get("reasons"):
        print(f" Evidência: {res5.get('reasons')[0]}")
    passed_all &= b5

    # -------------------------------------------------------------
    # Test 6: Perfect Legitimate Flow
    # -------------------------------------------------------------
    print("\n[CENÁRIO 6] Fluxo Legítimo (Desafio fresco + hash ambiental íntegro)...")
    valid_ch6 = get_challenge()
    env_hash6 = compute_env_hash(valid_ch6["nonce"], signals)
    res6 = send_assessment({
        "challenge": valid_ch6,
        "environmentalHash": env_hash6,
        "signals": signals
    })
    b6 = res6.get("isBot") is False and res6.get("action") == "ALLOW"
    status6 = "✅ PERMITIDO COM SUCESSO" if b6 else "❌ FALHA"
    print(f" {status6}: isBot={res6.get('isBot')}, ação={res6.get('action')}")
    passed_all &= b6

    print("\n" + "=" * 70)
    if passed_all:
        print("🎉 TODOS OS 6 CENÁRIOS CRIPTOGRÁFICOS PASSARAM COM SUCESSO ABSOLUTO!")
    else:
        print("⚠️ ALGUNS CENÁRIOS FALHARAM. VERIFIQUE OS LOGS ACIMA.")
    print("=" * 70)
    return passed_all

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
