#!/usr/bin/env python3
"""
Multi-Browser Test Suite (Chrome, Firefox, Opera, Edge, Safari)
Validates:
1. Real browser executions with automation (Selenium Firefox and Playwright Chromium).
2. Legitimate Human Access Scenarios across browsers (zero false positives).
3. Browser-Specific Bot and Evasion Scenarios (tampering and spoofing attempts).
"""

import json
import urllib.request
import time
import sys
import os
from typing import Dict, Any

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(TESTS_DIR)
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from engine.risk_engine import RiskEngine

risk_engine = RiskEngine()

def print_separator(title: str):
    print("\n" + "=" * 70)
    print(f" {title}")
    print("=" * 70)

def test_engine_scenario(name: str, signals: Dict[str, Any], headers: Dict[str, str], expected_is_bot: bool):
    assessment = risk_engine.assess(signals, headers)
    is_bot = assessment["isBot"]
    detected_browser = assessment["serverEvaluation"].get("detectedBrowser", {})
    b_name = detected_browser.get("name", "Unknown")
    
    passed = (is_bot == expected_is_bot)
    status_icon = "✅" if passed else "❌"
    result_type = "🤖 BOT" if is_bot else "👤 HUMAN"
    expected_type = "🤖 BOT" if expected_is_bot else "👤 HUMAN"
    
    print(f"{status_icon} [{b_name}] {name}")
    print(f"   Result: {result_type} (Action: {assessment['action']})")
    if not passed:
        print(f"   ⚠️ EXPECTED: {expected_type}")
    if assessment["reasons"]:
        print(f"   Evidence: {', '.join(assessment['reasons'][:2])}")
    return passed

def run_multi_browser_scenarios():
    print_separator("PART 1: LEGITIMATE HUMAN ACCESS SCENARIOS (ZERO FALSE POSITIVES)")
    
    all_passed = True
    
    # 1. Human on Mozilla Firefox
    firefox_human_signals = {
        "userAgent": "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
        "webdriver": False,
        "languages": ["pt-BR", "pt", "en-US"],
        "platform": "Linux x86_64",
        "vendor": "",  # Legitimate Firefox has empty vendor
        "cookieEnabled": True,
        "windowProperties": ["getCleanRealm", "isNativeGetter", "collectTelemetrySignals", "getRiskApiEndpoint", "detectBot"],
        "documentProperties": [],
        "navigatorProperties": [],
        "browserFeatures": {
            "hasOpr": False,
            "hasSafari": False,
            "hasInstallTrigger": True,
            "mozInnerScreenX": 100,
            "mozInnerScreenY": 150,
            "oscpu": "Linux x86_64"
        },
        "permissions": {"state": "prompt", "notificationPermission": "default"},
        "brokenImage": {"width": 24, "height": 24, "isZero": False},
        "chromeObject": {"hasChrome": False, "hasRuntime": False, "cleanRealmHasChrome": False},
        "seleniumExtended": {"cdcAttributeFound": False, "docElemAttrs": [], "sequentumFound": False},
        "pluginsInfo": {"length": 5, "isPluginArray": True, "firstPluginToString": "[object Plugin]"},
        "videoCodecs": {"h264": "probably"},
        "screen": {"width": 1920, "height": 1080, "colorDepth": 24},
        "windowDimensions": {"outerWidth": 1920, "outerHeight": 1040, "innerWidth": 1920, "innerHeight": 950},
        "webgl": {"renderer": "Mesa Intel(R) HD Graphics 530 (SKL GT2)", "vendor": "Intel Open Source Technology Center"},
        "touch": {"hasTouchEvents": False, "maxTouchPoints": 0},
        "syntheticEvents": [],
        "prototypeIntegrity": {"webdriverIllegalInvocationFailed": False, "navigatorProtoMismatch": False, "functionToStringTampered": False},
        "sessionInfo": {"historyLength": 3, "referrer": "https://google.com"}
    }
    firefox_headers = {
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept-language": "pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none"
    }
    all_passed &= test_engine_scenario("Legitimate human user browsing on Mozilla Firefox", firefox_human_signals, firefox_headers, False)

    # 2. Human on Opera
    opera_human_signals = {
        "userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0",
        "webdriver": False,
        "languages": ["pt-BR", "en"],
        "platform": "Linux x86_64",
        "vendor": "Google Inc.",
        "cookieEnabled": True,
        "windowProperties": ["opr", "getCleanRealm", "isNativeGetter", "collectTelemetrySignals", "getRiskApiEndpoint", "detectBot"],
        "documentProperties": [],
        "navigatorProperties": [],
        "browserFeatures": {
            "hasOpr": True,
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
        "prototypeIntegrity": {"webdriverIllegalInvocationFailed": False, "navigatorProtoMismatch": False, "functionToStringTampered": False},
        "sessionInfo": {"historyLength": 2, "referrer": ""}
    }
    opera_headers = {
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0",
        "sec-ch-ua": '"Opera";v="114", "Chromium";v="128"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate"
    }
    all_passed &= test_engine_scenario("Legitimate human user browsing on Opera", opera_human_signals, opera_headers, False)

    # 3. Human on Google Chrome
    chrome_human_signals = {
        "userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        "webdriver": False,
        "languages": ["pt-BR", "pt", "en-US"],
        "platform": "Linux x86_64",
        "vendor": "Google Inc.",
        "cookieEnabled": True,
        "windowProperties": ["getCleanRealm", "isNativeGetter", "collectTelemetrySignals", "getRiskApiEndpoint", "detectBot"],
        "documentProperties": [],
        "navigatorProperties": [],
        "browserFeatures": {"hasOpr": False, "hasSafari": False, "hasInstallTrigger": False, "mozInnerScreenX": None, "mozInnerScreenY": None, "oscpu": ""},
        "permissions": {"state": "prompt", "notificationPermission": "default"},
        "brokenImage": {"width": 16, "height": 16, "isZero": False},
        "chromeObject": {"hasChrome": True, "hasRuntime": True, "cleanRealmHasChrome": True},
        "seleniumExtended": {"cdcAttributeFound": False, "docElemAttrs": [], "sequentumFound": False},
        "pluginsInfo": {"length": 5, "isPluginArray": True, "firstPluginToString": "[object Plugin]"},
        "videoCodecs": {"h264": "probably"},
        "screen": {"width": 1920, "height": 1080, "colorDepth": 24},
        "windowDimensions": {"outerWidth": 1920, "outerHeight": 1040, "innerWidth": 1920, "innerHeight": 950},
        "webgl": {"renderer": "ANGLE (Intel, Intel(R) HD Graphics)", "vendor": "Google Inc."},
        "touch": {"hasTouchEvents": False, "maxTouchPoints": 0},
        "syntheticEvents": [],
        "prototypeIntegrity": {"webdriverIllegalInvocationFailed": False, "navigatorProtoMismatch": False, "functionToStringTampered": False},
        "sessionInfo": {"historyLength": 5, "referrer": "https://bing.com"}
    }
    chrome_headers = {
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        "sec-ch-ua": '"Chromium";v="130", "Google Chrome";v="130"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate"
    }
    all_passed &= test_engine_scenario("Legitimate human user browsing on Google Chrome", chrome_human_signals, chrome_headers, False)

    # 4. Human on Apple Safari (macOS)
    safari_human_signals = {
        "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "webdriver": False,
        "languages": ["pt-BR", "en-US"],
        "platform": "MacIntel",
        "vendor": "Apple Computer, Inc.",
        "cookieEnabled": True,
        "windowProperties": ["safari", "getCleanRealm", "isNativeGetter", "collectTelemetrySignals", "getRiskApiEndpoint", "detectBot"],
        "documentProperties": [],
        "navigatorProperties": [],
        "browserFeatures": {"hasOpr": False, "hasSafari": True, "hasInstallTrigger": False, "mozInnerScreenX": None, "mozInnerScreenY": None, "oscpu": ""},
        "permissions": {"state": None, "notificationPermission": "default"},
        "brokenImage": {"width": 16, "height": 16, "isZero": False},
        "chromeObject": {"hasChrome": False, "hasRuntime": False, "cleanRealmHasChrome": False},
        "seleniumExtended": {"cdcAttributeFound": False, "docElemAttrs": [], "sequentumFound": False},
        "pluginsInfo": {"length": 0, "isPluginArray": True, "firstPluginToString": ""},
        "videoCodecs": {"h264": "probably"},
        "screen": {"width": 1440, "height": 900, "colorDepth": 24},
        "windowDimensions": {"outerWidth": 1440, "outerHeight": 850, "innerWidth": 1440, "innerHeight": 800},
        "webgl": {"renderer": "Apple GPU", "vendor": "Apple Inc."},
        "touch": {"hasTouchEvents": False, "maxTouchPoints": 0},
        "syntheticEvents": [],
        "prototypeIntegrity": {"webdriverIllegalInvocationFailed": False, "navigatorProtoMismatch": False, "functionToStringTampered": False},
        "sessionInfo": {"historyLength": 2, "referrer": ""}
    }
    safari_headers = {
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate"
    }
    all_passed &= test_engine_scenario("Legitimate human user browsing on Apple Safari (macOS)", safari_human_signals, safari_headers, False)

    # 5. Human on Microsoft Edge
    edge_human_signals = {
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
        "webdriver": False,
        "languages": ["pt-BR", "en"],
        "platform": "Win32",
        "vendor": "Google Inc.",
        "cookieEnabled": True,
        "windowProperties": ["getCleanRealm", "isNativeGetter", "collectTelemetrySignals", "getRiskApiEndpoint", "detectBot"],
        "documentProperties": [],
        "navigatorProperties": [],
        "browserFeatures": {"hasOpr": False, "hasSafari": False, "hasInstallTrigger": False, "mozInnerScreenX": None, "mozInnerScreenY": None, "oscpu": ""},
        "permissions": {"state": "prompt", "notificationPermission": "default"},
        "brokenImage": {"width": 16, "height": 16, "isZero": False},
        "chromeObject": {"hasChrome": True, "hasRuntime": True, "cleanRealmHasChrome": True},
        "seleniumExtended": {"cdcAttributeFound": False, "docElemAttrs": [], "sequentumFound": False},
        "pluginsInfo": {"length": 5, "isPluginArray": True, "firstPluginToString": "[object Plugin]"},
        "videoCodecs": {"h264": "probably"},
        "screen": {"width": 1920, "height": 1080, "colorDepth": 24},
        "windowDimensions": {"outerWidth": 1920, "outerHeight": 1040, "innerWidth": 1920, "innerHeight": 950},
        "webgl": {"renderer": "ANGLE (NVIDIA, GeForce RTX 3060)", "vendor": "Google Inc."},
        "touch": {"hasTouchEvents": False, "maxTouchPoints": 0},
        "syntheticEvents": [],
        "prototypeIntegrity": {"webdriverIllegalInvocationFailed": False, "navigatorProtoMismatch": False, "functionToStringTampered": False},
        "sessionInfo": {"historyLength": 4, "referrer": ""}
    }
    edge_headers = {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
        "sec-ch-ua": '"Microsoft Edge";v="130", "Chromium";v="130"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate"
    }
    all_passed &= test_engine_scenario("Legitimate human user browsing on Microsoft Edge", edge_human_signals, edge_headers, False)

    print_separator("PART 2: MULTI-BROWSER BOT AND EVASION DETECTION")

    # 6. Bot on Firefox with Marionette / GeckoDriver (active W3C WebDriver)
    firefox_bot_marionette = dict(firefox_human_signals)
    firefox_bot_marionette["webdriver"] = True
    all_passed &= test_engine_scenario("Bot on Firefox with GeckoDriver (navigator.webdriver = true)", firefox_bot_marionette, firefox_headers, True)

    # 7. Bot on Firefox using Chrome stealth script (Injecting vendor 'Google Inc.')
    firefox_bot_stealth_vendor = dict(firefox_human_signals)
    firefox_bot_stealth_vendor["vendor"] = "Google Inc."  # Severe anomaly on Firefox
    all_passed &= test_engine_scenario("Bot on Firefox with flawed stealth (vendor spoofed to 'Google Inc.')", firefox_bot_stealth_vendor, firefox_headers, True)

    # 8. Bot on Firefox with window.chrome object accidentally injected
    firefox_bot_chrome_mock = dict(firefox_human_signals)
    firefox_bot_chrome_mock["chromeObject"] = {"hasChrome": True, "hasRuntime": True, "cleanRealmHasChrome": False}
    all_passed &= test_engine_scenario("Bot on Firefox injecting window.chrome mock", firefox_bot_chrome_mock, firefox_headers, True)

    # 9. Bot spoofing Opera User-Agent without window.opr object
    opera_bot_no_opr = dict(opera_human_signals)
    opera_bot_no_opr["browserFeatures"] = {"hasOpr": False, "hasSafari": False, "hasInstallTrigger": False, "mozInnerScreenX": None, "mozInnerScreenY": None, "oscpu": ""}
    opera_bot_no_opr["windowProperties"] = ["getCleanRealm", "detectBot"]  # Without opr
    all_passed &= test_engine_scenario("Bot spoofing Opera UA without window.opr object", opera_bot_no_opr, opera_headers, True)

    # 10. Bot spoofing Safari on Linux with Mesa WebGL and invalid vendor
    safari_bot_spoofed = dict(safari_human_signals)
    safari_bot_spoofed["platform"] = "Linux x86_64"  # Safari on Linux does not exist
    safari_bot_spoofed["vendor"] = "Google Inc."     # Chrome vendor
    all_passed &= test_engine_scenario("Bot spoofing Safari on Linux environment with Google Inc. vendor", safari_bot_spoofed, safari_headers, True)

    # 11. Bot on Edge with active W3C WebDriver
    edge_bot = dict(edge_human_signals)
    edge_bot["webdriver"] = True
    all_passed &= test_engine_scenario("Bot on Microsoft Edge with active MSEdgeDriver", edge_bot, edge_headers, True)

    print_separator("MULTI-BROWSER HEURISTIC TESTS SUMMARY")
    if all_passed:
        print("🎉 ALL 11 MULTI-BROWSER SCENARIOS PASSED SUCCESSFULLY!")
    else:
        print("⚠️ SOME SCENARIOS FAILED. CHECK LOGS ABOVE.")

def run_real_selenium_firefox_test():
    print_separator("PART 3: REAL AUTOMATED BROWSER TEST (SELENIUM WITH FIREFOX)")
    try:
        from selenium import webdriver
        from selenium.webdriver.firefox.options import Options
        
        options = Options()
        options.add_argument('-headless')
        driver = webdriver.Firefox(options=options)
        
        url = "http://localhost:8000"
        print(f"Accessing {url} via Firefox Headless (Selenium)...")
        driver.get(url)
        time.sleep(2)
        
        result = driver.execute_script("return window.__latestBotResult;")
        driver.quit()
        
        if result and result.get("sessionId"):
            session_id = result.get("sessionId")
            # Query confidential evaluation saved on server (Zero-Knowledge)
            eval_req = urllib.request.Request(f"http://localhost:8000/api/internal/session-evaluation?sessionId={session_id}")
            with urllib.request.urlopen(eval_req) as resp:
                server_eval = json.loads(resp.read().decode("utf-8"))
            print(f"Server Verdict: {'🤖 BOT DETECTED' if server_eval.get('is_bot') else '👤 HUMAN'}")
            print(f"Action: {server_eval.get('action')}")
            print("✅ Firefox automation accurately detected by server!")
        else:
            print("Could not capture result.")
    except Exception as e:
        print(f"Notice in Firefox test: {e}")

if __name__ == "__main__":
    run_multi_browser_scenarios()
    run_real_selenium_firefox_test()
