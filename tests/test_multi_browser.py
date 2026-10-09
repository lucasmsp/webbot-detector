#!/usr/bin/env python3
"""
Heuristic and Multi-Browser Tests (Pytest).
Validates:
1. Legitimate Human Access Scenarios across multiple browsers (Chrome, Firefox, Safari, Edge, Opera).
2. Bot Detection and Browser-Specific Evasion Scenarios.
3. Optional E2E test with Selenium Firefox (if geckodriver is available).
"""

import pytest
import shutil
from engine.risk_engine import RiskEngine

risk_engine = RiskEngine()

# --------------------------------------------------------------------------
# Fixtures and Multi-Browser Scenario Definitions
# --------------------------------------------------------------------------

HUMAN_SCENARIOS = [
    (
        "Mozilla Firefox",
        {
            "userAgent": "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
            "webdriver": False,
            "languages": ["pt-BR", "pt", "en-US"],
            "platform": "Linux x86_64",
            "vendor": "",
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
        },
        {
            "user-agent": "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "none"
        }
    ),
    (
        "Opera",
        {
            "userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0",
            "webdriver": False,
            "languages": ["pt-BR", "en"],
            "platform": "Linux x86_64",
            "vendor": "Google Inc.",
            "cookieEnabled": True,
            "windowProperties": ["opr", "getCleanRealm", "isNativeGetter", "collectTelemetrySignals", "getRiskApiEndpoint", "detectBot"],
            "documentProperties": [],
            "navigatorProperties": [],
            "browserFeatures": {"hasOpr": True, "hasSafari": False, "hasInstallTrigger": False, "mozInnerScreenX": None, "mozInnerScreenY": None, "oscpu": ""},
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
        },
        {
            "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0",
            "sec-ch-ua": '"Opera";v="114", "Chromium";v="128"',
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate"
        }
    ),
    (
        "Google Chrome",
        {
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
        },
        {
            "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
            "sec-ch-ua": '"Chromium";v="130", "Google Chrome";v="130"',
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate"
        }
    ),
    (
        "Apple Safari (macOS)",
        {
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
        },
        {
            "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate"
        }
    ),
    (
        "Microsoft Edge",
        {
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
        },
        {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
            "sec-ch-ua": '"Microsoft Edge";v="130", "Chromium";v="130"',
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate"
        }
    )
]

BOT_SCENARIOS = [
    (
        "Firefox with GeckoDriver (webdriver = true)",
        {
            "userAgent": "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
            "webdriver": True,
            "languages": ["pt-BR", "en-US"],
            "platform": "Linux x86_64",
            "vendor": "",
            "windowProperties": ["getCleanRealm", "detectBot"]
        },
        {"user-agent": "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"}
    ),
    (
        "Firefox with vendor spoofed to 'Google Inc.'",
        {
            "userAgent": "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
            "webdriver": False,
            "languages": ["pt-BR"],
            "platform": "Linux x86_64",
            "vendor": "Google Inc.",
            "windowProperties": ["getCleanRealm", "detectBot"]
        },
        {"user-agent": "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"}
    ),
    (
        "Firefox injecting mock of window.chrome",
        {
            "userAgent": "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
            "webdriver": False,
            "languages": ["pt-BR"],
            "platform": "Linux x86_64",
            "vendor": "",
            "chromeObject": {"hasChrome": True, "hasRuntime": True, "cleanRealmHasChrome": False},
            "windowProperties": ["chrome", "getCleanRealm", "detectBot"]
        },
        {"user-agent": "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"}
    ),
    (
        "Opera in UA without window.opr object",
        {
            "userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0",
            "webdriver": False,
            "languages": ["pt-BR"],
            "platform": "Linux x86_64",
            "vendor": "Google Inc.",
            "browserFeatures": {"hasOpr": False, "hasSafari": False, "hasInstallTrigger": False},
            "windowProperties": ["getCleanRealm", "detectBot"]
        },
        {"user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0"}
    ),
    (
        "Safari spoofed on Linux",
        {
            "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
            "webdriver": False,
            "languages": ["pt-BR"],
            "platform": "Linux x86_64",
            "vendor": "Google Inc.",
            "windowProperties": ["getCleanRealm", "detectBot"]
        },
        {"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15"}
    ),
    (
        "Edge with active MSEdgeDriver",
        {
            "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
            "webdriver": True,
            "languages": ["pt-BR"],
            "platform": "Win32",
            "vendor": "Google Inc.",
            "windowProperties": ["getCleanRealm", "detectBot"]
        },
        {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0"}
    )
]


@pytest.mark.parametrize("name,signals,headers", HUMAN_SCENARIOS)
def test_human_legitimate_browsers(name, signals, headers):
    """Real browsers of human users must not be blocked (Zero False Positives)."""
    assessment = risk_engine.assess(signals, headers)
    assert assessment["isBot"] is False, f"Falso Positivo gerado para humano no {name}: {assessment['reasons']}"
    assert assessment["action"] == "ALLOW"


@pytest.mark.parametrize("name,signals,headers", BOT_SCENARIOS)
def test_bot_and_evasion_scenarios(name, signals, headers):
    """Inconsistent automations and evasions must be detected as bots."""
    assessment = risk_engine.assess(signals, headers)
    assert assessment["isBot"] is True, f"Falha ao detectar bot/evasão em {name}"
    assert assessment["action"] == "BLOCK"
    assert len(assessment["reasons"]) > 0


@pytest.mark.skipif(not shutil.which("geckodriver"), reason="geckodriver not installed in PATH")
def test_real_selenium_firefox(server_url):
    """Real E2E test with headless Selenium Firefox browser."""
    from selenium import webdriver
    from selenium.webdriver.firefox.options import Options
    import time
    import json
    import urllib.request

    options = Options()
    options.add_argument('-headless')
    driver = webdriver.Firefox(options=options)

    try:
        driver.get(server_url)
        time.sleep(2)
        result = driver.execute_script("return window.__latestBotResult;")
        assert result is not None, "window.__latestBotResult not populated"
        session_id = result.get("sessionId")
        assert session_id, "Session ID not returned"

        # Query internal server evaluation
        eval_req = urllib.request.Request(f"{server_url}/api/internal/session-evaluation?sessionId={session_id}")
        with urllib.request.urlopen(eval_req) as resp:
            server_eval = json.loads(resp.read().decode("utf-8"))

        assert server_eval.get("is_bot") is True
        assert server_eval.get("action") == "BLOCK"
    finally:
        driver.quit()
