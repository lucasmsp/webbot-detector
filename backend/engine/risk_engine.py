"""
Risk Assessment and Automation Detection Engine

Blind Property Harvesting & Zero-Knowledge:
- Evaluates:
  1. CDC ChromeDriver artifacts and documentElement attributes.
  2. Permissions API inconsistency (Notification.permission vs permissions.query).
  3. Missing or spoofed window.chrome object (including against Clean Realm).
  4. Broken Image dimensions (0x0 in pure headless).
  5. PluginArray stringification and Plugin mock ([object Plugin]).
  6. Software WebGL Vendor/Renderer (SwiftShader, Mesa OffScreen, Brian Paul).
  7. Proprietary media codecs (H.264 in Chrome).
  8. Confidential automation blacklists (Selenium, Puppeteer, Playwright, Cypress, etc.).
"""

import re
from typing import Dict, Any, List, Set, Optional, Tuple

try:
    from engine.crypto_challenge import crypto_manager
except ImportError:
    try:
        from crypto_challenge import crypto_manager
    except ImportError:
        crypto_manager = None


class RiskEngine:
    def __init__(self):
        # Known signatures of pure HTTP clients (non-rendering)
        self.raw_http_clients = [
            (re.compile(r"curl\/", re.I), "cURL"),
            (re.compile(r"Wget\/", re.I), "Wget"),
            (re.compile(r"python-requests", re.I), "Python Requests"),
            (re.compile(r"aiohttp", re.I), "Python aiohttp"),
            (re.compile(r"httpx", re.I), "Python HTTPX"),
            (re.compile(r"Go-http-client", re.I), "Go HTTP Client"),
            (re.compile(r"Java\/", re.I), "Java HTTP Client"),
            (re.compile(r"libwww-perl", re.I), "Perl libwww"),
            (re.compile(r"PostmanRuntime", re.I), "Postman Runtime"),
            (re.compile(r"node-fetch", re.I), "Node.js Fetch"),
            (re.compile(r"Axios", re.I), "Axios HTTP"),
            (re.compile(r"Scrapy", re.I), "Scrapy Framework"),
            (re.compile(r"Apify", re.I), "Apify Scraper"),
        ]

        # Signatures of crawlers and indexing bots
        self.crawler_regex = re.compile(
            r"Googlebot|Bingbot|YandexBot|DuckDuckBot|Baiduspider|Slurp|Exabot|facebot|ia_archiver|crawler|spider|bot",
            re.I
        )

        # -------------------------------------------------------------
        # Server-Side Property Blacklists
        # -------------------------------------------------------------
        self.selenium_signatures: Set[str] = {
            "__selenium_unwrapped",
            "__webdriver_evaluate",
            "__selenium_evaluate",
            "__driver_evaluate",
            "__driver_unwrapped",
            "__webdriver_unwrapped",
            "__fxdriver_evaluate",
            "__fxdriver_unwrapped",
            "__webdriver_script_function",
            "__webdriver_script_func",
            "__webdriver_script_fn",
            "_Selenium_IDE_Recorder",
            "_selenium",
            "calledSelenium",
            "callSelenium",
            "_WEBDRIVER_ELEM_CACHE",
            "ChromeDriverw",
            "driver-evaluate",
            "webdriver-evaluate",
            "selenium-evaluate",
            "webdriverCommand",
            "webdriver-evaluate-response",
            "__webdriverFunc",
            "__$webdriverAsyncExecutor",
            "__lastWatirAlert",
            "__lastWatirConfirm",
            "__lastWatirPrompt",
            "$chrome_asyncScriptInfo",
            "$cdc_asdjflasutopfhvcZLmcfl_",
            "marionette",
            "__marionette",
            "operadriver",
            "safaridriver"
        }

        self.automation_signatures: Set[str] = {
            "__playwright",
            "__nightmare",
            "callPhantom",
            "_phantom",
            "phantom",
            "Cypress",
            "__cypress__",
            "awesomium",
            "domAutomation",
            "domAutomationController"
        }

        self.macro_signatures: Set[str] = {
            "__autoHotkey",
            "__pyautogui",
            "_xdotool",
            "robotjs"
        }

        self.mobile_automation_signatures: Set[str] = {
            "_appium",
            "__selendroid",
            "calabash"
        }

        # In W3C WebIDL, the 'navigator' object must NEVER have these properties
        # as own properties (they must reside exclusively in Navigator.prototype).
        self.navigator_forbidden_own_props: Set[str] = {
            "webdriver",
            "plugins",
            "languages",
            "platform"
        }

    def _detect_browser_profile(self, signals: Dict[str, Any], headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Identifies the browser family (Chrome, Opera, Firefox, Edge, Safari)
        by cross-referencing HTTP headers with client JavaScript signals.
        """
        ua = (signals.get("userAgent", "") or headers.get("user-agent", "")).strip()
        features = signals.get("browserFeatures", {})
        window_props = [p.lower() for p in signals.get("windowProperties", [])]

        has_opr = bool(features.get("hasOpr")) or ("opr" in window_props)
        has_install_trigger = bool(features.get("hasInstallTrigger"))
        has_moz_screen = features.get("mozInnerScreenX") is not None
        has_safari_obj = bool(features.get("hasSafari")) or ("safari" in window_props)

        is_opera = bool(re.search(r"OPR\/|Opera", ua, re.I)) or has_opr
        is_firefox = bool(re.search(r"Firefox|FxiOS", ua, re.I)) or has_install_trigger or has_moz_screen
        is_edge = bool(re.search(r"Edg\/|Edge\/", ua, re.I)) and not is_opera
        is_safari = bool(re.search(r"Safari\/", ua, re.I)) and bool(re.search(r"Version\/", ua, re.I)) and not (is_opera or is_firefox or is_edge or bool(re.search(r"Chrome|Chromium", ua, re.I)))
        is_chrome = bool(re.search(r"Chrome|Chromium", ua, re.I)) and not (is_opera or is_firefox or is_edge or is_safari)

        if is_firefox:
            family = "firefox"
            name = "Mozilla Firefox"
            engine = "gecko"
            is_chromium = False
        elif is_opera:
            family = "opera"
            name = "Opera"
            engine = "blink"
            is_chromium = True
        elif is_edge:
            family = "edge"
            name = "Microsoft Edge"
            engine = "blink"
            is_chromium = True
        elif is_safari:
            family = "safari"
            name = "Apple Safari"
            engine = "webkit"
            is_chromium = False
        elif is_chrome:
            family = "chrome"
            name = "Google Chrome / Chromium"
            engine = "blink"
            is_chromium = True
        else:
            family = "other"
            name = "Navegador Desconhecido / Genérico"
            engine = "unknown"
            is_chromium = bool(re.search(r"Chrome|Chromium", ua, re.I))

        return {
            "family": family,
            "name": name,
            "engine": engine,
            "is_chromium": is_chromium,
            "is_firefox": is_firefox,
            "is_opera": is_opera,
            "is_edge": is_edge,
            "is_safari": is_safari,
            "is_chrome": is_chrome,
            "userAgent": ua
        }

    def assess(
        self,
        client_signals: Dict[str, Any],
        http_headers: Dict[str, str],
        challenge: Optional[Dict[str, Any]] = None,
        environmental_hash: Optional[str] = None,
        require_challenge: bool = False
    ) -> Dict[str, Any]:
        """
        Executes multi-layered analysis cross-referencing client telemetry
        with HTTP network headers and server confidential rules,
        with native multi-browser support (Chrome, Opera, Firefox, Safari, Edge)
        and HMAC cryptographic challenge validation and environmental integrity.
        """
        client_signals = client_signals or {}
        http_headers = {k.lower(): v for k, v in (http_headers or {}).items()}

        browser_profile = self._detect_browser_profile(client_signals, http_headers)

        reasons_cat1 = self._evaluate_category_1_network(
            client_signals,
            http_headers,
            browser_profile,
            challenge=challenge,
            environmental_hash=environmental_hash,
            require_challenge=require_challenge
        )
        reasons_cat2 = self._evaluate_category_2_automation(client_signals, http_headers, browser_profile)
        reasons_cat3 = self._evaluate_category_3_stealth(client_signals, http_headers, browser_profile)
        reasons_cat4 = self._evaluate_category_4_crawlers(client_signals, http_headers)
        reasons_cat5 = self._evaluate_category_5_macros(client_signals)
        reasons_cat6 = self._evaluate_category_6_mobile(client_signals, http_headers)

        categories = {
            "http_protocol": {
                "id": "http_protocol",
                "title": "1. Nível de Rede e Protocolo HTTP",
                "subtitle": "Validação de headers HTTP, TLS, cURL, Requests e integridade de rede",
                "detected": len(reasons_cat1) > 0,
                "reasons": reasons_cat1
            },
            "browser_automation": {
                "id": "browser_automation",
                "title": "2. Automação de Navegadores (Headless / WebDriver)",
                "subtitle": "Selenium, Puppeteer, Playwright, Cypress, Broken Image e CDC artifacts",
                "detected": len(reasons_cat2) > 0,
                "reasons": reasons_cat2
            },
            "stealth_browsers": {
                "id": "stealth_browsers",
                "title": "3. Navegadores Anti-Detecção (Stealth Browsers)",
                "subtitle": "Spoofing de WebIDL, Permissions Mismatch, mock de window.chrome e WebGL software",
                "detected": len(reasons_cat3) > 0,
                "reasons": reasons_cat3
            },
            "crawlers_scrapers": {
                "id": "crawlers_scrapers",
                "title": "4. Frameworks de Web Scraping em Larga Escala (Crawlers)",
                "subtitle": "Scrapy, Apify, padrões de sessão efêmera e robôs de indexação",
                "detected": len(reasons_cat4) > 0,
                "reasons": reasons_cat4
            },
            "os_macros": {
                "id": "os_macros",
                "title": "5. Automação de Interface do SO (OS Macros)",
                "subtitle": "Eventos sintéticos (isTrusted = false), PyAutoGUI, AutoHotkey",
                "detected": len(reasons_cat5) > 0,
                "reasons": reasons_cat5
            },
            "mobile_emulators": {
                "id": "mobile_emulators",
                "title": "6. Automação Mobile e Emuladores",
                "subtitle": "Inconsistências de GPU desktop sob mobile UA, Appium, ausência de touch",
                "detected": len(reasons_cat6) > 0,
                "reasons": reasons_cat6
            }
        }

        all_reasons = (
            reasons_cat1 + reasons_cat2 + reasons_cat3 +
            reasons_cat4 + reasons_cat5 + reasons_cat6
        )
        unique_reasons = list(dict.fromkeys(all_reasons))
        triggered_count = sum(1 for c in categories.values() if c["detected"])
        is_bot = triggered_count > 0
        action = "BLOCK" if is_bot else "ALLOW"

        return {
            "isBot": is_bot,
            "action": action,
            "totalCategoriesTriggered": triggered_count,
            "categories": categories,
            "reasons": unique_reasons,
            "serverEvaluation": {
                "engine": "Incognia-Case-Server-Risk-Engine",
                "version": "2.3.0",
                "zeroKnowledgeClient": True,
                "intoliAndFpScannerCoverage": True,
                "detectedBrowser": {
                    "family": browser_profile["family"],
                    "name": browser_profile["name"],
                    "engine": browser_profile["engine"],
                    "isChromium": browser_profile["is_chromium"]
                },
                "supportedBrowsers": ["Google Chrome", "Mozilla Firefox", "Opera", "Microsoft Edge", "Apple Safari"]
            }
        }

    def _get_global_properties(self, signals: Dict[str, Any]) -> Set[str]:
        """Consolidates blind property lists from window and document sent by client."""
        w_props = set(signals.get("windowProperties", []))
        d_props = set(signals.get("documentProperties", []))
        return w_props | d_props

    def _evaluate_category_1_network(
        self,
        signals: Dict[str, Any],
        headers: Dict[str, str],
        browser: Dict[str, Any],
        challenge: Optional[Dict[str, Any]] = None,
        environmental_hash: Optional[str] = None,
        require_challenge: bool = False
    ) -> List[str]:
        reasons = []
        ua_header = headers.get("user-agent", "")
        client_ua = signals.get("userAgent", "")

        # 1. Check real HTTP request User-Agent on server
        for pattern, name in self.raw_http_clients:
            if pattern.search(ua_header) or pattern.search(client_ua):
                reasons.append(f"Cabeçalho de rede aponta para cliente HTTP sem renderizador gráfico: {name}.")

        # 2. Inconsistency between HTTP network User-Agent vs JavaScript User-Agent
        if ua_header and client_ua and ua_header != client_ua:
            reasons.append("Inconsistência de rede: User-Agent enviado pelo HTTP difere do reportado pelo JavaScript.")

        # 3. W3C Fetch Metadata and Client Hints header validation adapted per browser
        sec_fetch_dest = headers.get("sec-fetch-dest")
        sec_fetch_mode = headers.get("sec-fetch-mode")
        sec_ch_ua = headers.get("sec-ch-ua")

        # Chromium (Chrome, Edge, Opera) must send Fetch Metadata and Client Hints on page requests
        if browser["is_chromium"] and len(headers) > 3 and "curl" not in ua_header.lower():
            if not sec_fetch_dest and not sec_fetch_mode and not sec_ch_ua:
                reasons.append(f"Inconsistência de protocolo: Ausência de cabeçalhos W3C Fetch Metadata esperados em {browser['name']}.")

        # Firefox and Safari DO NOT send 'sec-ch-ua'. If present, indicates Chromium spoofing pretending to be Firefox/Safari
        if (browser["is_firefox"] or browser["is_safari"]) and sec_ch_ua:
            reasons.append(f"Inconsistência de protocolo: Cabeçalho 'sec-ch-ua' (exclusivo de Chromium) detectado sob {browser['name']} (spoofing de User-Agent).")

        # 4. Missing screen or zero dimensions on client
        screen = signals.get("screen", {})
        if screen.get("width") == 0 or screen.get("height") == 0:
            reasons.append("Ausência de propriedades de tela (screen.width/height ausentes ou zerados).")
        if screen.get("colorDepth") == 0:
            reasons.append("Profundidade de cores inválida (colorDepth zerado).")

        # 5. Cryptographic Challenge and Environmental Binding validation (Anti-Replay & Anti-Tampering)
        active_challenge = challenge if challenge is not None else signals.get("challenge")
        active_env_hash = environmental_hash if environmental_hash is not None else signals.get("environmentalHash")

        if crypto_manager is not None:
            if active_challenge is not None:
                valid, challenge_err = crypto_manager.verify_challenge(active_challenge)
                if not valid:
                    reasons.append(f"Falha de integridade criptográfica: {challenge_err}")
                else:
                    nonce = active_challenge.get("nonce", "")
                    valid_env, env_err = crypto_manager.verify_environmental_binding(nonce, signals, active_env_hash)
                    if not valid_env:
                        reasons.append(f"Falha de amarração ambiental: {env_err}")
            elif require_challenge:
                reasons.append("Falha de protocolo: Desafio criptográfico ausente na requisição (requisição avulsa ou simulada sem obtenção de token prévio).")

        return reasons

    def _evaluate_category_2_automation(self, signals: Dict[str, Any], headers: Dict[str, str], browser: Dict[str, Any]) -> List[str]:
        reasons = []
        ua = browser["userAgent"]

        # 1. Standard W3C WebDriver (universal for Chrome, Firefox, Opera, Safari, Edge)
        if signals.get("webdriver") is True:
            reasons.append("Propriedade navigator.webdriver ativa (W3C WebDriver).")

        # 2. Global property evaluation (Blind Property Harvesting)
        global_props = self._get_global_properties(signals)

        selenium_matches = global_props.intersection(self.selenium_signatures)
        if selenium_matches:
            reasons.append(f"Variáveis injetadas pelo Selenium/Marionette detectadas ({', '.join(sorted(selenium_matches))}).")

        automation_matches = global_props.intersection(self.automation_signatures)
        if automation_matches:
            reasons.append(f"Variáveis globais de automação detectadas ({', '.join(sorted(automation_matches))}).")

        # 3. Extended ChromeDriver / OperaDriver traces (Intoli CDC & Document Attributes)
        selenium_ext = signals.get("seleniumExtended", {})
        if selenium_ext.get("cdcAttributeFound"):
            reasons.append("Padrão CDC de ChromeDriver/OperaDriver ($cdc_...) detectado em propriedades do objeto document.")

        doc_attrs = selenium_ext.get("docElemAttrs", [])
        if doc_attrs:
            reasons.append(f"Atributos de automação detectados no elemento HTML raiz ({', '.join(doc_attrs)}).")

        if selenium_ext.get("sequentumFound"):
            reasons.append("Assinatura de automação corporativa Sequentum detectada no escopo global.")

        # 4. V8 Inspector Trap (V8 Console & Getter Trap / CDP Detection)
        v8_trap = signals.get("v8InspectorTrap", {})
        if (
            signals.get("cdpDetected") is True
            or v8_trap.get("cdpDetected") is True
            or v8_trap.get("stackTrapTriggered") is True
            or v8_trap.get("customGetterTriggered") is True
        ):
            reasons.append("Detecção de Chrome DevTools Protocol (CDP): Armadilha do Inspetor do V8 acionada (inspeção de console ativa via connect_over_cdp).")

        # 5. Broken Image Test (Intoli Broken Image Dimensions)
        broken_img = signals.get("brokenImage", {})
        if broken_img.get("isZero") is True:
            reasons.append("Inconsistência de renderização gráfica: Imagem quebrada retornou dimensões zeradas (0x0, típico de Headless sem layout ativo).")

        # 6. Missing window.chrome object (ONLY applicable to Chromium-based browsers: Chrome, Edge, Opera)
        chrome_obj = signals.get("chromeObject", {})
        if browser["is_chromium"] and chrome_obj.get("hasChrome") is False:
            reasons.append(f"Ausência do objeto window.chrome sob navegador declarado como {browser['name']}.")

        # 7. Zero window dimensions
        window_dim = signals.get("windowDimensions", {})
        if window_dim.get("outerWidth") == 0 and window_dim.get("outerHeight") == 0:
            reasons.append("Dimensões de janela zeradas (outerWidth/outerHeight === 0).")

        # 8. Headless User-Agent
        if re.search(r"HeadlessChrome|HeadlessEdg|HeadlessFirefox|Headless", ua, re.I):
            reasons.append("User-Agent aponta explicitamente para navegador Headless.")

        # 9. Specific Headless Firefox detection (zero inner screen coordinates)
        if browser["is_firefox"]:
            features = signals.get("browserFeatures", {})
            moz_x = features.get("mozInnerScreenX")
            moz_y = features.get("mozInnerScreenY")
            if moz_x == 0 and moz_y == 0 and window_dim.get("outerWidth") == 0:
                reasons.append("Detecção de Headless Firefox: Coordenadas mozInnerScreenX/Y zeradas em janela sem layout.")

        return reasons

    def _evaluate_category_3_stealth(self, signals: Dict[str, Any], headers: Dict[str, str], browser: Dict[str, Any]) -> List[str]:
        reasons = []
        ua = browser["userAgent"]

        # 1. 'navigator' Object Spoofing (own navigatorProperties - universal WebIDL)
        nav_own_props = set(signals.get("navigatorProperties", []))
        spoofed_nav_props = nav_own_props.intersection(self.navigator_forbidden_own_props)

        for prop in sorted(spoofed_nav_props):
            reasons.append(f"Spoofing: 'navigator.{prop}' redefinido diretamente na instância.")

        # 2. Permissions API inconsistency (Headless Chromium specific quirk)
        perm = signals.get("permissions", {})
        if browser["is_chromium"]:
            if perm.get("notificationPermission") == "denied" and perm.get("state") == "prompt":
                reasons.append("Inconsistência na Permissions API: Notification.permission é 'denied' enquanto query('notifications') é 'prompt' (anomalia clássica de Headless Chrome/Opera/Edge).")

        # 3. Mocked window.chrome vs Clean Realm test & Cross-browser validation
        chrome_obj = signals.get("chromeObject", {})
        if browser["is_chromium"]:
            if chrome_obj.get("hasChrome") is True and chrome_obj.get("cleanRealmHasChrome") is False:
                reasons.append(f"Spoofing: window.chrome presente na janela principal mas ausente no Clean Realm (mock injetado via script de stealth em {browser['name']}).")
        elif browser["is_firefox"] or browser["is_safari"]:
            # In legitimate Firefox and Safari, window.chrome NEVER exists natively.
            if chrome_obj.get("hasChrome") is True:
                reasons.append(f"Inconsistência de ambiente: Objeto 'window.chrome' detectado sob {browser['name']} (injeção acidental de mock de evasão desenvolvido para Chrome).")

        # 4. Specific Opera consistency (window.opr)
        features = signals.get("browserFeatures", {})
        has_opr = bool(features.get("hasOpr")) or ("opr" in [p.lower() for p in signals.get("windowProperties", [])])
        if browser["is_opera"] and not has_opr:
            reasons.append("Inconsistência de navegador: User-Agent declara Opera (OPR), mas o objeto 'window.opr' está ausente (falsificação de User-Agent).")
        elif not browser["is_opera"] and has_opr:
            reasons.append(f"Inconsistência de navegador: Objeto 'window.opr' presente sob navegador declarado como {browser['name']}.")

        # 5. Specific Safari consistency (Apple Computer vendor & Apple ecosystem)
        if browser["is_safari"]:
            platform = signals.get("platform", "")
            if platform and not re.search(r"Mac|iPhone|iPad|iPod", platform, re.I):
                reasons.append(f"Inconsistência de plataforma: Safari é exclusivo do ecossistema Apple, mas navigator.platform declara '{platform}'.")

        # 6. Prototype and WebIDL tests (universal)
        proto_integrity = signals.get("prototypeIntegrity", {})
        if proto_integrity.get("webdriverIllegalInvocationFailed"):
            reasons.append("Spoofing: Getter de 'Navigator.prototype.webdriver' adulterado (falha em Illegal Invocation).")

        if proto_integrity.get("navigatorProtoMismatch"):
            reasons.append("Spoofing: A cadeia de protótipos do objeto 'navigator' foi corrompida.")

        if proto_integrity.get("functionToStringTampered"):
            reasons.append("Spoofing: 'Function.prototype.toString' sofreu monkey-patching para disfarçar mocks.")

        # 7. Plugins and PluginArray spoofing (Intoli Plugins Type Test)
        plugins_info = signals.get("pluginsInfo", {})
        if plugins_info and not plugins_info.get("isPluginArray", True):
            reasons.append("Spoofing: 'navigator.plugins' não é instância legítima de PluginArray.")

        first_plugin_str = plugins_info.get("firstPluginToString", "")
        if plugins_info.get("length", 0) > 0 and first_plugin_str and first_plugin_str != "[object Plugin]":
            reasons.append(f"Spoofing: Objeto de plugin adulterado (navigator.plugins[0].toString() retornou '{first_plugin_str}' em vez de '[object Plugin]').")

        languages = signals.get("languages", [])
        if isinstance(languages, list) and len(languages) == 0:
            reasons.append("Inconsistência de idiomas: Lista 'navigator.languages' está vazia.")

        # 8. WebGL Software Renderers and Suspicious Vendors (Intoli & FPScanner)
        webgl = signals.get("webgl", {})
        renderer = webgl.get("renderer", "") or ""
        vendor = webgl.get("vendor", "") or ""

        if re.search(r"SwiftShader", renderer, re.I):
            reasons.append(f"Renderizador WebGL de software: '{renderer}' (típico de containers headless / stealth).")
        elif re.search(r"Mesa OffScreen", renderer, re.I):
            reasons.append(f"Renderizador WebGL offscreen de virtualização: '{renderer}'.")
        elif re.search(r"llvmpipe|Mesa", renderer, re.I) and re.search(r"Windows|Macintosh", ua, re.I):
            reasons.append(f"Inconsistência de plataforma: Renderizador Linux ({renderer}) sob User-Agent declarado.")

        if vendor in ["Brian Paul"]:
            reasons.append(f"Vendor WebGL suspeito de driver virtualizado/mesa: '{vendor}'.")

        # 9. Proprietary Video Codecs (FPScanner Video Codecs Test)
        video_codecs = signals.get("videoCodecs", {})
        if browser["is_chromium"] and video_codecs.get("h264") and video_codecs.get("h264") != "probably":
            reasons.append(f"Inconsistência de codecs de mídia: Ausência de suporte ao codec proprietário H.264 esperado em {browser['name']}.")

        # 10. Platform Inconsistency (Intoli & FPScanner Platform Mismatch)
        platform = signals.get("platform", "")
        if platform:
            p_low = platform.lower()
            ua_low = ua.lower()
            if "win" in p_low and ("linux" in ua_low or "macintosh" in ua_low or "android" in ua_low):
                reasons.append(f"Inconsistência de plataforma: navigator.platform declara '{platform}', mas User-Agent indica outro sistema operacional.")
            elif "linux" in p_low and ("windows" in ua_low or "macintosh" in ua_low):
                reasons.append(f"Inconsistência de plataforma: navigator.platform declara '{platform}', mas User-Agent indica outro sistema operacional.")
            elif "mac" in p_low and ("windows" in ua_low or "linux" in ua_low):
                reasons.append(f"Inconsistência de plataforma: navigator.platform declara '{platform}', mas User-Agent indica outro sistema operacional.")

        # 11. Vendor Cross-Validation (navigator.vendor) adapted per browser
        nav_vendor = signals.get("vendor", "")
        if browser["is_firefox"]:
            # In Firefox, navigator.vendor is MANDATORILY an empty string ("")
            if nav_vendor != "":
                reasons.append(f"Inconsistência de fabricante: User-Agent declara Mozilla Firefox, mas navigator.vendor declara '{nav_vendor}' (típico de script de evasão de Chrome aplicado indevidamente ao Firefox).")
        elif browser["is_safari"]:
            # In Safari, navigator.vendor is "Apple Computer, Inc."
            if nav_vendor != "Apple Computer, Inc.":
                reasons.append(f"Inconsistência de fabricante: User-Agent declara Safari, mas navigator.vendor declara '{nav_vendor}' (esperado 'Apple Computer, Inc.').")
        elif browser["is_chromium"]:
            # In Chromium-based browsers (Chrome, Opera, Edge), navigator.vendor is "Google Inc."
            if nav_vendor and nav_vendor != "Google Inc.":
                reasons.append(f"Inconsistência de fabricante: navigator.vendor ('{nav_vendor}') difere de 'Google Inc.' esperado em {browser['name']}.")

        # 12. Platform validation in Firefox (navigator.oscpu)
        if browser["is_firefox"]:
            oscpu = features.get("oscpu", "")
            if oscpu:
                ua_low = ua.lower()
                oscpu_low = oscpu.lower()
                if "linux" in ua_low and "win" in oscpu_low:
                    reasons.append(f"Inconsistência de plataforma: navigator.oscpu declara '{oscpu}', mas User-Agent indica Linux.")
                elif "windows" in ua_low and "linux" in oscpu_low:
                    reasons.append(f"Inconsistência de plataforma: navigator.oscpu declara '{oscpu}', mas User-Agent indica Windows.")

        return reasons

    def _evaluate_category_4_crawlers(self, signals: Dict[str, Any], headers: Dict[str, str]) -> List[str]:
        reasons = []
        ua = signals.get("userAgent", "") or headers.get("user-agent", "")

        if self.crawler_regex.search(ua) and not re.search(r"Mobile|Chrome|Safari", ua, re.I):
            reasons.append("User-Agent identificado como Crawler / Robô de indexação.")
        elif re.search(r"Scrapy|Apify", ua, re.I):
            reasons.append("User-Agent aponta para framework de web scraping em larga escala (Scrapy/Apify).")

        session_info = signals.get("sessionInfo", {})
        history_len = session_info.get("historyLength", 0)
        referrer = session_info.get("referrer", "")
        if history_len == 1 and referrer == "" and re.search(r"bot|spider|crawl", ua, re.I):
            reasons.append("Padrão de sessão de crawler isolada sem navegação prévia.")

        return reasons

    def _evaluate_category_5_macros(self, signals: Dict[str, Any]) -> List[str]:
        reasons = []

        # 1. Synthetic events (isTrusted === false)
        synthetic_events = signals.get("syntheticEvents", [])
        if synthetic_events:
            for event_desc in synthetic_events:
                reasons.append(event_desc)

        # 2. Intersection with confidential macro signatures
        global_props = self._get_global_properties(signals)
        macro_matches = global_props.intersection(self.macro_signatures)
        if macro_matches:
            reasons.append(f"Rastros de script de automação de macro detectados no escopo global ({', '.join(sorted(macro_matches))}).")

        return reasons

    def _evaluate_category_6_mobile(self, signals: Dict[str, Any], headers: Dict[str, str]) -> List[str]:
        reasons = []
        ua = signals.get("userAgent", "") or headers.get("user-agent", "")
        is_mobile_ua = bool(re.search(r"Android|iPhone|iPad|iPod", ua, re.I))

        touch_info = signals.get("touch", {})
        has_touch_events = touch_info.get("hasTouchEvents", False)
        max_touch_points = touch_info.get("maxTouchPoints", 0)

        # 1. Mobile UA without touch support
        if is_mobile_ua and not has_touch_events and max_touch_points == 0:
            reasons.append("Inconsistência Mobile: User-Agent mobile sem pontos de toque ou eventos touch (ontouchstart).")

        # 2. Desktop GPU under Mobile UA
        webgl = signals.get("webgl", {})
        renderer = webgl.get("renderer", "") or ""
        if is_mobile_ua:
            if re.search(r"NVIDIA|Radeon|GeForce|Intel\(R\)|AMD", renderer, re.I) and not re.search(r"Adreno|Mali|PowerVR|Apple", renderer, re.I):
                reasons.append(f"Inconsistência de Emulador Mobile: GPU de desktop ('{renderer}') sob User-Agent mobile.")
            if re.search(r"VMware|VirtualBox|llvmpipe|SwiftShader", renderer, re.I):
                reasons.append(f"Ambiente virtualizado de emulador móvel detectado: '{renderer}'.")

        # 3. Intersection with confidential mobile automation signatures
        global_props = self._get_global_properties(signals)
        mobile_matches = global_props.intersection(self.mobile_automation_signatures)
        if mobile_matches:
            reasons.append(f"Framework de automação mobile ({', '.join(sorted(mobile_matches))}) detectado.")

        return reasons
