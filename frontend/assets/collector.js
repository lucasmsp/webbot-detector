/**
 * Passive Telemetry Sensor (Client-Side Sensor / Telemetry Collector)
 *
 * Industry Best Practices (Blind Property Harvesting & Multidimensional Probes):
 * This script contains NO detection rules, does NOT evaluate individual properties,
 * and does NOT decide whether access is human or bot (Zero-Knowledge).
 *
 * It extracts comprehensive environment metrics (including Intoli tests,
 * FingerprintScanner, Permissions API, CDC artifacts, broken image, and WebGL)
 * for confidential evaluation inside the server-side risk engine.
 */

async function collectTelemetrySignals() {
    const cleanRealm = (typeof getCleanRealm === 'function') ? getCleanRealm() : null;
    const isNativeCheck = (typeof isNativeGetter === 'function') ? isNativeGetter : () => true;

    // 1. GPU / WebGL Extraction (Intoli & FPScanner)
    let webglRenderer = "";
    let webglVendor = "";
    try {
        if (typeof document !== 'undefined' && document.createElement) {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (gl) {
                const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                if (debugInfo) {
                    webglRenderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || "";
                    webglVendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || "";
                }
            }
        }
    } catch (e) {}

    // 2. Optimized Blind Property Harvesting (Delta Harvesting via Clean Realm)
    let windowProperties = [];
    let documentProperties = [];

    if (typeof window !== 'undefined') {
        let cleanWindowProps = null;
        try {
            if (cleanRealm && cleanRealm.Object) {
                cleanWindowProps = new Set(cleanRealm.Object.getOwnPropertyNames(cleanRealm));
            }
        } catch (e) {}

        windowProperties = Object.getOwnPropertyNames(window).filter(key => {
            if (cleanWindowProps) {
                return !cleanWindowProps.has(key) || key.startsWith('_') || key.startsWith('$');
            }
            return key.startsWith('_') || key.startsWith('$');
        });
    }

    if (typeof document !== 'undefined') {
        let cleanDocProps = null;
        try {
            if (cleanRealm && cleanRealm.document && cleanRealm.Object) {
                cleanDocProps = new Set(cleanRealm.Object.getOwnPropertyNames(cleanRealm.document));
            }
        } catch (e) {}

        documentProperties = Object.getOwnPropertyNames(document).filter(key => {
            if (cleanDocProps) {
                return !cleanDocProps.has(key) || key.startsWith('_') || key.startsWith('$');
            }
            return key.startsWith('_') || key.startsWith('$');
        });
    }

    const navigatorProperties = (typeof navigator !== 'undefined')
        ? Object.getOwnPropertyNames(navigator)
        : [];

    // 3. Prototype and WebIDL Integrity Tests
    let webdriverIllegalInvocationFailed = false;
    let navigatorProtoMismatch = false;
    let functionToStringTampered = false;

    if (typeof Navigator !== 'undefined' && typeof navigator !== 'undefined') {
        const protoDesc = Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver');
        if (protoDesc && protoDesc.get) {
            webdriverIllegalInvocationFailed = !isNativeCheck(Navigator.prototype, 'webdriver');
        }
        navigatorProtoMismatch = (Object.getPrototypeOf(navigator) !== Navigator.prototype);
    }

    if (cleanRealm && typeof Function !== 'undefined') {
        try {
            const cleanToString = cleanRealm.Function.prototype.toString;
            const currentToStringCode = cleanToString.call(Function.prototype.toString);
            functionToStringTampered = !currentToStringCode.includes('[native code]');
        } catch (e) {}
    }

    // 4. Notification Permissions Test (Intoli / FPScanner Permissions Mismatch)
    let permissionState = null;
    let notificationPermission = (typeof Notification !== 'undefined') ? Notification.permission : null;
    try {
        if (typeof navigator !== 'undefined' && navigator.permissions && navigator.permissions.query) {
            const pStatus = await Promise.race([
                navigator.permissions.query({ name: 'notifications' }),
                new Promise(resolve => setTimeout(() => resolve(null), 150))
            ]);
            if (pStatus) {
                permissionState = pStatus.state;
            }
        }
    } catch (e) {}

    // 5. Broken Image Dimensions Test (Intoli Broken Image Dimensions with DOM attachment)
    let brokenImage = { width: -1, height: -1, isZero: false };
    if (typeof document !== 'undefined' && document.createElement) {
        try {
            brokenImage = await new Promise(resolve => {
                const img = document.createElement('img');
                img.style.position = 'absolute';
                img.style.left = '-9999px';
                img.style.top = '-9999px';
                img.style.width = 'auto';
                img.style.height = 'auto';
                
                const cleanup = () => {
                    if (img.parentNode) {
                        try { img.parentNode.removeChild(img); } catch (e) {}
                    }
                };

                const timer = setTimeout(() => {
                    cleanup();
                    resolve({ width: -1, height: -1, isZero: false });
                }, 150);

                img.onerror = () => {
                    clearTimeout(timer);
                    const isZero = (img.width === 0 && img.height === 0);
                    const res = { width: img.width, height: img.height, isZero: isZero };
                    cleanup();
                    resolve(res);
                };

                (document.body || document.documentElement).appendChild(img);
                img.src = "data:image/svg+xml;base64,invalid";
            });
        } catch (e) {}
    }

    // 6. window.chrome Object Test and Clean Realm Presence (Intoli / FPScanner)
    const hasChrome = (typeof window !== 'undefined') && (typeof window.chrome !== 'undefined');
    const hasChromeRuntime = hasChrome && (typeof window.chrome.runtime !== 'undefined');
    let cleanRealmHasChrome = null;
    if (cleanRealm && cleanRealm.window) {
        try {
            cleanRealmHasChrome = (typeof cleanRealm.window.chrome !== 'undefined');
        } catch (e) {
            cleanRealmHasChrome = null;
        }
    }

    // 6.1 Browser-Specific Signals for Non-Chrome Engines (Opera, Firefox, Safari)
    const browserFeatures = {
        hasOpr: (typeof window !== 'undefined') && (typeof window.opr !== 'undefined'),
        hasSafari: (typeof window !== 'undefined') && (typeof window.safari !== 'undefined'),
        hasInstallTrigger: (typeof InstallTrigger !== 'undefined'),
        mozInnerScreenX: (typeof window !== 'undefined' && typeof window.mozInnerScreenX !== 'undefined') ? window.mozInnerScreenX : null,
        mozInnerScreenY: (typeof window !== 'undefined' && typeof window.mozInnerScreenY !== 'undefined') ? window.mozInnerScreenY : null,
        oscpu: (typeof navigator !== 'undefined' && navigator.oscpu) ? navigator.oscpu : ""
    };

    // 7. Advanced ChromeDriver Traces (CDC Regex & Document Attributes)
    let cdcAttributeFound = false;
    let docElemAttrs = [];
    let sequentumFound = false;

    if (typeof document !== 'undefined') {
        try {
            for (const key of Object.getOwnPropertyNames(document)) {
                if (/\$[a-z]dc_/.test(key) && document[key] && typeof document[key].cache_ !== 'undefined') {
                    cdcAttributeFound = true;
                    break;
                }
            }
            if (document.documentElement) {
                for (const attr of ['selenium', 'webdriver', 'driver']) {
                    if (document.documentElement.hasAttribute(attr)) {
                        docElemAttrs.push(attr);
                    }
                }
            }
        } catch (e) {}
    }

    if (typeof window !== 'undefined' && window.external) {
        try {
            sequentumFound = window.external.toString().includes('Sequentum');
        } catch (e) {}
    }

    // 8. Plugins Stringification Test (Intoli Plugins Type Test)
    let firstPluginToString = "";
    if (typeof navigator !== 'undefined' && navigator.plugins && navigator.plugins.length > 0 && navigator.plugins[0]) {
        try {
            firstPluginToString = navigator.plugins[0].toString();
        } catch (e) {
            firstPluginToString = "error";
        }
    }

    // 9. Proprietary Video Codecs Support (FPScanner Video Codecs)
    let videoH264 = "";
    if (typeof document !== 'undefined' && document.createElement) {
        try {
            const video = document.createElement('video');
            if (video && video.canPlayType) {
                videoH264 = video.canPlayType('video/mp4; codecs="avc1.42E01E"') || "";
            }
        } catch (e) {}
    }

    // 10. Hairline Feature Test (Modernizr / Intoli Hairline Feature)
    let hairlineSupported = false;
    if (typeof window !== 'undefined' && window.matchMedia) {
        try {
            hairlineSupported = window.matchMedia('(-webkit-min-device-pixel-ratio: 2), (min-resolution: 192dpi)').matches;
        } catch (e) {}
    }

    // 11. Media Devices and Battery Probing (FPScanner Media Devices & Battery)
    let mediaDevicesCount = -1;
    if (typeof navigator !== 'undefined' && navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
        try {
            const devices = await Promise.race([
                navigator.mediaDevices.enumerateDevices(),
                new Promise(resolve => setTimeout(() => resolve(null), 150))
            ]);
            if (devices) {
                mediaDevicesCount = devices.length;
            }
        } catch (e) {}
    }

    const hasBatteryApi = (typeof navigator !== 'undefined') && (typeof navigator.getBattery === 'function');

    // 12. V8 Inspector Trap (V8 Console & Getter Trap / CDP Probe)
    let cdpDetected = false;
    let stackTrapTriggered = false;
    let customGetterTriggered = false;

    try {
        const errorTrap = new Error();
        Object.defineProperty(errorTrap, 'stack', {
            configurable: true,
            enumerable: false,
            get() {
                stackTrapTriggered = true;
                cdpDetected = true;
                return "";
            }
        });

        const objTrap = {};
        Object.defineProperty(objTrap, 'cdpProbe', {
            configurable: true,
            enumerable: true,
            get() {
                customGetterTriggered = true;
                cdpDetected = true;
                return "cdp_active";
            }
        });

        if (typeof console !== 'undefined' && console.debug) {
            console.debug(errorTrap);
            console.debug(objTrap);
        }

        // Await microtasks/IPC turn for asynchronous CDP protocol inspection
        await new Promise(resolve => setTimeout(resolve, 80));
    } catch (e) {}

    // 13. Consolidated Telemetry Payload Assembly
    const signals = {
        timestamp: Date.now(),
        cdpDetected: cdpDetected,
        v8InspectorTrap: {
            cdpDetected: cdpDetected,
            stackTrapTriggered: stackTrapTriggered,
            customGetterTriggered: customGetterTriggered
        },
        userAgent: (typeof navigator !== 'undefined' && navigator.userAgent) ? navigator.userAgent : "",
        webdriver: (typeof navigator !== 'undefined') ? navigator.webdriver : null,
        languages: (typeof navigator !== 'undefined' && Array.isArray(navigator.languages)) ? [...navigator.languages] : [],
        hardwareConcurrency: (typeof navigator !== 'undefined') ? navigator.hardwareConcurrency : null,
        deviceMemory: (typeof navigator !== 'undefined') ? navigator.deviceMemory : null,
        platform: (typeof navigator !== 'undefined') ? navigator.platform : "",
        vendor: (typeof navigator !== 'undefined') ? navigator.vendor : "",
        cookieEnabled: (typeof navigator !== 'undefined') ? navigator.cookieEnabled : true,

        // Blind Property Harvesting
        windowProperties: windowProperties,
        documentProperties: documentProperties,
        navigatorProperties: navigatorProperties,

        // Intoli & FPScanner Probes
        permissions: {
            state: permissionState,
            notificationPermission: notificationPermission
        },
        brokenImage: brokenImage,
        chromeObject: {
            hasChrome: hasChrome,
            hasRuntime: hasChromeRuntime,
            cleanRealmHasChrome: cleanRealmHasChrome
        },
        browserFeatures: browserFeatures,
        seleniumExtended: {
            cdcAttributeFound: cdcAttributeFound,
            docElemAttrs: docElemAttrs,
            sequentumFound: sequentumFound
        },
        pluginsInfo: {
            length: (typeof navigator !== 'undefined' && navigator.plugins) ? navigator.plugins.length : 0,
            isPluginArray: (typeof PluginArray !== 'undefined' && typeof navigator !== 'undefined' && navigator.plugins instanceof PluginArray),
            firstPluginToString: firstPluginToString
        },
        videoCodecs: {
            h264: videoH264
        },
        hardwareExtended: {
            hairlineSupported: hairlineSupported,
            mediaDevicesCount: mediaDevicesCount,
            hasBatteryApi: hasBatteryApi
        },

        screen: {
            width: (typeof window !== 'undefined' && window.screen) ? window.screen.width : 0,
            height: (typeof window !== 'undefined' && window.screen) ? window.screen.height : 0,
            colorDepth: (typeof window !== 'undefined' && window.screen) ? window.screen.colorDepth : 0
        },

        windowDimensions: {
            outerWidth: (typeof window !== 'undefined') ? window.outerWidth : 0,
            outerHeight: (typeof window !== 'undefined') ? window.outerHeight : 0,
            innerWidth: (typeof window !== 'undefined') ? window.innerWidth : 0,
            innerHeight: (typeof window !== 'undefined') ? window.innerHeight : 0
        },

        webgl: {
            renderer: webglRenderer,
            vendor: webglVendor
        },

        touch: {
            hasTouchEvents: (typeof window !== 'undefined') && ('ontouchstart' in window),
            maxTouchPoints: (typeof navigator !== 'undefined' && navigator.maxTouchPoints) ? navigator.maxTouchPoints : 0
        },

        syntheticEvents: (typeof InteractionMonitor !== 'undefined')
            ? [...InteractionMonitor.syntheticEventsDetected]
            : [],

        prototypeIntegrity: {
            webdriverIllegalInvocationFailed: webdriverIllegalInvocationFailed,
            navigatorProtoMismatch: navigatorProtoMismatch,
            functionToStringTampered: functionToStringTampered
        },

        sessionInfo: {
            historyLength: (typeof window !== 'undefined' && window.history) ? window.history.length : 0,
            referrer: (typeof document !== 'undefined') ? document.referrer : ""
        }
    };

    return signals;
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { collectTelemetrySignals };
}
