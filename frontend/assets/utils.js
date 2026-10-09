/**
 * Shared utilities for automation detection and environment isolation.
 */

/**
 * Temporarily creates a "Clean Realm" (clean iframe) to retrieve
 * original, untampered references of native prototypes and functions.
 */
function getCleanRealm() {
    try {
        if (typeof document === 'undefined' || !document.createElement) return null;
        const iframe = document.createElement('iframe');
        iframe.style.display = 'none';
        (document.body || document.documentElement).appendChild(iframe);
        const cleanWindow = iframe.contentWindow;
        iframe.parentNode.removeChild(iframe);
        return cleanWindow;
    } catch (e) {
        return null;
    }
}

/**
 * Verifies whether a getter or function is genuinely native to the browser,
 * testing for 'TypeError: Illegal invocation' when invoked
 * with an invalid 'this' context (strict WebIDL specification requirement).
 */
function isNativeGetter(proto, propName) {
    try {
        const desc = Object.getOwnPropertyDescriptor(proto, propName);
        if (!desc || typeof desc.get !== 'function') return false;

        try {
            desc.get.call({});
            return false; // If NO error is thrown, the function was mocked in pure JavaScript
        } catch (err) {
            // Native getters must strictly throw a TypeError ("Illegal invocation")
            return err instanceof TypeError;
        }
    } catch (e) {
        return false;
    }
}

/**
 * Passive behavioral telemetry monitor for detecting macros and synthetic events.
 */
const InteractionMonitor = {
    syntheticEventsDetected: [],
    clicksLogged: 0,
    mouseMovesLogged: 0,
    lastClickTimestamp: 0,

    init() {
        if (typeof window === 'undefined' || !window.addEventListener) return;

        window.addEventListener('click', (e) => {
            this.clicksLogged++;
            this.lastClickTimestamp = Date.now();
            if (e.isTrusted === false) {
                this.syntheticEventsDetected.push("Synthetic click event (isTrusted = false) intercepted.");
            }
        }, { passive: true, capture: true });

        window.addEventListener('mousemove', (e) => {
            this.mouseMovesLogged++;
            if (e.isTrusted === false) {
                this.syntheticEventsDetected.push("Synthetic mousemove event (isTrusted = false) intercepted.");
            }
        }, { passive: true, capture: true });
    }
};

// Initialize user interaction event capture
InteractionMonitor.init();

if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        getCleanRealm,
        isNativeGetter,
        InteractionMonitor
    };
}
