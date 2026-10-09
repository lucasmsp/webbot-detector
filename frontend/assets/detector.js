/**
 * Detection Sensor Orchestrator & Server Communication (Client SDK)
 *
 * Industry Best Practice Architecture (Zero-Knowledge Client):
 * 1. Client leverages 'collector.js' to extract raw telemetry signals.
 * 2. Dispatches data payload via POST /api/assess-risk to the Server.
 * 3. Server (Risk Engine) evaluates rules confidentially, cross-references
 *    with HTTP network headers, and returns the risk classification.
 */

// Support for Node.js / CommonJS imports
if (typeof require !== 'undefined' && typeof module !== 'undefined') {
    try {
        const utils = require('./utils.js');
        global.getCleanRealm = global.getCleanRealm || utils.getCleanRealm;
        global.isNativeGetter = global.isNativeGetter || utils.isNativeGetter;
        global.InteractionMonitor = global.InteractionMonitor || utils.InteractionMonitor;

        const collector = require('./collector.js');
        global.collectTelemetrySignals = global.collectTelemetrySignals || collector.collectTelemetrySignals;
    } catch (e) {}
}

/**
 * Determines the correct Risk API endpoint on the backend
 */
function getRiskApiEndpoint() {
    if (typeof window !== 'undefined' && window.location && window.location.protocol.startsWith('http')) {
        return '/api/assess-risk';
    }
    // Fallback to default local server if opened via file://
    return 'http://localhost:8000/api/assess-risk';
}

/**
 * Determines the cryptographic challenge endpoint on the backend
 */
function getChallengeEndpoint() {
    if (typeof window !== 'undefined' && window.location && window.location.protocol.startsWith('http')) {
        return '/api/challenge';
    }
    return 'http://localhost:8000/api/challenge';
}

/**
 * Computes Environmental Binding Hash integrity
 * using native browser Web Crypto API (SubtleCrypto).
 */
async function computeEnvironmentalHash(nonce, signals) {
    try {
        if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
            const screen = signals.screen || {};
            const webgl = signals.webgl || {};
            const parts = [
                String(nonce || ""),
                String(signals.userAgent || ""),
                String(screen.width || 0),
                String(screen.height || 0),
                String(screen.colorDepth || 0),
                String(signals.hardwareConcurrency || ""),
                String(webgl.renderer || ""),
                String(signals.platform || "")
            ];
            const bindingString = parts.join("|");
            const encoder = new TextEncoder();
            const data = encoder.encode(bindingString);
            const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
            return Array.from(new Uint8Array(hashBuffer))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
        }
    } catch (e) {
        console.warn("[Crypto] Failed to compute native environmental hash:", e);
    }
    return null;
}

/**
 * Main function retrieving cryptographic challenge, collecting telemetry,
 * binding environmental metrics, and querying the server risk engine.
 */
async function detectBot() {
    const riskEndpoint = getRiskApiEndpoint();
    const challengeEndpoint = getChallengeEndpoint();

    // 1. Retrieve ephemeral cryptographic challenge from server (Nonce + HMAC signature)
    let challengeData = null;
    try {
        const chResponse = await fetch(challengeEndpoint, {
            method: 'GET',
            headers: {
                'X-Requested-With': 'Incognia-Case-Sensor'
            }
        });
        if (chResponse.ok) {
            challengeData = await chResponse.json();
        }
    } catch (chErr) {
        console.warn("[Crypto Challenge] Warning contacting challenge endpoint:", chErr.message);
    }

    // 2. Collect raw passive telemetry signals from browser
    const signals = (typeof collectTelemetrySignals === 'function')
        ? await collectTelemetrySignals()
        : {};

    // 3. Compute Environmental Binding Hash bound to challenge Nonce
    const nonce = challengeData ? challengeData.nonce : "";
    const environmentalHash = await computeEnvironmentalHash(nonce, signals);

    const payload = {
        sessionId: "sess_" + Math.random().toString(36).substring(2) + Date.now().toString(36),
        challenge: challengeData,
        environmentalHash: environmentalHash,
        signals: signals
    };

    try {
        const response = await fetch(riskEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'Incognia-Case-Sensor'
            },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            throw new Error(`Server responded with status ${response.status}`);
        }

        const serverAssessment = await response.json();
        window.__latestBotResult = serverAssessment;
        return serverAssessment;

    } catch (err) {
        console.warn("[Risk Engine] Unable to contact server endpoint:", riskEndpoint, err.message);

        // Informative fallback if backend is offline
        const fallbackResult = {
            isBot: signals.webdriver === true || (signals.automationGlobals && Object.values(signals.automationGlobals).some(Boolean)),
            action: "OFFLINE_FALLBACK",
            totalCategoriesTriggered: 1,
            serverEvaluation: {
                online: false,
                warning: "Servidor offline. Para avaliação completa com regras confidenciais, execute 'python server.py'."
            },
            categories: {
                server_status: {
                    id: "server_status",
                    title: "Servidor Backend Offline",
                    subtitle: "Inicie o servidor com 'python server.py' para a avaliação multicamadas",
                    detected: true,
                    reasons: ["Não foi possível conectar a " + riskEndpoint + " (" + err.message + ")"]
                }
            },
            reasons: ["Servidor de regras de risco indisponível (" + err.message + ")"]
        };

        window.__latestBotResult = fallbackResult;
        return fallbackResult;
    }
}

// Compatibility when imported as CommonJS module
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { detectBot, getRiskApiEndpoint, getChallengeEndpoint, computeEnvironmentalHash };
}
