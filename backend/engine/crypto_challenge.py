"""
Cryptographic Challenge and Telemetry Integrity Module

Responsible for:
1. Dynamic Challenge Generation with Nonce and HMAC-SHA256 Signature (Anti-Tampering).
2. Strict Temporal Validation (Anti-reuse expiration window).
3. Single-Use Nonce Management (Anti-Replay Protection).
4. Environmental Binding Hash Verification against JSON payload tampering.
"""

import os
import time
import hmac
import hashlib
import secrets
import threading
from typing import Dict, Any, Tuple, Optional


class NonceStore:
    """In-memory storage with automatic expiration for Replay Attack protection."""
    def __init__(self, max_age_seconds: int = 30):
        self.max_age_seconds = max_age_seconds
        self.used_nonces: Dict[str, float] = {}
        self.lock = threading.Lock()

    def is_used_or_consume(self, nonce: str) -> bool:
        """Returns True if the nonce was already consumed (Replay). Otherwise records it and returns False."""
        now = time.time()
        with self.lock:
            # Purge expired nonces
            expired = [n for n, t in self.used_nonces.items() if (now - t) > self.max_age_seconds]
            for n in expired:
                del self.used_nonces[n]

            if nonce in self.used_nonces:
                return True

            self.used_nonces[nonce] = now
            return False

    def clear(self):
        with self.lock:
            self.used_nonces.clear()


class CryptoChallengeManager:
    def __init__(self, secret: Optional[bytes] = None, max_age_seconds: int = 30):
        self.secret = secret or os.environ.get(
            "INCOGNIA_CHALLENGE_SECRET",
            "incognia-case-v8-crypto-secret-2026-key"
        ).encode("utf-8")
        self.max_age_seconds = max_age_seconds
        self.nonce_store = NonceStore(max_age_seconds=max_age_seconds)

    def generate_challenge(self) -> Dict[str, Any]:
        """Generates a new challenge signed with cryptographic nonce and timestamp."""
        nonce = secrets.token_hex(16)
        ts = int(time.time())
        data = f"{nonce}:{ts}".encode("utf-8")
        signature = hmac.new(self.secret, data, hashlib.sha256).hexdigest()

        return {
            "challengeId": f"ch_{nonce[:8]}",
            "nonce": nonce,
            "timestamp": ts,
            "signature": signature,
            "maxAgeSeconds": self.max_age_seconds
        }

    def verify_challenge(self, challenge: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validates challenge authenticity, lifespan, and uniqueness."""
        if not isinstance(challenge, dict):
            return False, "Cryptographic challenge structure missing or invalid."

        nonce = challenge.get("nonce")
        ts = challenge.get("timestamp")
        signature = challenge.get("signature")

        if not nonce or not ts or not signature:
            return False, "Incomplete challenge parameters (nonce, timestamp, or signature missing)."

        try:
            ts_int = int(ts)
        except (ValueError, TypeError):
            return False, "Invalid challenge timestamp format."

        now = int(time.time())
        delta = now - ts_int

        # 1. Temporal window validation
        if delta < 0:
            return False, "Challenge timestamp resides in the future (desynchronized clock or tampering)."
        if delta > self.max_age_seconds:
            return False, f"Challenge expired ({delta}s elapsed, limit is {self.max_age_seconds}s)."

        # 2. HMAC signature validation
        expected_data = f"{nonce}:{ts_int}".encode("utf-8")
        expected_sig = hmac.new(self.secret, expected_data, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(signature), expected_sig):
            return False, "Invalid challenge HMAC signature (credential forgery attempt)."

        # 3. Single-use nonce validation (Anti-Replay)
        if self.nonce_store.is_used_or_consume(nonce):
            return False, "Replay Attack detected: Nonce has already been consumed."

        return True, None

    def compute_expected_environmental_hash(self, nonce: str, signals: Dict[str, Any]) -> str:
        """Computes expected environmental binding hash from extracted signals."""
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
        binding_str = "|".join(parts)
        return hashlib.sha256(binding_str.encode("utf-8")).hexdigest()

    def verify_environmental_binding(
        self,
        nonce: str,
        signals: Dict[str, Any],
        received_hash: str
    ) -> Tuple[bool, Optional[str]]:
        """Verifies whether client-generated environmental binding hash matches telemetry metrics."""
        if not received_hash:
            return False, "Environmental binding hash (environmentalHash) missing from payload."

        expected_hash = self.compute_expected_environmental_hash(nonce, signals)
        if not hmac.compare_digest(str(received_hash).lower(), expected_hash.lower()):
            return False, "Invalid environmental integrity hash (telemetry tampering or environment spoofing)."

        return True, None


# Default global instance used by server
crypto_manager = CryptoChallengeManager()
