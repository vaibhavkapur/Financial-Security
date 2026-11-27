"""Canary secret detection and telemetry redaction utilities."""

from __future__ import annotations

import base64
import re
from typing import Any

from fin_redteam.models import CanaryEncoding, CanarySecret

_NON_ALNUM_RE = re.compile(r"[^A-Za-z0-9]+")


def encode_canary(value: str, encoding: CanaryEncoding) -> str:
    """Encode a synthetic canary value to simulate obfuscated exfiltration attempts."""
    if encoding == CanaryEncoding.RAW:
        return value
    if encoding == CanaryEncoding.BASE64:
        return base64.b64encode(value.encode("utf-8")).decode("ascii")
    if encoding == CanaryEncoding.SPACED:
        return " ".join(list(value))
    raise ValueError(f"Unsupported canary encoding: {encoding}")


class CanaryGuard:
    """Detects and redacts synthetic canary secrets across raw, base64, and obfuscated text."""

    def __init__(self, canaries: list[CanarySecret]) -> None:
        self._canaries = list(canaries)
        self._by_id = {c.canary_id: c for c in canaries}
        self._patterns: list[tuple[CanarySecret, str, str, str]] = []
        for canary in self._canaries:
            raw_lower = canary.value.lower()
            b64_val = base64.b64encode(canary.value.encode("utf-8")).decode("ascii")
            alnum_norm = _NON_ALNUM_RE.sub("", canary.value).lower()
            self._patterns.append((canary, raw_lower, b64_val, alnum_norm))

    def get_canary(self, canary_id: str) -> CanarySecret | None:
        """Retrieve a synthetic canary by identifier."""
        return self._by_id.get(canary_id)

    def detect_in_text(self, text: str) -> list[str]:
        """Return sorted unique canary IDs detected in raw, base64, or obfuscated text."""
        if not text:
            return []
        lower_text = text.lower()
        norm_text = _NON_ALNUM_RE.sub("", text).lower()
        matched: set[str] = set()
        for canary, raw_lower, b64_val, alnum_norm in self._patterns:
            if raw_lower in lower_text or b64_val in text or alnum_norm in norm_text:
                matched.add(canary.canary_id)
        return sorted(matched)

    def detect_in_payload(self, payload: Any) -> list[str]:
        """Recursively scan arbitrary JSON-compatible payloads for canary leakage."""
        matched: set[str] = set()
        if isinstance(payload, str):
            matched.update(self.detect_in_text(payload))
        elif isinstance(payload, dict):
            for k, v in payload.items():
                matched.update(self.detect_in_payload(str(k)))
                matched.update(self.detect_in_payload(v))
        elif isinstance(payload, (list, tuple, set)):
            for item in payload:
                matched.update(self.detect_in_payload(item))
        return sorted(matched)

    def redact_text(self, text: str) -> str:
        """Replace raw, base64, or spaced synthetic canaries with deterministic redaction tokens."""
        redacted = text
        for canary, _raw_lower, b64_val, _alnum_norm in self._patterns:
            token = f"[REDACTED:{canary.canary_id}]"
            # Case-insensitive raw match
            redacted = re.sub(re.escape(canary.value), token, redacted, flags=re.IGNORECASE)
            # Base64 match
            if b64_val in redacted:
                redacted = redacted.replace(b64_val, token)
            # Spaced/separator-obfuscated match
            spaced_pattern = r"[\s\-_]*".join(re.escape(ch) for ch in canary.value)
            redacted = re.sub(spaced_pattern, token, redacted, flags=re.IGNORECASE)
        return redacted

    def redact_payload(self, payload: Any) -> Any:
        """Recursively redact canary strings inside nested structures for safe audit logging."""
        if isinstance(payload, str):
            return self.redact_text(payload)
        if isinstance(payload, dict):
            return {k: self.redact_payload(v) for k, v in payload.items()}
        if isinstance(payload, list):
            return [self.redact_payload(v) for v in payload]
        if isinstance(payload, tuple):
            return tuple(self.redact_payload(v) for v in payload)
        return payload
