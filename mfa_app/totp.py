"""RFC 6238 TOTP, implemented from scratch on the stdlib.

The library deliberately contains no Flask/database dependencies so the time
boundary behaviour can be unit-tested in isolation:

* ``verify`` accepts a drift window of adjacent time-steps (default +/- one
  30-second step);
* it reports the *counter* that matched, so the service layer can enforce
  "one code, one use" by requiring counters to move forward per device —
  which also makes a backwards clock adjustment harmless (a code whose
  counter is <= the last accepted counter is rejected outright).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import urllib.parse
from dataclasses import dataclass

BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def generate_secret(length: int = 20) -> str:
    """Return a new base32-encoded shared secret (RFC 4648, no padding).

    20 random bytes (160 bits, matching the RFC 4226/6238 reference key size)
    encode to 32 base32 characters — the size Google Authenticator expects.
    """
    random_bytes = secrets.token_bytes(length)
    return base64.b32encode(random_bytes).decode().rstrip("=")


def _decode_secret(secret: str) -> bytes:
    padded = secret.upper().replace(" ", "") + "=" * (-len(secret) % 8)
    return base64.b32decode(padded, casefold=True)


def counter_at(timestamp: float, period: int) -> int:
    return int(timestamp) // period


def hotp(secret: str, counter: int, digits: int = 6) -> str:
    """RFC 4226 HOTP."""
    key = _decode_secret(secret)
    msg = struct.pack(">Q", counter)
    mac = hmac.new(key, msg, hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    binary = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFF_FFFF
    return str(binary % (10 ** digits)).zfill(digits)


def totp(secret: str, timestamp: float, period: int = 30, digits: int = 6) -> str:
    return hotp(secret, counter_at(timestamp, period), digits)


@dataclass(frozen=True)
class TOTPMatch:
    counter: int
    drift_steps: int  # 0 = exact step, +/-N = accepted via the drift window


def verify(
    secret: str,
    code: str,
    timestamp: float,
    *,
    period: int = 30,
    digits: int = 6,
    window: int = 1,
) -> TOTPMatch | None:
    """Check ``code`` at ``timestamp`` allowing ``window`` adjacent steps.

    Returns the matched counter (and drift) or ``None``. Constant-time
    comparison is used for every candidate so the window does not leak
    timing information.
    """
    if not code or not code.strip().isdigit() or len(code.strip()) != digits:
        return None
    candidate = code.strip()
    current = counter_at(timestamp, period)
    matched: TOTPMatch | None = None
    # Check the exact step first; keep scanning so every candidate gets an
    # HMAC comparison regardless of where the match is.
    for drift in range(0, -window - 1, -1):
        counter = current + drift
        expected = hotp(secret, counter, digits)
        if hmac.compare_digest(expected, candidate) and matched is None:
            matched = TOTPMatch(counter=counter, drift_steps=drift)
    for drift in range(1, window + 1):
        counter = current + drift
        expected = hotp(secret, counter, digits)
        if hmac.compare_digest(expected, candidate) and matched is None:
            matched = TOTPMatch(counter=counter, drift_steps=drift)
    return matched


def provisioning_uri(secret: str, account_name: str, issuer: str, digits: int = 6,
                     period: int = 30) -> str:
    """otpauth:// URI consumed by Google Authenticator and friends."""
    params = urllib.parse.urlencode({
        "secret": secret,
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": digits,
        "period": period,
    })
    label = urllib.parse.quote(f"{issuer}:{account_name}")
    return f"otpauth://totp/{label}?{params}"
