"""RFC 6238 conformance and time-boundary tests for the TOTP primitive."""

from __future__ import annotations

import pytest

from mfa_app import totp

# RFC 6238 appendix B test vector (SHA-1, 8 digits, 30s step).
import base64 as _b64

RFC_SECRET = _b64.b32encode(b"12345678901234567890").decode().rstrip("=")
RFC_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


@pytest.mark.parametrize("timestamp,expected", RFC_VECTORS)
def test_rfc6238_sha1_vectors(timestamp, expected):
    assert totp.totp(RFC_SECRET, timestamp, period=30, digits=8) == expected


def _b32(ascii_seed: str) -> str:  # retained for any ad-hoc vector use
    return base64.b32encode(ascii_seed.encode()).decode().rstrip("=")


def test_generate_secret_is_base32_and_unique():
    s1 = totp.generate_secret()
    s2 = totp.generate_secret()
    assert s1 != s2
    assert all(c in totp.BASE32_ALPHABET for c in s1)
    assert len(s1) == 32


def test_verify_accepts_current_code(clock_frozen_secret):
    secret, now = clock_frozen_secret
    code = totp.totp(secret, now)
    match = totp.verify(secret, code, now)
    assert match is not None
    assert match.counter == totp.counter_at(now, 30)
    assert match.drift_steps == 0


def test_rejects_wrong_code():
    secret = totp.generate_secret()
    assert totp.verify(secret, "000000", 1_000_000.0) is None


@pytest.mark.parametrize("bad", ["", "12345", "1234567", "abcdef", "12 345"])
def test_rejects_malformed_input(bad):
    secret = totp.generate_secret()
    assert totp.verify(secret, bad, 1_000_000.0) is None


# ------------------------------------------------------- 30s switch boundary

def test_code_valid_until_last_millisecond_of_step():
    secret = totp.generate_secret()
    boundary = 999_990  # exact step boundary: counter 33332 -> 33333
    code = totp.totp(secret, boundary - 1)
    # 1ms before the switch the old code still verifies...
    match = totp.verify(secret, code, boundary - 1)
    assert match and match.counter == 33332
    # ...and at the boundary itself the old counter is already one behind
    # (still accepted here via the +/-1 drift window, but with drift -1).
    match_at_boundary = totp.verify(secret, code, boundary)
    assert match_at_boundary and match_at_boundary.drift_steps == -1


def test_new_code_appears_exactly_at_boundary():
    secret = totp.generate_secret()
    boundary = 999_990
    new_code = totp.totp(secret, boundary)  # counter 33333
    assert totp.totp(secret, boundary - 1) != new_code
    match = totp.verify(secret, new_code, boundary)
    assert match and match.counter == 33333 and match.drift_steps == 0


def test_half_step_both_sides_of_boundary_share_window():
    secret = totp.generate_secret()
    boundary = 999_990
    old_code = totp.totp(secret, boundary - 15)
    new_code = totp.totp(secret, boundary + 15)
    # 15s after the switch both the previous step's code (drift -1) and the
    # current code (drift 0) verify.
    assert totp.verify(secret, old_code, boundary + 15).drift_steps == -1
    assert totp.verify(secret, new_code, boundary + 15).drift_steps == 0


def test_code_two_steps_away_is_outside_window():
    secret = totp.generate_secret()
    now = 1_000_000.0
    stale_code = totp.totp(secret, now - 60)  # two full steps back
    assert totp.verify(secret, stale_code, now, window=1) is None
    # but a wider window would accept it
    assert totp.verify(secret, stale_code, now, window=2) is not None


def test_future_drift_accepted_within_window():
    secret = totp.generate_secret()
    now = 1_000_000.0
    future_code = totp.totp(secret, now + 30)
    match = totp.verify(secret, future_code, now, window=1)
    assert match and match.drift_steps == 1


def test_fractional_seconds_truncate_toward_step_start():
    secret = totp.generate_secret()
    boundary = 999_990
    code = totp.totp(secret, boundary + 29.999)
    match = totp.verify(secret, code, boundary + 29.999)
    assert match and match.counter == 33333


@pytest.fixture()
def clock_frozen_secret():
    secret = totp.generate_secret()
    return secret, 1_000_000.0
