"""Cross-check our hand-rolled TOTP against the pyotp reference library."""

import pyotp
import pytest

from mfa_app import totp
from mfa_app.clock import clock


@pytest.mark.parametrize("offset", [-30, -1, 0, 1, 29, 30, 45])
def test_generated_codes_match_pyotp(offset):
    secret = totp.generate_secret()
    ts = 1_000_000.0 + offset
    assert totp.totp(secret, ts) == pyotp.TOTP(secret).at(ts)


def test_provisioning_uri_parses_in_pyotp():
    secret = totp.generate_secret()
    uri = totp.provisioning_uri(secret, "alice@example.com", "MFA Demo")
    parsed = pyotp.parse_uri(uri)
    assert isinstance(parsed, pyotp.TOTP)
    assert parsed.secret == secret
    assert parsed.issuer == "MFA Demo"
    # Round-trip: a code pyotp generates from the URI is accepted by us.
    code = pyotp.TOTP(secret).at(clock.now())
    assert totp.verify(secret, code, clock.now()) is not None


def test_pyotp_secret_verifies_in_our_implementation():
    pyotp_secret = pyotp.random_base32()
    code = pyotp.TOTP(pyotp_secret).at(clock.now())
    match = totp.verify(pyotp_secret, code, clock.now())
    assert match is not None and match.drift_steps == 0
