"""Replay protection and clock roll-back behaviour at the service layer.

Scenario behind these tests: a user switches phones and the new device's
clock is wrong — either ahead then corrected, or simply behind. A TOTP code
that was already accepted (or any code from an earlier time-step) must never
be accepted twice.
"""

import pytest

from mfa_app import totp
from mfa_app.clock import clock
from mfa_app.services import ACTIONS, LockedError


def test_same_code_cannot_be_used_twice(make_user, make_device, service):
    user, device, secret = make_device(make_user())
    # Confirmation already consumed the current step's counter; move to the
    # next 30s step before generating a "fresh" login code.
    clock.advance(30)
    code = totp.totp(secret, clock.now())

    first = service.verify_totp(user, code, None)
    assert first.ok
    second = service.verify_totp(user, code, None)
    assert not second.ok and second.reason == "replayed_code"


def test_replay_blocked_even_after_step_advances(make_user, make_device, service, repos):
    user, device, secret = make_device(make_user())
    clock.advance(30)  # next 30s step
    code = totp.totp(secret, clock.now())
    assert service.verify_totp(user, code, None).ok

    clock.advance(30)
    # The *old* code is inside the drift window at the primitive level...
    primitive = totp.verify(secret, code, clock.now(), window=1)
    assert primitive is not None and primitive.drift_steps == -1
    # ...but the service must reject it because its counter is not fresh.
    result = service.verify_totp(user, code, None)
    assert not result.ok and result.reason == "replayed_code"


def test_clock_rolled_back_old_step_code_rejected(make_user, make_device, service):
    user, device, secret = make_device(make_user())
    clock.advance(30)
    # Accept a code at the fresh step (33334).
    assert service.verify_totp(user, totp.totp(secret, clock.now()), None).ok

    # Phone clock jumps backwards by 45s: generated codes now come from an
    # earlier step the drift window would normally accept.
    clock.advance(-45)
    rolled_back_code = totp.totp(secret, clock.now())
    result = service.verify_totp(user, rolled_back_code, None)
    assert not result.ok and result.reason == "replayed_code"


def test_clock_rolled_back_then_catches_up_works_again(make_user, make_device, service):
    user, device, secret = make_device(make_user())
    clock.advance(30)
    assert service.verify_totp(user, totp.totp(secret, clock.now()), None).ok

    clock.advance(-45)
    assert not service.verify_totp(
        user, totp.totp(secret, clock.now()), None).ok

    # Clock corrected back to real time and a new step has begun.
    clock.advance(75)
    fresh = totp.totp(secret, clock.now())
    assert service.verify_totp(user, fresh, None).ok


def test_exact_boundary_code_acceptance_and_replay(make_user, make_device, service):
    """Walk the frozen clock up to an exact 30s switch point (1_000_050)."""
    user, device, secret = make_device(make_user())  # last counter = 33333
    boundary = 1_000_050  # step 33334 -> 33335
    # 1ms before the boundary: accept the old-step code (counter 33334).
    clock.freeze(boundary - 1)
    old_code = totp.totp(secret, clock.now())
    assert service.verify_totp(user, old_code, None).ok

    # At the boundary the same code is a replay even though the primitive
    # still accepts it via the -1 drift step.
    clock.freeze(boundary)
    result = service.verify_totp(user, old_code, None)
    assert not result.ok and result.reason == "replayed_code"

    # The brand-new step's code works and records the higher counter.
    new_code = totp.totp(secret, clock.now())
    assert service.verify_totp(user, new_code, None).ok


def test_replay_is_audited_and_counts_as_failure(make_user, make_device, service, repos):
    user, device, secret = make_device(make_user())
    clock.advance(30)
    code = totp.totp(secret, clock.now())
    service.verify_totp(user, code, None)
    service.verify_totp(user, code, None)

    rows = repos["audit"].list_all(action=ACTIONS["MFA_REPLAY"])
    assert len(rows) == 1 and rows[0]["result"] == "denied"
    refreshed = repos["users"].get(user["id"])
    assert refreshed["failed_attempts"] == 1


def test_replay_counters_are_per_device(make_user, make_device, service):
    user = make_user()
    _, device1, secret1 = make_device(user, name="phone-a")
    _, device2, secret2 = make_device(user, name="phone-b")
    clock.advance(30)

    code1 = totp.totp(secret1, clock.now())
    code2 = totp.totp(secret2, clock.now())
    assert service.verify_totp(user, code1, None).ok
    assert service.verify_totp(user, code2, None).ok
    # Reusing either code fails, but each device tracks its own counter.
    assert service.verify_totp(user, code1, None).reason == "replayed_code"
    assert service.verify_totp(user, code2, None).reason == "replayed_code"


def test_lockout_does_not_corrupt_counter_state(make_user, make_device, service):
    user, device, secret = make_device(make_user())
    # Burn the failure budget with wrong codes.
    for _ in range(5):
        service.verify_totp(user, "000000", None)
    with pytest.raises(LockedError):
        service.verify_totp(user, totp.totp(secret, clock.now()), None)

    # After the lock expires the correct code works and resets the counter.
    clock.advance(400)
    assert service.verify_totp(
        user, totp.totp(secret, clock.now()), None).ok
