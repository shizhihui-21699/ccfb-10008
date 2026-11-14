"""Progressive lockout: thresholds, escalating delays, expiry, admin unlock."""

import pytest

from mfa_app import totp
from mfa_app.clock import clock
from mfa_app.services import ACTIONS, LockedError


def _fail(service, user, code="000000"):
    return service.verify_totp(user, code, None)


def test_first_four_failures_do_not_lock(make_user, make_device, service, repos):
    user, _, _ = make_device(make_user())
    for _ in range(4):
        result = _fail(service, user)
        assert not result.ok
    refreshed = repos["users"].get(user["id"])
    assert refreshed["locked_until"] is None
    assert service.lockout_remaining(refreshed) == 0


def test_fifth_failure_engages_base_lock(make_user, make_device, service, repos):
    user, _, _ = make_device(make_user())
    for _ in range(4):
        _fail(service, user)
    _fail(service, user)  # 5th -> locked

    refreshed = repos["users"].get(user["id"])
    assert refreshed["locked_until"] == pytest.approx(clock.now() + 15)
    with pytest.raises(LockedError):
        service.verify_totp(user, "000000", None)


def test_lock_delay_escalates_progressively(make_user, make_device, service):
    user, _, _ = make_device(make_user())
    for _ in range(5):
        _fail(service, user)
    assert service._lock_delay(5) == 15
    assert service._lock_delay(6) == 30
    assert service._lock_delay(7) == 45
    # caps at the configured maximum
    assert service._lock_delay(99) == 300


def test_attempts_during_lock_are_refused_without_counter_change(
        make_user, make_device, service, repos):
    user, _, _ = make_device(make_user())
    for _ in range(5):
        _fail(service, user)
    before = repos["users"].get(user["id"])["failed_attempts"]
    with pytest.raises(LockedError):
        service.verify_totp(user, "000000", None)
    after = repos["users"].get(user["id"])["failed_attempts"]
    assert before == after == 5


def test_lock_expires_and_resets_counter(make_user, make_device, service, repos):
    user, _, secret = make_device(make_user())
    for _ in range(5):
        _fail(service, user)
    clock.advance(16)  # base lock (15s) elapsed

    refreshed = repos["users"].get(user["id"])
    assert service.lockout_remaining(refreshed) == 0
    cleared = repos["users"].get(user["id"])
    assert cleared["failed_attempts"] == 0 and cleared["locked_until"] is None
    # correct code on a *fresh* step works immediately after expiry (the
    # confirmation step's counter was already consumed, so advance one step)
    clock.advance(30)
    assert service.verify_totp(
        user, totp.totp(secret, clock.now()), None).ok


def test_backup_code_failures_share_the_lockout_counter(
        make_user, make_device, make_backups, service, repos):
    user, _, _ = make_device(make_user())
    make_backups(user)
    for _ in range(4):
        assert not service.verify_backup_code(user, "WRONG-CODE", None).ok
    assert not service.verify_backup_code(user, "WRONG-CODE", None).ok
    refreshed = repos["users"].get(user["id"])
    assert refreshed["locked_until"] is not None
    with pytest.raises(LockedError):
        service.verify_backup_code(user, "WRONG-CODE", None)


def test_successful_verify_clears_partial_failure_count(
        make_user, make_device, service, repos):
    user, _, secret = make_device(make_user())
    for _ in range(3):
        _fail(service, user)
    clock.advance(30)
    assert service.verify_totp(
        user, totp.totp(secret, clock.now()), None).ok
    refreshed = repos["users"].get(user["id"])
    assert refreshed["failed_attempts"] == 0 and refreshed["locked_until"] is None


def test_admin_unlock_is_audited(make_user, make_device, service, repos):
    admin = make_user(username="boss", admin=True)
    target, _, _ = make_device(make_user(username="bob"))
    for _ in range(5):
        _fail(service, target)

    service.admin_unlock(admin, target["id"], ip="127.0.0.1")
    refreshed = repos["users"].get(target["id"])
    assert refreshed["failed_attempts"] == 0 and refreshed["locked_until"] is None
    rows = repos["audit"].list_all(action=ACTIONS["ADMIN_UNLOCK"])
    assert len(rows) == 1
    assert rows[0]["user_id"] == admin["id"]
    assert "bob" in rows[0]["detail"]


def test_lock_events_are_audited(make_user, make_device, service, repos):
    user, _, _ = make_device(make_user())
    for _ in range(5):
        _fail(service, user)
    locked = repos["audit"].list_all(action=ACTIONS["ACCOUNT_LOCKED"])
    assert len(locked) == 1 and locked[0]["result"] == "success"

    clock.advance(16)
    service.lockout_remaining(repos["users"].get(user["id"]))
    expired = repos["audit"].list_all(action=ACTIONS["ACCOUNT_LOCKED_EXPIRED"])
    assert len(expired) == 1
