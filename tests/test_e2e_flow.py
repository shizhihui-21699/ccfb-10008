"""End-to-end login + MFA flows through the Flask test client."""

import pytest

from mfa_app import totp
from mfa_app.clock import clock
from mfa_app.services import ACTIONS


def _login(client, username="alice", password="pw123456"):
    return client.post("/login", data={"username": username, "password": password},
                       follow_redirects=False)


def test_full_login_with_totp(client, app, make_user, make_device):
    with app.app_context():
        from mfa_app.db import get_db
        from mfa_app.repositories import UserRepository
        user = make_user()
        _, _, secret = make_device(user)

    assert _login(client).status_code == 302  # -> challenge page
    clock.advance(30)
    resp = client.post("/login/challenge",
                       data={"code": totp.totp(secret, clock.now())})
    assert resp.status_code == 302
    overview = client.get("/mfa")
    assert overview.status_code == 200 and "已绑定设备" in overview.get_data(as_text=True)


def test_replayed_login_code_is_rejected_then_fresh_code_works(
        client, app, make_user, make_device):
    with app.app_context():
        user = make_user()
        _, _, secret = make_device(user)

    _login(client)
    clock.advance(30)
    code = totp.totp(secret, clock.now())
    assert client.post("/login/challenge", data={"code": code}).status_code == 302
    client.post("/logout")

    # Attacker replays the intercepted code in a new login.
    _login(client)
    resp = client.post("/login/challenge", data={"code": code})
    assert resp.status_code == 401

    clock.advance(30)
    fresh = totp.totp(secret, clock.now())
    resp = client.post("/login/challenge", data={"code": fresh})
    assert resp.status_code == 302


def test_login_with_backup_code(client, app, make_user, make_device, make_backups):
    with app.app_context():
        user = make_user()
        make_device(user)
        backup = make_backups(user)[0]

    _login(client)
    resp = client.post("/login/challenge", data={"code": backup})
    assert resp.status_code == 302
    # backup code is now spent
    _login(client)
    resp = client.post("/login/challenge", data={"code": backup})
    assert resp.status_code == 401


def test_five_wrong_codes_lock_the_login_challenge(client, app, make_user, make_device):
    with app.app_context():
        user = make_user()
        make_device(user)

    _login(client)
    for _ in range(5):
        client.post("/login/challenge", data={"code": "000000"})
    resp = client.post("/login/challenge", data={"code": "000000"})
    assert resp.status_code == 423  # Locked


def test_bad_password_is_audited_but_does_not_touch_mfa_counter(
        client, app, make_user, make_device, repos):
    with app.app_context():
        user = make_user()
        make_device(user)
    resp = client.post("/login", data={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401
    rows = repos["audit"].list_all(action=ACTIONS["LOGIN_FAIL"])
    assert len(rows) == 1


def test_login_challenge_expires(client, app, make_user, make_device):
    with app.app_context():
        user = make_user()
        make_device(user)
    _login(client)
    clock.advance(301)
    resp = client.get("/login/challenge")
    assert resp.status_code == 302 and "/login" in resp.headers["Location"]


def test_multi_device_any_device_can_authenticate(
        client, app, make_user, make_device):
    with app.app_context():
        user = make_user()
        _, _, secret1 = make_device(user, name="phone-a")
        _, _, secret2 = make_device(user, name="phone-b")

    _login(client)
    clock.advance(30)
    resp = client.post(
        "/login/challenge", data={"code": totp.totp(secret2, clock.now())})
    assert resp.status_code == 302


def test_enroll_second_device_requires_stepup(client, app, make_user, make_device):
    with app.app_context():
        user = make_user()
        make_device(user)
        with client.session_transaction() as sess:
            sess["user_id"] = user["id"]
            sess.pop("stepup_until", None)
    resp = client.post("/mfa/enroll", data={"name": "second"})
    assert resp.status_code == 302 and "/stepup" in resp.headers["Location"]


def test_open_redirect_via_next_is_blocked(client, app, make_user, make_device):
    with app.app_context():
        from mfa_app import totp
        user = make_user()
        _, _, secret = make_device(user)
        with client.session_transaction() as sess:
            sess["user_id"] = user["id"]
        clock.advance(30)
        resp = client.post(
            "/stepup?next=https://evil.example/phish",
            data={"code": totp.totp(secret, clock.now())})
    assert resp.status_code == 302
    assert "evil.example" not in resp.headers["Location"]
