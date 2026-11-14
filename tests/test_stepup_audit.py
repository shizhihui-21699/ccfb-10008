"""Step-up verification, audit completeness and sensitive-route protection."""

import pytest

from mfa_app import totp
from mfa_app.clock import clock
from mfa_app.services import ACTIONS


def test_stepup_grant_expires_after_ttl(app):
    with app.app_context():
        from mfa_app.auth import grant_stepup, stepup_valid
        with app.test_request_context():
            grant_stepup(120)
            assert stepup_valid()
            clock.advance(121)
            assert not stepup_valid()


def test_sensitive_route_requires_stepup(client, app, make_user, make_device):
    with app.app_context():
        user = make_user()
        make_device(user)
        with client.session_transaction() as sess:
            sess["user_id"] = user["id"]
            sess.pop("stepup_until", None)

    resp = client.post("/mfa/disable")
    assert resp.status_code == 302
    assert "/stepup" in resp.headers["Location"]


def test_stepup_then_sensitive_route_succeeds(client, app, make_user, make_device):
    with app.app_context():
        user = make_user()
        _, device, secret = make_device(user)
        with client.session_transaction() as sess:
            sess["user_id"] = user["id"]
        clock.advance(30)
        code = totp.totp(secret, clock.now())

    resp = client.post("/stepup", data={"code": code})
    assert resp.status_code == 302

    resp = client.post("/mfa/disable")
    assert resp.status_code == 302

    with app.app_context():
        from mfa_app.db import get_db
        from mfa_app.repositories import DeviceRepository
        assert DeviceRepository(get_db()).list_for_user(user["id"]) == []


def test_every_sensitive_action_writes_audit(
        client, app, make_user, make_device, make_backups, repos):
    with app.app_context():
        user = make_user()
        _, device, secret = make_device(user)
        make_backups(user)
        device_id = device["id"]
        with client.session_transaction() as sess:
            sess["user_id"] = user["id"]
        clock.advance(30)
        code = totp.totp(secret, clock.now())

    client.post("/stepup", data={"code": code})
    client.post("/mfa/backup-codes")          # regenerate while step-up fresh
    client.post(f"/mfa/devices/{device_id}/delete")

    with app.app_context():
        actions = {r["action"] for r in repos["audit"].list_all(limit=100)}
    assert ACTIONS["BACKUP_GENERATE"] in actions
    assert ACTIONS["DEVICE_REMOVE"] in actions
    assert ACTIONS["MFA_VERIFY"] in actions


def test_audit_records_include_ip_and_result(
        client, app, make_user, make_device, repos):
    with app.app_context():
        user = make_user()
        _, _, secret = make_device(user)
        with client.session_transaction() as sess:
            sess["user_id"] = user["id"]
        clock.advance(30)

    client.post("/stepup", data={"code": totp.totp(secret, clock.now())},
                environ_overrides={"REMOTE_ADDR": "10.0.0.7"})

    with app.app_context():
        rows = repos["audit"].list_all(action=ACTIONS["MFA_VERIFY"])
        assert rows
        assert rows[0]["ip"] == "10.0.0.7"
        assert rows[0]["result"] == "success"


def test_admin_routes_forbidden_for_normal_user(client, app, make_user):
    with app.app_context():
        user = make_user()
        with client.session_transaction() as sess:
            sess["user_id"] = user["id"]
    assert client.get("/admin").status_code == 403
    assert client.get("/admin/audit").status_code == 403
