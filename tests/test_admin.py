"""Admin console: device listing, audit filtering/pagination, unlock API."""

import pytest

from mfa_app.services import ACTIONS


def test_admin_sees_all_users_devices_and_lock_state(
        client, app, make_user, make_device, service):
    with app.app_context():
        admin = make_user(username="root", admin=True)
        bob = make_user(username="bob")
        make_device(bob, "pixel")
        for _ in range(5):
            service.verify_totp(bob, "000000", None)
        with client.session_transaction() as sess:
            sess["user_id"] = admin["id"]

    page = client.get("/admin").get_data(as_text=True)
    assert "bob" in page and "pixel" in page


def test_audit_filter_by_action_and_username(
        client, app, make_user, make_device, service):
    with app.app_context():
        admin = make_user(username="root", admin=True)
        alice = make_user(username="alice")
        make_device(alice)
        service.verify_totp(alice, "000000", None)  # denied mfa.fail
        with client.session_transaction() as sess:
            sess["user_id"] = admin["id"]

    body = client.get(
        f"/admin/audit?action={ACTIONS['MFA_FAIL']}&username=alice"
    ).get_data(as_text=True)
    # The row appears in the data table (not merely in the filter dropdown).
    assert "<code>mfa.fail</code>" in body
    # a different action filter excludes the data row (dropdown still lists it)
    other = client.get(
        f"/admin/audit?action={ACTIONS['LOGIN_PASSWORD']}").get_data(as_text=True)
    assert "<code>mfa.fail</code>" not in other


def test_audit_pagination(client, app, make_user, make_device, service):
    with app.app_context():
        admin = make_user(username="root", admin=True)
        alice = make_user(username="alice")
        make_device(alice)
        # Audit rows written directly: enough to cross the 25-row page size
        # without tripping alice's MFA lockout (which is irrelevant to admin).
        for i in range(30):
            service.audit.record("test.pagination", "success",
                                 user_id=alice["id"], username="alice",
                                 detail={"n": i})
        with client.session_transaction() as sess:
            sess["user_id"] = admin["id"]

    page1 = client.get("/admin/audit?page=1")
    page2 = client.get("/admin/audit?page=2")
    assert page1.status_code == page2.status_code == 200
    assert "第 1 / 2 页" in page1.get_data(as_text=True)


def test_admin_unlock_endpoint_clears_lock(
        client, app, make_user, make_device, service, repos):
    with app.app_context():
        admin = make_user(username="root", admin=True)
        bob = make_user(username="bob")
        make_device(bob)
        for _ in range(5):
            service.verify_totp(bob, "000000", None)
        bob_id = bob["id"]
        with client.session_transaction() as sess:
            sess["user_id"] = admin["id"]

    resp = client.post(f"/admin/users/{bob_id}/unlock")
    assert resp.status_code == 204

    with app.app_context():
        refreshed = repos["users"].get(bob_id)
        assert refreshed["locked_until"] is None
        assert refreshed["failed_attempts"] == 0
        assert repos["audit"].list_all(action=ACTIONS["ADMIN_UNLOCK"])


def test_unknown_user_filter_returns_empty_not_all_rows(client, app, make_user):
    with app.app_context():
        admin = make_user(username="root", admin=True)
        with client.session_transaction() as sess:
            sess["user_id"] = admin["id"]
    body = client.get("/admin/audit?username=ghost").get_data(as_text=True)
    assert "没有匹配记录" in body
