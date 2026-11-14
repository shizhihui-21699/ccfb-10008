"""Recovery (rebind) flow: backup code -> recovery window -> replacement."""

import pytest

from mfa_app import totp
from mfa_app.clock import clock
from mfa_app.services import ACTIONS


def test_recovery_consumes_backup_code_and_grants_token(
        make_user, make_device, make_backups, service, repos):
    user, _, _ = make_device(make_user())
    code = make_backups(user)[0]

    result = service.begin_recovery(user, code, None)
    assert result.ok and result.data["recovery_token"]
    # the backup code is spent
    assert not service.verify_backup_code(user, code, None).ok
    rows = repos["audit"].list_all(action=ACTIONS["RECOVERY_START"])
    assert len(rows) == 1


def test_recovery_with_bad_code_fails(make_user, make_device, make_backups, service):
    user, _, _ = make_device(make_user())
    make_backups(user)
    result = service.begin_recovery(user, "NOPE-NOPE", None)
    assert not result.ok


def test_complete_recovery_retires_all_other_devices(
        make_user, make_device, service, repos):
    user, old_device, _ = make_device(make_user(), name="old-phone")
    _, second_device, _ = make_device(user, name="work-phone")

    pending = service.begin_enrollment(user, "new-phone", None)
    confirm = service.complete_recovery(
        user, pending["device_id"],
        totp.totp(pending["secret"], clock.now()), None)
    assert confirm.ok

    remaining = repos["devices"].list_for_user(user["id"])
    assert [d["id"] for d in remaining] == [pending["device_id"]]
    assert repos["devices"].get(old_device["id"]) is None
    assert repos["devices"].get(second_device["id"]) is None
    rows = repos["audit"].list_all(action=ACTIONS["RECOVERY_COMPLETE"])
    assert len(rows) == 1


def test_recovery_confirmation_rejects_wrong_code(
        make_user, make_device, service, repos):
    user, _, _ = make_device(make_user())
    pending = service.begin_enrollment(user, "new-phone", None)
    result = service.complete_recovery(
        user, pending["device_id"], "000000", None)
    assert not result.ok
    # pending device remains unconfirmed, nothing was retired
    assert repos["devices"].get(pending["device_id"])["confirmed"] == 0


def test_recovery_window_expires(client, app, make_user, make_device, make_backups):
    """End-to-end HTTP check of the 5-minute recovery session TTL."""
    with app.app_context():
        user = make_user(username="ren")
        make_device(user, "phone")
        code = make_backups(user)[0]
        with client.session_transaction() as sess:
            sess["user_id"] = user["id"]

    resp = client.post("/mfa/recovery", data={"code": code})
    assert resp.status_code == 302

    clock.advance(301)  # past RECOVERY_TTL_SECONDS (300)
    resp = client.get("/mfa/recovery/enroll")
    assert resp.status_code == 302 and "/mfa/recovery" in resp.headers["Location"]
