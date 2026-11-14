"""First-device bootstrap: a user with no device enrolls before full login."""

from mfa_app import totp
from mfa_app.clock import clock


def test_bootstrap_enrollment_completes_login(client, app, make_user, repos):
    with app.app_context():
        user = make_user(username="newbie")
        assert repos["devices"].list_for_user(user["id"]) == []

    # password succeeds but routes to bootstrap, not the MFA challenge
    resp = client.post("/login",
                       data={"username": "newbie", "password": "pw123456"})
    assert resp.status_code == 302
    assert "/login/bootstrap" in resp.headers["Location"]

    resp = client.post("/login/bootstrap", data={"name": "my-phone"})
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    import re
    device_id = int(re.search(
        r"/login/bootstrap/(\d+)/confirm", body).group(1))
    secret = re.search(r"<code[^>]*>([A-Z2-7]{32})</code>", body).group(1)

    resp = client.post(
        f"/login/bootstrap/{device_id}/confirm",
        data={"code": totp.totp(secret, clock.now())})
    assert resp.status_code == 302

    with app.app_context():
        devices = repos["devices"].list_for_user(user["id"])
        assert len(devices) == 1 and devices[0]["confirmed"] == 1

    # session is now fully authenticated
    assert client.get("/mfa").status_code == 200


def test_bootstrap_challenge_cannot_be_reused_after_logout(client, app, make_user):
    with app.app_context():
        make_user(username="newbie2")
    client.post("/login", data={"username": "newbie2", "password": "pw123456"})
    client.post("/logout")
    resp = client.get("/login/bootstrap")
    assert resp.status_code == 302 and "/login" in resp.headers["Location"]


def test_bootstrap_wrong_code_does_not_login(client, app, make_user):
    with app.app_context():
        make_user(username="newbie3")
    client.post("/login", data={"username": "newbie3", "password": "pw123456"})
    resp = client.post("/login/bootstrap", data={"name": "p"})
    import re
    device_id = int(re.search(
        r"/login/bootstrap/(\d+)/confirm", resp.get_data(as_text=True)).group(1))
    resp = client.post(f"/login/bootstrap/{device_id}/confirm",
                       data={"code": "000000"})
    # bounced back to bootstrap, not authenticated
    assert resp.status_code == 302
    assert client.get("/mfa").status_code == 302
