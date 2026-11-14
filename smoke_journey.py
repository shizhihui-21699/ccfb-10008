"""Manual smoke journey: run with the project venv, -I isolated mode."""
import os
import re
import sys
import tempfile

sys.path.insert(0, "/Users/shizhihui/ccfb/runs/10008/workspace")

from werkzeug.security import generate_password_hash  # noqa: E402

from mfa_app import totp  # noqa: E402
from mfa_app.app import create_app  # noqa: E402
from mfa_app.clock import clock  # noqa: E402

os.environ["MFA_DB_PATH"] = "/tmp/mfa_smoke.sqlite3"
for suffix in ("", "-wal", "-shm"):
    path = os.environ["MFA_DB_PATH"] + suffix
    if os.path.exists(path):
        os.remove(path)
clock.freeze(1_000_000.0)
app = create_app({"TESTING": True})
c = app.test_client()

with app.app_context():
    from mfa_app.db import get_db
    from mfa_app.repositories import DeviceRepository, UserRepository
    from mfa_app.services import build_service

    db = get_db()
    svc = build_service(app, db)
    uid = UserRepository(db).create("alice", generate_password_hash("pw123456"))
    admin_id = UserRepository(db).create("boss", generate_password_hash("pw"), True)
    user = UserRepository(db).get(uid)
    p = svc.begin_enrollment(user, "iphone", None)
    secret = p["secret"]
    assert svc.confirm_enrollment(
        user, p["device_id"], totp.totp(secret, clock.now()), None).ok
    backups = svc.regenerate_backups(user, None)
    db.commit()

# 1. password -> challenge -> TOTP
r = c.post("/login", data={"username": "alice", "password": "pw123456"})
assert r.status_code == 302 and "/challenge" in r.headers["Location"]
clock.advance(30)
code = totp.totp(secret, clock.now())
assert c.post("/login/challenge", data={"code": code}).status_code == 302
print("1. login + TOTP OK")

# 2. replay
c.post("/logout")
c.post("/login", data={"username": "alice", "password": "pw123456"})
assert c.post("/login/challenge", data={"code": code}).status_code == 401
print("2. replay rejected OK")

# 3. clock rollback
clock.advance(-45)
assert c.post(
    "/login/challenge",
    data={"code": totp.totp(secret, clock.now())}).status_code == 401
print("3. clock rollback rejected OK")

# 4. lockout
for _ in range(4):
    c.post("/login/challenge", data={"code": "000000"})
assert c.post("/login/challenge", data={"code": "000000"}).status_code == 423
print("4. progressive lockout (423) OK")

# 5. backup code blocked while locked, works after
assert c.post("/login/challenge", data={"code": backups[0]}).status_code == 423
clock.advance(200)
assert c.post("/login/challenge", data={"code": backups[0]}).status_code == 302
print("5. backup-code login after lock expiry OK (one-time consumed)")

# 6. step-up: the login grant expires after its TTL, then the sensitive
#    operation must demand a fresh factor.
clock.advance(121)
r = c.post("/mfa/backup-codes")
assert r.status_code == 302 and "/stepup" in r.headers["Location"], r.status_code
clock.advance(30)
c.post("/stepup", data={"code": totp.totp(secret, clock.now())})
r = c.post("/mfa/backup-codes")
assert r.status_code == 200 and "请立即保存" in r.get_data(as_text=True)
# capture one code from the freshly generated batch for recovery below
fresh_backup = re.search(
    r"<div>([A-Z0-9-]+)</div>", r.get_data(as_text=True)).group(1)
print("6. step-up gating + backup regeneration OK")

# 7. recovery rebind (uses a code from the *current* batch; the old batch
#    was invalidated by regeneration in step 6)
assert c.post("/mfa/recovery", data={"code": fresh_backup}).status_code == 302
r = c.post("/mfa/recovery/enroll", data={"name": "new-phone"})
assert r.status_code == 200
new_id = int(re.search(
    r"/mfa/recovery/(\d+)/confirm", r.get_data(as_text=True)).group(1))
new_secret = re.search(
    r"<code[^>]*>([A-Z2-7]{32})</code>", r.get_data(as_text=True)).group(1)
assert c.post(
    f"/mfa/recovery/{new_id}/confirm",
    data={"code": totp.totp(new_secret, clock.now())}).status_code == 302
with app.app_context():
    devs = DeviceRepository(get_db()).list_for_user(uid)
    assert len(devs) == 1 and devs[0]["name"] == "new-phone"
print("7. recovery rebind: old device retired OK")

# 8. admin
with c.session_transaction() as s:
    s.clear()
    s["user_id"] = admin_id
r = c.get("/admin")
assert r.status_code == 200 and "new-phone" in r.get_data(as_text=True)
r = c.get("/admin/audit?action=mfa.replay_blocked")
assert "<code>mfa.replay_blocked</code>" in r.get_data(as_text=True)
assert c.post(f"/admin/users/{uid}/unlock").status_code == 204
print("8. admin devices + audit filter + unlock OK")

print("\nALL SMOKE CHECKS PASSED")
