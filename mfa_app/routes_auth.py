"""Authentication routes: password login + MFA challenge + step-up."""

from __future__ import annotations

from urllib.parse import urlparse

from flask import (
    Blueprint, current_app, flash, redirect, render_template, request, session,
    url_for,
)
from werkzeug.security import check_password_hash

from .auth import (
    SESSION_LOGIN_CHALLENGE, SESSION_USER, grant_stepup, login_user,
    logout_user, login_required, current_user,
)
from .clock import clock
from .db import get_db
from .repositories import AuditRepository, DeviceRepository, UserRepository
from .services import ACTIONS, LockedError, MFAService, build_service

bp = Blueprint("auth", __name__)


def _service() -> MFAService:
    return build_service(current_app, get_db())


def _safe_redirect(target: str | None, fallback: str):
    """Only same-site relative paths are honored (open-redirect guard)."""
    if not target:
        return redirect(fallback)
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc or not target.startswith("/"):
        return redirect(fallback)
    return redirect(target)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        users = UserRepository(get_db())
        audit = AuditRepository(get_db())
        user = users.get_by_username(username)
        ip = request.remote_addr
        if user is None or not check_password_hash(user["password_hash"], password):
            audit.record(ACTIONS["LOGIN_FAIL"], "denied", username=username, ip=ip,
                         detail={"reason": "bad_credentials"})
            flash("用户名或密码错误。", "danger")
            return render_template("login.html"), 401

        svc = _service()
        try:
            remaining = svc.lockout_remaining(user)
        except Exception:
            remaining = 0
        if remaining:
            audit.record(ACTIONS["LOGIN_MFA"], "denied", user_id=user["id"],
                         username=username, ip=ip,
                         detail={"reason": "locked", "remaining": remaining})
            flash(f"账户已锁定，请 {int(remaining) + 1} 秒后再试。", "danger")
            return render_template("login.html"), 423

        # Password OK. Users with no confirmed device are bootstrapped
        # straight into first-device enrollment; everyone else gets the MFA
        # challenge. The pending id is held in the signed session cookie with
        # a short expiry.
        has_device = bool(DeviceRepository(get_db()).list_for_user(user["id"]))
        session[SESSION_LOGIN_CHALLENGE] = {
            "user_id": user["id"], "expires_at": clock.now()
            + current_app.config["LOGIN_CHALLENGE_TTL_SECONDS"],
            "bootstrap": not has_device,
        }
        audit.record(ACTIONS["LOGIN_PASSWORD"], "success",
                     user_id=user["id"], username=username, ip=ip)
        if not has_device:
            return redirect(url_for("auth.bootstrap_enroll"))
        return redirect(url_for("auth.challenge"))

    return render_template("login.html")


@bp.route("/login/challenge", methods=["GET", "POST"])
def challenge():
    pending = session.get(SESSION_LOGIN_CHALLENGE)
    if not pending or pending.get("expires_at", 0) <= clock.now():
        flash("登录会话已过期，请重新登录。", "warning")
        return redirect(url_for("auth.login"))
    users = UserRepository(get_db())
    user = users.get(pending["user_id"])
    if user is None:
        session.pop(SESSION_LOGIN_CHALLENGE, None)
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = request.form.get("code", "")
        svc = _service()
        try:
            result = svc.verify_second_factor(user, code, request.remote_addr,
                                              action=ACTIONS["LOGIN_MFA"])
        except LockedError as exc:
            remaining = exc.locked_until - clock.now()
            flash(f"尝试次数过多，账户锁定 {int(remaining) + 1} 秒。", "danger")
            return render_template("challenge.html"), 423
        if result.ok:
            login_user(user["id"])
            grant_stepup(current_app.config["STEPUP_TTL_SECONDS"])
            flash("登录成功。", "success")
            return redirect(url_for("mfa.overview"))
        flash("验证码错误或已被使用。", "danger")
        return render_template("challenge.html"), 401

    return render_template("challenge.html")


@bp.route("/login/bootstrap", methods=["GET", "POST"])
def bootstrap_enroll():
    """First-device enrollment for a user whose password just succeeded."""
    pending = session.get(SESSION_LOGIN_CHALLENGE)
    if not pending or not pending.get("bootstrap") \
            or pending.get("expires_at", 0) <= clock.now():
        flash("登录会话已过期，请重新登录。", "warning")
        return redirect(url_for("auth.login"))
    users = UserRepository(get_db())
    user = users.get(pending["user_id"])
    if user is None or DeviceRepository(get_db()).list_for_user(user["id"]):
        session.pop(SESSION_LOGIN_CHALLENGE, None)
        return redirect(url_for("auth.login"))

    svc = _service()
    if request.method == "POST":
        name = (request.form.get("name") or "首台设备").strip()
        enroll = svc.begin_enrollment(user, name, request.remote_addr)
        return render_template("bootstrap_confirm.html", pending=enroll)
    return render_template("bootstrap_enroll.html")


@bp.post("/login/bootstrap/<int:device_id>/confirm")
def bootstrap_confirm(device_id: int):
    pending = session.get(SESSION_LOGIN_CHALLENGE)
    if not pending or not pending.get("bootstrap") \
            or pending.get("expires_at", 0) <= clock.now():
        return redirect(url_for("auth.login"))
    users = UserRepository(get_db())
    user = users.get(pending["user_id"])
    if user is None:
        return redirect(url_for("auth.login"))
    result = _service().confirm_enrollment(
        user, device_id, request.form.get("code", ""), request.remote_addr)
    if not result.ok:
        flash("验证码不正确，请重试。", "danger")
        return redirect(url_for("auth.bootstrap_enroll"))
    # Device confirmed -> the MFA login is now complete.
    login_user(user["id"])
    grant_stepup(current_app.config["STEPUP_TTL_SECONDS"])
    flash("首台设备绑定成功，建议立即生成备用码。", "success")
    return redirect(url_for("mfa.backup_codes"))


@bp.route("/stepup", methods=["GET", "POST"])
@login_required
def stepup():
    next_url = request.args.get("next") or request.form.get("next")
    user = current_user()
    if request.method == "POST":
        code = request.form.get("code", "")
        svc = _service()
        try:
            result = svc.verify_second_factor(user, code, request.remote_addr)
        except LockedError as exc:
            remaining = exc.locked_until - clock.now()
            flash(f"账户锁定中，请 {int(remaining) + 1} 秒后再试。", "danger")
            return render_template("stepup.html", next=next_url), 423
        if result.ok:
            grant_stepup(current_app.config["STEPUP_TTL_SECONDS"])
            flash("二次验证通过。", "success")
            return _safe_redirect(next_url, url_for("mfa.overview"))
        flash("二次验证失败。", "danger")
        return render_template("stepup.html", next=next_url), 401
    return render_template("stepup.html", next=next_url)


@bp.post("/logout")
def logout():
    logout_user()
    flash("已退出登录。", "info")
    return redirect(url_for("auth.login"))
