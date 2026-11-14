"""Self-service MFA routes: devices, backup codes, recovery re-enrollment."""

from __future__ import annotations

from flask import (
    Blueprint, current_app, flash, g, redirect, render_template, request,
    session, url_for,
)

from .auth import (
    SESSION_RECOVERY_UNTIL, grant_recovery, login_required, recovery_valid,
    require_stepup, stepup_valid,
)
from .clock import clock
from .db import get_db
from .repositories import BackupCodeRepository, DeviceRepository
from .services import LockedError, MFAService, MFAServiceError, build_service

bp = Blueprint("mfa", __name__, url_prefix="/mfa")


def _service() -> MFAService:
    return build_service(current_app, get_db())


def _backup_counts(user):
    total, unused = BackupCodeRepository(get_db()).counts(user["id"])
    return {"total": total, "unused": unused}


@bp.get("")
@login_required
def overview():
    devices = DeviceRepository(get_db()).list_for_user(g.user["id"])
    return render_template(
        "overview.html", devices=devices, backup_counts=_backup_counts(g.user))


# -------------------------------------------------------------- enrollment

@bp.route("/enroll", methods=["GET", "POST"])
@login_required
def enroll():
    """First device needs no step-up (the user just logged in with MFA, or
    has no device yet); additional devices are a sensitive operation."""
    existing = DeviceRepository(get_db()).list_for_user(g.user["id"])
    if existing and not stepup_valid():
        return redirect(url_for("auth.stepup",
                                next=request.path))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if not name:
            flash("请填写设备名称。", "danger")
            return render_template("enroll.html"), 400
        try:
            pending = _service().begin_enrollment(g.user, name, request.remote_addr)
        except MFAServiceError as exc:
            flash(str(exc), "danger")
            return render_template("enroll.html"), 400
        return render_template("enroll_confirm.html", pending=pending)
    return render_template("enroll.html")


@bp.post("/enroll/<int:device_id>/confirm")
@login_required
def enroll_confirm(device_id: int):
    code = request.form.get("code", "")
    try:
        result = _service().confirm_enrollment(
            g.user, device_id, code, request.remote_addr)
    except MFAServiceError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("mfa.overview"))
    if not result.ok:
        flash("验证码不正确，请用 App 中的当前码重试。", "danger")
        return redirect(url_for("mfa.enroll"))
    flash("设备绑定成功。", "success")
    return redirect(url_for("mfa.overview"))


# ------------------------------------------------------------------ devices

@bp.post("/devices/<int:device_id>/delete")
@require_stepup
def delete_device(device_id: int):
    try:
        _service().remove_device(g.user, device_id, request.remote_addr)
    except MFAServiceError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("mfa.overview"))
    flash("设备已移除。", "success")
    return redirect(url_for("mfa.overview"))


# ------------------------------------------------------------- backup codes

@bp.route("/backup-codes", methods=["GET", "POST"])
@login_required
def backup_codes():
    if request.method == "POST":
        if not stepup_valid():
            return redirect(url_for("auth.stepup", next=request.path))
        codes = _service().regenerate_backups(g.user, request.remote_addr)
        flash("新备用码已生成，旧码立即作废——请立刻安全保存。", "warning")
        return render_template("backup_codes.html", codes=codes,
                               counts=_backup_counts(g.user))
    return render_template("backup_codes.html", codes=None,
                           counts=_backup_counts(g.user))


# -------------------------------------------------------- recovery (rebind)

@bp.route("/recovery", methods=["GET", "POST"])
@login_required
def recovery():
    """换绑恢复流程：消耗一个一次性备用码 -> 短恢复窗口 -> 绑定新设备，
    其余已确认设备在新设备确认后全部注销。"""
    if request.method == "POST":
        code = request.form.get("code", "")
        try:
            result = _service().begin_recovery(
                g.user, code, request.remote_addr)
        except LockedError as exc:
            remaining = exc.locked_until - clock.now()
            flash(f"账户锁定中，请 {int(remaining) + 1} 秒后再试。", "danger")
            return render_template("recovery.html"), 423
        if not result.ok:
            flash("备用码无效或已使用。", "danger")
            return render_template("recovery.html"), 401
        grant_recovery(current_app.config["RECOVERY_TTL_SECONDS"])
        flash("身份已确认，请在 5 分钟内绑定新设备。", "success")
        return redirect(url_for("mfa.recovery_enroll"))
    return render_template("recovery.html")


@bp.route("/recovery/enroll", methods=["GET", "POST"])
@login_required
def recovery_enroll():
    if not recovery_valid():
        flash("恢复会话不存在或已过期，请重新走恢复流程。", "warning")
        return redirect(url_for("mfa.recovery"))
    if request.method == "POST":
        name = request.form.get("name", "").strip() or "恢复设备"
        pending = _service().begin_enrollment(g.user, name, request.remote_addr)
        return render_template("recovery_confirm.html", pending=pending)
    return render_template("recovery_enroll.html")


@bp.post("/recovery/<int:device_id>/confirm")
@login_required
def recovery_confirm(device_id: int):
    if not recovery_valid():
        flash("恢复会话已过期。", "warning")
        return redirect(url_for("mfa.recovery"))
    code = request.form.get("code", "")
    result = _service().complete_recovery(
        g.user, device_id, code, request.remote_addr)
    if not result.ok:
        flash("验证码不正确。", "danger")
        return redirect(url_for("mfa.recovery_enroll"))
    session.pop(SESSION_RECOVERY_UNTIL, None)
    flash("新设备已绑定，旧设备已全部注销。", "success")
    return redirect(url_for("mfa.overview"))


# ----------------------------------------------------------------- disable

@bp.post("/disable")
@require_stepup
def disable():
    _service().disable_mfa(g.user, request.remote_addr)
    flash("MFA 已停用，所有设备与备用码已清除。", "warning")
    return redirect(url_for("mfa.overview"))
