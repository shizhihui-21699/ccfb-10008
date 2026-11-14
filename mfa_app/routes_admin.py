"""Read-only admin console: devices and audit records, plus CLI unlock."""

from __future__ import annotations

from flask import Blueprint, abort, current_app, g, render_template, request

from .auth import admin_required
from .db import get_db
from .repositories import AuditRepository, DeviceRepository, UserRepository
from .services import ACTIONS, MFAServiceError, build_service

bp = Blueprint("admin", __name__, url_prefix="/admin")

PAGE_SIZE = 25


@bp.get("")
@admin_required
def index():
    users = UserRepository(get_db()).list_all()
    devices = DeviceRepository(get_db()).list_all()
    return render_template("admin_index.html", users=users, devices=devices)


@bp.get("/audit")
@admin_required
def audit():
    action = request.args.get("action") or None
    username = request.args.get("username") or None
    page = max(int(request.args.get("page", 1)), 1)

    users = UserRepository(get_db())
    user_id = None
    if username:
        target = users.get_by_username(username.strip())
        user_id = target["id"] if target else -1  # -1 -> empty result, not "all"

    repo = AuditRepository(get_db())
    total = repo.count(user_id=user_id, action=action)
    offset = (page - 1) * PAGE_SIZE
    rows = repo.list_all(limit=PAGE_SIZE, offset=offset,
                         user_id=user_id, action=action)
    pages = max((total + PAGE_SIZE - 1) // PAGE_SIZE, 1)
    return render_template(
        "admin_audit.html", rows=rows, page=page, pages=pages, total=total,
        actions=sorted(ACTIONS.values()), action=action, username=username)


@bp.post("/users/<int:user_id>/unlock")
@admin_required
def unlock(user_id: int):
    try:
        build_service(current_app, get_db()).admin_unlock(
            g.user, user_id, request.remote_addr)
    except MFAServiceError:
        abort(404)
    return ("", 204)


@bp.get("/users/<int:user_id>/devices")
@admin_required
def user_devices(user_id: int):
    users = UserRepository(get_db())
    target = users.get(user_id)
    if target is None:
        abort(404)
    devices = DeviceRepository(get_db()).list_for_user(
        user_id, confirmed_only=False)
    return render_template("admin_devices.html", target=target, devices=devices)
