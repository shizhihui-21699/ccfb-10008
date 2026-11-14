"""Session helpers and view decorators (login, step-up, admin)."""

from __future__ import annotations

from functools import wraps

from flask import abort, flash, g, redirect, session, url_for

from .clock import clock

SESSION_USER = "user_id"
SESSION_STEPUP_UNTIL = "stepup_until"
SESSION_LOGIN_CHALLENGE = "login_challenge"
SESSION_RECOVERY_UNTIL = "recovery_until"


def login_user(user_id: int) -> None:
    session.clear()
    session[SESSION_USER] = user_id
    session.permanent = True


def logout_user() -> None:
    session.clear()


def current_user():
    return getattr(g, "user", None)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user_id = session.get(SESSION_USER)
        if user_id is None:
            return redirect(url_for("auth.login"))
        from .db import get_db
        from .repositories import UserRepository
        user = UserRepository(get_db()).get(user_id)
        if user is None:
            session.clear()
            return redirect(url_for("auth.login"))
        g.user = user
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not g.user["is_admin"]:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def grant_stepup(ttl: int) -> None:
    session[SESSION_STEPUP_UNTIL] = clock.now() + ttl


def stepup_valid() -> bool:
    until = session.get(SESSION_STEPUP_UNTIL)
    return until is not None and until > clock.now()


def require_stepup(view):
    """Sensitive operations demand a fresh second factor (default 2 min)."""
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not stepup_valid():
            flash("请先完成二次验证以继续该敏感操作。", "warning")
            return redirect(url_for("auth.stepup", next=view.__name__))
        return view(*args, **kwargs)
    return wrapped


def grant_recovery(ttl: int) -> None:
    session[SESSION_RECOVERY_UNTIL] = clock.now() + ttl


def recovery_valid() -> bool:
    until = session.get(SESSION_RECOVERY_UNTIL)
    return until is not None and until > clock.now()
