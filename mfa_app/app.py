"""Application factory, CLI commands and entry point."""

from __future__ import annotations

import click
from flask import Flask, redirect, url_for
from werkzeug.security import generate_password_hash

from .config import Config
from .db import get_db, init_app
from .repositories import AuditRepository, UserRepository
from .services import ACTIONS, build_service


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(Config.as_dict())
    if config:
        app.config.update(config)

    init_app(app)

    from .routes_auth import bp as auth_bp
    from .routes_mfa import bp as mfa_bp
    from .routes_admin import bp as admin_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(mfa_bp)
    app.register_blueprint(admin_bp)

    @app.get("/")
    def index():
        return redirect(url_for("mfa.overview"))

    _register_cli(app)
    return app


def _register_cli(app: Flask) -> None:
    @app.cli.command("create-user")
    @click.argument("username")
    @click.argument("password")
    @click.option("--admin", is_flag=True, help="grant the admin role")
    def create_user(username: str, password: str, admin: bool) -> None:
        """Create a user (the MFA secret/devices are enrolled from the UI)."""
        users = UserRepository(get_db())
        if users.get_by_username(username):
            raise click.ClickException(f"user {username!r} already exists")
        user_id = users.create(username, generate_password_hash(password), admin)
        AuditRepository(get_db()).record(
            "user.create", "success", user_id=user_id, username=username)
        get_db().commit()
        click.echo(f"created user {username!r} (id={user_id}, admin={admin})")

    @app.cli.command("unlock")
    @click.argument("username")
    def unlock(username: str) -> None:
        """Clear a progressive lockout (audited)."""
        users = UserRepository(get_db())
        user = users.get_by_username(username)
        if user is None:
            raise click.ClickException(f"user {username!r} not found")
        svc = build_service(app, get_db())
        svc.admin_unlock(user, user["id"], ip="cli")
        get_db().commit()
        click.echo(f"unlocked {username!r}")
