"""Shared pytest fixtures.

The clock is frozen for every test at a fixed instant deliberately chosen to
sit *inside* a 30-second TOTP step, so individual tests can advance to the
exact boundary and roll the clock backwards.
"""

from __future__ import annotations

import os
import sys

import pytest
from werkzeug.security import generate_password_hash

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mfa_app import totp  # noqa: E402
from mfa_app.app import create_app  # noqa: E402
from mfa_app.clock import clock  # noqa: E402
from mfa_app.crypto import SecretBox  # noqa: E402
from mfa_app.db import get_db  # noqa: E402
from mfa_app.repositories import (  # noqa: E402
    AuditRepository, BackupCodeRepository, DeviceRepository, UserRepository,
)
from mfa_app.services import build_service  # noqa: E402

# 1_000_000 is step 33333 (boundary at 999_990); gives us 20s of headroom to
# walk up to the step switch.
FROZEN_NOW = 1_000_000.0
PERIOD = 30


@pytest.fixture(autouse=True)
def frozen_clock():
    clock.freeze(FROZEN_NOW)
    yield clock
    clock.reset()


@pytest.fixture()
def app(tmp_path):
    db_path = tmp_path / "test.sqlite3"
    application = create_app({
        "DATABASE_PATH": str(db_path),
        "TESTING": True,
        "SECRET_KEY": "test-secret",
        "TOTP_ENCRYPTION_KEY": _fernet_key(),
        "WTF_CSRF_ENABLED": False,
    })
    yield application


def _fernet_key() -> str:
    from cryptography.fernet import Fernet
    return Fernet.generate_key().decode()


@pytest.fixture()
def conn(app):
    # Use the exact connection the app's get_db() returns, so service-layer
    # writes and repository assertions always share one transaction.
    with app.app_context():
        connection = get_db()
        yield connection
        # Keep this connection's writes visible to later request contexts:
        # the normal teardown would roll back, so commit explicitly.
        connection.commit()


@pytest.fixture()
def repos(conn):
    return {
        "users": UserRepository(conn),
        "devices": DeviceRepository(conn),
        "backups": BackupCodeRepository(conn),
        "audit": AuditRepository(conn),
    }


@pytest.fixture()
def service(app, conn):
    # Build inside the shared app context (conn) so the service talks to the
    # same SQLite connection as the repositories fixture.
    return build_service(app, conn)


@pytest.fixture()
def client(app):
    return app.test_client()


# ----------------------------------------------------------- factory helpers

@pytest.fixture()
def make_user(repos):
    def _make(username="alice", password="pw123456", admin=False):
        uid = repos["users"].create(
            username, generate_password_hash(password), admin)
        return repos["users"].get(uid)
    return _make


@pytest.fixture()
def make_device(service, repos):
    """Create + confirm a device; returns (user_row, device_row, secret)."""
    def _make(user, name="phone"):
        pending = service.begin_enrollment(user, name, ip=None)
        code = totp.totp(pending["secret"], clock.now())
        result = service.confirm_enrollment(user, pending["device_id"], code, None)
        assert result.ok
        device = repos["devices"].get(pending["device_id"])
        return user, device, pending["secret"]
    return _make


@pytest.fixture()
def make_backups(service, repos):
    def _make(user):
        codes = service.regenerate_backups(user, ip=None)
        return codes
    return _make


def code_at(secret: str, timestamp: float) -> str:
    return totp.totp(secret, timestamp, period=PERIOD)
