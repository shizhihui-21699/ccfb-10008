"""Application configuration."""

from __future__ import annotations

import os
import secrets

from cryptography.fernet import Fernet


class ConfigError(RuntimeError):
    pass


class Config:
    # --- storage / crypto ---
    DATABASE_PATH = os.environ.get("MFA_DB_PATH", "instance/mfa.sqlite3")
    # Fernet key for TOTP secrets at rest. Generated ephemerally if unset
    # (dev only): rotation/backing store is an operational concern.
    TOTP_ENCRYPTION_KEY = os.environ.get("MFA_TOTP_KEY") or Fernet.generate_key().decode()
    # Pepper for backup-code HMAC; ephemeral in dev if unset.
    BACKUP_CODE_PEPPER = os.environ.get("MFA_BACKUP_PEPPER") or secrets.token_hex(32)

    # --- TOTP (RFC 6238) ---
    TOTP_PERIOD = 30
    TOTP_DIGITS = 6
    # How many adjacent 30s steps are accepted in each direction (clock drift).
    TOTP_WINDOW = 1
    TOTP_ISSUER = "MFA Demo"

    # --- progressive lockout ---
    LOCKOUT_THRESHOLD = 5          # consecutive failures before lock engages
    LOCKOUT_BASE_SECONDS = 15
    LOCKOUT_STEP_SECONDS = 15      # each further failure adds another step
    LOCKOUT_MAX_SECONDS = 300

    # --- step-up / recovery sessions ---
    STEPUP_TTL_SECONDS = 120
    RECOVERY_TTL_SECONDS = 300
    LOGIN_CHALLENGE_TTL_SECONDS = 300

    # --- backup codes ---
    BACKUP_CODE_COUNT = 10
    BACKUP_CODE_GROUPS = 2         # e.g. "K7QP2-9F4XZ"

    # --- sessions ---
    SECRET_KEY = os.environ.get("MFA_SECRET_KEY") or secrets.token_hex(32)

    @classmethod
    def as_dict(cls) -> dict:
        """Snapshot of current values. Environment variables are re-read on
        every call (not baked in at import time), so tests/CLI can point at a
        different database via ``MFA_DB_PATH`` before creating the app."""
        env_overrides = {
            "DATABASE_PATH": os.environ.get("MFA_DB_PATH", cls.DATABASE_PATH),
            "TOTP_ENCRYPTION_KEY": os.environ.get(
                "MFA_TOTP_KEY", cls.TOTP_ENCRYPTION_KEY),
            "BACKUP_CODE_PEPPER": os.environ.get(
                "MFA_BACKUP_PEPPER", cls.BACKUP_CODE_PEPPER),
            "SECRET_KEY": os.environ.get("MFA_SECRET_KEY", cls.SECRET_KEY),
        }
        values = {key: getattr(cls, key) for key in dir(cls) if key.isupper()}
        values.update(env_overrides)
        return values
