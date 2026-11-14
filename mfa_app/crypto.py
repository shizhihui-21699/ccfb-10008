"""Crypto primitives: TOTP secret encryption and backup-code hashing."""

from __future__ import annotations

import hashlib
import hmac

from cryptography.fernet import Fernet


class SecretBox:
    """Encrypts TOTP shared secrets at rest (Fernet, AES-128-CBC + HMAC)."""

    def __init__(self, key: str | bytes):
        self._fernet = Fernet(key if isinstance(key, bytes) else key.encode())

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> str:
        return self._fernet.decrypt(token.encode()).decode()


def hash_backup_code(code: str, pepper: str) -> str:
    """One-way hash of a backup code.

    Backup codes are high-entropy secrets, so a keyed HMAC-SHA-256 (the key is
    the server-side pepper) is sufficient and cheaper than a memory-hard KDF;
    plaintext codes are never stored.
    """
    normalized = normalize_backup_code(code)
    return hmac.new(
        pepper.encode(), normalized.encode(), hashlib.sha256
    ).hexdigest()


def normalize_backup_code(code: str) -> str:
    """Upper-case, strip separators/whitespace. No ambiguous-char rewriting:
    codes are drawn from the RFC 4648 base32 alphabet without 0/1/8/9."""
    return "".join(ch for ch in code.upper() if ch.isalnum())
