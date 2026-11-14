"""Crypto helpers: secret encryption round-trip and backup-code hashing."""

import pytest

from cryptography.fernet import Fernet

from mfa_app.crypto import SecretBox, hash_backup_code, normalize_backup_code


def test_totp_secret_encryption_roundtrip():
    box = SecretBox(Fernet.generate_key())
    secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    token = box.encrypt(secret)
    assert token != secret and secret not in token
    assert box.decrypt(token) == secret


def test_encryption_is_non_deterministic():
    box = SecretBox(Fernet.generate_key())
    secret = "JBSWY3DPEHPK3PXP"
    assert box.encrypt(secret) != box.encrypt(secret)


def test_backup_hash_requires_correct_pepper():
    h = hash_backup_code("ABCDE-FGHJK", "pepper")
    assert h == hash_backup_code("ABCDE-FGHJK", "pepper")
    assert h != hash_backup_code("ABCDE-FGHJK", "other-pepper")


@pytest.mark.parametrize("raw,expected", [
    ("abcde-fghjk", "ABCDEFGHJK"),
    (" ab cd ", "ABCD"),
    ("K7QP2-9F4XZ", "K7QP29F4XZ"),
])
def test_normalize_strips_separators_and_upper_cases(raw, expected):
    assert normalize_backup_code(raw) == expected
