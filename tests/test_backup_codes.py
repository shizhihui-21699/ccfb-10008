"""Backup codes: hashed storage, one-time use, regeneration, normalization."""

import pytest

from mfa_app.crypto import hash_backup_code, normalize_backup_code
from mfa_app.services import ACTIONS


def test_codes_are_stored_only_as_hashes(make_user, make_backups, conn):
    user = make_user()
    codes = make_backups(user)
    rows = conn.execute(
        "SELECT code_hash FROM backup_codes WHERE user_id = ?", (user["id"],)
    ).fetchall()
    assert len(rows) == len(codes)
    stored = {r["code_hash"] for r in rows}
    for plaintext in codes:
        assert plaintext not in stored
        assert normalize_backup_code(plaintext) not in stored


def test_backup_code_succeeds_once_then_is_consumed(
        make_user, make_device, make_backups, service, repos):
    user, _, _ = make_device(make_user())
    codes = make_backups(user)
    code = codes[0]

    first = service.verify_backup_code(user, code, None)
    assert first.ok
    row = repos["backups"].list_for_user(user["id"])[0]
    assert row["used_at"] is not None

    second = service.verify_backup_code(user, code, None)
    assert not second.ok and second.reason == "invalid_backup_code"


def test_backup_code_normalization_accepts_lowercase_and_spaces(
        make_user, make_device, make_backups, service):
    user, _, _ = make_device(make_user())
    code = make_backups(user)[0]
    relaxed = code.lower().replace("-", " ")
    assert service.verify_backup_code(user, relaxed, None).ok


def test_unknown_code_is_rejected_and_audited(
        make_user, make_device, make_backups, service, repos):
    user, _, _ = make_device(make_user())
    make_backups(user)
    result = service.verify_backup_code(user, "ZZZZZ-ZZZZZ", None)
    assert not result.ok
    rows = repos["audit"].list_all(action=ACTIONS["MFA_FAIL"])
    assert rows and rows[0]["result"] == "denied"


def test_regeneration_invalidates_old_codes(
        make_user, make_device, service, repos):
    user, _, _ = make_device(make_user())
    old = service.regenerate_backups(user, None)
    service.regenerate_backups(user, None)  # rotate
    assert not service.verify_backup_code(user, old[0], None).ok
    total, unused = repos["backups"].counts(user["id"])
    assert total == 10 and unused == 10


def test_hashes_are_unique_even_for_identical_looking_inputs():
    h1 = hash_backup_code("ABCDE-FGHJK", "pepper-a")
    h2 = hash_backup_code("ABCDE-FGHJK", "pepper-b")
    h3 = hash_backup_code("ABCDE-FGHJK", "pepper-a")
    assert h1 != h2 and h1 == h3


def test_backup_codes_have_configured_format(make_user, service):
    codes = service.regenerate_backups(make_user(), None)
    assert len(codes) == 10
    for code in codes:
        groups = code.split("-")
        assert len(groups) == 2 and all(len(g) == 5 for g in groups)
        assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in code if c != "-")
