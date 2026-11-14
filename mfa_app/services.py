"""Business logic: lockout, second-factor verification, enrollment, recovery.

All rules live here and operate against repositories plus the injectable
clock, so they can be unit-tested without any Flask request context.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Callable

from . import totp
from .clock import clock
from .crypto import SecretBox, hash_backup_code, normalize_backup_code
from .repositories import (
    AuditRepository,
    BackupCodeRepository,
    DeviceRepository,
    UserRepository,
)

# Audit action names (single source of truth for the admin filters).
ACTIONS = {
    "LOGIN_PASSWORD": "login.password",
    "LOGIN_MFA": "login.mfa",
    "LOGIN_FAIL": "login.fail",
    "MFA_VERIFY": "mfa.verify",
    "MFA_FAIL": "mfa.fail",
    "MFA_REPLAY": "mfa.replay_blocked",
    "DEVICE_ENROLL_START": "device.enroll_start",
    "DEVICE_ENROLL_CONFIRM": "device.enroll_confirm",
    "DEVICE_REMOVE": "device.remove",
    "MFA_DISABLE": "mfa.disable",
    "BACKUP_GENERATE": "backup.generate",
    "BACKUP_USE": "backup.use",
    "RECOVERY_START": "recovery.start",
    "RECOVERY_COMPLETE": "recovery.complete",
    "ACCOUNT_LOCKED": "account.locked",
    "ACCOUNT_LOCKED_EXPIRED": "account.lock_expired",
    "ADMIN_UNLOCK": "admin.unlock",
}

RESULT_OK = "success"
RESULT_DENIED = "denied"


class MFAServiceError(Exception):
    """Denial that should be surfaced to the user."""


class LockedError(MFAServiceError):
    def __init__(self, locked_until: float):
        self.locked_until = locked_until
        super().__init__("account temporarily locked")


@dataclass
class ServiceResult:
    ok: bool
    reason: str | None = None
    data: dict | None = None


def generate_backup_codes(count: int, groups: int) -> list[str]:
    """High-entropy, human-typeable codes (base32 alphabet, no 0/1/8/9)."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    codes = []
    for _ in range(count):
        parts = [
            "".join(secrets.choice(alphabet) for _ in range(5))
            for _ in range(groups)
        ]
        codes.append("-".join(parts))
    return codes


class MFAService:
    def __init__(self, config: dict, users: UserRepository, devices: DeviceRepository,
                 backups: BackupCodeRepository, audit: AuditRepository,
                 box: SecretBox):
        self.cfg = config
        self.users = users
        self.devices = devices
        self.backups = backups
        self.audit = audit
        self.box = box

    # ------------------------------------------------------------------ lock

    def lockout_remaining(self, user) -> float:
        """Seconds remaining on an active lock, 0 otherwise. An expired lock is
        lazily cleared (the user starts with a clean failure counter)."""
        locked_until = user["locked_until"]
        if locked_until is None:
            return 0.0
        remaining = locked_until - clock.now()
        if remaining <= 0:
            self.users.reset_lock(user["id"])
            self.audit.record(
                ACTIONS["ACCOUNT_LOCKED_EXPIRED"], RESULT_OK,
                user_id=user["id"], username=user["username"],
                detail={"locked_until": locked_until},
            )
            return 0.0
        return remaining

    def _lock_delay(self, failed_attempts: int) -> int:
        """Progressive delay once the threshold is crossed.

        Attempts 1..threshold-1 carry no lock; the threshold-th failure locks
        for the base delay and every subsequent failure adds another step,
        capped at the configured maximum.
        """
        if failed_attempts < self.cfg["LOCKOUT_THRESHOLD"]:
            return 0
        steps = failed_attempts - self.cfg["LOCKOUT_THRESHOLD"] + 1
        delay = self.cfg["LOCKOUT_BASE_SECONDS"] + (steps - 1) * self.cfg[
            "LOCKOUT_STEP_SECONDS"]
        return min(delay, self.cfg["LOCKOUT_MAX_SECONDS"])

    def _register_failure(self, stale_user, action: str, reason: str,
                          ip: str | None, device_id: int | None = None) -> None:
        # Re-read: the caller's Row object may be stale relative to earlier
        # writes in the same request, so incrementing its counter would
        # clobber newer failure counts.
        user = self.users.get(stale_user["id"])
        attempts = user["failed_attempts"] + 1
        delay = self._lock_delay(attempts)
        locked_until = clock.now() + delay if delay else None
        self.users.set_lock(user["id"], attempts, locked_until)
        self.audit.record(
            action, RESULT_DENIED, user_id=user["id"], username=user["username"],
            ip=ip, device_id=device_id,
            detail={"reason": reason, "failed_attempts": attempts,
                    "locked_for_seconds": delay},
        )
        if delay:
            self.audit.record(
                ACTIONS["ACCOUNT_LOCKED"], RESULT_OK,
                user_id=user["id"], username=user["username"], ip=ip,
                detail={"locked_until": locked_until, "failed_attempts": attempts},
            )

    def _register_success(self, stale_user, action: str, ip: str | None,
                          device_id: int | None = None,
                          detail: dict | None = None) -> None:
        user = self.users.get(stale_user["id"])
        if user["failed_attempts"] or user["locked_until"] is not None:
            self.users.reset_lock(user["id"])
        self.audit.record(action, RESULT_OK, user_id=user["id"],
                          username=user["username"], ip=ip,
                          device_id=device_id, detail=detail)

    # ------------------------------------------------------------- enrollment

    def begin_enrollment(self, user, name: str, ip: str | None) -> dict:
        if self.devices.find(user["id"], name):
            raise MFAServiceError("device name already exists")
        secret = totp.generate_secret()
        device_id = self.devices.create_pending(
            user["id"], name, self.box.encrypt(secret))
        self.audit.record(
            ACTIONS["DEVICE_ENROLL_START"], RESULT_OK,
            user_id=user["id"], username=user["username"], ip=ip,
            device_id=device_id, detail={"name": name},
        )
        return {
            "device_id": device_id,
            "name": name,
            "secret": secret,
            "uri": totp.provisioning_uri(
                secret, user["username"], self.cfg["TOTP_ISSUER"],
                digits=self.cfg["TOTP_DIGITS"], period=self.cfg["TOTP_PERIOD"]),
        }

    def confirm_enrollment(self, user, device_id: int, code: str,
                           ip: str | None) -> ServiceResult:
        device = self.devices.get(device_id)
        if device is None or device["user_id"] != user["id"]:
            raise MFAServiceError("device not found")
        if device["confirmed"]:
            raise MFAServiceError("device already confirmed")
        secret = self.box.decrypt(device["secret_ciphertext"])
        match = totp.verify(
            secret, code, clock.now(),
            period=self.cfg["TOTP_PERIOD"], digits=self.cfg["TOTP_DIGITS"],
            window=self.cfg["TOTP_WINDOW"],
        )
        if match is None:
            # Enrollment typos do not feed the login lockout counter.
            self.audit.record(ACTIONS["MFA_FAIL"], RESULT_DENIED,
                              user_id=user["id"], username=user["username"],
                              ip=ip, device_id=device_id,
                              detail={"stage": "enrollment_confirm"})
            return ServiceResult(False, reason="invalid_code")
        self.devices.confirm(device_id, match.counter)
        self.audit.record(ACTIONS["DEVICE_ENROLL_CONFIRM"], RESULT_OK,
                          user_id=user["id"], username=user["username"],
                          ip=ip, device_id=device_id,
                          detail={"counter": match.counter})
        return ServiceResult(True, data={"device_id": device_id})

    def remove_device(self, user, device_id: int, ip: str | None) -> None:
        device = self.devices.get(device_id)
        if device is None or device["user_id"] != user["id"]:
            raise MFAServiceError("device not found")
        self.devices.delete(device_id)
        self.audit.record(ACTIONS["DEVICE_REMOVE"], RESULT_OK,
                          user_id=user["id"], username=user["username"], ip=ip,
                          device_id=device_id, detail={"name": device["name"]})

    def disable_mfa(self, user, ip: str | None) -> None:
        self.devices.delete_for_user(user["id"])
        self.backups.replace_all(user["id"], [])
        self.audit.record(ACTIONS["MFA_DISABLE"], RESULT_OK,
                          user_id=user["id"], username=user["username"], ip=ip)

    # ------------------------------------------------------------ backup codes

    def regenerate_backups(self, user, ip: str | None) -> list[str]:
        plaintext = generate_backup_codes(
            self.cfg["BACKUP_CODE_COUNT"], self.cfg["BACKUP_CODE_GROUPS"])
        hashes = [hash_backup_code(c, self.cfg["BACKUP_CODE_PEPPER"])
                  for c in plaintext]
        self.backups.replace_all(user["id"], hashes)
        self.audit.record(ACTIONS["BACKUP_GENERATE"], RESULT_OK,
                          user_id=user["id"], username=user["username"], ip=ip,
                          detail={"count": len(plaintext)})
        return plaintext

    # ----------------------------------------------------------- verification

    def verify_totp(self, stale_user, code: str, ip: str | None,
                    *, action: str = ACTIONS["MFA_VERIFY"]) -> ServiceResult:
        """Verify against *any* of the user's confirmed devices.

        Replay protection is per device via the monotonically increasing
        ``last_counter``. A clock that moves backwards can only produce
        counters <= one already accepted, so replayed/old codes are rejected
        even when the drift window would otherwise accept them.
        """
        user = self.users.get(stale_user["id"])  # fresh lock/counter state
        remaining = self.lockout_remaining(user)
        if remaining:
            raise LockedError(user["locked_until"])

        confirmed = self.devices.list_for_user(user["id"])
        if not confirmed:
            raise MFAServiceError("no confirmed device")

        for device in confirmed:
            secret = self.box.decrypt(device["secret_ciphertext"])
            match = totp.verify(
                secret, code, clock.now(),
                period=self.cfg["TOTP_PERIOD"], digits=self.cfg["TOTP_DIGITS"],
                window=self.cfg["TOTP_WINDOW"],
            )
            if match is None:
                continue
            last_counter = device["last_counter"]
            if last_counter is not None and match.counter <= last_counter:
                # Same code reused, or a code from a step in the past
                # (including the clock-rolled-back scenario).
                self.audit.record(
                    ACTIONS["MFA_REPLAY"], RESULT_DENIED,
                    user_id=user["id"], username=user["username"], ip=ip,
                    device_id=device["id"],
                    detail={"counter": match.counter,
                            "last_counter": last_counter},
                )
                self._register_failure(user, ACTIONS["MFA_FAIL"],
                                       "replayed_code", ip, device["id"])
                return ServiceResult(False, reason="replayed_code")
            self.devices.update_counter(device["id"], match.counter)
            self._register_success(user, action, ip, device["id"],
                                   detail={"counter": match.counter,
                                           "drift_steps": match.drift_steps})
            return ServiceResult(True, data={"device_id": device["id"]})

        self._register_failure(user, ACTIONS["MFA_FAIL"], "invalid_code", ip)
        return ServiceResult(False, reason="invalid_code")

    def verify_backup_code(self, stale_user, code: str, ip: str | None,
                           *, action: str = ACTIONS["BACKUP_USE"]) -> ServiceResult:
        user = self.users.get(stale_user["id"])  # fresh lock/counter state
        remaining = self.lockout_remaining(user)
        if remaining:
            raise LockedError(user["locked_until"])
        try:
            normalized = normalize_backup_code(code)
        except Exception:
            normalized = ""
        code_hash = hash_backup_code(normalized, self.cfg["BACKUP_CODE_PEPPER"])
        row = self.backups.find_unused(user["id"], code_hash)
        if row is None:
            self._register_failure(user, ACTIONS["MFA_FAIL"],
                                   "invalid_backup_code", ip)
            return ServiceResult(False, reason="invalid_backup_code")
        # Atomic one-time consume: the WHERE used_at IS NULL guard means a
        # concurrent double-submit can only succeed once (rowcount == 0 here
        # means the race was lost).
        if self.backups.mark_used(row["id"]) == 0:
            self._register_failure(user, ACTIONS["MFA_FAIL"],
                                   "backup_code_race", ip)
            return ServiceResult(False, reason="invalid_backup_code")
        self._register_success(user, action, ip, detail={"backup_id": row["id"]})
        return ServiceResult(True, data={"backup_id": row["id"]})

    def verify_second_factor(self, user, code: str, ip: str | None,
                             *, action: str | None = None) -> ServiceResult:
        """Dispatch entry point: TOTP first, fall back to backup-code format.

        A backup code contains letters (and a separator); a TOTP code is
        pure digits. MFA failures of either kind share the lockout counter.
        """
        stripped = code.strip()
        if stripped.isdigit():
            return self.verify_totp(user, stripped, ip,
                                    action=action or ACTIONS["MFA_VERIFY"])
        return self.verify_backup_code(user, stripped, ip,
                                       action=action or ACTIONS["BACKUP_USE"])

    # -------------------------------------------------------------- recovery

    def begin_recovery(self, user, code: str, ip: str | None) -> ServiceResult:
        """The re-enrollment ("换绑") flow: prove identity with a one-time
        backup code, receive a short-lived recovery grant in exchange."""
        result = self.verify_backup_code(
            user, code, ip, action=ACTIONS["RECOVERY_START"])
        if not result.ok:
            return result
        token = secrets.token_urlsafe(32)
        return ServiceResult(True, data={"recovery_token": token})

    def complete_recovery(self, user, device_id: int, code: str,
                          ip: str | None) -> ServiceResult:
        """Confirm the replacement device and retire all other devices."""
        result = self.confirm_enrollment(user, device_id, code, ip)
        if not result.ok:
            return result
        for device in self.devices.list_for_user(user["id"]):
            if device["id"] != device_id:
                self.devices.delete(device["id"])
        self.audit.record(ACTIONS["RECOVERY_COMPLETE"], RESULT_OK,
                          user_id=user["id"], username=user["username"], ip=ip,
                          device_id=device_id)
        return ServiceResult(True)

    def admin_unlock(self, admin, target_user_id: int, ip: str | None) -> None:
        target = self.users.get(target_user_id)
        if target is None:
            raise MFAServiceError("user not found")
        self.users.reset_lock(target["id"])
        self.audit.record(ACTIONS["ADMIN_UNLOCK"], RESULT_OK,
                          user_id=admin["id"], username=admin["username"], ip=ip,
                          detail={"target_user_id": target_user_id,
                                  "target_username": target["username"]})


def build_service(app, conn, box: SecretBox | None = None) -> MFAService:
    box = box or SecretBox(app.config["TOTP_ENCRYPTION_KEY"])
    return MFAService(
        app.config,
        UserRepository(conn),
        DeviceRepository(conn),
        BackupCodeRepository(conn),
        AuditRepository(conn),
        box,
    )
