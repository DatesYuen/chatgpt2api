from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Literal


BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
AUTH_KEYS_FILE = DATA_DIR / "auth_keys.json"

AuthRole = Literal["admin", "user"]

PASSWORD_HASH_NAME = "pbkdf2_sha256"
PASSWORD_HASH_ITERATIONS = 240000
DEFAULT_DAILY_IMAGE_LIMIT = 20
SESSION_TOKEN_PREFIX = "cg2a_session"


class QuotaExceededError(RuntimeError):
    def __init__(self, remaining: int, limit: int):
        self.remaining = max(0, int(remaining or 0))
        self.limit = max(0, int(limit or 0))
        super().__init__(f"daily image quota exceeded, remaining={self.remaining}, limit={self.limit}")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_key(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _urlsafe_b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _urlsafe_b64decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("utf-8"))


class AuthService:
    def __init__(self, store_file: Path):
        self.store_file = store_file
        self._lock = Lock()
        self._items = self._load()

    @staticmethod
    def _clean(value: object) -> str:
        return str(value or "").strip()

    @staticmethod
    def _normalize_username(value: object) -> str:
        raw = str(value or "").strip().lower()
        parts: list[str] = []
        previous_was_separator = False
        for char in raw:
            if char.isascii() and char.isalnum():
                parts.append(char)
                previous_was_separator = False
                continue
            if char in {"-", "_", ".", "@"} and not previous_was_separator:
                parts.append("-")
                previous_was_separator = True
        return "".join(parts).strip("-")

    @classmethod
    def _username_base(cls, role: AuthRole, display_name: str, item_id: str) -> str:
        normalized = cls._normalize_username(display_name)
        if normalized:
            return normalized
        prefix = "admin" if role == "admin" else "user"
        return f"{prefix}-{item_id[:6]}"

    def _unique_username(self, preferred: str, *, role: AuthRole, item_id: str, exclude_id: str | None = None) -> str:
        base = self._normalize_username(preferred) or self._username_base(role, preferred, item_id)
        taken = {
            self._clean(item.get("username")).lower()
            for item in self._items
            if item.get("id") != exclude_id
        }
        if base not in taken:
            return base
        for index in range(2, 1000):
            candidate = f"{base}-{index}"
            if candidate not in taken:
                return candidate
        return f"{base}-{uuid.uuid4().hex[:6]}"

    @staticmethod
    def _today_key() -> str:
        return datetime.now().astimezone().date().isoformat()

    @staticmethod
    def _trim_usage_map(raw: object) -> dict[str, dict[str, int]]:
        if not isinstance(raw, dict):
            return {}
        normalized: dict[str, dict[str, int]] = {}
        for day, payload in raw.items():
            if not isinstance(payload, dict):
                continue
            day_key = str(day or "").strip()
            if not day_key:
                continue
            normalized[day_key] = {
                "used": max(0, int(payload.get("used") or 0)),
                "reserved": max(0, int(payload.get("reserved") or 0)),
            }
        recent_days = sorted(normalized.keys(), reverse=True)[:7]
        return {day: normalized[day] for day in recent_days}

    def _normalize_item(self, raw: object) -> dict[str, object] | None:
        if not isinstance(raw, dict):
            return None

        role = self._clean(raw.get("role")).lower()
        if role not in {"admin", "user"}:
            return None

        item_id = self._clean(raw.get("id")) or uuid.uuid4().hex[:12]

        # Backward-compat for the legacy key-only records.
        legacy_key_hash = self._clean(raw.get("key_hash"))
        display_name = self._clean(raw.get("display_name") or raw.get("name"))
        if not display_name:
            display_name = "管理员" if role == "admin" else "普通用户"

        username = self._normalize_username(raw.get("username"))
        if not username:
            username = self._username_base(role, display_name, item_id)

        created_at = self._clean(raw.get("created_at")) or _now_iso()
        last_used_at = self._clean(raw.get("last_used_at")) or None

        daily_limit = raw.get("daily_image_limit")
        try:
            normalized_daily_limit = max(0, int(daily_limit if daily_limit is not None else DEFAULT_DAILY_IMAGE_LIMIT))
        except (TypeError, ValueError):
            normalized_daily_limit = DEFAULT_DAILY_IMAGE_LIMIT

        password_hash = self._clean(raw.get("password_hash"))
        api_key_hash = self._clean(raw.get("api_key_hash") or legacy_key_hash)
        authentik_subject = self._clean(raw.get("authentik_subject"))
        authentik_username = self._normalize_username(raw.get("authentik_username"))
        quota_usage = self._trim_usage_map(raw.get("quota_usage"))

        return {
            "id": item_id,
            "username": username,
            "display_name": display_name,
            "role": role,
            "enabled": bool(raw.get("enabled", True)),
            "password_hash": password_hash,
            "api_key_hash": api_key_hash,
            "authentik_subject": authentik_subject,
            "authentik_username": authentik_username,
            "daily_image_limit": normalized_daily_limit,
            "created_at": created_at,
            "last_used_at": last_used_at,
            "quota_usage": quota_usage,
        }

    def _load(self) -> list[dict[str, object]]:
        if not self.store_file.exists():
            return []
        try:
            raw = json.loads(self.store_file.read_text(encoding="utf-8"))
        except Exception:
            return []
        items = raw.get("items") if isinstance(raw, dict) else raw
        if not isinstance(items, list):
            return []

        normalized_items = [item for raw_item in items if (item := self._normalize_item(raw_item)) is not None]
        self._items = []
        for item in normalized_items:
            next_item = dict(item)
            next_item["username"] = self._unique_username(
                str(item.get("username") or ""),
                role=str(item.get("role") or "user"),  # type: ignore[arg-type]
                item_id=str(item.get("id") or uuid.uuid4().hex[:12]),
                exclude_id=str(item.get("id") or ""),
            )
            self._items.append(next_item)
        return self._items

    def _save(self) -> None:
        self.store_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {"items": self._items}
        self.store_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def _get_quota_snapshot(self, item: dict[str, object]) -> dict[str, object]:
        limit = max(0, int(item.get("daily_image_limit") or 0))
        today = self._today_key()
        usage_map = self._trim_usage_map(item.get("quota_usage"))
        bucket = usage_map.get(today) or {"used": 0, "reserved": 0}
        used = max(0, int(bucket.get("used") or 0))
        reserved = max(0, int(bucket.get("reserved") or 0))
        remaining = max(0, limit - used - reserved)
        return {
            "daily_image_limit": limit,
            "quota_used": used,
            "quota_reserved": reserved,
            "quota_remaining": remaining,
            "quota_day": today,
            "quota_reset_at": f"{today}T23:59:59",
        }

    def _public_item(self, item: dict[str, object]) -> dict[str, object]:
        quota = self._get_quota_snapshot(item) if item.get("role") == "user" else {}
        return {
            "id": item.get("id"),
            "username": item.get("username"),
            "name": item.get("display_name"),
            "display_name": item.get("display_name"),
            "role": item.get("role"),
            "enabled": bool(item.get("enabled", True)),
            "created_at": item.get("created_at"),
            "last_used_at": item.get("last_used_at"),
            "has_password": bool(self._clean(item.get("password_hash"))),
            "has_api_key": bool(self._clean(item.get("api_key_hash"))),
            "authentik_subject": item.get("authentik_subject") or "",
            "authentik_username": item.get("authentik_username") or "",
            "daily_image_limit": int(item.get("daily_image_limit") or 0),
            **quota,
        }

    @staticmethod
    def _password_hash(password: str) -> str:
        salt = secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            PASSWORD_HASH_ITERATIONS,
        )
        return f"{PASSWORD_HASH_NAME}${PASSWORD_HASH_ITERATIONS}${salt}${digest.hex()}"

    @staticmethod
    def _verify_password(password: str, password_hash: str) -> bool:
        parts = str(password_hash or "").split("$", 3)
        if len(parts) != 4 or parts[0] != PASSWORD_HASH_NAME:
            return False
        try:
            iterations = int(parts[1])
        except ValueError:
            return False
        salt = parts[2]
        expected = parts[3]
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            str(password or "").encode("utf-8"),
            salt.encode("utf-8"),
            iterations,
        ).hex()
        return hmac.compare_digest(expected, digest)

    @staticmethod
    def _session_secret() -> bytes:
        from services.config import config

        auth_key = str(getattr(config, "auth_key", "") or "").strip()
        seed = auth_key or "chatgpt2api-session-secret"
        return hashlib.sha256(seed.encode("utf-8")).digest()

    def _sign_session_payload(self, payload: dict[str, object]) -> str:
        payload_json = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        encoded_payload = _urlsafe_b64encode(payload_json)
        signature = hmac.new(self._session_secret(), encoded_payload.encode("utf-8"), hashlib.sha256).digest()
        return f"{SESSION_TOKEN_PREFIX}.{encoded_payload}.{_urlsafe_b64encode(signature)}"

    def _verify_session_payload(self, token: str) -> dict[str, object] | None:
        prefix = f"{SESSION_TOKEN_PREFIX}."
        if not str(token or "").startswith(prefix):
            return None
        try:
            _, encoded_payload, encoded_signature = token.split(".", 2)
        except ValueError:
            return None
        expected_signature = hmac.new(
            self._session_secret(),
            encoded_payload.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        try:
            provided_signature = _urlsafe_b64decode(encoded_signature)
            payload = json.loads(_urlsafe_b64decode(encoded_payload).decode("utf-8"))
        except Exception:
            return None
        if not hmac.compare_digest(expected_signature, provided_signature):
            return None
        if not isinstance(payload, dict):
            return None
        try:
            expires_at = int(payload.get("exp") or 0)
        except (TypeError, ValueError):
            return None
        if expires_at <= int(time.time()):
            return None
        return payload

    def list_users(self, role: AuthRole | None = None) -> list[dict[str, object]]:
        with self._lock:
            items = [item for item in self._items if role is None or item.get("role") == role]
            return [self._public_item(item) for item in items]

    def list_keys(self, role: AuthRole | None = None) -> list[dict[str, object]]:
        return self.list_users(role=role)

    def get_user(self, user_id: str) -> dict[str, object] | None:
        normalized_id = self._clean(user_id)
        if not normalized_id:
            return None
        with self._lock:
            for item in self._items:
                if item.get("id") == normalized_id:
                    return dict(item)
        return None

    def get_public_user(self, user_id: str) -> dict[str, object] | None:
        item = self.get_user(user_id)
        if item is None:
            return None
        return self._public_item(item)

    def _build_identity_from_item(self, item: dict[str, object]) -> dict[str, object]:
        identity = self._public_item(item)
        identity["subject_id"] = item.get("id")
        return identity

    def create_user(
        self,
        *,
        username: str,
        display_name: str = "",
        role: AuthRole = "user",
        password: str = "",
        enabled: bool = True,
        daily_image_limit: int = DEFAULT_DAILY_IMAGE_LIMIT,
        authentik_subject: str = "",
        authentik_username: str = "",
    ) -> dict[str, object]:
        item_id = uuid.uuid4().hex[:12]
        normalized_username = self._normalize_username(username) or self._username_base(role, display_name, item_id)
        normalized_display_name = self._clean(display_name) or normalized_username
        item = {
            "id": item_id,
            "username": normalized_username,
            "display_name": normalized_display_name,
            "role": role,
            "enabled": bool(enabled),
            "password_hash": self._password_hash(password) if self._clean(password) else "",
            "api_key_hash": "",
            "authentik_subject": self._clean(authentik_subject),
            "authentik_username": self._normalize_username(authentik_username),
            "daily_image_limit": max(0, int(daily_image_limit or 0)),
            "created_at": _now_iso(),
            "last_used_at": None,
            "quota_usage": {},
        }
        with self._lock:
            item["username"] = self._unique_username(str(item["username"]), role=role, item_id=item_id)
            self._items.append(item)
            self._save()
        return self._public_item(item)

    def create_key(self, *, role: AuthRole, name: str = "") -> tuple[dict[str, object], str]:
        user = self.create_user(
            username="",
            display_name=name or ("管理员" if role == "admin" else "普通用户"),
            role=role,
        )
        item, raw_key = self.reset_api_key(str(user.get("id") or ""))
        if item is None:
            raise RuntimeError("failed to create key")
        return item, raw_key

    def update_user(self, user_id: str, updates: dict[str, object]) -> dict[str, object] | None:
        normalized_id = self._clean(user_id)
        if not normalized_id:
            return None
        with self._lock:
            for index, item in enumerate(self._items):
                if item.get("id") != normalized_id:
                    continue
                next_item = dict(item)
                if "username" in updates and updates.get("username") is not None:
                    next_item["username"] = self._unique_username(
                        self._clean(updates.get("username")),
                        role=str(next_item.get("role") or "user"),  # type: ignore[arg-type]
                        item_id=normalized_id,
                        exclude_id=normalized_id,
                    )
                if "display_name" in updates or "name" in updates:
                    display_name = self._clean(updates.get("display_name") or updates.get("name"))
                    next_item["display_name"] = display_name or str(next_item.get("username") or next_item.get("display_name") or "")
                if "role" in updates and updates.get("role") in {"admin", "user"}:
                    next_item["role"] = str(updates.get("role"))
                if "enabled" in updates and updates.get("enabled") is not None:
                    next_item["enabled"] = bool(updates.get("enabled"))
                if "password" in updates and updates.get("password") is not None:
                    password = self._clean(updates.get("password"))
                    next_item["password_hash"] = self._password_hash(password) if password else ""
                if "daily_image_limit" in updates and updates.get("daily_image_limit") is not None:
                    try:
                        next_item["daily_image_limit"] = max(0, int(updates.get("daily_image_limit") or 0))
                    except (TypeError, ValueError):
                        pass
                if "authentik_subject" in updates and updates.get("authentik_subject") is not None:
                    next_item["authentik_subject"] = self._clean(updates.get("authentik_subject"))
                if "authentik_username" in updates and updates.get("authentik_username") is not None:
                    next_item["authentik_username"] = self._normalize_username(updates.get("authentik_username"))
                self._items[index] = next_item
                self._save()
                return self._public_item(next_item)
        return None

    def update_key(
        self,
        key_id: str,
        updates: dict[str, object],
        *,
        role: AuthRole | None = None,
    ) -> dict[str, object] | None:
        item = self.get_user(key_id)
        if item is None:
            return None
        if role is not None and item.get("role") != role:
            return None
        return self.update_user(key_id, updates)

    def delete_user(self, user_id: str) -> bool:
        normalized_id = self._clean(user_id)
        if not normalized_id:
            return False
        with self._lock:
            before = len(self._items)
            self._items = [item for item in self._items if item.get("id") != normalized_id]
            if len(self._items) == before:
                return False
            self._save()
            return True

    def delete_key(self, key_id: str, *, role: AuthRole | None = None) -> bool:
        item = self.get_user(key_id)
        if item is None:
            return False
        if role is not None and item.get("role") != role:
            return False
        return self.delete_user(key_id)

    def reset_api_key(self, user_id: str) -> tuple[dict[str, object] | None, str]:
        normalized_id = self._clean(user_id)
        if not normalized_id:
            return None, ""
        with self._lock:
            for index, item in enumerate(self._items):
                if item.get("id") != normalized_id:
                    continue
                role = str(item.get("role") or "user")
                raw_key = f"cg2a_{role}_{secrets.token_urlsafe(24)}"
                next_item = dict(item)
                next_item["api_key_hash"] = _hash_key(raw_key)
                self._items[index] = next_item
                self._save()
                return self._public_item(next_item), raw_key
        return None, ""

    def authenticate_api_key(self, raw_key: str) -> dict[str, object] | None:
        candidate = self._clean(raw_key)
        if not candidate:
            return None
        candidate_hash = _hash_key(candidate)
        with self._lock:
            for index, item in enumerate(self._items):
                if not bool(item.get("enabled", True)):
                    continue
                stored_hash = self._clean(item.get("api_key_hash"))
                if not stored_hash or not hmac.compare_digest(stored_hash, candidate_hash):
                    continue
                next_item = dict(item)
                next_item["last_used_at"] = _now_iso()
                self._items[index] = next_item
                self._save()
                return self._build_identity_from_item(next_item)
        return None

    def authenticate_password(self, username: str, password: str) -> dict[str, object] | None:
        normalized_username = self._normalize_username(username)
        if not normalized_username or not self._clean(password):
            return None
        with self._lock:
            for index, item in enumerate(self._items):
                if not bool(item.get("enabled", True)):
                    continue
                if self._clean(item.get("username")).lower() != normalized_username:
                    continue
                password_hash = self._clean(item.get("password_hash"))
                if not password_hash or not self._verify_password(password, password_hash):
                    return None
                next_item = dict(item)
                next_item["last_used_at"] = _now_iso()
                self._items[index] = next_item
                self._save()
                return self._build_identity_from_item(next_item)
        return None

    def issue_session_token(self, identity: dict[str, object], *, ttl_seconds: int = 86400 * 30) -> str:
        now = int(time.time())
        subject_id = self._clean(identity.get("id") or identity.get("subject_id"))
        is_legacy_admin = subject_id == "legacy-admin"
        payload = {
            "kind": "legacy-admin" if is_legacy_admin else "user",
            "sub": subject_id,
            "sid": uuid.uuid4().hex,
            "iat": now,
            "exp": now + max(300, int(ttl_seconds or 0)),
        }
        return self._sign_session_payload(payload)

    def authenticate_session(self, raw_token: str) -> dict[str, object] | None:
        payload = self._verify_session_payload(raw_token)
        if payload is None:
            return None
        if payload.get("kind") == "legacy-admin":
            return {
                "id": "legacy-admin",
                "username": "admin",
                "name": "管理员",
                "display_name": "管理员",
                "role": "admin",
                "enabled": True,
                "created_at": None,
                "last_used_at": None,
            }
        subject_id = self._clean(payload.get("sub"))
        if not subject_id:
            return None
        with self._lock:
            for index, item in enumerate(self._items):
                if item.get("id") != subject_id or not bool(item.get("enabled", True)):
                    continue
                next_item = dict(item)
                next_item["last_used_at"] = _now_iso()
                self._items[index] = next_item
                self._save()
                return self._build_identity_from_item(next_item)
        return None

    def authenticate(self, raw_token: str) -> dict[str, object] | None:
        return self.authenticate_session(raw_token) or self.authenticate_api_key(raw_token)

    def _find_user_index_by_predicate(self, predicate) -> int:
        for index, item in enumerate(self._items):
            if predicate(item):
                return index
        return -1

    def find_by_authentik_subject(self, subject: str) -> dict[str, object] | None:
        normalized_subject = self._clean(subject)
        if not normalized_subject:
            return None
        with self._lock:
            index = self._find_user_index_by_predicate(
                lambda item: self._clean(item.get("authentik_subject")) == normalized_subject
            )
            if index < 0:
                return None
            return dict(self._items[index])

    def find_by_username(self, username: str) -> dict[str, object] | None:
        normalized_username = self._normalize_username(username)
        if not normalized_username:
            return None
        with self._lock:
            index = self._find_user_index_by_predicate(
                lambda item: self._clean(item.get("username")).lower() == normalized_username
            )
            if index < 0:
                return None
            return dict(self._items[index])

    def find_by_authentik_username(self, username: str) -> dict[str, object] | None:
        normalized_username = self._normalize_username(username)
        if not normalized_username:
            return None
        with self._lock:
            index = self._find_user_index_by_predicate(
                lambda item: self._clean(item.get("authentik_username")).lower() == normalized_username
            )
            if index < 0:
                return None
            return dict(self._items[index])

    def upsert_authentik_user(self, claims: dict[str, object]) -> dict[str, object]:
        subject = self._clean(claims.get("sub"))
        preferred_username = self._clean(claims.get("preferred_username") or claims.get("username"))
        display_name = self._clean(claims.get("name") or preferred_username or claims.get("email")) or preferred_username or "普通用户"

        if subject:
            existing_by_subject = self.find_by_authentik_subject(subject)
            if existing_by_subject is not None:
                updated = self.update_user(
                    str(existing_by_subject.get("id") or ""),
                    {
                        "authentik_subject": subject,
                        "authentik_username": preferred_username,
                        "display_name": display_name or existing_by_subject.get("display_name"),
                    },
                )
                if updated is not None:
                    return updated

        matched = self.find_by_authentik_username(preferred_username) or self.find_by_username(preferred_username)
        if matched is not None:
            updated = self.update_user(
                str(matched.get("id") or ""),
                {
                    "authentik_subject": subject,
                    "authentik_username": preferred_username,
                    "display_name": matched.get("display_name") or display_name,
                },
            )
            if updated is not None:
                return updated

        return self.create_user(
            username=preferred_username or "authentik-user",
            display_name=display_name,
            role="user",
            enabled=True,
            daily_image_limit=DEFAULT_DAILY_IMAGE_LIMIT,
            authentik_subject=subject,
            authentik_username=preferred_username,
        )

    def get_quota_status(self, user_id: str) -> dict[str, object] | None:
        item = self.get_user(user_id)
        if item is None or item.get("role") != "user":
            return None
        return self._get_quota_snapshot(item)

    def reserve_daily_quota(self, user_id: str, amount: int) -> dict[str, object] | None:
        normalized_id = self._clean(user_id)
        requested = max(0, int(amount or 0))
        if not normalized_id or requested <= 0:
            return None
        with self._lock:
            for index, item in enumerate(self._items):
                if item.get("id") != normalized_id:
                    continue
                if item.get("role") != "user":
                    return None
                next_item = dict(item)
                usage_map = self._trim_usage_map(next_item.get("quota_usage"))
                today = self._today_key()
                bucket = dict(usage_map.get(today) or {"used": 0, "reserved": 0})
                limit = max(0, int(next_item.get("daily_image_limit") or 0))
                remaining = max(0, limit - int(bucket.get("used") or 0) - int(bucket.get("reserved") or 0))
                if remaining < requested:
                    raise QuotaExceededError(remaining=remaining, limit=limit)
                bucket["reserved"] = int(bucket.get("reserved") or 0) + requested
                usage_map[today] = bucket
                next_item["quota_usage"] = usage_map
                self._items[index] = next_item
                self._save()
                return {"user_id": normalized_id, "day": today, "amount": requested}
        return None

    def settle_daily_quota(self, reservation: dict[str, object] | None, success_count: int) -> None:
        if not reservation:
            return
        normalized_id = self._clean(reservation.get("user_id"))
        day = self._clean(reservation.get("day"))
        amount = max(0, int(reservation.get("amount") or 0))
        used_increment = max(0, min(amount, int(success_count or 0)))
        if not normalized_id or not day or amount <= 0:
            return
        with self._lock:
            for index, item in enumerate(self._items):
                if item.get("id") != normalized_id:
                    continue
                next_item = dict(item)
                usage_map = self._trim_usage_map(next_item.get("quota_usage"))
                bucket = dict(usage_map.get(day) or {"used": 0, "reserved": 0})
                bucket["reserved"] = max(0, int(bucket.get("reserved") or 0) - amount)
                bucket["used"] = max(0, int(bucket.get("used") or 0) + used_increment)
                usage_map[day] = bucket
                next_item["quota_usage"] = usage_map
                self._items[index] = next_item
                self._save()
                return


auth_service = AuthService(AUTH_KEYS_FILE)
