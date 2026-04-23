from __future__ import annotations

import json
import secrets
import time
import urllib.parse
import urllib.request
from threading import Lock

from services.config import config


class AuthentikService:
    def __init__(self) -> None:
        self._lock = Lock()
        self._states: dict[str, dict[str, object]] = {}
        self._tickets: dict[str, dict[str, object]] = {}
        self._discovery_cache: dict[str, tuple[float, dict[str, object]]] = {}

    @staticmethod
    def _now() -> float:
        return time.time()

    @staticmethod
    def _clean(value: object) -> str:
        return str(value or "").strip()

    def get_settings(self) -> dict[str, object]:
        return config.get_authentik_settings()

    def is_enabled(self) -> bool:
        settings = self.get_settings()
        return bool(settings.get("enabled")) and bool(self._clean(settings.get("issuer"))) and bool(
            self._clean(settings.get("client_id"))
        )

    @staticmethod
    def _request_json(url: str, *, method: str = "GET", headers: dict[str, str] | None = None, data: bytes | None = None) -> dict[str, object]:
        request_headers = {
            "Accept": "application/json",
            # Some reverse proxies / WAF rules reject the default Python urllib UA with 403.
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            ),
            **(headers or {}),
        }
        request = urllib.request.Request(url, data=data, headers=request_headers, method=method)
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))
        if not isinstance(payload, dict):
            raise RuntimeError("invalid response payload")
        return payload

    def discover(self) -> dict[str, object]:
        settings = self.get_settings()
        issuer = self._clean(settings.get("issuer")).rstrip("/")
        if not issuer:
            raise RuntimeError("authentik issuer is not configured")
        now = self._now()
        with self._lock:
            cached = self._discovery_cache.get(issuer)
            if cached and cached[0] > now:
                return dict(cached[1])
        well_known = f"{issuer}/.well-known/openid-configuration"
        payload = self._request_json(well_known)
        with self._lock:
            self._discovery_cache[issuer] = (now + 300, payload)
        return payload

    def create_state(self, redirect_to: str) -> str:
        state = secrets.token_urlsafe(24)
        with self._lock:
            self._states[state] = {
                "redirect_to": self._clean(redirect_to) or "/login",
                "expires_at": self._now() + 600,
            }
        return state

    def pop_state(self, state: str) -> dict[str, object] | None:
        normalized = self._clean(state)
        if not normalized:
            return None
        with self._lock:
            payload = self._states.pop(normalized, None)
        if not isinstance(payload, dict):
            return None
        if float(payload.get("expires_at") or 0) <= self._now():
            return None
        return payload

    def build_authorization_url(self, *, redirect_uri: str, redirect_to: str) -> str:
        settings = self.get_settings()
        if not self.is_enabled():
            raise RuntimeError("authentik is not configured")
        discovery = self.discover()
        authorization_endpoint = self._clean(discovery.get("authorization_endpoint"))
        if not authorization_endpoint:
            raise RuntimeError("authentik authorization endpoint is unavailable")
        state = self.create_state(redirect_to)
        scopes = self._clean(settings.get("scopes")) or "openid profile email"
        params = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": self._clean(settings.get("client_id")),
                "scope": scopes,
                "redirect_uri": redirect_uri,
                "state": state,
            }
        )
        return f"{authorization_endpoint}?{params}"

    def exchange_code(self, *, code: str, redirect_uri: str) -> dict[str, object]:
        settings = self.get_settings()
        discovery = self.discover()
        token_endpoint = self._clean(discovery.get("token_endpoint"))
        userinfo_endpoint = self._clean(discovery.get("userinfo_endpoint"))
        if not token_endpoint or not userinfo_endpoint:
            raise RuntimeError("authentik oidc endpoints are unavailable")

        body = urllib.parse.urlencode(
            {
                "grant_type": "authorization_code",
                "code": self._clean(code),
                "client_id": self._clean(settings.get("client_id")),
                "client_secret": self._clean(settings.get("client_secret")),
                "redirect_uri": redirect_uri,
            }
        ).encode("utf-8")
        token_payload = self._request_json(
            token_endpoint,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=body,
        )
        access_token = self._clean(token_payload.get("access_token"))
        if not access_token:
            raise RuntimeError("authentik access token is missing")
        return self._request_json(
            userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        )

    def issue_ticket(self, identity: dict[str, object]) -> str:
        ticket = f"cg2a_ticket_{secrets.token_urlsafe(24)}"
        with self._lock:
            self._tickets[ticket] = {
                "identity": dict(identity),
                "expires_at": self._now() + 120,
            }
        return ticket

    def consume_ticket(self, ticket: str) -> dict[str, object] | None:
        normalized = self._clean(ticket)
        if not normalized:
            return None
        with self._lock:
            payload = self._tickets.pop(normalized, None)
        if not isinstance(payload, dict):
            return None
        if float(payload.get("expires_at") or 0) <= self._now():
            return None
        identity = payload.get("identity")
        return dict(identity) if isinstance(identity, dict) else None


authentik_service = AuthentikService()
