from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from threading import Event, Thread
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from fastapi import APIRouter, FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from services.account_service import account_service
from services.auth_service import QuotaExceededError, auth_service
from services.authentik_service import authentik_service
from services.chatgpt_service import ChatGPTService
from services.config import config
from services.cpa_service import cpa_config, cpa_import_service, list_remote_files
from services.proxy_service import test_proxy
from services.sub2api_service import (
    list_remote_accounts as sub2api_list_remote_accounts,
    list_remote_groups as sub2api_list_remote_groups,
    sub2api_config,
    sub2api_import_service,
)

from services.image_service import ImageGenerationError
from services.version import get_app_version

BASE_DIR = Path(__file__).resolve().parents[1]
WEB_DIST_DIR = BASE_DIR / "web_dist"


class ImageGenerationRequest(BaseModel):
    prompt: str = Field(..., min_length=1)
    model: str = "auto"
    n: int = Field(default=1, ge=1, le=4)
    response_format: str = "b64_json"
    history_disabled: bool = True


class AccountCreateRequest(BaseModel):
    tokens: list[str] = Field(default_factory=list)


class AccountDeleteRequest(BaseModel):
    tokens: list[str] = Field(default_factory=list)


class AccountRefreshRequest(BaseModel):
    access_tokens: list[str] = Field(default_factory=list)


class AccountUpdateRequest(BaseModel):
    access_token: str = Field(default="")
    type: str | None = None
    status: str | None = None
    quota: int | None = None


class ChatCompletionRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    model: str | None = None
    prompt: str | None = None
    n: int | None = None
    stream: bool | None = None
    modalities: list[str] | None = None
    messages: list[dict[str, object]] | None = None


class ResponseCreateRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    model: str | None = None
    input: object | None = None
    tools: list[dict[str, object]] | None = None
    tool_choice: object | None = None
    stream: bool | None = None


class CPAPoolCreateRequest(BaseModel):
    name: str = ""
    base_url: str = ""
    secret_key: str = ""


class CPAPoolUpdateRequest(BaseModel):
    name: str | None = None
    base_url: str | None = None
    secret_key: str | None = None


class CPAImportRequest(BaseModel):
    names: list[str] = Field(default_factory=list)


class SettingsUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="allow")


class PasswordLoginRequest(BaseModel):
    username: str = ""
    password: str = ""


class AuthTicketExchangeRequest(BaseModel):
    ticket: str = ""


class UserCreateRequest(BaseModel):
    username: str = ""
    display_name: str = ""
    role: str = "user"
    password: str = ""
    enabled: bool | None = None
    daily_image_limit: int = 20
    authentik_username: str = ""


class UserUpdateRequest(BaseModel):
    username: str | None = None
    display_name: str | None = None
    role: str | None = None
    password: str | None = None
    enabled: bool | None = None
    daily_image_limit: int | None = None
    authentik_username: str | None = None


class Sub2APIServerCreateRequest(BaseModel):
    name: str = ""
    base_url: str = ""
    email: str = ""
    password: str = ""
    api_key: str = ""
    group_id: str = ""


class Sub2APIServerUpdateRequest(BaseModel):
    name: str | None = None
    base_url: str | None = None
    email: str | None = None
    password: str | None = None
    api_key: str | None = None
    group_id: str | None = None


class Sub2APIImportRequest(BaseModel):
    account_ids: list[str] = Field(default_factory=list)


class ProxyUpdateRequest(BaseModel):
    enabled: bool | None = None
    url: str | None = None


class ProxyTestRequest(BaseModel):
    url: str = ""


def build_model_item(model_id: str) -> dict[str, object]:
    return {
        "id": model_id,
        "object": "model",
        "created": 0,
        "owned_by": "chatgpt2api",
    }


def sanitize_cpa_pool(pool: dict | None) -> dict | None:
    if not isinstance(pool, dict):
        return None
    return {
        key: value
        for key, value in pool.items()
        if key != "secret_key"
    }


def sanitize_cpa_pools(pools: list[dict]) -> list[dict]:
    return [sanitized for pool in pools if (sanitized := sanitize_cpa_pool(pool)) is not None]


_SUB2API_HIDDEN_FIELDS = {"password", "api_key"}


def sanitize_sub2api_server(server: dict | None) -> dict | None:
    if not isinstance(server, dict):
        return None
    sanitized = {key: value for key, value in server.items() if key not in _SUB2API_HIDDEN_FIELDS}
    sanitized["has_api_key"] = bool(str(server.get("api_key") or "").strip())
    return sanitized


def sanitize_sub2api_servers(servers: list[dict]) -> list[dict]:
    return [sanitized for server in servers if (sanitized := sanitize_sub2api_server(server)) is not None]


def extract_bearer_token(authorization: str | None) -> str:
    scheme, _, value = str(authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return ""
    return value.strip()


def _legacy_admin_identity(token: str) -> dict[str, object] | None:
    legacy_auth_key = str(config.auth_key or "").strip()
    if not legacy_auth_key or token != legacy_auth_key:
        return None
    return {
        "id": "legacy-admin",
        "subject_id": "legacy-admin",
        "username": "admin",
        "name": "管理员",
        "display_name": "管理员",
        "role": "admin",
        "enabled": True,
        "created_at": None,
        "last_used_at": None,
    }


def require_identity(authorization: str | None, *, roles: tuple[str, ...] | None = None) -> dict[str, object]:
    token = extract_bearer_token(authorization)
    identity = _legacy_admin_identity(token) or auth_service.authenticate(token)
    if identity is None:
        raise HTTPException(status_code=401, detail={"error": "authorization is invalid"})
    if roles is not None and str(identity.get("role") or "") not in roles:
        raise HTTPException(status_code=403, detail={"error": "forbidden"})
    return identity


def require_admin(authorization: str | None) -> dict[str, object]:
    return require_identity(authorization, roles=("admin",))


def resolve_image_base_url(request: Request) -> str:
    configured_base_url = str(getattr(config, "base_url", "") or "").strip()
    return configured_base_url or f"{request.url.scheme}://{request.headers.get('host', request.url.netloc)}"


def resolve_public_base_url(request: Request) -> str:
    configured_base_url = str(getattr(config, "base_url", "") or "").strip().rstrip("/")
    if configured_base_url:
        return configured_base_url

    forwarded_proto = str(request.headers.get("x-forwarded-proto") or "").strip()
    forwarded_host = str(request.headers.get("x-forwarded-host") or "").strip()
    if forwarded_proto and forwarded_host:
        return f"{forwarded_proto}://{forwarded_host}".rstrip("/")

    host = str(request.headers.get("host") or request.url.netloc).strip()
    return f"{request.url.scheme}://{host}".rstrip("/")


def build_public_callback_url(request: Request, path: str) -> str:
    return f"{resolve_public_base_url(request)}{path if path.startswith('/') else f'/{path}'}"


def build_auth_payload(identity: dict[str, object], app_version: str, *, token: str | None = None) -> dict[str, object]:
    quota = auth_service.get_quota_status(str(identity.get("id") or identity.get("subject_id") or "")) or {}
    return {
        "ok": True,
        "version": app_version,
        "token": token,
        "role": identity.get("role"),
        "subject_id": identity.get("id") or identity.get("subject_id"),
        "username": identity.get("username") or ("admin" if identity.get("id") == "legacy-admin" else ""),
        "name": identity.get("name") or identity.get("display_name") or identity.get("username"),
        "quota_limit": quota.get("daily_image_limit"),
        "quota_remaining": quota.get("quota_remaining"),
        "quota_used": quota.get("quota_used"),
        "quota_reset_at": quota.get("quota_reset_at"),
    }


def append_query_value(target: str, **updates: str) -> str:
    parsed = urlparse(target or "/login")
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    for key, value in updates.items():
        if value:
            query[key] = value
    return urlunparse(parsed._replace(query=urlencode(query)))


def with_trailing_slash(path: str) -> str:
    normalized = str(path or "").strip() or "/"
    if normalized == "/":
        return normalized
    return normalized if normalized.endswith("/") else f"{normalized}/"


def start_limited_account_watcher(stop_event: Event) -> Thread:
    interval_seconds = config.refresh_account_interval_minute * 60

    def worker() -> None:
        while not stop_event.is_set():
            try:
                limited_tokens = account_service.list_limited_tokens()
                if limited_tokens:
                    print(f"[account-limited-watcher] checking {len(limited_tokens)} limited accounts")
                    account_service.refresh_accounts(limited_tokens)
            except Exception as exc:
                print(f"[account-limited-watcher] fail {exc}")
            stop_event.wait(interval_seconds)

    thread = Thread(target=worker, name="limited-account-watcher", daemon=True)
    thread.start()
    return thread


def resolve_web_asset(requested_path: str) -> Path | None:
    if not WEB_DIST_DIR.exists():
        return None

    clean_path = requested_path.strip("/")
    if not clean_path:
        candidates = [WEB_DIST_DIR / "index.html"]
    else:
        relative_path = Path(clean_path)
        # Prefer exported route directories (`/login/ -> login/index.html`) over legacy flat files.
        candidates = []
        if relative_path.suffix:
            candidates.append(WEB_DIST_DIR / relative_path)
        candidates.extend([
            WEB_DIST_DIR / relative_path / "index.html",
            WEB_DIST_DIR / f"{clean_path}.html",
            WEB_DIST_DIR / relative_path,
        ])

    for candidate in candidates:
        try:
            candidate.relative_to(WEB_DIST_DIR)
        except ValueError:
            continue
        if candidate.is_file():
            return candidate

    return None


def create_app() -> FastAPI:
    chatgpt_service = ChatGPTService(account_service, auth_service)
    app_version = get_app_version()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        stop_event = Event()
        thread = start_limited_account_watcher(stop_event)
        try:
            yield
        finally:
            stop_event.set()
            thread.join(timeout=1)

    app = FastAPI(title="chatgpt2api", version=app_version, lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    router = APIRouter()

    @router.get("/v1/models")
    async def list_models():
        return {
            "object": "list",
            "data": [
                build_model_item("gpt-image-1"),
                build_model_item("gpt-image-2"),
            ],
        }

    @router.post("/auth/login")
    async def login(authorization: str | None = Header(default=None)):
        identity = require_identity(authorization)
        token = auth_service.issue_session_token(identity)
        return build_auth_payload(identity, app_version, token=token)

    @router.post("/auth/login/password")
    async def login_with_password(body: PasswordLoginRequest):
        identity = auth_service.authenticate_password(body.username, body.password)
        if identity is None:
            raise HTTPException(status_code=401, detail={"error": "username or password is invalid"})
        token = auth_service.issue_session_token(identity)
        return build_auth_payload(identity, app_version, token=token)

    @router.get("/auth/me")
    async def auth_me(authorization: str | None = Header(default=None)):
        identity = require_identity(authorization)
        return build_auth_payload(identity, app_version)

    @router.get("/auth/authentik/start")
    async def authentik_start(request: Request, redirect_to: str | None = Query(default=None)):
        try:
            redirect_uri = build_public_callback_url(request, "/auth/authentik/callback")
            start_url = authentik_service.build_authorization_url(
                redirect_uri=redirect_uri,
                redirect_to=with_trailing_slash(str(redirect_to or "/login")),
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail={"error": str(exc)}) from exc
        return RedirectResponse(start_url)

    @router.get("/auth/authentik/callback", name="authentik_callback")
    async def authentik_callback(
        request: Request,
        state: str = "",
        code: str = "",
        error: str | None = None,
    ):
        state_payload = authentik_service.pop_state(state)
        redirect_to = with_trailing_slash(str((state_payload or {}).get("redirect_to") or "/login"))
        if error:
            return RedirectResponse(append_query_value(redirect_to, auth_error=str(error)))
        if state_payload is None:
            return RedirectResponse(append_query_value(redirect_to, auth_error="invalid_state"))
        try:
            claims = authentik_service.exchange_code(
                code=code,
                redirect_uri=build_public_callback_url(request, "/auth/authentik/callback"),
            )
            user = auth_service.upsert_authentik_user(claims)
            identity = auth_service.get_public_user(str(user.get("id") or ""))
            if identity is None:
                raise RuntimeError("failed to load authentik user")
            identity = {
                **identity,
                "id": user.get("id"),
                "subject_id": user.get("id"),
            }
            ticket = authentik_service.issue_ticket(identity)
        except Exception as exc:
            return RedirectResponse(append_query_value(redirect_to, auth_error=str(exc)))
        return RedirectResponse(append_query_value(redirect_to, authentik_ticket=ticket))

    @router.post("/auth/exchange")
    async def exchange_auth_ticket(body: AuthTicketExchangeRequest):
        identity = authentik_service.consume_ticket(body.ticket)
        if identity is None:
            raise HTTPException(status_code=401, detail={"error": "auth ticket is invalid"})
        token = auth_service.issue_session_token(identity)
        return build_auth_payload(identity, app_version, token=token)

    @router.get("/auth/authentik/status")
    async def authentik_status():
        return {"enabled": authentik_service.is_enabled()}

    @router.get("/version")
    async def get_version():
        return {"version": app_version}

    @router.get("/api/settings")
    async def get_settings(authorization: str | None = Header(default=None)):
        require_admin(authorization)
        return {"config": config.get()}

    @router.post("/api/settings")
    async def save_settings(
            body: SettingsUpdateRequest,
            authorization: str | None = Header(default=None),
    ):
        require_admin(authorization)
        payload = body.model_dump(mode="python")
        payload.pop("auth-key", None)
        try:
            return {"config": config.update(payload)}
        except Exception as exc:
            raise HTTPException(status_code=500, detail={"error": f"save settings failed: {exc}"}) from exc

    @router.get("/api/auth/users")
    async def list_users(authorization: str | None = Header(default=None)):
        require_admin(authorization)
        return {"items": auth_service.list_users()}

    @router.post("/api/auth/users")
    async def create_user(body: UserCreateRequest, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        role = str(body.role or "user").strip().lower()
        if role not in {"admin", "user"}:
            raise HTTPException(status_code=400, detail={"error": "role is invalid"})
        item = auth_service.create_user(
            username=body.username,
            display_name=body.display_name,
            role=role,  # type: ignore[arg-type]
            password=body.password,
            enabled=True if body.enabled is None else bool(body.enabled),
            daily_image_limit=body.daily_image_limit,
            authentik_username=body.authentik_username,
        )
        return {"item": item, "items": auth_service.list_users()}

    @router.post("/api/auth/users/{key_id}")
    async def update_user(
            key_id: str,
            body: UserUpdateRequest,
            authorization: str | None = Header(default=None),
    ):
        require_admin(authorization)
        updates = {
            key: value
            for key, value in {
                "username": body.username,
                "display_name": body.display_name,
                "role": body.role,
                "password": body.password,
                "enabled": body.enabled,
                "daily_image_limit": body.daily_image_limit,
                "authentik_username": body.authentik_username,
            }.items()
            if value is not None
        }
        if not updates:
            raise HTTPException(status_code=400, detail={"error": "no updates provided"})
        item = auth_service.update_user(key_id, updates)
        if item is None:
            raise HTTPException(status_code=404, detail={"error": "user not found"})
        return {"item": item, "items": auth_service.list_users()}

    @router.delete("/api/auth/users/{key_id}")
    async def delete_user(key_id: str, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        if not auth_service.delete_user(key_id):
            raise HTTPException(status_code=404, detail={"error": "user not found"})
        return {"items": auth_service.list_users()}

    @router.post("/api/auth/users/{key_id}/api-key")
    async def reset_user_api_key(key_id: str, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        item, raw_key = auth_service.reset_api_key(key_id)
        if item is None:
            raise HTTPException(status_code=404, detail={"error": "user not found"})
        return {"item": item, "key": raw_key, "items": auth_service.list_users()}

    @router.get("/api/accounts")
    async def get_accounts(authorization: str | None = Header(default=None)):
        require_admin(authorization)
        return {"items": account_service.list_accounts()}

    @router.post("/api/accounts")
    async def create_accounts(body: AccountCreateRequest, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        tokens = [str(token or "").strip() for token in body.tokens if str(token or "").strip()]
        if not tokens:
            raise HTTPException(status_code=400, detail={"error": "tokens is required"})
        result = account_service.add_accounts(tokens)
        refresh_result = account_service.refresh_accounts(tokens)
        return {
            **result,
            "refreshed": refresh_result.get("refreshed", 0),
            "errors": refresh_result.get("errors", []),
            "items": refresh_result.get("items", result.get("items", [])),
        }

    @router.delete("/api/accounts")
    async def delete_accounts(body: AccountDeleteRequest, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        tokens = [str(token or "").strip() for token in body.tokens if str(token or "").strip()]
        if not tokens:
            raise HTTPException(status_code=400, detail={"error": "tokens is required"})
        return account_service.delete_accounts(tokens)

    @router.post("/api/accounts/refresh")
    async def refresh_accounts(body: AccountRefreshRequest, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        access_tokens = [str(token or "").strip() for token in body.access_tokens if str(token or "").strip()]
        if not access_tokens:
            access_tokens = account_service.list_tokens()
        if not access_tokens:
            raise HTTPException(status_code=400, detail={"error": "access_tokens is required"})
        return account_service.refresh_accounts(access_tokens)

    @router.post("/api/accounts/update")
    async def update_account(body: AccountUpdateRequest, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        access_token = str(body.access_token or "").strip()
        if not access_token:
            raise HTTPException(status_code=400, detail={"error": "access_token is required"})

        updates = {
            key: value
            for key, value in {
                "type": body.type,
                "status": body.status,
                "quota": body.quota,
            }.items()
            if value is not None
        }
        if not updates:
            raise HTTPException(status_code=400, detail={"error": "no updates provided"})

        account = account_service.update_account(access_token, updates)
        if account is None:
            raise HTTPException(status_code=404, detail={"error": "account not found"})
        return {"item": account, "items": account_service.list_accounts()}

    @router.post("/v1/images/generations")
    async def generate_images(
            body: ImageGenerationRequest,
            request: Request,
            authorization: str | None = Header(default=None)
    ):
        identity = require_identity(authorization)
        base_url = resolve_image_base_url(request)
        try:
            return await run_in_threadpool(
                chatgpt_service.generate_with_pool,
                body.prompt,
                body.model,
                body.n,
                body.response_format,
                base_url,
                identity,
            )
        except QuotaExceededError as exc:
            raise HTTPException(status_code=429, detail={"error": f"daily image quota exceeded, remaining={exc.remaining}"}) from exc
        except ImageGenerationError as exc:
            raise HTTPException(status_code=502, detail={"error": str(exc)}) from exc

    @router.post("/v1/images/edits")
    async def edit_images(
            request: Request,
            authorization: str | None = Header(default=None),
            image: list[UploadFile] | None = File(default=None),
            image_list: list[UploadFile] | None = File(default=None, alias="image[]"),
            prompt: str = Form(...),
            model: str = Form(default="gpt-image-1"),
            n: int = Form(default=1),
            response_format: str = Form(default="b64_json"),
    ):
        identity = require_identity(authorization)
        if n < 1 or n > 4:
            raise HTTPException(status_code=400, detail={"error": "n must be between 1 and 4"})

        uploads = [*(image or []), *(image_list or [])]
        if not uploads:
            raise HTTPException(status_code=400, detail={"error": "image file is required"})

        base_url = resolve_image_base_url(request)

        images: list[tuple[bytes, str, str]] = []
        for upload in uploads:
            image_data = await upload.read()
            if not image_data:
                raise HTTPException(status_code=400, detail={"error": "image file is empty"})

            file_name = upload.filename or "image.png"
            mime_type = upload.content_type or "image/png"
            images.append((image_data, file_name, mime_type))

        try:
            return await run_in_threadpool(
                chatgpt_service.edit_with_pool,
                prompt,
                images,
                model,
                n,
                response_format,
                base_url,
                identity,
            )
        except QuotaExceededError as exc:
            raise HTTPException(status_code=429, detail={"error": f"daily image quota exceeded, remaining={exc.remaining}"}) from exc
        except ImageGenerationError as exc:
            raise HTTPException(status_code=502, detail={"error": str(exc)}) from exc

    @router.post("/v1/chat/completions")
    async def create_chat_completion(body: ChatCompletionRequest, authorization: str | None = Header(default=None)):
        identity = require_identity(authorization)
        return await run_in_threadpool(chatgpt_service.create_image_completion, body.model_dump(mode="python"), identity)

    @router.post("/v1/responses")
    async def create_response(body: ResponseCreateRequest, authorization: str | None = Header(default=None)):
        identity = require_identity(authorization)
        return await run_in_threadpool(chatgpt_service.create_response, body.model_dump(mode="python"), identity)

    # ── CPA multi-pool endpoints ────────────────────────────────────

    @router.get("/api/cpa/pools")
    async def list_cpa_pools(authorization: str | None = Header(default=None)):
        require_admin(authorization)
        return {"pools": sanitize_cpa_pools(cpa_config.list_pools())}

    @router.post("/api/cpa/pools")
    async def create_cpa_pool(
            body: CPAPoolCreateRequest,
            authorization: str | None = Header(default=None),
    ):
        require_admin(authorization)
        if not body.base_url.strip():
            raise HTTPException(status_code=400, detail={"error": "base_url is required"})
        if not body.secret_key.strip():
            raise HTTPException(status_code=400, detail={"error": "secret_key is required"})
        pool = cpa_config.add_pool(
            name=body.name,
            base_url=body.base_url,
            secret_key=body.secret_key,
        )
        return {"pool": sanitize_cpa_pool(pool), "pools": sanitize_cpa_pools(cpa_config.list_pools())}

    @router.post("/api/cpa/pools/{pool_id}")
    async def update_cpa_pool(
            pool_id: str,
            body: CPAPoolUpdateRequest,
            authorization: str | None = Header(default=None),
    ):
        require_admin(authorization)
        pool = cpa_config.update_pool(pool_id, body.model_dump(exclude_none=True))
        if pool is None:
            raise HTTPException(status_code=404, detail={"error": "pool not found"})
        return {"pool": sanitize_cpa_pool(pool), "pools": sanitize_cpa_pools(cpa_config.list_pools())}

    @router.delete("/api/cpa/pools/{pool_id}")
    async def delete_cpa_pool(
            pool_id: str,
            authorization: str | None = Header(default=None),
    ):
        require_admin(authorization)
        if not cpa_config.delete_pool(pool_id):
            raise HTTPException(status_code=404, detail={"error": "pool not found"})
        return {"pools": sanitize_cpa_pools(cpa_config.list_pools())}

    @router.get("/api/cpa/pools/{pool_id}/files")
    async def cpa_pool_files(
            pool_id: str,
            authorization: str | None = Header(default=None),
    ):
        require_admin(authorization)
        pool = cpa_config.get_pool(pool_id)
        if pool is None:
            raise HTTPException(status_code=404, detail={"error": "pool not found"})
        files = await run_in_threadpool(list_remote_files, pool)
        return {"pool_id": pool_id, "files": files}

    @router.post("/api/cpa/pools/{pool_id}/import")
    async def cpa_pool_import(
            pool_id: str,
            body: CPAImportRequest,
            authorization: str | None = Header(default=None),
    ):
        require_admin(authorization)
        pool = cpa_config.get_pool(pool_id)
        if pool is None:
            raise HTTPException(status_code=404, detail={"error": "pool not found"})
        try:
            job = cpa_import_service.start_import(pool, body.names)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail={"error": str(exc)}) from exc
        return {"import_job": job}

    @router.get("/api/cpa/pools/{pool_id}/import")
    async def cpa_pool_import_progress(pool_id: str, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        pool = cpa_config.get_pool(pool_id)
        if pool is None:
            raise HTTPException(status_code=404, detail={"error": "pool not found"})
        return {"import_job": pool.get("import_job")}

    # ── Sub2API endpoints ─────────────────────────────────────────────

    @router.get("/api/sub2api/servers")
    async def list_sub2api_servers(authorization: str | None = Header(default=None)):
        require_admin(authorization)
        return {"servers": sanitize_sub2api_servers(sub2api_config.list_servers())}

    @router.post("/api/sub2api/servers")
    async def create_sub2api_server(
            body: Sub2APIServerCreateRequest,
            authorization: str | None = Header(default=None),
    ):
        require_admin(authorization)
        if not body.base_url.strip():
            raise HTTPException(status_code=400, detail={"error": "base_url is required"})
        has_login = body.email.strip() and body.password.strip()
        has_api_key = bool(body.api_key.strip())
        if not has_login and not has_api_key:
            raise HTTPException(
                status_code=400,
                detail={"error": "email+password or api_key is required"},
            )
        server = sub2api_config.add_server(
            name=body.name,
            base_url=body.base_url,
            email=body.email,
            password=body.password,
            api_key=body.api_key,
            group_id=body.group_id,
        )
        return {
            "server": sanitize_sub2api_server(server),
            "servers": sanitize_sub2api_servers(sub2api_config.list_servers()),
        }

    @router.post("/api/sub2api/servers/{server_id}")
    async def update_sub2api_server(
            server_id: str,
            body: Sub2APIServerUpdateRequest,
            authorization: str | None = Header(default=None),
    ):
        require_admin(authorization)
        server = sub2api_config.update_server(server_id, body.model_dump(exclude_none=True))
        if server is None:
            raise HTTPException(status_code=404, detail={"error": "server not found"})
        return {
            "server": sanitize_sub2api_server(server),
            "servers": sanitize_sub2api_servers(sub2api_config.list_servers()),
        }

    @router.delete("/api/sub2api/servers/{server_id}")
    async def delete_sub2api_server(
            server_id: str,
            authorization: str | None = Header(default=None),
    ):
        require_admin(authorization)
        if not sub2api_config.delete_server(server_id):
            raise HTTPException(status_code=404, detail={"error": "server not found"})
        return {"servers": sanitize_sub2api_servers(sub2api_config.list_servers())}

    @router.get("/api/sub2api/servers/{server_id}/groups")
    async def sub2api_server_groups(
            server_id: str,
            authorization: str | None = Header(default=None),
    ):
        require_admin(authorization)
        server = sub2api_config.get_server(server_id)
        if server is None:
            raise HTTPException(status_code=404, detail={"error": "server not found"})
        try:
            groups = await run_in_threadpool(sub2api_list_remote_groups, server)
        except Exception as exc:
            raise HTTPException(status_code=502, detail={"error": str(exc)}) from exc
        return {"server_id": server_id, "groups": groups}

    @router.get("/api/sub2api/servers/{server_id}/accounts")
    async def sub2api_server_accounts(
            server_id: str,
            authorization: str | None = Header(default=None),
    ):
        require_admin(authorization)
        server = sub2api_config.get_server(server_id)
        if server is None:
            raise HTTPException(status_code=404, detail={"error": "server not found"})
        try:
            accounts = await run_in_threadpool(sub2api_list_remote_accounts, server)
        except Exception as exc:
            raise HTTPException(status_code=502, detail={"error": str(exc)}) from exc
        return {"server_id": server_id, "accounts": accounts}

    @router.post("/api/sub2api/servers/{server_id}/import")
    async def sub2api_server_import(
            server_id: str,
            body: Sub2APIImportRequest,
            authorization: str | None = Header(default=None),
    ):
        require_admin(authorization)
        server = sub2api_config.get_server(server_id)
        if server is None:
            raise HTTPException(status_code=404, detail={"error": "server not found"})
        try:
            job = sub2api_import_service.start_import(server, body.account_ids)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail={"error": str(exc)}) from exc
        return {"import_job": job}

    @router.get("/api/sub2api/servers/{server_id}/import")
    async def sub2api_server_import_progress(
            server_id: str,
            authorization: str | None = Header(default=None),
    ):
        require_admin(authorization)
        server = sub2api_config.get_server(server_id)
        if server is None:
            raise HTTPException(status_code=404, detail={"error": "server not found"})
        return {"import_job": server.get("import_job")}

    # ── Upstream proxy endpoints ─────────────────────────────────────

    @router.post("/api/proxy/test")
    async def test_proxy_endpoint(
            body: ProxyTestRequest,
            authorization: str | None = Header(default=None),
    ):
        require_admin(authorization)
        candidate = (body.url or "").strip()
        if not candidate:
            candidate = config.get_proxy_settings()
        if not candidate:
            raise HTTPException(status_code=400, detail={"error": "proxy url is required"})
        result = await run_in_threadpool(test_proxy, candidate)
        return {"result": result}

    app.include_router(router)

    # 挂载静态图片目录
    images_dir = getattr(config, "images_dir", None)
    if images_dir is not None and Path(images_dir).exists():
        app.mount("/images", StaticFiles(directory=str(images_dir)), name="images")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_web(full_path: str, request: Request):
        normalized_path = full_path.strip("/")
        if normalized_path and "." not in Path(normalized_path).name and not request.url.path.endswith("/"):
            directory_index = WEB_DIST_DIR / normalized_path / "index.html"
            try:
                directory_index.relative_to(WEB_DIST_DIR)
            except ValueError:
                directory_index = Path("__invalid__")
            if directory_index.is_file():
                redirect_target = f"{request.url.path}/"
                if request.url.query:
                    redirect_target = f"{redirect_target}?{request.url.query}"
                return RedirectResponse(redirect_target, status_code=307)

        asset = resolve_web_asset(full_path)
        if asset is not None:
            return FileResponse(asset)

        # Static assets (_next/*) must not fallback to HTML — return 404
        if full_path.strip("/").startswith("_next/"):
            raise HTTPException(status_code=404, detail="Not Found")

        fallback = resolve_web_asset("")
        if fallback is None:
            raise HTTPException(status_code=404, detail="Not Found")
        return FileResponse(fallback)

    return app
