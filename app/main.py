import hashlib
import json
import logging
import os
import secrets
import sqlite3
import time
import traceback
from dataclasses import dataclass
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote
from zoneinfo import ZoneInfo

import httpx
from fastapi import Body, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware


APP_ROOT = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(APP_ROOT / "templates"))


@dataclass
class Settings:
    cookiecloud_target_url: str
    db_path: Path
    timezone_name: str
    dashboard_username: str
    dashboard_password: str
    recent_log_limit: int
    session_secret: str
    session_cookie_name: str
    session_max_age: int
    wecom_corp_id: str
    wecom_agent_id: str
    wecom_secret: str
    wecom_to_user: str
    wecom_to_party: str
    wecom_to_tag: str

    @property
    def timezone(self) -> ZoneInfo:
        return ZoneInfo(self.timezone_name)

    @property
    def dashboard_auth_enabled(self) -> bool:
        return bool(self.dashboard_username or self.dashboard_password)

    @property
    def wecom_enabled(self) -> bool:
        return all((self.wecom_corp_id, self.wecom_agent_id, self.wecom_secret)) and any(
            (self.wecom_to_user, self.wecom_to_party, self.wecom_to_tag)
        )

    @property
    def app_log_path(self) -> Path:
        return self.db_path.with_name("monitor-runtime.log")

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            cookiecloud_target_url=os.getenv("COOKIECLOUD_TARGET_URL", "http://cookiecloud:8088").rstrip("/"),
            db_path=Path(os.getenv("MONITOR_DB_PATH", "/data/monitor.db")),
            timezone_name=os.getenv("MONITOR_TIMEZONE", "Asia/Shanghai"),
            dashboard_username=os.getenv("DASHBOARD_USERNAME", ""),
            dashboard_password=os.getenv("DASHBOARD_PASSWORD", ""),
            recent_log_limit=max(int(os.getenv("RECENT_LOG_LIMIT", "50")), 10),
            session_secret=os.getenv("SESSION_SECRET", "") or secrets.token_hex(32),
            session_cookie_name=os.getenv("SESSION_COOKIE_NAME", "cookiecloud_monitor_session"),
            session_max_age=max(int(os.getenv("SESSION_MAX_AGE", "1209600")), 3600),
            wecom_corp_id=os.getenv("WECOM_CORP_ID", ""),
            wecom_agent_id=os.getenv("WECOM_AGENT_ID", ""),
            wecom_secret=os.getenv("WECOM_SECRET", ""),
            wecom_to_user=os.getenv("WECOM_TO_USER", ""),
            wecom_to_party=os.getenv("WECOM_TO_PARTY", ""),
            wecom_to_tag=os.getenv("WECOM_TO_TAG", ""),
        )


settings = Settings.from_env()
app = FastAPI(title="CookieCloud Monitor", version="0.1.0")
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    session_cookie=settings.session_cookie_name,
    max_age=settings.session_max_age,
    same_site="lax",
    https_only=False,
)
app.mount("/static", StaticFiles(directory=str(APP_ROOT / "static")), name="static")


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> Response:
    log_runtime_exception(source="unhandled_exception", message="Unhandled application exception", exc=exc, request=request)
    accepts_json = "application/json" in (request.headers.get("accept") or "").lower()
    if accepts_json or request.url.path.startswith("/api/"):
        return JSONResponse(status_code=500, content={"status": "error", "message": "服务内部错误，请到运行日志页面查看详情"})
    return PlainTextResponse("Internal Server Error", status_code=500)


CREATE_LOGS_SQL = """
CREATE TABLE IF NOT EXISTS sync_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    occurred_day TEXT NOT NULL,
    action TEXT NOT NULL,
    sync_uuid TEXT,
    outcome TEXT NOT NULL,
    http_status INTEGER,
    duration_ms INTEGER NOT NULL,
    request_method TEXT NOT NULL,
    request_path TEXT NOT NULL,
    query_string TEXT,
    client_ip TEXT,
    user_agent TEXT,
    payload_size INTEGER NOT NULL DEFAULT 0,
    payload_hash TEXT,
    response_size INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,
    response_excerpt TEXT
);
"""

CREATE_INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_sync_logs_day_action
ON sync_logs (occurred_day, action, outcome);
"""

CREATE_SYNC_STATES_SQL = """
CREATE TABLE IF NOT EXISTS sync_states (
    sync_uuid TEXT PRIMARY KEY,
    first_seen_at TEXT NOT NULL,
    last_sync_at TEXT NOT NULL,
    last_payload_hash TEXT,
    last_cookie_count INTEGER,
    last_site_count INTEGER,
    total_sync_count INTEGER NOT NULL DEFAULT 1
);
"""

CREATE_AUTH_EVENTS_SQL = """
CREATE TABLE IF NOT EXISTS auth_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    username TEXT NOT NULL,
    client_ip TEXT,
    user_agent TEXT,
    outcome TEXT NOT NULL
);
"""

CREATE_AUTH_EVENTS_INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_auth_events_occurred_at
ON auth_events (occurred_at DESC);
"""

CREATE_APP_SETTINGS_SQL = """
CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

CREATE_RUNTIME_LOGS_SQL = """
CREATE TABLE IF NOT EXISTS runtime_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    level TEXT NOT NULL,
    source TEXT NOT NULL,
    message TEXT NOT NULL,
    traceback_text TEXT,
    request_method TEXT,
    request_path TEXT,
    client_ip TEXT,
    sync_uuid TEXT
);
"""

CREATE_RUNTIME_LOGS_INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_runtime_logs_occurred_at
ON runtime_logs (occurred_at DESC);
"""


class LoginRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)
    next: str = "/dashboard"


WECOM_TOKEN_CACHE: dict[str, Any] = {"access_token": None, "expires_at": 0.0}
LOGGER = logging.getLogger("cookiecloud_monitor")

MANAGED_SETTING_KEYS = {
    "cookiecloud_target_url",
    "timezone_name",
    "dashboard_username",
    "dashboard_password",
    "recent_log_limit",
    "wecom_corp_id",
    "wecom_agent_id",
    "wecom_secret",
    "wecom_to_user",
    "wecom_to_party",
    "wecom_to_tag",
}


def get_db_connection() -> sqlite3.Connection:
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(settings.db_path)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with get_db_connection() as connection:
        connection.execute(CREATE_LOGS_SQL)
        connection.execute(CREATE_INDEX_SQL)
        connection.execute(CREATE_SYNC_STATES_SQL)
        connection.execute(CREATE_AUTH_EVENTS_SQL)
        connection.execute(CREATE_AUTH_EVENTS_INDEX_SQL)
        connection.execute(CREATE_APP_SETTINGS_SQL)
        connection.execute(CREATE_RUNTIME_LOGS_SQL)
        connection.execute(CREATE_RUNTIME_LOGS_INDEX_SQL)
        connection.commit()


def configure_app_logging() -> None:
    if LOGGER.handlers:
        return

    settings.app_log_path.parent.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s %(message)s")

    file_handler = RotatingFileHandler(
        settings.app_log_path,
        maxBytes=2 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(logging.INFO)

    LOGGER.setLevel(logging.INFO)
    LOGGER.addHandler(file_handler)
    LOGGER.addHandler(stream_handler)
    LOGGER.propagate = False


@app.on_event("startup")
def on_startup() -> None:
    configure_app_logging()
    init_db()
    refresh_runtime_settings()
    LOGGER.info("CookieCloud Monitor started target=%s log_path=%s", settings.cookiecloud_target_url, settings.app_log_path)


def now_local() -> datetime:
    return datetime.now(settings.timezone)


def load_app_settings_map() -> dict[str, str]:
    with get_db_connection() as connection:
        rows = connection.execute("SELECT key, value FROM app_settings").fetchall()
    return {str(row["key"]): str(row["value"]) for row in rows}


def refresh_runtime_settings() -> None:
    stored = load_app_settings_map()
    for key in MANAGED_SETTING_KEYS:
        if key not in stored:
            continue
        value = stored[key]
        if key == "cookiecloud_target_url":
            settings.cookiecloud_target_url = value.rstrip("/") or settings.cookiecloud_target_url
        elif key == "timezone_name":
            settings.timezone_name = value or settings.timezone_name
        elif key == "recent_log_limit":
            try:
                settings.recent_log_limit = max(int(value), 10)
            except ValueError:
                continue
        else:
            setattr(settings, key, value)


def save_runtime_settings(values: dict[str, str]) -> None:
    timestamp = now_local().isoformat(timespec="seconds")
    with get_db_connection() as connection:
        for key, value in values.items():
            if key not in MANAGED_SETTING_KEYS:
                continue
            connection.execute(
                """
                INSERT INTO app_settings (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at
                """,
                (key, value, timestamp),
            )
        connection.commit()
    refresh_runtime_settings()


def managed_settings_snapshot() -> dict[str, str]:
    return {
        "cookiecloud_target_url": settings.cookiecloud_target_url,
        "timezone_name": settings.timezone_name,
        "dashboard_username": settings.dashboard_username,
        "dashboard_password": settings.dashboard_password,
        "recent_log_limit": str(settings.recent_log_limit),
        "wecom_corp_id": settings.wecom_corp_id,
        "wecom_agent_id": settings.wecom_agent_id,
        "wecom_secret": settings.wecom_secret,
        "wecom_to_user": settings.wecom_to_user,
        "wecom_to_party": settings.wecom_to_party,
        "wecom_to_tag": settings.wecom_to_tag,
    }


def notification_target_summary() -> str:
    targets = []
    if settings.wecom_to_user:
        targets.append(f"成员 {settings.wecom_to_user}")
    if settings.wecom_to_party:
        targets.append(f"部门 {settings.wecom_to_party}")
    if settings.wecom_to_tag:
        targets.append(f"标签 {settings.wecom_to_tag}")
    return " / ".join(targets) if targets else "未配置接收对象"


def runtime_status_summary() -> dict[str, str]:
    return {
        "notification_status": "已启用" if settings.wecom_enabled else "未配置",
        "notification_target": notification_target_summary(),
        "proxy_mode": "前置代理模式",
        "proxy_hint": "请让浏览器插件请求当前 Monitor 地址，或由反向代理先转到 Monitor，再转发到真正的 CookieCloud。",
        "target_url": settings.cookiecloud_target_url,
    }


def normalize_form_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def maybe_json_bytes(raw: bytes) -> Any | None:
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def extract_candidate(form_data: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = form_data.get(key)
        if value:
            return normalize_form_value(value)
    return None


def extract_candidate_from_payload(payload: Any, *keys: str) -> str | None:
    if isinstance(payload, dict):
        for key in keys:
            value = payload.get(key)
            if value:
                return normalize_form_value(value)
        for value in payload.values():
            nested = extract_candidate_from_payload(value, *keys)
            if nested:
                return nested
        return None

    if isinstance(payload, list):
        for item in payload:
            nested = extract_candidate_from_payload(item, *keys)
            if nested:
                return nested

    return None


def extract_candidate_from_raw_body(raw_body: bytes, content_type: str, *keys: str) -> str | None:
    if "application/json" not in content_type.lower() or not raw_body:
        return None

    payload = maybe_json_bytes(raw_body)
    if payload is None:
        return None

    return extract_candidate_from_payload(payload, *keys)


def parse_form_map_from_raw_body(raw_body: bytes, content_type: str) -> dict[str, Any]:
    if not raw_body:
        return {}

    lowered = content_type.lower()
    if "application/x-www-form-urlencoded" in lowered:
        try:
            return {key: value for key, value in parse_qsl(raw_body.decode("utf-8", errors="replace"), keep_blank_values=True)}
        except Exception:
            return {}

    if "application/json" in lowered:
        try:
            payload = json.loads(raw_body.decode("utf-8", errors="replace"))
            if isinstance(payload, dict):
                return {str(key): value for key, value in payload.items()}
        except Exception:
            return {}

    return {}


def summarize_json_payload_structure(raw_body: bytes, content_type: str) -> str:
    if "application/json" not in content_type.lower() or not raw_body:
        return "json_root=-"

    try:
        payload = json.loads(raw_body.decode("utf-8", errors="replace"))
    except Exception:
        return "json_root=invalid"

    if isinstance(payload, dict):
        keys = ", ".join(sorted(str(key) for key in payload.keys())) or "-"
        return f"json_root=dict; json_keys={keys}"

    if isinstance(payload, list):
        if payload and isinstance(payload[0], dict):
            keys = ", ".join(sorted(str(key) for key in payload[0].keys())) or "-"
            return f"json_root=list; first_item_keys={keys}; list_length={len(payload)}"
        return f"json_root=list; list_length={len(payload)}"

    return f"json_root={type(payload).__name__}"


def summarize_transport_headers(source_headers: Any) -> str:
    if source_headers is None:
        return "content_encoding=-; transfer_encoding=-; content_length=-"

    content_encoding = source_headers.get("content-encoding") or "-"
    transfer_encoding = source_headers.get("transfer-encoding") or "-"
    content_length = source_headers.get("content-length") or "-"
    return (
        f"content_encoding={content_encoding}; "
        f"transfer_encoding={transfer_encoding}; "
        f"content_length={content_length}"
    )


def build_request_debug_summary(
    *,
    content_type: str,
    payload_size: int,
    payload_hash: str | None,
    form_map: dict[str, Any],
    sync_uuid: str | None,
    raw_body: bytes | None = None,
    source_headers: Any = None,
) -> str:
    keys = ", ".join(sorted(form_map.keys())) if form_map else "-"
    return (
        f"content_type={content_type or '-'}; "
        f"{summarize_transport_headers(source_headers)}; "
        f"payload_size={payload_size}; "
        f"payload_hash={payload_hash or '-'}; "
        f"form_keys={keys}; "
        f"detected_uuid={sync_uuid or '-'}; "
        f"{summarize_json_payload_structure(raw_body or b'', content_type)}"
    )


def build_payload_digest(form_data: dict[str, Any]) -> tuple[int, str | None]:
    preferred_value = extract_candidate(
        form_data,
        "encrypted",
        "cookie_data",
        "data",
        "payload",
        "local_storage_data",
    )
    raw_text = preferred_value
    if raw_text is None:
        items = []
        for key in sorted(form_data.keys()):
            if "password" in key.lower():
                continue
            items.append(f"{key}={normalize_form_value(form_data[key])}")
        raw_text = "&".join(items)
    if not raw_text:
        return 0, None
    raw_bytes = raw_text.encode("utf-8")
    return len(raw_bytes), hashlib.sha256(raw_bytes).hexdigest()


def parse_response_excerpt(raw: bytes) -> str | None:
    if not raw:
        return None
    text = raw.decode("utf-8", errors="replace").strip()
    if len(text) > 300:
        return text[:300] + "..."
    return text or None


def build_response_excerpt(action: str, outcome: str, raw_body: bytes, json_body: Any | None) -> str | None:
    if action == "download" and outcome == "success":
        return "[redacted successful download payload]"
    if action == "upload" and outcome == "success" and isinstance(json_body, dict):
        compact_text = json.dumps(json_body, ensure_ascii=False)
        if len(compact_text) > 300:
            return compact_text[:300] + "..."
        return compact_text
    return parse_response_excerpt(raw_body)


def classify_upload(status_code: int, json_body: Any | None, raw_body: bytes) -> tuple[str, str | None]:
    if 200 <= status_code < 300:
        if isinstance(json_body, dict):
            for key in ("error", "message", "msg"):
                value = json_body.get(key)
                if value and "error" in str(value).lower():
                    return "failed", str(value)
            if json_body.get("status") in {"error", "failed"}:
                return "failed", normalize_form_value(json_body.get("message") or json_body.get("error"))
        return "success", None
    return "failed", parse_response_excerpt(raw_body) or f"HTTP {status_code}"


def classify_download(status_code: int, json_body: Any | None, raw_body: bytes) -> tuple[str, str | None]:
    if not (200 <= status_code < 300):
        return "failed", parse_response_excerpt(raw_body) or f"HTTP {status_code}"
    if isinstance(json_body, dict):
        if any(json_body.get(key) for key in ("encrypted", "cookie_data", "local_storage_data")):
            return "success", None
        if json_body.get("status") in {"error", "failed"}:
            return "failed", normalize_form_value(json_body.get("message") or json_body.get("error"))
    return "success", None


def client_ip_from_request(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return None


def filtered_response_headers(source_headers: httpx.Headers) -> dict[str, str]:
    excluded = {"content-length", "connection", "transfer-encoding", "content-encoding", "keep-alive", "content-type"}
    return {key: value for key, value in source_headers.items() if key.lower() not in excluded}


def build_target_url(path: str) -> str:
    return f"{settings.cookiecloud_target_url}{path}"


def sanitize_next_path(next_path: str | None) -> str:
    if not next_path or not next_path.startswith("/") or next_path.startswith("//"):
        return "/dashboard"
    return next_path


def build_login_redirect(next_path: str | None) -> RedirectResponse:
    destination = sanitize_next_path(next_path)
    return RedirectResponse(url=f"/login?next={quote(destination, safe='/=?&')}", status_code=303)


def is_authenticated(request: Request) -> bool:
    if not settings.dashboard_auth_enabled:
        return True
    return bool(request.session.get("authenticated"))


def require_api_auth(request: Request) -> None:
    if not is_authenticated(request):
        raise HTTPException(status_code=401, detail="请先登录")


def record_auth_event(request: Request, username: str, outcome: str) -> None:
    with get_db_connection() as connection:
        connection.execute(
            """
            INSERT INTO auth_events (occurred_at, username, client_ip, user_agent, outcome)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                now_local().isoformat(timespec="seconds"),
                username,
                client_ip_from_request(request),
                request.headers.get("user-agent"),
                outcome,
            ),
        )
        connection.commit()


def parse_json_text(raw_text: str | None) -> Any | None:
    if not raw_text:
        return None
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        return None


def iter_cookie_like_entries(value: Any) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    if isinstance(value, dict):
        if {"name", "value"}.issubset(value.keys()):
            matches.append(value)
        for item in value.values():
            matches.extend(iter_cookie_like_entries(item))
    elif isinstance(value, list):
        for item in value:
            matches.extend(iter_cookie_like_entries(item))
    return matches


def extract_sync_counts(form_data: dict[str, Any]) -> tuple[int | None, int | None]:
    payload = parse_json_text(
        extract_candidate(
            form_data,
            "cookie_data",
            "data",
            "payload",
            "local_storage_data",
        )
    )
    if payload is None:
        return None, None

    cookies = iter_cookie_like_entries(payload)
    if not cookies:
        return None, None

    domains = {
        normalize_form_value(item.get("domain") or item.get("host") or item.get("site") or item.get("url"))
        for item in cookies
        if item.get("domain") or item.get("host") or item.get("site") or item.get("url")
    }
    return len(cookies), len(domains) if domains else None


def update_sync_state(
    sync_uuid: str | None,
    payload_hash: str | None,
    cookie_count: int | None,
    site_count: int | None,
) -> dict[str, Any]:
    if not sync_uuid:
        return {
            "is_first_sync": False,
            "payload_changed": False,
            "cookie_count": cookie_count,
            "site_count": site_count,
            "previous_cookie_count": None,
            "cookie_delta": None,
        }

    timestamp = now_local().isoformat(timespec="seconds")
    with get_db_connection() as connection:
        existing = connection.execute("SELECT * FROM sync_states WHERE sync_uuid = ?", (sync_uuid,)).fetchone()

        if existing is None:
            connection.execute(
                """
                INSERT INTO sync_states (
                    sync_uuid, first_seen_at, last_sync_at, last_payload_hash,
                    last_cookie_count, last_site_count, total_sync_count
                ) VALUES (?, ?, ?, ?, ?, ?, 1)
                """,
                (sync_uuid, timestamp, timestamp, payload_hash, cookie_count, site_count),
            )
            connection.commit()
            return {
                "is_first_sync": True,
                "payload_changed": bool(payload_hash),
                "cookie_count": cookie_count,
                "site_count": site_count,
                "previous_cookie_count": None,
                "cookie_delta": None,
            }

        previous_cookie_count = existing["last_cookie_count"]
        previous_site_count = existing["last_site_count"]
        next_cookie_count = cookie_count if cookie_count is not None else previous_cookie_count
        next_site_count = site_count if site_count is not None else previous_site_count
        payload_changed = bool(payload_hash and payload_hash != existing["last_payload_hash"])
        cookie_delta = None
        if previous_cookie_count is not None and cookie_count is not None:
            cookie_delta = cookie_count - previous_cookie_count

        connection.execute(
            """
            UPDATE sync_states
            SET last_sync_at = ?,
                last_payload_hash = ?,
                last_cookie_count = ?,
                last_site_count = ?,
                total_sync_count = total_sync_count + 1
            WHERE sync_uuid = ?
            """,
            (timestamp, payload_hash, next_cookie_count, next_site_count, sync_uuid),
        )
        connection.commit()

    return {
        "is_first_sync": False,
        "payload_changed": payload_changed,
        "cookie_count": next_cookie_count,
        "site_count": next_site_count,
        "previous_cookie_count": previous_cookie_count,
        "cookie_delta": cookie_delta,
    }


async def get_wecom_access_token() -> str:
    now_ts = time.time()
    cached_token = WECOM_TOKEN_CACHE.get("access_token")
    if cached_token and now_ts < float(WECOM_TOKEN_CACHE.get("expires_at", 0)):
        return str(cached_token)

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            "https://qyapi.weixin.qq.com/cgi-bin/gettoken",
            params={"corpid": settings.wecom_corp_id, "corpsecret": settings.wecom_secret},
        )
        response.raise_for_status()
        payload = response.json()

    if payload.get("errcode") != 0:
        raise RuntimeError(payload.get("errmsg") or "获取企业微信 access_token 失败")

    expires_in = int(payload.get("expires_in", 7200))
    token = str(payload["access_token"])
    WECOM_TOKEN_CACHE["access_token"] = token
    WECOM_TOKEN_CACHE["expires_at"] = now_ts + max(expires_in - 120, 60)
    return token


async def send_wecom_markdown(title: str, body_lines: list[str]) -> None:
    if not settings.wecom_enabled:
        return

    receiver_payload = {
        "touser": settings.wecom_to_user or None,
        "toparty": settings.wecom_to_party or None,
        "totag": settings.wecom_to_tag or None,
    }
    message_payload = {key: value for key, value in receiver_payload.items() if value}
    if not message_payload:
        return

    token = await get_wecom_access_token()
    message_payload.update(
        {
            "msgtype": "markdown",
            "agentid": int(settings.wecom_agent_id),
            "markdown": {"content": "\n".join([f"# {title}", *body_lines])},
            "safe": 0,
            "enable_duplicate_check": 0,
        }
    )

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            "https://qyapi.weixin.qq.com/cgi-bin/message/send",
            params={"access_token": token},
            json=message_payload,
        )
        response.raise_for_status()
        payload = response.json()

    if payload.get("errcode") != 0:
        raise RuntimeError(payload.get("errmsg") or "发送企业微信消息失败")


async def send_login_notification(request: Request, username: str) -> None:
    if not settings.wecom_enabled:
        return
    await send_wecom_markdown(
        "CookieCloud 控制台登录提醒",
        [
            f"> 登录账号：`{username}`",
            f"> 时间：`{now_local().isoformat(timespec='seconds')}`",
            f"> IP：`{client_ip_from_request(request) or '-'}`",
            f"> UA：`{(request.headers.get('user-agent') or '-')[:180]}`",
        ],
    )


async def send_sync_notification(sync_uuid: str, state: dict[str, Any], request: Request) -> None:
    if not settings.wecom_enabled:
        return

    title = ""
    if state["is_first_sync"]:
        title = "CookieCloud 首次同步提醒"
    elif state["cookie_delta"] is not None and state["cookie_delta"] > 0:
        title = "CookieCloud CK 数量增加"
    elif state["cookie_delta"] is not None and state["cookie_delta"] < 0:
        title = "CookieCloud CK 数量减少"
    elif state["payload_changed"]:
        title = "CookieCloud 同步内容更新"
    else:
        return

    body_lines = [
        f"> UUID：`{sync_uuid}`",
        f"> 时间：`{now_local().isoformat(timespec='seconds')}`",
        f"> 来源 IP：`{client_ip_from_request(request) or '-'}`",
        f"> 当前 CK 数：`{state['cookie_count'] if state['cookie_count'] is not None else '-'}`",
        f"> 站点数：`{state['site_count'] if state['site_count'] is not None else '-'}`",
    ]
    if state["previous_cookie_count"] is not None:
        body_lines.append(f"> 变更前 CK 数：`{state['previous_cookie_count']}`")
    if state["cookie_delta"] is not None:
        sign = "+" if state["cookie_delta"] > 0 else ""
        body_lines.append(f"> 变化值：`{sign}{state['cookie_delta']}`")

    await send_wecom_markdown(title, body_lines)


async def send_test_notification(request: Request) -> None:
    await send_wecom_markdown(
        "CookieCloud 测试通知",
        [
            "> 这是一条来自 CookieCloud Monitor 的测试消息。",
            f"> 时间：`{now_local().isoformat(timespec='seconds')}`",
            f"> 上游地址：`{settings.cookiecloud_target_url}`",
            f"> 接收对象：`{notification_target_summary()}`",
            f"> 触发人：`{request.session.get('username') or settings.dashboard_username or 'unknown'}`",
        ],
    )


def record_sync_log(
    *,
    action: str,
    sync_uuid: str | None,
    outcome: str,
    http_status: int | None,
    duration_ms: int,
    request_method: str,
    request_path: str,
    query_string: str,
    client_ip: str | None,
    user_agent: str | None,
    payload_size: int,
    payload_hash: str | None,
    response_size: int,
    error_message: str | None,
    response_excerpt: str | None,
) -> None:
    timestamp = now_local()
    with get_db_connection() as connection:
        connection.execute(
            """
            INSERT INTO sync_logs (
                occurred_at, occurred_day, action, sync_uuid, outcome, http_status,
                duration_ms, request_method, request_path, query_string, client_ip,
                user_agent, payload_size, payload_hash, response_size, error_message,
                response_excerpt
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp.isoformat(timespec="seconds"),
                timestamp.strftime("%Y-%m-%d"),
                action,
                sync_uuid,
                outcome,
                http_status,
                duration_ms,
                request_method,
                request_path,
                query_string,
                client_ip,
                user_agent,
                payload_size,
                payload_hash,
                response_size,
                error_message,
                response_excerpt,
            ),
        )
        connection.commit()


def record_runtime_log(
    *,
    level: str,
    source: str,
    message: str,
    traceback_text: str | None = None,
    request_method: str | None = None,
    request_path: str | None = None,
    client_ip: str | None = None,
    sync_uuid: str | None = None,
) -> None:
    with get_db_connection() as connection:
        connection.execute(
            """
            INSERT INTO runtime_logs (
                occurred_at, level, source, message, traceback_text,
                request_method, request_path, client_ip, sync_uuid
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now_local().isoformat(timespec="seconds"),
                level,
                source,
                message,
                traceback_text,
                request_method,
                request_path,
                client_ip,
                sync_uuid,
            ),
        )
        connection.commit()


def log_runtime_event(
    *,
    level: str,
    source: str,
    message: str,
    traceback_text: str | None = None,
    request: Request | None = None,
    sync_uuid: str | None = None,
) -> None:
    log_method = getattr(LOGGER, level.lower(), LOGGER.info)
    if traceback_text:
        log_method("%s\n%s", message, traceback_text)
    else:
        log_method("%s", message)

    record_runtime_log(
        level=level.upper(),
        source=source,
        message=message,
        traceback_text=traceback_text,
        request_method=request.method if request else None,
        request_path=request.url.path if request else None,
        client_ip=client_ip_from_request(request) if request else None,
        sync_uuid=sync_uuid,
    )


def log_runtime_exception(*, source: str, message: str, exc: Exception, request: Request | None = None, sync_uuid: str | None = None) -> None:
    log_runtime_event(
        level="error",
        source=source,
        message=f"{message}: {exc}",
        traceback_text="".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
        request=request,
        sync_uuid=sync_uuid,
    )


def require_page_auth(request: Request) -> RedirectResponse | None:
    if is_authenticated(request):
        return None
    next_path = request.url.path
    if request.url.query:
        next_path = f"{next_path}?{request.url.query}"
    return build_login_redirect(next_path)


async def forward_to_cookiecloud(
    *,
    method: str,
    path: str,
    content: bytes | None = None,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    async with httpx.AsyncClient(timeout=15.0) as client:
        return await client.request(method, build_target_url(path), content=content, params=params, headers=headers)


def filtered_request_headers(source_headers: Any) -> dict[str, str]:
    allowed = {"content-type", "content-encoding"}
    return {key: value for key, value in source_headers.items() if key.lower() in allowed}


@app.get("/", include_in_schema=False)
async def root(request: Request) -> Response:
    accept = (request.headers.get("accept") or "").lower()
    user_agent = (request.headers.get("user-agent") or "").lower()
    wants_html = "text/html" in accept or "mozilla" in user_agent

    if not wants_html:
        return PlainTextResponse("CookieCloud Monitor OK", status_code=200)

    return TEMPLATES.TemplateResponse(
        "index.html",
        {
            "request": request,
            "dashboard_url": "/dashboard",
            "settings_url": "/settings",
            "health_url": "/healthz",
            "target_url": settings.cookiecloud_target_url,
        },
    )


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: str | None = Query(default="/dashboard")) -> Response:
    if is_authenticated(request):
        return RedirectResponse(url=sanitize_next_path(next), status_code=303)
    return TEMPLATES.TemplateResponse(
        "login.html",
        {
            "request": request,
            "next_path": sanitize_next_path(next),
            "auth_enabled": settings.dashboard_auth_enabled,
        },
    )


async def complete_login(request: Request, username: str, redirect_to: str) -> None:
    request.session.clear()
    request.session["authenticated"] = True
    request.session["username"] = username
    request.session["logged_in_at"] = now_local().isoformat(timespec="seconds")
    record_auth_event(request, username, "success")
    try:
        await send_login_notification(request, username)
    except Exception:
        pass


@app.post("/auth/login")
async def login(request: Request, payload: LoginRequest = Body(...)) -> JSONResponse:
    redirect_to = sanitize_next_path(payload.next)
    if not settings.dashboard_auth_enabled:
        return JSONResponse({"ok": True, "redirect": redirect_to})

    username_matches = secrets.compare_digest(payload.username, settings.dashboard_username)
    password_matches = secrets.compare_digest(payload.password, settings.dashboard_password)
    if not (username_matches and password_matches):
        record_auth_event(request, payload.username, "failed")
        return JSONResponse(status_code=401, content={"message": "账号或密码错误"})

    await complete_login(request, payload.username, redirect_to)
    return JSONResponse({"ok": True, "redirect": redirect_to})


@app.post("/auth/login-form")
async def login_form(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form("/dashboard"),
) -> Response:
    redirect_to = sanitize_next_path(next)
    if not settings.dashboard_auth_enabled:
        return RedirectResponse(url=redirect_to, status_code=303)

    username_matches = secrets.compare_digest(username, settings.dashboard_username)
    password_matches = secrets.compare_digest(password, settings.dashboard_password)
    if not (username_matches and password_matches):
        record_auth_event(request, username, "failed")
        return TEMPLATES.TemplateResponse(
            "login.html",
            {
                "request": request,
                "next_path": redirect_to,
                "auth_enabled": settings.dashboard_auth_enabled,
                "fallback_error": "账号或密码错误",
                "fallback_username": username,
            },
            status_code=401,
        )

    await complete_login(request, username, redirect_to)
    return RedirectResponse(url=redirect_to, status_code=303)


@app.get("/auth/logout")
@app.post("/auth/logout")
async def logout(request: Request) -> Response:
    request.session.clear()
    if "application/json" in (request.headers.get("accept") or ""):
        return JSONResponse({"ok": True, "redirect": "/login"})
    return RedirectResponse(url="/login", status_code=303)


@app.get("/api/me")
async def api_me(request: Request) -> dict[str, Any]:
    return {
        "authenticated": is_authenticated(request),
        "username": request.session.get("username"),
        "auth_enabled": settings.dashboard_auth_enabled,
    }


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/update")
async def proxy_update(request: Request) -> Response:
    raw_body = await request.body()
    content_type = request.headers.get("content-type", "")
    form_map: dict[str, Any] = {}
    try:
        form = await request.form()
        form_map = dict(form.multi_items())
    except Exception:
        form_map = parse_form_map_from_raw_body(raw_body, content_type)
    sync_uuid = extract_candidate(form_map, "uuid", "userUUID", "user_uuid", "id")
    if not sync_uuid:
        sync_uuid = extract_candidate_from_raw_body(raw_body, content_type, "uuid", "userUUID", "user_uuid", "id")
    payload_size, payload_hash = build_payload_digest(form_map)
    if payload_size == 0 and raw_body:
        payload_size = len(raw_body)
        payload_hash = hashlib.sha256(raw_body).hexdigest()
    cookie_count, site_count = extract_sync_counts(form_map)
    start_time = time.perf_counter()
    request_debug = build_request_debug_summary(
        content_type=content_type,
        payload_size=payload_size,
        payload_hash=payload_hash,
        form_map=form_map,
        sync_uuid=sync_uuid,
        raw_body=raw_body,
        source_headers=request.headers,
    )

    try:
        upstream_response = await forward_to_cookiecloud(
            method="POST",
            path="/update",
            content=raw_body,
            headers=filtered_request_headers(request.headers),
        )
        duration_ms = int((time.perf_counter() - start_time) * 1000)
        raw_body = upstream_response.content
        json_body = maybe_json_bytes(raw_body)
        outcome, error_message = classify_upload(upstream_response.status_code, json_body, raw_body)
        sync_state: dict[str, Any] | None = None
        if outcome == "success":
            sync_state = update_sync_state(sync_uuid, payload_hash, cookie_count, site_count)
        record_sync_log(
            action="upload",
            sync_uuid=sync_uuid,
            outcome=outcome,
            http_status=upstream_response.status_code,
            duration_ms=duration_ms,
            request_method="POST",
            request_path="/update",
            query_string=request.url.query,
            client_ip=client_ip_from_request(request),
            user_agent=request.headers.get("user-agent"),
            payload_size=payload_size,
            payload_hash=payload_hash,
            response_size=len(raw_body),
            error_message=error_message,
            response_excerpt=build_response_excerpt("upload", outcome, raw_body, json_body),
        )
        if outcome == "failed":
            response_excerpt = build_response_excerpt("upload", outcome, raw_body, json_body)
            log_runtime_event(
                level="error" if upstream_response.status_code >= 500 else "warning",
                source="proxy_update",
                message=(
                    f"Upstream /update returned {upstream_response.status_code}: {error_message or 'unknown error'}; "
                    f"response_excerpt={response_excerpt or '-'}; {request_debug}"
                ),
                request=request,
                sync_uuid=sync_uuid,
            )
        if outcome == "success" and sync_uuid and sync_state is not None:
            try:
                await send_sync_notification(sync_uuid, sync_state, request)
            except Exception:
                pass
        return Response(
            content=raw_body,
            status_code=upstream_response.status_code,
            media_type=upstream_response.headers.get("content-type"),
            headers=filtered_response_headers(upstream_response.headers),
        )
    except Exception as exc:
        duration_ms = int((time.perf_counter() - start_time) * 1000)
        error_message = str(exc)
        record_sync_log(
            action="upload",
            sync_uuid=sync_uuid,
            outcome="failed",
            http_status=None,
            duration_ms=duration_ms,
            request_method="POST",
            request_path="/update",
            query_string=request.url.query,
            client_ip=client_ip_from_request(request),
            user_agent=request.headers.get("user-agent"),
            payload_size=payload_size,
            payload_hash=payload_hash,
            response_size=0,
            error_message=error_message,
            response_excerpt=None,
        )
        log_runtime_exception(
            source="proxy_update",
            message=f"Proxy update request failed; {request_debug}",
            exc=exc,
            request=request,
            sync_uuid=sync_uuid,
        )
        return JSONResponse(status_code=502, content={"status": "error", "message": "CookieCloud 上传转发失败"})


@app.api_route("/get/{sync_uuid}", methods=["GET", "POST"])
async def proxy_get(sync_uuid: str, request: Request) -> Response:
    start_time = time.perf_counter()
    form_map: dict[str, Any] = {}
    params: dict[str, Any] = dict(request.query_params)
    data: Any = None
    content: bytes | None = None
    headers: dict[str, str] | None = None
    content_type = request.headers.get("content-type", "")

    if request.method == "POST":
        raw_body = await request.body()
        content = raw_body
        headers = filtered_request_headers(request.headers)
        try:
            form = await request.form()
            form_map = dict(form.multi_items())
        except Exception:
            form_map = parse_form_map_from_raw_body(raw_body, content_type)

    payload_size, payload_hash = build_payload_digest(form_map)
    if payload_size == 0 and content:
        payload_size = len(content)
        payload_hash = hashlib.sha256(content).hexdigest()
    request_debug = build_request_debug_summary(
        content_type=content_type,
        payload_size=payload_size,
        payload_hash=payload_hash,
        form_map=form_map,
        sync_uuid=sync_uuid,
        raw_body=content,
        source_headers=request.headers,
    )

    try:
        upstream_response = await forward_to_cookiecloud(
            method=request.method,
            path=f"/get/{sync_uuid}",
            content=content,
            params=params or None,
            headers=headers,
        )
        duration_ms = int((time.perf_counter() - start_time) * 1000)
        raw_body = upstream_response.content
        json_body = maybe_json_bytes(raw_body)
        outcome, error_message = classify_download(upstream_response.status_code, json_body, raw_body)
        record_sync_log(
            action="download",
            sync_uuid=sync_uuid,
            outcome=outcome,
            http_status=upstream_response.status_code,
            duration_ms=duration_ms,
            request_method=request.method,
            request_path=f"/get/{sync_uuid}",
            query_string=request.url.query,
            client_ip=client_ip_from_request(request),
            user_agent=request.headers.get("user-agent"),
            payload_size=payload_size,
            payload_hash=payload_hash,
            response_size=len(raw_body),
            error_message=error_message,
            response_excerpt=build_response_excerpt("download", outcome, raw_body, json_body),
        )
        if outcome == "failed":
            response_excerpt = build_response_excerpt("download", outcome, raw_body, json_body)
            log_runtime_event(
                level="error" if upstream_response.status_code >= 500 else "warning",
                source="proxy_get",
                message=(
                    f"Upstream /get/{sync_uuid} returned {upstream_response.status_code}: {error_message or 'unknown error'}; "
                    f"response_excerpt={response_excerpt or '-'}; {request_debug}"
                ),
                request=request,
                sync_uuid=sync_uuid,
            )
        return Response(
            content=raw_body,
            status_code=upstream_response.status_code,
            media_type=upstream_response.headers.get("content-type"),
            headers=filtered_response_headers(upstream_response.headers),
        )
    except Exception as exc:
        duration_ms = int((time.perf_counter() - start_time) * 1000)
        error_message = str(exc)
        record_sync_log(
            action="download",
            sync_uuid=sync_uuid,
            outcome="failed",
            http_status=None,
            duration_ms=duration_ms,
            request_method=request.method,
            request_path=f"/get/{sync_uuid}",
            query_string=request.url.query,
            client_ip=client_ip_from_request(request),
            user_agent=request.headers.get("user-agent"),
            payload_size=payload_size,
            payload_hash=payload_hash,
            response_size=0,
            error_message=error_message,
            response_excerpt=None,
        )
        log_runtime_exception(
            source="proxy_get",
            message=f"Proxy download request failed; {request_debug}",
            exc=exc,
            request=request,
            sync_uuid=sync_uuid,
        )
        return JSONResponse(status_code=502, content={"status": "error", "message": "CookieCloud 下载转发失败"})


def fetch_summary_data() -> dict[str, Any]:
    today = now_local().strftime("%Y-%m-%d")
    seven_days_ago = (now_local() - timedelta(days=6)).strftime("%Y-%m-%d")

    with get_db_connection() as connection:
        today_rows = connection.execute(
            """
            SELECT action, outcome, COUNT(*) AS count
            FROM sync_logs
            WHERE occurred_day = ?
            GROUP BY action, outcome
            """,
            (today,),
        ).fetchall()
        recent_days_rows = connection.execute(
            """
            SELECT
                occurred_day,
                SUM(CASE WHEN outcome = 'success' THEN 1 ELSE 0 END) AS success_count,
                SUM(CASE WHEN outcome = 'failed' THEN 1 ELSE 0 END) AS failed_count,
                COUNT(*) AS total_count
            FROM sync_logs
            WHERE occurred_day >= ?
            GROUP BY occurred_day
            ORDER BY occurred_day ASC
            """,
            (seven_days_ago,),
        ).fetchall()
        uuid_rows = connection.execute(
            """
            SELECT
                COALESCE(sync_uuid, 'unknown') AS sync_uuid,
                COUNT(*) AS total_count,
                SUM(CASE WHEN outcome = 'success' THEN 1 ELSE 0 END) AS success_count,
                SUM(CASE WHEN outcome = 'failed' THEN 1 ELSE 0 END) AS failed_count,
                MAX(occurred_at) AS last_seen_at
            FROM sync_logs
            GROUP BY COALESCE(sync_uuid, 'unknown')
            ORDER BY last_seen_at DESC
            LIMIT 10
            """
        ).fetchall()
        sync_state_row = connection.execute(
            """
            SELECT COUNT(*) AS tracked_uuids, MAX(last_sync_at) AS last_sync_at
            FROM sync_states
            """
        ).fetchone()
        today_login_row = connection.execute(
            """
            SELECT COUNT(*) AS login_success_count
            FROM auth_events
            WHERE outcome = 'success' AND substr(occurred_at, 1, 10) = ?
            """,
            (today,),
        ).fetchone()

    today_map = {
        ("upload", "success"): 0,
        ("upload", "failed"): 0,
        ("download", "success"): 0,
        ("download", "failed"): 0,
    }
    for row in today_rows:
        today_map[(row["action"], row["outcome"])] = row["count"]

    daily_stats = []
    max_total = max([row["total_count"] for row in recent_days_rows], default=1)
    for row in recent_days_rows:
        daily_stats.append(
            {
                "occurred_day": row["occurred_day"],
                "success_count": row["success_count"],
                "failed_count": row["failed_count"],
                "total_count": row["total_count"],
                "bar_pct": round((row["total_count"] / max_total) * 100),
            }
        )

    uuid_summary = [
        {
            "sync_uuid": row["sync_uuid"],
            "total_count": row["total_count"],
            "success_count": row["success_count"],
            "failed_count": row["failed_count"],
            "last_seen_at": row["last_seen_at"],
        }
        for row in uuid_rows
    ]

    total_today = sum(today_map.values())
    success_today = today_map[("upload", "success")] + today_map[("download", "success")]
    success_rate = round((success_today / total_today) * 100, 1) if total_today else 0.0

    return {
        "today": today,
        "metrics": {
            "total_today": total_today,
            "success_today": success_today,
            "failed_today": total_today - success_today,
            "success_rate": success_rate,
            "upload_success": today_map[("upload", "success")],
            "upload_failed": today_map[("upload", "failed")],
            "download_success": today_map[("download", "success")],
            "download_failed": today_map[("download", "failed")],
            "tracked_uuids": sync_state_row["tracked_uuids"] if sync_state_row else 0,
            "last_sync_at": sync_state_row["last_sync_at"] if sync_state_row else None,
            "today_login_success": today_login_row["login_success_count"] if today_login_row else 0,
        },
        "daily_stats": daily_stats,
        "uuid_summary": uuid_summary,
        "notification_enabled": settings.wecom_enabled,
        "auth_enabled": settings.dashboard_auth_enabled,
    }


def fetch_recent_logs(
    *,
    sync_uuid: str | None,
    action: str | None,
    outcome: str | None,
    day: str | None,
) -> list[dict[str, Any]]:
    where_clauses = []
    params: list[Any] = []

    if sync_uuid:
        where_clauses.append("sync_uuid = ?")
        params.append(sync_uuid)
    if action:
        where_clauses.append("action = ?")
        params.append(action)
    if outcome:
        where_clauses.append("outcome = ?")
        params.append(outcome)
    if day:
        where_clauses.append("occurred_day = ?")
        params.append(day)

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
    query = f"""
        SELECT *
        FROM sync_logs
        {where_sql}
        ORDER BY occurred_at DESC, id DESC
        LIMIT ?
    """
    params.append(settings.recent_log_limit)

    with get_db_connection() as connection:
        rows = connection.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def fetch_recent_auth_events(limit: int = 8) -> list[dict[str, Any]]:
    with get_db_connection() as connection:
        rows = connection.execute(
            """
            SELECT occurred_at, username, client_ip, user_agent, outcome
            FROM auth_events
            ORDER BY occurred_at DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def fetch_recent_runtime_logs(limit: int = 10) -> list[dict[str, Any]]:
    with get_db_connection() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM runtime_logs
            ORDER BY occurred_at DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def fetch_runtime_log_by_id(log_id: int) -> dict[str, Any] | None:
    with get_db_connection() as connection:
        row = connection.execute("SELECT * FROM runtime_logs WHERE id = ?", (log_id,)).fetchone()
    return dict(row) if row else None


def build_settings_page_context(
    request: Request,
    *,
    message: str = "",
    error: str = "",
    form_overrides: dict[str, str] | None = None,
) -> dict[str, Any]:
    settings_form = managed_settings_snapshot()
    if form_overrides:
        settings_form.update({key: value for key, value in form_overrides.items() if key in settings_form})
    return {
        "request": request,
        "settings_form": settings_form,
        "message": message,
        "error": error,
        "dashboard_username": request.session.get("username") or settings.dashboard_username or "当前会话",
        "notification_status": "已启用" if settings.wecom_enabled else "未配置",
        "notification_target": notification_target_summary(),
        "logout_url": "/auth/logout",
    }


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    sync_uuid: str | None = Query(default=None),
    action: str | None = Query(default=None),
    outcome: str | None = Query(default=None),
    day: str | None = Query(default=None),
) -> HTMLResponse:
    redirect = require_page_auth(request)
    if redirect is not None:
        return redirect

    summary = fetch_summary_data()
    logs = fetch_recent_logs(sync_uuid=sync_uuid, action=action, outcome=outcome, day=day)
    auth_events = fetch_recent_auth_events()
    runtime_logs = fetch_recent_runtime_logs()
    status = runtime_status_summary()
    return TEMPLATES.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "summary": summary,
            "logs": logs,
            "auth_events": auth_events,
            "runtime_logs": runtime_logs,
            "filters": {
                "sync_uuid": sync_uuid or "",
                "action": action or "",
                "outcome": outcome or "",
                "day": day or "",
            },
            "target_url": status["target_url"],
            "recent_log_limit": settings.recent_log_limit,
            "notification_status": status["notification_status"],
            "notification_target": status["notification_target"],
            "proxy_mode": status["proxy_mode"],
            "proxy_hint": status["proxy_hint"],
            "dashboard_username": request.session.get("username") or settings.dashboard_username or "当前会话",
            "logout_url": "/auth/logout",
            "settings_url": "/settings",
            "runtime_logs_url": "/runtime-logs",
            "app_log_path": str(settings.app_log_path),
        },
    )


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(
    request: Request,
    message: str = Query(default=""),
    error: str = Query(default=""),
) -> Response:
    redirect = require_page_auth(request)
    if redirect is not None:
        return redirect
    return TEMPLATES.TemplateResponse("settings.html", build_settings_page_context(request, message=message, error=error))


@app.post("/settings")
async def update_settings(
    request: Request,
    cookiecloud_target_url: str = Form(...),
    timezone_name: str = Form("Asia/Shanghai"),
    recent_log_limit: str = Form("50"),
    dashboard_username: str = Form(""),
    dashboard_password: str = Form(""),
    wecom_corp_id: str = Form(""),
    wecom_agent_id: str = Form(""),
    wecom_secret: str = Form(""),
    wecom_to_user: str = Form(""),
    wecom_to_party: str = Form(""),
    wecom_to_tag: str = Form(""),
) -> Response:
    redirect = require_page_auth(request)
    if redirect is not None:
        return redirect

    cleaned_values = {
        "cookiecloud_target_url": cookiecloud_target_url.strip().rstrip("/"),
        "timezone_name": timezone_name.strip() or "Asia/Shanghai",
        "recent_log_limit": recent_log_limit.strip() or "50",
        "dashboard_username": dashboard_username.strip(),
        "dashboard_password": dashboard_password.strip(),
        "wecom_corp_id": wecom_corp_id.strip(),
        "wecom_agent_id": wecom_agent_id.strip(),
        "wecom_secret": wecom_secret.strip(),
        "wecom_to_user": wecom_to_user.strip(),
        "wecom_to_party": wecom_to_party.strip(),
        "wecom_to_tag": wecom_to_tag.strip(),
    }
    form_values = {**cleaned_values, "dashboard_password": ""}

    if not cleaned_values["cookiecloud_target_url"].startswith(("http://", "https://")):
        return TEMPLATES.TemplateResponse(
            "settings.html",
            build_settings_page_context(
                request,
                error="CookieCloud 上游地址必须以 http:// 或 https:// 开头。",
                form_overrides=form_values,
            ),
            status_code=400,
        )

    try:
        ZoneInfo(cleaned_values["timezone_name"])
    except Exception:
        return TEMPLATES.TemplateResponse(
            "settings.html",
            build_settings_page_context(
                request,
                error="时区格式无效，请填写例如 Asia/Shanghai。",
                form_overrides=form_values,
            ),
            status_code=400,
        )

    try:
        cleaned_values["recent_log_limit"] = str(max(int(cleaned_values["recent_log_limit"]), 10))
        form_values["recent_log_limit"] = cleaned_values["recent_log_limit"]
    except ValueError:
        return TEMPLATES.TemplateResponse(
            "settings.html",
            build_settings_page_context(request, error="最近日志条数必须是数字。", form_overrides=form_values),
            status_code=400,
        )

    if cleaned_values["dashboard_username"] and not (cleaned_values["dashboard_password"] or settings.dashboard_password):
        return TEMPLATES.TemplateResponse(
            "settings.html",
            build_settings_page_context(
                request,
                error="开启登录保护时必须同时设置登录密码。",
                form_overrides=form_values,
            ),
            status_code=400,
        )

    if cleaned_values["dashboard_password"] and not cleaned_values["dashboard_username"]:
        return TEMPLATES.TemplateResponse(
            "settings.html",
            build_settings_page_context(
                request,
                error="填写登录密码前，请先填写登录账号。",
                form_overrides=form_values,
            ),
            status_code=400,
        )

    if not cleaned_values["dashboard_username"]:
        cleaned_values["dashboard_password"] = ""
    elif not cleaned_values["dashboard_password"]:
        cleaned_values["dashboard_password"] = settings.dashboard_password

    save_runtime_settings(cleaned_values)
    return RedirectResponse(url="/settings?message=配置已保存", status_code=303)


@app.post("/settings/test-notification")
async def test_notification(request: Request) -> Response:
    redirect = require_page_auth(request)
    if redirect is not None:
        return redirect

    if not settings.wecom_enabled:
        return RedirectResponse(url="/settings?error=企业微信应用参数未完整配置", status_code=303)

    try:
        await send_test_notification(request)
    except Exception as exc:
        return RedirectResponse(url=f"/settings?error={quote(str(exc))}", status_code=303)
    return RedirectResponse(url="/settings?message=测试通知已发送", status_code=303)


@app.get("/logs/{log_id}", response_class=HTMLResponse)
async def log_detail(
    log_id: int,
    request: Request,
) -> Response:
    redirect = require_page_auth(request)
    if redirect is not None:
        return redirect

    with get_db_connection() as connection:
        row = connection.execute("SELECT * FROM sync_logs WHERE id = ?", (log_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="日志不存在")
    return TEMPLATES.TemplateResponse("detail.html", {"request": request, "log": dict(row)})


@app.get("/runtime-logs", response_class=HTMLResponse)
async def runtime_logs_page(request: Request) -> Response:
    redirect = require_page_auth(request)
    if redirect is not None:
        return redirect

    return TEMPLATES.TemplateResponse(
        "runtime_logs.html",
        {
            "request": request,
            "logs": fetch_recent_runtime_logs(limit=50),
            "logout_url": "/auth/logout",
            "dashboard_url": "/dashboard",
            "app_log_path": str(settings.app_log_path),
        },
    )


@app.get("/runtime-logs/{log_id}", response_class=HTMLResponse)
async def runtime_log_detail(log_id: int, request: Request) -> Response:
    redirect = require_page_auth(request)
    if redirect is not None:
        return redirect

    log = fetch_runtime_log_by_id(log_id)
    if log is None:
        raise HTTPException(status_code=404, detail="运行日志不存在")

    return TEMPLATES.TemplateResponse(
        "runtime_log_detail.html",
        {
            "request": request,
            "log": log,
            "dashboard_url": "/dashboard",
            "runtime_logs_url": "/runtime-logs",
        },
    )


@app.get("/api/summary")
async def api_summary(request: Request) -> dict[str, Any]:
    require_api_auth(request)
    return fetch_summary_data()


@app.get("/api/logs")
async def api_logs(
    request: Request,
    sync_uuid: str | None = Query(default=None),
    action: str | None = Query(default=None),
    outcome: str | None = Query(default=None),
    day: str | None = Query(default=None),
) -> dict[str, Any]:
    require_api_auth(request)
    return {"items": fetch_recent_logs(sync_uuid=sync_uuid, action=action, outcome=outcome, day=day)}
