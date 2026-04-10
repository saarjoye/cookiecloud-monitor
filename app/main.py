import base64
import asyncio
import gzip
import hashlib
import json
import logging
import os
import secrets
import sqlite3
import time
import traceback
import zlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote, urlparse
from zoneinfo import ZoneInfo

import httpx
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
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
    cookiecloud_sync_password: str
    db_path: Path
    timezone_name: str
    dashboard_username: str
    dashboard_password: str
    recent_log_limit: int
    session_secret: str
    session_cookie_name: str
    session_max_age: int
    notification_public_base_url: str
    wecom_corp_id: str
    wecom_agent_id: str
    wecom_secret: str
    wecom_api_base_url: str
    wecom_message_type: str
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

    @property
    def encrypted_site_details_enabled(self) -> bool:
        return bool(self.cookiecloud_sync_password)

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            cookiecloud_target_url=os.getenv("COOKIECLOUD_TARGET_URL", "http://cookiecloud:8088").rstrip("/"),
            cookiecloud_sync_password=os.getenv("COOKIECLOUD_SYNC_PASSWORD", ""),
            db_path=Path(os.getenv("MONITOR_DB_PATH", "/data/monitor.db")),
            timezone_name=os.getenv("MONITOR_TIMEZONE", "Asia/Shanghai"),
            dashboard_username=os.getenv("DASHBOARD_USERNAME", ""),
            dashboard_password=os.getenv("DASHBOARD_PASSWORD", ""),
            recent_log_limit=max(int(os.getenv("RECENT_LOG_LIMIT", "50")), 10),
            session_secret=os.getenv("SESSION_SECRET", "") or secrets.token_hex(32),
            session_cookie_name=os.getenv("SESSION_COOKIE_NAME", "cookiecloud_monitor_session"),
            session_max_age=max(int(os.getenv("SESSION_MAX_AGE", "1209600")), 3600),
            notification_public_base_url=os.getenv("NOTIFICATION_PUBLIC_BASE_URL", "").strip().rstrip("/"),
            wecom_corp_id=os.getenv("WECOM_CORP_ID", ""),
            wecom_agent_id=os.getenv("WECOM_AGENT_ID", ""),
            wecom_secret=os.getenv("WECOM_SECRET", ""),
            wecom_api_base_url=(os.getenv("WECOM_API_BASE_URL", "https://qyapi.weixin.qq.com").strip() or "https://qyapi.weixin.qq.com").rstrip("/"),
            wecom_message_type=(
                os.getenv("WECOM_MESSAGE_TYPE", "news").strip().lower()
                if os.getenv("WECOM_MESSAGE_TYPE", "news").strip().lower() in {"text", "news"}
                else "news"
            ),
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

CREATE_SYNC_SITES_SQL = """
CREATE TABLE IF NOT EXISTS sync_sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sync_log_id INTEGER NOT NULL,
    sync_uuid TEXT,
    synced_at TEXT NOT NULL,
    site_name TEXT NOT NULL,
    site_domain TEXT NOT NULL
);
"""

CREATE_SYNC_SITES_LOG_INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_sync_sites_log_id
ON sync_sites (sync_log_id, site_domain, site_name);
"""

CREATE_SYNC_SITES_SYNCED_AT_INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_sync_sites_synced_at
ON sync_sites (synced_at DESC, id DESC);
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
    "notification_public_base_url",
    "wecom_corp_id",
    "wecom_agent_id",
    "wecom_secret",
    "wecom_api_base_url",
    "wecom_message_type",
    "wecom_to_user",
    "wecom_to_party",
    "wecom_to_tag",
}


def get_db_connection() -> sqlite3.Connection:
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(settings.db_path)
    connection.row_factory = sqlite3.Row
    return connection


def ensure_table_columns(connection: sqlite3.Connection, table_name: str, required_columns: dict[str, str]) -> None:
    existing_columns = {
        str(row["name"])
        for row in connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    }
    for column_name, column_sql in required_columns.items():
        if column_name in existing_columns:
            continue
        connection.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_sql}")


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
        connection.execute(CREATE_SYNC_SITES_SQL)
        connection.execute(CREATE_SYNC_SITES_LOG_INDEX_SQL)
        connection.execute(CREATE_SYNC_SITES_SYNCED_AT_INDEX_SQL)
        ensure_table_columns(
            connection,
            "sync_sites",
            {
                "site_signature": "site_signature TEXT",
            },
        )
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
        elif key == "wecom_message_type":
            settings.wecom_message_type = normalize_wecom_message_type(value)
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
        "notification_public_base_url": settings.notification_public_base_url,
        "wecom_corp_id": settings.wecom_corp_id,
        "wecom_agent_id": settings.wecom_agent_id,
        "wecom_secret": settings.wecom_secret,
        "wecom_api_base_url": settings.wecom_api_base_url,
        "wecom_message_type": settings.wecom_message_type,
        "wecom_to_user": settings.wecom_to_user,
        "wecom_to_party": settings.wecom_to_party,
        "wecom_to_tag": settings.wecom_to_tag,
    }


def build_wecom_api_url(path: str) -> str:
    return f"{settings.wecom_api_base_url.rstrip('/')}/{path.lstrip('/')}"


def normalize_wecom_message_type(value: str | None = None) -> str:
    normalized = (value or settings.wecom_message_type or "news").strip().lower()
    return normalized if normalized in {"text", "news"} else "news"


def build_monitor_page_url(request: Request, path: str) -> str:
    base = settings.notification_public_base_url or str(request.base_url).rstrip("/")
    relative_path = path if path.startswith("/") else f"/{path}"
    return f"{base}{relative_path}"


def normalize_notification_line(line: str) -> str:
    normalized = line.strip()
    if normalized.startswith("> "):
        normalized = normalized[2:]
    return normalized.replace("`", "")


def build_wecom_text_content(title: str, body_lines: list[str]) -> str:
    normalized_lines = [normalize_notification_line(line) for line in body_lines if normalize_notification_line(line)]
    return "\n".join([title, *normalized_lines])


def build_wecom_news_payload(title: str, body_lines: list[str], request: Request, target_path: str) -> dict[str, Any]:
    normalized_lines = [normalize_notification_line(line) for line in body_lines if normalize_notification_line(line)]
    description = "\n".join(normalized_lines)
    if len(description) > 220:
        description = f"{description[:217]}..."
    return {
        "articles": [
            {
                "title": title[:64],
                "description": description or "点击查看 CookieCloud Monitor 详情",
                "url": build_monitor_page_url(request, target_path),
                "picurl": build_monitor_page_url(request, "/static/wecom-card.svg"),
            }
        ]
    }


def build_wecom_news_articles(
    title: str,
    body_lines: list[str],
    request: Request,
    target_path: str,
    extra_articles: list[dict[str, str]] | None = None,
) -> list[dict[str, str]]:
    base_article = build_wecom_news_payload(title, body_lines, request, target_path)["articles"][0]
    articles = [base_article]
    if extra_articles:
        for item in extra_articles:
            description = str(item.get("description") or "").strip()
            if len(description) > 220:
                description = f"{description[:217]}..."
            articles.append(
                {
                "title": str(item.get("title") or title)[:64],
                "description": description or "点击查看 CookieCloud Monitor 详情",
                "url": str(item.get("url") or build_monitor_page_url(request, target_path)),
                "picurl": str(item.get("picurl") or build_monitor_page_url(request, "/static/wecom-card.png")),
            }
        )
    return articles[:8]


def build_wecom_message_payload(
    title: str,
    body_lines: list[str],
    request: Request,
    target_path: str,
    extra_articles: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    receiver_payload = {
        "touser": settings.wecom_to_user or None,
        "toparty": settings.wecom_to_party or None,
        "totag": settings.wecom_to_tag or None,
    }
    message_payload = {key: value for key, value in receiver_payload.items() if value}
    message_payload["agentid"] = int(settings.wecom_agent_id)
    message_payload["safe"] = 0
    message_payload["enable_duplicate_check"] = 0

    message_type = normalize_wecom_message_type()
    if message_type == "text":
        message_payload["msgtype"] = "text"
        message_payload["text"] = {"content": build_wecom_text_content(title, body_lines)}
        return message_payload

    message_payload["msgtype"] = "news"
    message_payload["news"] = {
        "articles": build_wecom_news_articles(title, body_lines, request, target_path, extra_articles=extra_articles)
    }
    return message_payload


def derive_sync_change_title(state: dict[str, Any]) -> str:
    site_changes = state.get("site_changes") or {}
    change_types = list(site_changes.get("change_types") or [])
    if state.get("is_first_sync"):
        return "CookieCloud 首次同步"
    if change_types == ["上传"]:
        return "CookieCloud 站点上传"
    if change_types == ["更新"]:
        return "CookieCloud 站点更新"
    if change_types == ["删除"]:
        return "CookieCloud 站点删除"
    if change_types:
        return "CookieCloud 站点变更"
    if state.get("cookie_delta") is not None and state["cookie_delta"] > 0:
        return "CookieCloud CK 数量增加"
    if state.get("cookie_delta") is not None and state["cookie_delta"] < 0:
        return "CookieCloud CK 数量减少"
    if state.get("payload_changed"):
        return "CookieCloud 同步内容更新"
    return "CookieCloud 同步提醒"


def build_sync_notification_lines(sync_uuid: str, state: dict[str, Any], request: Request) -> list[str]:
    site_changes = state.get("site_changes") or {}
    body_lines = [
        f"> 客户端类型：`{state.get('client_type') or '未知客户端'}`",
        f"> UUID：`{sync_uuid}`",
        f"> 时间：`{now_local().isoformat(timespec='seconds')}`",
        f"> 来源 IP：`{client_ip_from_request(request) or '-'}`",
        f"> 变更类型：`{site_changes.get('change_type_label') or '无站点变化'}`",
        f"> 站点变更汇总：`{site_changes.get('summary_line') or '上传 0 / 更新 0 / 删除 0'}`",
        f"> 当前 CK 数：`{state['cookie_count'] if state['cookie_count'] is not None else '-'}`",
        f"> 站点数：`{state['site_count'] if state['site_count'] is not None else '-'}`",
    ]
    if state.get("previous_cookie_count") is not None:
        body_lines.append(f"> 变更前 CK 数：`{state['previous_cookie_count']}`")
    if state.get("cookie_delta") is not None:
        sign = "+" if state["cookie_delta"] > 0 else ""
        body_lines.append(f"> 变化值：`{sign}{state['cookie_delta']}`")

    for label, key in (("上传站点", "uploaded_sites"), ("更新站点", "updated_sites"), ("删除站点", "deleted_sites")):
        site_names = list(site_changes.get(key) or [])
        if not site_names:
            continue
        body_lines.append(f"> {label}：`{format_site_name_list(site_names, limit=8)}`")
    return body_lines


def build_sync_news_articles(state: dict[str, Any], request: Request, target_path: str) -> list[dict[str, str]]:
    site_changes = state.get("site_changes") or {}
    extra_articles: list[dict[str, str]] = []
    for title, key in (("上传站点", "uploaded_sites"), ("更新站点", "updated_sites"), ("删除站点", "deleted_sites")):
        site_names = list(site_changes.get(key) or [])
        if not site_names:
            continue
        extra_articles.append(
            {
                "title": f"{title} · {len(site_names)}",
                "description": format_site_name_list(site_names, limit=8),
                "url": build_monitor_page_url(request, target_path),
            }
        )
    return extra_articles


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


def decode_request_body_for_inspection(raw_body: bytes, content_encoding: str) -> bytes:
    if not raw_body:
        return raw_body

    encoding = (content_encoding or "").lower().strip()
    if not encoding or encoding == "identity":
        return raw_body

    try:
        if encoding == "gzip":
            return gzip.decompress(raw_body)
        if encoding == "deflate":
            return zlib.decompress(raw_body)
        if encoding == "x-gzip":
            return gzip.decompress(raw_body)
    except Exception:
        return raw_body

    return raw_body


def derive_cookiecloud_passphrases(sync_uuid: str) -> list[str]:
    if not sync_uuid or not settings.cookiecloud_sync_password:
        return []

    digest = hashlib.md5(f"{sync_uuid}-{settings.cookiecloud_sync_password}".encode("utf-8")).hexdigest()
    candidates = [digest[:16], digest]
    seen: set[str] = set()
    return [item for item in candidates if item and not (item in seen or seen.add(item))]


def evp_bytes_to_key(passphrase: bytes, salt: bytes, *, key_length: int = 32, iv_length: int = 16) -> tuple[bytes, bytes]:
    material = b""
    block = b""
    while len(material) < key_length + iv_length:
        block = hashlib.md5(block + passphrase + salt).digest()
        material += block
    return material[:key_length], material[key_length : key_length + iv_length]


def decrypt_cookiecloud_payload(sync_uuid: str, encrypted_payload: str) -> Any | None:
    passphrases = derive_cookiecloud_passphrases(sync_uuid)
    if not passphrases or not encrypted_payload:
        return None

    try:
        raw = base64.b64decode(encrypted_payload)
        if len(raw) <= 16 or not raw.startswith(b"Salted__"):
            return None
        salt = raw[8:16]
        ciphertext = raw[16:]
    except Exception:
        return None

    for passphrase in passphrases:
        try:
            key, iv = evp_bytes_to_key(passphrase.encode("utf-8"), salt)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return json.loads(plaintext.decode("utf-8"))
        except Exception:
            continue

    LOGGER.warning("Unable to decrypt CookieCloud payload for sync_uuid=%s", sync_uuid)
    return None


def maybe_json_bytes(raw: bytes) -> Any | None:
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def has_meaningful_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict, tuple, set)):
        return bool(value)
    return True


def extract_candidate(form_data: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = form_data.get(key)
        if value:
            return normalize_form_value(value)
    return None


def extract_value_from_payload(payload: Any, *keys: str) -> Any | None:
    if isinstance(payload, dict):
        for key in keys:
            value = payload.get(key)
            if has_meaningful_value(value):
                return value
        for value in payload.values():
            nested = extract_value_from_payload(value, *keys)
            if has_meaningful_value(nested):
                return nested
        return None

    if isinstance(payload, list):
        for item in payload:
            nested = extract_value_from_payload(item, *keys)
            if has_meaningful_value(nested):
                return nested

    return None


def extract_candidate_from_payload(payload: Any, *keys: str) -> str | None:
    value = extract_value_from_payload(payload, *keys)
    if not has_meaningful_value(value):
        return None
    return normalize_form_value(value)


def extract_candidate_from_raw_body(raw_body: bytes, content_type: str, *keys: str) -> str | None:
    if "application/json" not in content_type.lower() or not raw_body:
        return None

    payload = maybe_json_bytes(raw_body)
    if payload is None:
        return None

    return extract_candidate_from_payload(payload, *keys)


def extract_structured_sync_payload(
    form_data: dict[str, Any],
    raw_body: bytes,
    content_type: str,
    sync_uuid: str | None = None,
) -> Any | None:
    raw_payload = maybe_json_bytes(raw_body) if "application/json" in content_type.lower() else None
    candidate_keys = ("cookie_data", "data", "payload", "local_storage_data")

    for source in (form_data, raw_payload):
        if not source:
            continue

        candidate = extract_value_from_payload(source, *candidate_keys)
        for value in (candidate, source):
            if isinstance(value, str):
                parsed = parse_json_text(value)
                if parsed is not None:
                    return parsed
            elif isinstance(value, (dict, list)) and iter_cookie_like_entries(value):
                return value

    if sync_uuid:
        encrypted_payload = None
        for source in (form_data, raw_payload):
            if not source:
                continue
            encrypted_payload = extract_candidate_from_payload(source, "encrypted")
            if encrypted_payload:
                break

        if encrypted_payload:
            decrypted_payload = decrypt_cookiecloud_payload(sync_uuid, encrypted_payload)
            if isinstance(decrypted_payload, (dict, list)):
                return decrypted_payload

    return None


def normalize_site_domain(value: Any) -> str:
    raw = normalize_form_value(value).strip()
    if not raw:
        return ""

    if "://" in raw:
        parsed = urlparse(raw)
        raw = parsed.hostname or parsed.netloc or raw

    raw = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if ":" in raw and raw.count(":") == 1:
        raw = raw.split(":", 1)[0]
    return raw.lstrip(".").strip().lower()


def derive_site_name(entry: dict[str, Any], site_domain: str) -> str:
    for key in ("site_name", "siteName", "title", "site", "host", "domain"):
        value = normalize_form_value(entry.get(key)).strip()
        if value:
            if key in {"host", "domain"}:
                return normalize_site_domain(value) or site_domain or value
            return value
    return site_domain or "未知站点"


def normalize_site_entry_for_signature(entry: dict[str, Any], site_domain: str) -> dict[str, Any]:
    normalized: dict[str, Any] = {
        "site_domain": site_domain,
        "name": normalize_form_value(entry.get("name")).strip(),
        "domain": normalize_site_domain(entry.get("domain") or site_domain),
        "path": normalize_form_value(entry.get("path")).strip() or "/",
        "value": normalize_form_value(entry.get("value")),
        "expirationDate": normalize_form_value(entry.get("expirationDate") or entry.get("expires") or entry.get("expiration")),
        "secure": bool(entry.get("secure")),
        "httpOnly": bool(entry.get("httpOnly") or entry.get("httponly")),
        "sameSite": normalize_form_value(entry.get("sameSite") or entry.get("same_site")).strip().lower(),
    }
    if not normalized["name"]:
        normalized["name"] = normalize_form_value(entry.get("key")).strip()
    return normalized


def build_site_signature(entries: list[dict[str, Any]]) -> str:
    ordered_entries = sorted(
        entries,
        key=lambda item: (
            normalize_form_value(item.get("name")),
            normalize_form_value(item.get("domain")),
            normalize_form_value(item.get("path")),
            normalize_form_value(item.get("value")),
        ),
    )
    payload = json.dumps(ordered_entries, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def extract_sync_site_snapshots(
    form_data: dict[str, Any],
    raw_body: bytes,
    content_type: str,
    sync_uuid: str | None = None,
) -> list[dict[str, str]]:
    payload = extract_structured_sync_payload(form_data, raw_body, content_type, sync_uuid)
    if payload is None:
        return []

    grouped: dict[str, dict[str, Any]] = {}
    for entry, domain_hint in collect_cookie_like_entries(payload):
        site_domain = normalize_site_domain(
            entry.get("domain") or entry.get("host") or entry.get("site") or entry.get("url") or domain_hint
        )
        if not site_domain:
            continue
        site_name = derive_site_name(entry, site_domain)[:120]
        bucket = grouped.setdefault(
            site_domain,
            {
                "site_name": site_name,
                "site_domain": site_domain[:255],
                "entries": [],
            },
        )
        if bucket["site_name"] == bucket["site_domain"] and site_name != bucket["site_domain"]:
            bucket["site_name"] = site_name
        bucket["entries"].append(normalize_site_entry_for_signature(entry, site_domain))

    snapshots: list[dict[str, str]] = []
    for bucket in grouped.values():
        snapshots.append(
            {
                "site_name": str(bucket["site_name"])[:120],
                "site_domain": str(bucket["site_domain"])[:255],
                "site_signature": build_site_signature(list(bucket["entries"])),
            }
        )
    return sorted(snapshots, key=lambda item: (item["site_domain"], item["site_name"]))


def extract_sync_sites(
    form_data: dict[str, Any],
    raw_body: bytes,
    content_type: str,
    sync_uuid: str | None = None,
) -> list[dict[str, str]]:
    snapshots = extract_sync_site_snapshots(form_data, raw_body, content_type, sync_uuid)
    return [{"site_name": item["site_name"], "site_domain": item["site_domain"]} for item in snapshots]


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


def detect_client_type(
    request: Request,
    form_data: dict[str, Any],
    raw_body: bytes,
    content_type: str,
) -> str:
    candidate_texts: list[str] = []
    raw_payload = maybe_json_bytes(raw_body) if "application/json" in content_type.lower() else None

    for key in ("client_type", "clientType", "source", "platform", "from", "app", "appType"):
        if form_data.get(key):
            candidate_texts.append(normalize_form_value(form_data[key]).lower())
        if isinstance(raw_payload, dict):
            payload_value = extract_candidate_from_payload(raw_payload, key)
            if payload_value:
                candidate_texts.append(payload_value.lower())

    user_agent = (request.headers.get("user-agent") or "").lower()
    candidate_texts.append(user_agent)

    if any(
        token in text
        for text in candidate_texts
        for token in ("miniprogram", "mini program", "mini_program", "micromessenger", "wxwork")
    ):
        return "MP"
    if any(
        token in text
        for text in candidate_texts
        for token in ("extension", "chrome", "edg", "firefox", "mozilla", "safari")
    ):
        return "浏览器插件"
    return "未知客户端"


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


def collect_cookie_like_entries(value: Any, inherited_domain: str = "") -> list[tuple[dict[str, Any], str]]:
    matches: list[tuple[dict[str, Any], str]] = []

    if isinstance(value, dict):
        current_domain = normalize_site_domain(
            value.get("domain") or value.get("host") or value.get("site") or value.get("url") or inherited_domain
        )
        if {"name", "value"}.issubset(value.keys()):
            matches.append((value, current_domain or inherited_domain))

        for key, item in value.items():
            next_domain = current_domain or inherited_domain
            key_domain = normalize_site_domain(key)
            if key_domain:
                next_domain = key_domain
            matches.extend(collect_cookie_like_entries(item, next_domain))
    elif isinstance(value, list):
        for item in value:
            matches.extend(collect_cookie_like_entries(item, inherited_domain))

    return matches


def iter_cookie_like_entries(value: Any) -> list[dict[str, Any]]:
    return [entry for entry, _domain_hint in collect_cookie_like_entries(value)]


def extract_sync_counts(
    form_data: dict[str, Any],
    raw_body: bytes,
    content_type: str,
    sync_uuid: str | None = None,
) -> tuple[int | None, int | None]:
    payload = extract_structured_sync_payload(form_data, raw_body, content_type, sync_uuid)
    if payload is None:
        return None, None

    cookie_entries = collect_cookie_like_entries(payload)
    cookies = [entry for entry, _domain_hint in cookie_entries]
    if not cookies:
        return None, None

    domains = {
        normalize_site_domain(
            item.get("domain") or item.get("host") or item.get("site") or item.get("url") or domain_hint
        )
        for item, domain_hint in cookie_entries
        if item.get("domain") or item.get("host") or item.get("site") or item.get("url") or domain_hint
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
    cache_key = f"{settings.wecom_api_base_url}|{settings.wecom_corp_id}|{settings.wecom_secret}"
    cached_token = WECOM_TOKEN_CACHE.get("access_token")
    if (
        cached_token
        and WECOM_TOKEN_CACHE.get("cache_key") == cache_key
        and now_ts < float(WECOM_TOKEN_CACHE.get("expires_at", 0))
    ):
        return str(cached_token)

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            build_wecom_api_url("/cgi-bin/gettoken"),
            params={"corpid": settings.wecom_corp_id, "corpsecret": settings.wecom_secret},
        )
        response.raise_for_status()
        payload = response.json()

    if payload.get("errcode") != 0:
        raise RuntimeError(payload.get("errmsg") or "获取企业微信 access_token 失败")

    expires_in = int(payload.get("expires_in", 7200))
    token = str(payload["access_token"])
    WECOM_TOKEN_CACHE["access_token"] = token
    WECOM_TOKEN_CACHE["cache_key"] = cache_key
    WECOM_TOKEN_CACHE["expires_at"] = now_ts + max(expires_in - 120, 60)
    return token


async def send_wecom_notification(
    title: str,
    body_lines: list[str],
    request: Request,
    target_path: str = "/dashboard",
    *,
    extra_articles: list[dict[str, str]] | None = None,
) -> None:
    if not settings.wecom_enabled:
        return

    message_payload = build_wecom_message_payload(
        title,
        body_lines,
        request,
        target_path,
        extra_articles=extra_articles,
    )
    if not message_payload:
        return

    token = await get_wecom_access_token()

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            build_wecom_api_url("/cgi-bin/message/send"),
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
    await send_wecom_notification(
        "CookieCloud 控制台登录提醒",
        [
            f"> 登录账号：`{username}`",
            f"> 时间：`{now_local().isoformat(timespec='seconds')}`",
            f"> IP：`{client_ip_from_request(request) or '-'}`",
            f"> UA：`{(request.headers.get('user-agent') or '-')[:180]}`",
        ],
        request,
        "/dashboard",
    )


async def send_sync_notification(sync_uuid: str, state: dict[str, Any], request: Request, sync_log_id: int | None = None) -> None:
    if not settings.wecom_enabled:
        return

    site_changes = state.get("site_changes") or {}
    if not (
        state.get("is_first_sync")
        or state.get("payload_changed")
        or state.get("cookie_delta") is not None
        or site_changes.get("uploaded_count")
        or site_changes.get("updated_count")
        or site_changes.get("deleted_count")
    ):
        return

    title = derive_sync_change_title(state)
    body_lines = build_sync_notification_lines(sync_uuid, state, request)
    target_path = f"/logs/{sync_log_id}" if sync_log_id else f"/dashboard?sync_uuid={quote(sync_uuid)}"
    await send_wecom_notification(
        title,
        body_lines,
        request,
        target_path,
        extra_articles=build_sync_news_articles(state, request, target_path),
    )


async def send_test_notification(request: Request) -> None:
    await send_wecom_notification(
        "CookieCloud 测试通知",
        [
            "> 这是一条来自 CookieCloud Monitor 的测试消息。",
            f"> 时间：`{now_local().isoformat(timespec='seconds')}`",
            f"> 上游地址：`{settings.cookiecloud_target_url}`",
            f"> 接收对象：`{notification_target_summary()}`",
            f"> 触发人：`{request.session.get('username') or settings.dashboard_username or 'unknown'}`",
        ],
        request,
        "/settings",
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
) -> dict[str, Any]:
    timestamp = now_local()
    with get_db_connection() as connection:
        cursor = connection.execute(
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
    return {"id": int(cursor.lastrowid), "occurred_at": timestamp.isoformat(timespec="seconds")}


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


def record_sync_sites(
    *,
    sync_log_id: int,
    sync_uuid: str | None,
    synced_at: str,
    sites: list[dict[str, str]],
) -> None:
    if not sites:
        return

    with get_db_connection() as connection:
        connection.executemany(
            """
            INSERT INTO sync_sites (sync_log_id, sync_uuid, synced_at, site_name, site_domain, site_signature)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    sync_log_id,
                    sync_uuid,
                    synced_at,
                    item["site_name"],
                    item["site_domain"],
                    item.get("site_signature"),
                )
                for item in sites
            ],
        )
        connection.commit()


def fetch_latest_site_snapshot_map(sync_uuid: str | None) -> dict[str, dict[str, Any]]:
    normalized_sync_uuid = (sync_uuid or "").strip()
    if not normalized_sync_uuid:
        return {}

    with get_db_connection() as connection:
        rows = connection.execute(
            """
            WITH latest_site AS (
                SELECT
                    site_name,
                    site_domain,
                    site_signature,
                    synced_at,
                    ROW_NUMBER() OVER (
                        PARTITION BY COALESCE(sync_uuid, 'unknown'), site_domain
                        ORDER BY synced_at DESC, id DESC
                    ) AS rn
                FROM sync_sites
                WHERE COALESCE(sync_uuid, 'unknown') = ?
            )
            SELECT site_name, site_domain, site_signature, synced_at
            FROM latest_site
            WHERE rn = 1
            """,
            (normalized_sync_uuid,),
        ).fetchall()
    return {str(row["site_domain"]): dict(row) for row in rows}


def render_site_label(site: dict[str, Any]) -> str:
    site_name = str(site.get("site_name") or "").strip()
    site_domain = str(site.get("site_domain") or "").strip()
    if site_name and site_domain and site_name != site_domain:
        return f"{site_name} ({site_domain})"
    return site_name or site_domain or "未知站点"


def format_site_name_list(site_names: list[str], *, limit: int = 8) -> str:
    if not site_names:
        return "-"
    if len(site_names) <= limit:
        return "、".join(site_names)
    return f"{'、'.join(site_names[:limit])} 等 {len(site_names)} 个站点"


def summarize_site_changes(sync_uuid: str | None, current_sites: list[dict[str, str]]) -> dict[str, Any]:
    previous_map = fetch_latest_site_snapshot_map(sync_uuid)
    current_map = {str(item["site_domain"]): item for item in current_sites if item.get("site_domain")}

    uploaded_sites = [current_map[key] for key in current_map.keys() - previous_map.keys()]
    deleted_sites = [previous_map[key] for key in previous_map.keys() - current_map.keys()]
    updated_sites: list[dict[str, Any]] = []
    unchanged_count = 0

    for site_domain in current_map.keys() & previous_map.keys():
        current_item = current_map[site_domain]
        previous_item = previous_map[site_domain]
        previous_signature = str(previous_item.get("site_signature") or "").strip()
        current_signature = str(current_item.get("site_signature") or "").strip()
        previous_name = str(previous_item.get("site_name") or "").strip()
        current_name = str(current_item.get("site_name") or "").strip()
        if previous_signature and current_signature:
            if previous_signature != current_signature or previous_name != current_name:
                updated_sites.append(current_item)
            else:
                unchanged_count += 1
            continue
        if previous_name != current_name:
            updated_sites.append(current_item)
        else:
            unchanged_count += 1

    uploaded_labels = [render_site_label(item) for item in sorted(uploaded_sites, key=render_site_label)]
    updated_labels = [render_site_label(item) for item in sorted(updated_sites, key=render_site_label)]
    deleted_labels = [render_site_label(item) for item in sorted(deleted_sites, key=render_site_label)]

    change_types = [
        label
        for label, count in (("上传", len(uploaded_labels)), ("更新", len(updated_labels)), ("删除", len(deleted_labels)))
        if count
    ]

    return {
        "uploaded_sites": uploaded_labels,
        "updated_sites": updated_labels,
        "deleted_sites": deleted_labels,
        "uploaded_count": len(uploaded_labels),
        "updated_count": len(updated_labels),
        "deleted_count": len(deleted_labels),
        "unchanged_count": unchanged_count,
        "change_types": change_types,
        "change_type_label": " / ".join(change_types) if change_types else "无站点变化",
        "summary_line": (
            f"上传 {len(uploaded_labels)} / 更新 {len(updated_labels)} / 删除 {len(deleted_labels)}"
        ),
    }


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
    content_encoding = request.headers.get("content-encoding", "")
    inspection_body = decode_request_body_for_inspection(raw_body, content_encoding)
    form_map: dict[str, Any] = {}
    if content_encoding and content_encoding.lower() != "identity":
        form_map = parse_form_map_from_raw_body(inspection_body, content_type)
    else:
        try:
            form = await request.form()
            form_map = dict(form.multi_items())
        except Exception:
            form_map = parse_form_map_from_raw_body(inspection_body, content_type)
    sync_uuid = extract_candidate(form_map, "uuid", "userUUID", "user_uuid", "id")
    if not sync_uuid:
        sync_uuid = extract_candidate_from_raw_body(inspection_body, content_type, "uuid", "userUUID", "user_uuid", "id")
    payload_size, payload_hash = build_payload_digest(form_map)
    if payload_size == 0 and raw_body:
        payload_size = len(raw_body)
        payload_hash = hashlib.sha256(raw_body).hexdigest()
    cookie_count, site_count = extract_sync_counts(form_map, inspection_body, content_type, sync_uuid)
    sync_sites = extract_sync_site_snapshots(form_map, inspection_body, content_type, sync_uuid)
    client_type = detect_client_type(request, form_map, inspection_body, content_type)
    start_time = time.perf_counter()
    request_debug = build_request_debug_summary(
        content_type=content_type,
        payload_size=payload_size,
        payload_hash=payload_hash,
        form_map=form_map,
        sync_uuid=sync_uuid,
        raw_body=inspection_body,
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
            sync_state["client_type"] = client_type
            sync_state["site_changes"] = summarize_site_changes(sync_uuid, sync_sites)
        sync_log = record_sync_log(
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
        if outcome == "success" and sync_sites:
            record_sync_sites(
                sync_log_id=sync_log["id"],
                sync_uuid=sync_uuid,
                synced_at=sync_log["occurred_at"],
                sites=sync_sites,
            )
        if outcome == "success" and not sync_uuid:
            log_runtime_event(
                level="warning",
                source="proxy_update",
                message=f"Upload succeeded but sync UUID was not identified; {request_debug}",
                request=request,
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
                await send_sync_notification(sync_uuid, sync_state, request, sync_log["id"])
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
    content_encoding = request.headers.get("content-encoding", "")
    inspection_body: bytes | None = None

    if request.method == "POST":
        raw_body = await request.body()
        content = raw_body
        inspection_body = decode_request_body_for_inspection(raw_body, content_encoding)
        headers = filtered_request_headers(request.headers)
        if content_encoding and content_encoding.lower() != "identity":
            form_map = parse_form_map_from_raw_body(inspection_body, content_type)
        else:
            try:
                form = await request.form()
                form_map = dict(form.multi_items())
            except Exception:
                form_map = parse_form_map_from_raw_body(inspection_body or raw_body, content_type)

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
        raw_body=inspection_body or content,
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
        logs = [dict(row) for row in rows]

        if not logs:
            return []

        log_ids = [int(item["id"]) for item in logs]
        placeholders = ",".join("?" for _ in log_ids)
        preview_rows = connection.execute(
            f"""
            SELECT sync_log_id, site_domain
            FROM sync_sites
            WHERE sync_log_id IN ({placeholders})
            ORDER BY site_domain ASC, id ASC
            """,
            log_ids,
        ).fetchall()

    preview_map: dict[int, dict[str, Any]] = {}
    for row in preview_rows:
        log_id = int(row["sync_log_id"])
        bucket = preview_map.setdefault(log_id, {"count": 0, "domains": []})
        bucket["count"] += 1
        if len(bucket["domains"]) < 3:
            bucket["domains"].append(str(row["site_domain"]))

    for item in logs:
        preview = preview_map.get(int(item["id"]), {"count": 0, "domains": []})
        item["site_count"] = int(preview["count"])
        item["site_preview"] = list(preview["domains"])

    return logs


def fetch_sync_sites_for_log(log_id: int) -> list[dict[str, Any]]:
    with get_db_connection() as connection:
        rows = connection.execute(
            """
            SELECT sync_log_id, sync_uuid, synced_at, site_name, site_domain
            FROM sync_sites
            WHERE sync_log_id = ?
            ORDER BY site_domain ASC, site_name ASC, id ASC
            """,
            (log_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def derive_site_status(
    *,
    site_synced_at: str,
    latest_uuid_outcome: str | None,
    latest_uuid_log_at: str | None,
) -> tuple[str, str]:
    if latest_uuid_outcome and latest_uuid_log_at and latest_uuid_log_at >= site_synced_at:
        return latest_uuid_outcome, latest_uuid_log_at
    return "success", site_synced_at


def fetch_site_catalog(
    *,
    sync_uuid: str | None = None,
    keyword: str | None = None,
    outcome: str | None = None,
) -> dict[str, Any]:
    with get_db_connection() as connection:
        rows = connection.execute(
            """
            WITH latest_site AS (
                SELECT
                    id,
                    sync_log_id,
                    COALESCE(sync_uuid, 'unknown') AS sync_uuid,
                    synced_at,
                    site_name,
                    site_domain,
                    ROW_NUMBER() OVER (
                        PARTITION BY COALESCE(sync_uuid, 'unknown'), site_domain
                        ORDER BY synced_at DESC, id DESC
                    ) AS rn
                FROM sync_sites
            ),
            latest_uuid_log AS (
                SELECT
                    id,
                    COALESCE(sync_uuid, 'unknown') AS sync_uuid,
                    occurred_at,
                    outcome,
                    http_status,
                    ROW_NUMBER() OVER (
                        PARTITION BY COALESCE(sync_uuid, 'unknown')
                        ORDER BY occurred_at DESC, id DESC
                    ) AS rn
                FROM sync_logs
            )
            SELECT
                latest_site.sync_log_id,
                latest_site.sync_uuid,
                latest_site.synced_at,
                latest_site.site_name,
                latest_site.site_domain,
                latest_uuid_log.id AS latest_log_id,
                latest_uuid_log.occurred_at AS latest_log_at,
                latest_uuid_log.outcome AS latest_log_outcome,
                latest_uuid_log.http_status AS latest_http_status
            FROM latest_site
            LEFT JOIN latest_uuid_log
                ON latest_uuid_log.sync_uuid = latest_site.sync_uuid
               AND latest_uuid_log.rn = 1
            WHERE latest_site.rn = 1
            ORDER BY latest_site.synced_at DESC, latest_site.site_domain ASC
            """
        ).fetchall()

    items: list[dict[str, Any]] = []
    lowered_keyword = (keyword or "").strip().lower()
    normalized_sync_uuid = (sync_uuid or "").strip()
    normalized_outcome = (outcome or "").strip()

    for row in rows:
        item = dict(row)
        latest_status, latest_time = derive_site_status(
            site_synced_at=str(item["synced_at"]),
            latest_uuid_outcome=str(item["latest_log_outcome"]) if item["latest_log_outcome"] else None,
            latest_uuid_log_at=str(item["latest_log_at"]) if item["latest_log_at"] else None,
        )
        item["latest_status"] = latest_status
        item["latest_status_label"] = "成功" if latest_status == "success" else "失败"
        item["latest_sync_at"] = latest_time
        item["detail_log_id"] = item["latest_log_id"] or item["sync_log_id"]

        if normalized_sync_uuid and item["sync_uuid"] != normalized_sync_uuid:
            continue
        if normalized_outcome and latest_status != normalized_outcome:
            continue
        if lowered_keyword:
            haystacks = (
                str(item["site_name"]).lower(),
                str(item["site_domain"]).lower(),
                str(item["sync_uuid"]).lower(),
            )
            if not any(lowered_keyword in value for value in haystacks):
                continue

        items.append(item)

    summary = {
        "total_sites": len(items),
        "success_sites": sum(1 for item in items if item["latest_status"] == "success"),
        "failed_sites": sum(1 for item in items if item["latest_status"] == "failed"),
        "tracked_uuids": len({str(item["sync_uuid"]) for item in items}),
    }
    return {"items": items, "summary": summary}


def fetch_known_sync_uuids(sync_uuid: str | None = None) -> list[str]:
    normalized_sync_uuid = (sync_uuid or "").strip()
    if normalized_sync_uuid:
        return [normalized_sync_uuid]

    with get_db_connection() as connection:
        state_rows = connection.execute(
            """
            SELECT sync_uuid
            FROM sync_states
            WHERE sync_uuid IS NOT NULL AND sync_uuid != ''
            ORDER BY last_sync_at DESC
            """
        ).fetchall()
        log_rows = connection.execute(
            """
            SELECT sync_uuid, MAX(occurred_at) AS last_seen_at
            FROM sync_logs
            WHERE sync_uuid IS NOT NULL AND sync_uuid != '' AND sync_uuid != 'unknown'
            GROUP BY sync_uuid
            ORDER BY last_seen_at DESC
            """
        ).fetchall()

    ordered: list[str] = []
    seen: set[str] = set()
    for rows in (state_rows, log_rows):
        for row in rows:
            value = str(row["sync_uuid"])
            if not value or value == "unknown" or value in seen:
                continue
            seen.add(value)
            ordered.append(value)
    return ordered


def fetch_latest_uuid_status_map(sync_uuids: list[str]) -> dict[str, dict[str, Any]]:
    if not sync_uuids:
        return {}

    placeholders = ",".join("?" for _ in sync_uuids)
    with get_db_connection() as connection:
        rows = connection.execute(
            f"""
            WITH latest_log AS (
                SELECT
                    id,
                    COALESCE(sync_uuid, 'unknown') AS sync_uuid,
                    occurred_at,
                    outcome,
                    http_status,
                    ROW_NUMBER() OVER (
                        PARTITION BY COALESCE(sync_uuid, 'unknown')
                        ORDER BY occurred_at DESC, id DESC
                    ) AS rn
                FROM sync_logs
                WHERE COALESCE(sync_uuid, 'unknown') IN ({placeholders})
            )
            SELECT sync_uuid, occurred_at, outcome, http_status, id
            FROM latest_log
            WHERE rn = 1
            """,
            sync_uuids,
        ).fetchall()
    return {str(row["sync_uuid"]): dict(row) for row in rows}


def fetch_latest_recorded_sites_by_uuid(sync_uuids: list[str]) -> dict[str, list[dict[str, Any]]]:
    if not sync_uuids:
        return {}

    placeholders = ",".join("?" for _ in sync_uuids)
    with get_db_connection() as connection:
        rows = connection.execute(
            f"""
            WITH latest_site AS (
                SELECT
                    sync_uuid,
                    synced_at,
                    site_name,
                    site_domain,
                    ROW_NUMBER() OVER (
                        PARTITION BY COALESCE(sync_uuid, 'unknown'), site_domain
                        ORDER BY synced_at DESC, id DESC
                    ) AS rn
                FROM sync_sites
                WHERE COALESCE(sync_uuid, 'unknown') IN ({placeholders})
            )
            SELECT sync_uuid, synced_at, site_name, site_domain
            FROM latest_site
            WHERE rn = 1
            ORDER BY synced_at DESC, site_domain ASC
            """,
            sync_uuids,
        ).fetchall()

    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row["sync_uuid"]), []).append(dict(row))
    return grouped


async def fetch_live_sites_for_uuid(sync_uuid: str) -> list[dict[str, str]]:
    try:
        params = {"password": settings.cookiecloud_sync_password} if settings.cookiecloud_sync_password else None
        upstream_response = await forward_to_cookiecloud(method="GET", path=f"/get/{sync_uuid}", params=params)
    except Exception as exc:
        LOGGER.warning("Live site fetch failed for sync_uuid=%s error=%s", sync_uuid, exc)
        return []

    if not (200 <= upstream_response.status_code < 300):
        LOGGER.warning(
            "Live site fetch returned non-2xx for sync_uuid=%s status=%s content_type=%s",
            sync_uuid,
            upstream_response.status_code,
            upstream_response.headers.get("content-type", "-"),
        )
        return []

    sites = extract_sync_sites(
        {},
        upstream_response.content,
        upstream_response.headers.get("content-type", ""),
        sync_uuid,
    )
    if sites:
        return sites

    excerpt = parse_response_excerpt(upstream_response.content) or "-"
    log_runtime_event(
        level="warning",
        source="live_site_catalog",
        message=(
            f"Unable to extract sites from upstream /get/{sync_uuid}; "
            f"content_type={upstream_response.headers.get('content-type', '-')}; "
            f"password_configured={'yes' if settings.cookiecloud_sync_password else 'no'}; "
            f"response_excerpt={excerpt}"
        ),
        sync_uuid=sync_uuid,
    )
    return []


async def build_live_site_catalog(
    *,
    sync_uuid: str | None = None,
    keyword: str | None = None,
    outcome: str | None = None,
) -> dict[str, Any]:
    sync_uuids = fetch_known_sync_uuids(sync_uuid)
    if not sync_uuids:
        return {"items": [], "summary": {"total_sites": 0, "success_sites": 0, "failed_sites": 0, "tracked_uuids": 0}}

    latest_status_map = fetch_latest_uuid_status_map(sync_uuids)
    recorded_site_map = fetch_latest_recorded_sites_by_uuid(sync_uuids)
    semaphore = asyncio.Semaphore(6)

    async def worker(uuid_value: str) -> tuple[str, list[dict[str, str]]]:
        async with semaphore:
            live_sites = await fetch_live_sites_for_uuid(uuid_value)
        return uuid_value, live_sites

    live_results = await asyncio.gather(*(worker(item) for item in sync_uuids))
    live_site_map = {uuid_value: sites for uuid_value, sites in live_results}

    items: list[dict[str, Any]] = []
    lowered_keyword = (keyword or "").strip().lower()
    normalized_outcome = (outcome or "").strip()

    for uuid_value in sync_uuids:
        latest_log = latest_status_map.get(uuid_value, {})
        latest_outcome = str(latest_log.get("outcome") or "success")
        latest_time = str(latest_log.get("occurred_at") or "")
        site_rows = live_site_map.get(uuid_value) or recorded_site_map.get(uuid_value, [])

        for site in site_rows:
            item = {
                "sync_uuid": uuid_value,
                "site_name": str(site["site_name"]),
                "site_domain": str(site["site_domain"]),
                "latest_status": latest_outcome,
                "latest_status_label": "成功" if latest_outcome == "success" else "失败",
                "latest_sync_at": latest_time or str(site.get("synced_at") or "-"),
                "synced_at": str(site.get("synced_at") or latest_time or "-"),
                "detail_log_id": latest_log.get("id"),
            }

            if normalized_outcome and item["latest_status"] != normalized_outcome:
                continue
            if lowered_keyword:
                haystacks = (
                    item["site_name"].lower(),
                    item["site_domain"].lower(),
                    item["sync_uuid"].lower(),
                )
                if not any(lowered_keyword in value for value in haystacks):
                    continue

            items.append(item)

    summary = {
        "total_sites": len(items),
        "success_sites": sum(1 for item in items if item["latest_status"] == "success"),
        "failed_sites": sum(1 for item in items if item["latest_status"] == "failed"),
        "tracked_uuids": len(sync_uuids),
    }
    return {"items": items, "summary": summary}


async def refresh_live_site_catalog(sync_uuid: str | None = None) -> dict[str, Any]:
    sync_uuids = fetch_known_sync_uuids(sync_uuid)
    if not sync_uuids:
        log_runtime_event(
            level="warning",
            source="live_site_catalog",
            message="Manual site refresh skipped because no tracked UUIDs were found.",
        )
        return {
            "ok": False,
            "message": "没有找到可刷新的 UUID。请先确认同步日志里已经出现过有效 UUID。",
            "uuid_count": 0,
            "site_count": 0,
        }

    semaphore = asyncio.Semaphore(6)

    async def worker(uuid_value: str) -> tuple[str, list[dict[str, str]]]:
        async with semaphore:
            return uuid_value, await fetch_live_sites_for_uuid(uuid_value)

    results = await asyncio.gather(*(worker(item) for item in sync_uuids))
    site_count = sum(len(sites) for _uuid, sites in results)
    success_uuids = [uuid_value for uuid_value, sites in results if sites]
    failed_uuids = [uuid_value for uuid_value, sites in results if not sites]

    log_runtime_event(
        level="info" if success_uuids else "warning",
        source="live_site_catalog",
        message=(
            f"Manual site refresh finished; tracked_uuids={len(sync_uuids)}; "
            f"uuids_with_sites={len(success_uuids)}; total_sites={site_count}; "
            f"empty_uuids={', '.join(failed_uuids[:10]) if failed_uuids else '-'}"
        ),
    )

    if success_uuids:
        return {
            "ok": True,
            "message": f"已刷新 {len(sync_uuids)} 个 UUID，识别到 {site_count} 个站点。",
            "uuid_count": len(sync_uuids),
            "site_count": site_count,
        }

    return {
        "ok": False,
        "message": "已触发刷新，但仍未识别出任何站点。请立刻查看运行日志中 source=live_site_catalog 的最新记录。",
        "uuid_count": len(sync_uuids),
        "site_count": 0,
    }


async def build_log_site_preview_map(sync_uuids: list[str]) -> dict[str, dict[str, Any]]:
    known_sync_uuids = [item for item in sync_uuids if item and item != "unknown"]
    if not known_sync_uuids:
        return {}

    semaphore = asyncio.Semaphore(6)

    async def worker(uuid_value: str) -> tuple[str, list[dict[str, str]]]:
        async with semaphore:
            return uuid_value, await fetch_live_sites_for_uuid(uuid_value)

    results = await asyncio.gather(*(worker(item) for item in known_sync_uuids))
    preview_map: dict[str, dict[str, Any]] = {}
    for uuid_value, sites in results:
        preview_map[uuid_value] = {
            "site_count": len(sites),
            "site_preview": [item["site_domain"] for item in sites[:3]],
        }
    return preview_map


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
        "encrypted_site_details_enabled": settings.encrypted_site_details_enabled,
        "active_nav": "settings",
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
    log_preview_map = await build_log_site_preview_map(
        [str(item["sync_uuid"]) for item in logs if item.get("sync_uuid") and item.get("sync_uuid") != "unknown"]
    )
    for item in logs:
        if item.get("site_count"):
            continue
        preview = log_preview_map.get(str(item.get("sync_uuid") or ""))
        if not preview:
            continue
        item["site_count"] = preview["site_count"]
        item["site_preview"] = preview["site_preview"]
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
            "sites_url": "/sites",
            "runtime_logs_url": "/runtime-logs",
            "app_log_path": str(settings.app_log_path),
            "active_nav": "dashboard",
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
    notification_public_base_url: str = Form(""),
    dashboard_username: str = Form(""),
    dashboard_password: str = Form(""),
    wecom_corp_id: str = Form(""),
    wecom_agent_id: str = Form(""),
    wecom_secret: str = Form(""),
    wecom_api_base_url: str = Form("https://qyapi.weixin.qq.com"),
    wecom_message_type: str = Form("news"),
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
        "notification_public_base_url": notification_public_base_url.strip().rstrip("/"),
        "dashboard_username": dashboard_username.strip(),
        "dashboard_password": dashboard_password.strip(),
        "wecom_corp_id": wecom_corp_id.strip(),
        "wecom_agent_id": wecom_agent_id.strip(),
        "wecom_secret": wecom_secret.strip(),
        "wecom_api_base_url": (wecom_api_base_url.strip() or "https://qyapi.weixin.qq.com").rstrip("/"),
        "wecom_message_type": normalize_wecom_message_type(wecom_message_type),
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

    if cleaned_values["notification_public_base_url"] and not cleaned_values["notification_public_base_url"].startswith(
        ("http://", "https://")
    ):
        return TEMPLATES.TemplateResponse(
            "settings.html",
            build_settings_page_context(
                request,
                error="通知外部访问地址必须以 http:// 或 https:// 开头。",
                form_overrides=form_values,
            ),
            status_code=400,
        )

    if not cleaned_values["wecom_api_base_url"].startswith(("http://", "https://")):
        return TEMPLATES.TemplateResponse(
            "settings.html",
            build_settings_page_context(
                request,
                error="企业微信 API 地址必须以 http:// 或 https:// 开头。",
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
    log = dict(row)
    sites = fetch_sync_sites_for_log(log_id)
    if not sites and log.get("sync_uuid") and log.get("sync_uuid") != "unknown":
        live_sites = await fetch_live_sites_for_uuid(str(log["sync_uuid"]))
        sites = [
            {
                "sync_log_id": log_id,
                "sync_uuid": log["sync_uuid"],
                "synced_at": log["occurred_at"],
                "site_name": item["site_name"],
                "site_domain": item["site_domain"],
            }
            for item in live_sites
        ]
    return TEMPLATES.TemplateResponse(
        "detail.html",
        {
            "request": request,
            "log": log,
            "sites": sites,
            "sites_url": "/sites",
            "dashboard_username": request.session.get("username") or settings.dashboard_username or "Monitor",
            "active_nav": "detail",
        },
    )


@app.get("/sites", response_class=HTMLResponse)
async def sites_page(
    request: Request,
    sync_uuid: str | None = Query(default=None),
    keyword: str | None = Query(default=None),
    outcome: str | None = Query(default=None),
    message: str = Query(default=""),
    error: str = Query(default=""),
) -> Response:
    redirect = require_page_auth(request)
    if redirect is not None:
        return redirect

    site_catalog = await build_live_site_catalog(sync_uuid=sync_uuid, keyword=keyword, outcome=outcome)
    return TEMPLATES.TemplateResponse(
        "sites.html",
        {
            "request": request,
            "site_catalog": site_catalog["items"],
            "site_summary": site_catalog["summary"],
            "filters": {
                "sync_uuid": sync_uuid or "",
                "keyword": keyword or "",
                "outcome": outcome or "",
            },
            "message": message,
            "error": error,
            "dashboard_url": "/dashboard",
            "runtime_logs_url": "/runtime-logs",
            "logout_url": "/auth/logout",
            "dashboard_username": request.session.get("username") or settings.dashboard_username or "Monitor",
            "active_nav": "sites",
        },
    )


@app.post("/sites/refresh")
async def refresh_sites(
    request: Request,
    sync_uuid: str = Form(""),
) -> Response:
    redirect = require_page_auth(request)
    if redirect is not None:
        return redirect

    result = await refresh_live_site_catalog(sync_uuid.strip() or None)
    query = f"sync_uuid={quote(sync_uuid.strip())}&" if sync_uuid.strip() else ""
    key = "message" if result["ok"] else "error"
    return RedirectResponse(url=f"/sites?{query}{key}={quote(result['message'])}", status_code=303)


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
            "dashboard_username": request.session.get("username") or settings.dashboard_username or "Monitor",
            "active_nav": "runtime_logs",
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
            "dashboard_username": request.session.get("username") or settings.dashboard_username or "Monitor",
            "active_nav": "runtime_logs",
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


@app.get("/api/sites")
async def api_sites(
    request: Request,
    sync_uuid: str | None = Query(default=None),
    keyword: str | None = Query(default=None),
    outcome: str | None = Query(default=None),
) -> dict[str, Any]:
    require_api_auth(request)
    return await build_live_site_catalog(sync_uuid=sync_uuid, keyword=keyword, outcome=outcome)
