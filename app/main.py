import hashlib
import json
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates


APP_ROOT = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(APP_ROOT / "templates"))
security = HTTPBasic(auto_error=False)


@dataclass(frozen=True)
class Settings:
    cookiecloud_target_url: str
    db_path: Path
    timezone_name: str
    dashboard_username: str
    dashboard_password: str
    recent_log_limit: int

    @property
    def timezone(self) -> ZoneInfo:
        return ZoneInfo(self.timezone_name)

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            cookiecloud_target_url=os.getenv("COOKIECLOUD_TARGET_URL", "http://cookiecloud:8088").rstrip("/"),
            db_path=Path(os.getenv("MONITOR_DB_PATH", "/data/monitor.db")),
            timezone_name=os.getenv("MONITOR_TIMEZONE", "Asia/Shanghai"),
            dashboard_username=os.getenv("DASHBOARD_USERNAME", ""),
            dashboard_password=os.getenv("DASHBOARD_PASSWORD", ""),
            recent_log_limit=max(int(os.getenv("RECENT_LOG_LIMIT", "50")), 10),
        )


settings = Settings.from_env()
app = FastAPI(title="CookieCloud Monitor", version="0.1.0")
app.mount("/static", StaticFiles(directory=str(APP_ROOT / "static")), name="static")


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


def get_db_connection() -> sqlite3.Connection:
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(settings.db_path)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with get_db_connection() as connection:
        connection.execute(CREATE_LOGS_SQL)
        connection.execute(CREATE_INDEX_SQL)
        connection.commit()


@app.on_event("startup")
def on_startup() -> None:
    init_db()


def now_local() -> datetime:
    return datetime.now(settings.timezone)


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


def require_dashboard_auth(credentials: HTTPBasicCredentials | None = Depends(security)) -> None:
    if not settings.dashboard_username and not settings.dashboard_password:
        return
    if credentials is None:
        raise HTTPException(status_code=401, headers={"WWW-Authenticate": "Basic"})
    username_matches = secrets.compare_digest(credentials.username, settings.dashboard_username)
    password_matches = secrets.compare_digest(credentials.password, settings.dashboard_password)
    if not (username_matches and password_matches):
        raise HTTPException(status_code=401, headers={"WWW-Authenticate": "Basic"})


async def forward_to_cookiecloud(
    *,
    method: str,
    path: str,
    data: Any = None,
    params: dict[str, Any] | None = None,
) -> httpx.Response:
    async with httpx.AsyncClient(timeout=15.0) as client:
        return await client.request(method, build_target_url(path), data=data, params=params)


@app.get("/", include_in_schema=False)
async def root() -> RedirectResponse:
    return RedirectResponse(url="/dashboard")


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/update")
async def proxy_update(request: Request) -> Response:
    form = await request.form()
    form_map: dict[str, Any] = dict(form.multi_items())
    sync_uuid = extract_candidate(form_map, "uuid", "userUUID", "user_uuid", "id")
    payload_size, payload_hash = build_payload_digest(form_map)
    start_time = time.perf_counter()

    try:
        upstream_response = await forward_to_cookiecloud(
            method="POST",
            path="/update",
            data=list(form.multi_items()),
        )
        duration_ms = int((time.perf_counter() - start_time) * 1000)
        raw_body = upstream_response.content
        json_body = maybe_json_bytes(raw_body)
        outcome, error_message = classify_upload(upstream_response.status_code, json_body, raw_body)
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
        return Response(
            content=raw_body,
            status_code=upstream_response.status_code,
            media_type=upstream_response.headers.get("content-type"),
            headers=filtered_response_headers(upstream_response.headers),
        )
    except httpx.HTTPError as exc:
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
        return JSONResponse(status_code=502, content={"status": "error", "message": "CookieCloud target is unavailable"})


@app.api_route("/get/{sync_uuid}", methods=["GET", "POST"])
async def proxy_get(sync_uuid: str, request: Request) -> Response:
    start_time = time.perf_counter()
    form_map: dict[str, Any] = {}
    params: dict[str, Any] = dict(request.query_params)
    data: Any = None

    if request.method == "POST":
        form = await request.form()
        form_map = dict(form.multi_items())
        data = list(form.multi_items())

    payload_size, payload_hash = build_payload_digest(form_map)

    try:
        upstream_response = await forward_to_cookiecloud(
            method=request.method,
            path=f"/get/{sync_uuid}",
            data=data,
            params=params or None,
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
        return Response(
            content=raw_body,
            status_code=upstream_response.status_code,
            media_type=upstream_response.headers.get("content-type"),
            headers=filtered_response_headers(upstream_response.headers),
        )
    except httpx.HTTPError as exc:
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
        return JSONResponse(status_code=502, content={"status": "error", "message": "CookieCloud target is unavailable"})


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
        },
        "daily_stats": daily_stats,
        "uuid_summary": uuid_summary,
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


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    sync_uuid: str | None = Query(default=None),
    action: str | None = Query(default=None),
    outcome: str | None = Query(default=None),
    day: str | None = Query(default=None),
    _: None = Depends(require_dashboard_auth),
) -> HTMLResponse:
    summary = fetch_summary_data()
    logs = fetch_recent_logs(sync_uuid=sync_uuid, action=action, outcome=outcome, day=day)
    return TEMPLATES.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "summary": summary,
            "logs": logs,
            "filters": {
                "sync_uuid": sync_uuid or "",
                "action": action or "",
                "outcome": outcome or "",
                "day": day or "",
            },
            "target_url": settings.cookiecloud_target_url,
            "recent_log_limit": settings.recent_log_limit,
        },
    )


@app.get("/logs/{log_id}", response_class=HTMLResponse)
async def log_detail(
    log_id: int,
    request: Request,
    _: None = Depends(require_dashboard_auth),
) -> HTMLResponse:
    with get_db_connection() as connection:
        row = connection.execute("SELECT * FROM sync_logs WHERE id = ?", (log_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Log not found")
    return TEMPLATES.TemplateResponse("detail.html", {"request": request, "log": dict(row)})


@app.get("/api/summary")
async def api_summary(_: None = Depends(require_dashboard_auth)) -> dict[str, Any]:
    return fetch_summary_data()


@app.get("/api/logs")
async def api_logs(
    sync_uuid: str | None = Query(default=None),
    action: str | None = Query(default=None),
    outcome: str | None = Query(default=None),
    day: str | None = Query(default=None),
    _: None = Depends(require_dashboard_auth),
) -> dict[str, Any]:
    return {"items": fetch_recent_logs(sync_uuid=sync_uuid, action=action, outcome=outcome, day=day)}
