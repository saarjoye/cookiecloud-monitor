# CookieCloud Monitor

CookieCloud Monitor is a standalone proxy service for [CookieCloud](https://github.com/easychen/CookieCloud).
It sits in front of CookieCloud, records sync activity into SQLite, exposes a web dashboard, adds a dedicated login page, and can push sync/login alerts to a WeCom application.

## What It Does

- Proxies CookieCloud upload and download traffic through `POST /update` and `GET/POST /get/{uuid}`
- Stores sync request metadata in SQLite
- Shows daily metrics, recent logs, 7-day trend, and UUID summary in a web dashboard
- Replaces browser basic-auth popups with a proper session-based login page
- Tracks first syncs and CK count changes when payloads can be parsed
- Pushes login and sync notifications to a WeCom app

## Architecture

The browser extension points to this service instead of pointing to CookieCloud directly:

1. The extension sends sync requests to CookieCloud Monitor
2. CookieCloud Monitor forwards the request to the real CookieCloud server
3. The proxy records metadata and renders operational dashboards
4. Optional WeCom notifications are sent for important events

The proxy does not persist raw cookie plaintext or LocalStorage plaintext.

## Quick Start

### Docker Compose

```yaml
services:
  monitor:
    image: ghcr.io/saarjoye/cookiecloud-monitor:latest
    container_name: cookiecloud-monitor
    restart: unless-stopped
    environment:
      COOKIECLOUD_TARGET_URL: http://192.168.1.2:8088
      MONITOR_DB_PATH: /data/monitor.db
      MONITOR_TIMEZONE: Asia/Shanghai
      DASHBOARD_USERNAME: admin
      DASHBOARD_PASSWORD: change-me
      SESSION_SECRET: replace-with-a-long-random-string
      RECENT_LOG_LIMIT: 50
    volumes:
      - /home/docker/cookiecloud-monitor/data:/data
    ports:
      - "8090:8090"
```

If you want to build locally instead of using the published image:

```bash
docker compose up -d --build
```

### Browser Extension Target

Point the CookieCloud browser extension to:

```text
http://YOUR_SERVER_IP:8090
```

### Dashboard

Open:

```text
http://YOUR_SERVER_IP:8090/dashboard
```

If dashboard credentials are configured, unauthenticated users are redirected to `/login`.

## Environment Variables

| Variable | Description | Default |
| --- | --- | --- |
| `COOKIECLOUD_TARGET_URL` | Upstream CookieCloud URL | `http://cookiecloud:8088` |
| `MONITOR_DB_PATH` | SQLite database path | `/data/monitor.db` |
| `MONITOR_TIMEZONE` | Display timezone | `Asia/Shanghai` |
| `DASHBOARD_USERNAME` | Dashboard username | empty |
| `DASHBOARD_PASSWORD` | Dashboard password | empty |
| `RECENT_LOG_LIMIT` | Recent log rows on dashboard | `50` |
| `SESSION_SECRET` | Session signing secret | random at boot if empty |
| `SESSION_COOKIE_NAME` | Session cookie name | `cookiecloud_monitor_session` |
| `SESSION_MAX_AGE` | Session lifetime in seconds | `1209600` |
| `WECOM_CORP_ID` | WeCom corp ID | empty |
| `WECOM_AGENT_ID` | WeCom agent ID | empty |
| `WECOM_SECRET` | WeCom app secret | empty |
| `WECOM_TO_USER` | WeCom target user(s) | empty |
| `WECOM_TO_PARTY` | WeCom target department(s) | empty |
| `WECOM_TO_TAG` | WeCom target tag(s) | empty |

## WeCom Notifications

When WeCom credentials are configured, the service can send markdown notifications for:

- Successful dashboard logins
- First-time sync for a UUID
- CK count increase
- CK count decrease
- Payload updates when the payload hash changes

CK count tracking is best-effort. If CookieCloud sends only encrypted payloads, the proxy can still detect first syncs and payload updates, but may not be able to calculate exact CK counts.

## API Endpoints

- `GET /dashboard` - dashboard page
- `GET /login` - React login page
- `POST /auth/login` - session login
- `POST /auth/logout` - session logout
- `GET /api/me` - current auth/session info
- `GET /api/summary` - dashboard summary JSON
- `GET /api/logs` - recent log JSON
- `POST /update` - proxy upload request to CookieCloud
- `GET/POST /get/{uuid}` - proxy download request to CookieCloud
- `GET /healthz` - health check

## Docker Image Publishing

GitHub Actions publishes images through `.github/workflows/publish-image.yml`.

Default target:

- `ghcr.io/saarjoye/cookiecloud-monitor`

Optional Docker Hub target:

- `docker.io/<your-dockerhub-username>/cookiecloud-monitor`

To enable Docker Hub publishing, configure these repository values:

| Type | Name |
| --- | --- |
| Variable | `DOCKERHUB_USERNAME` |
| Secret | `DOCKERHUB_TOKEN` |

## Local Development

Frontend:

```bash
cd frontend
npm install
npm run build
```

Backend syntax check:

```bash
python -m compileall app
```
